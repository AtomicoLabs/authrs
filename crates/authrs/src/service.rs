use crate::crypto::{self, JwtIssuer};
use sha2::{Digest, Sha256};
use crate::error::{AuthError, DeliverError};
use crate::http::HttpClient;
use crate::mail::{self, Mailer, Outgoing};
use crate::oauth;
use authrs_store::{EmailSettings, Flags, Hold, NewUser, OtpCheck, ProviderRow, Store, StoreError, TemplateRow, UserRow};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Url,
    WebauthnBuilder,
};

const ACCESS_TTL: u64 = 900;
const REFRESH_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const MINUTE: i64 = 60_000;

/// What the host application decides for each request.
pub trait Host: Send + Sync {
    /// Tenant for this request. One deployment may use a single id.
    fn tenant(&self, headers: &HeaderMap) -> Uuid;
    /// Extra access-token claims. `sub`, `role`, `exp`, and `iat` are ignored.
    fn claims(&self, tenant: Uuid, user: Uuid) -> Map<String, Value>;
    /// When false, `POST /auth/v1/invite` returns 401.
    fn invite_allowed(&self, headers: &HeaderMap) -> bool;
    /// Public origin used in links, without a trailing slash.
    fn public_base(&self) -> String;
    /// Relying-party and mail display name.
    fn display_name(&self) -> String;
}

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }
}

#[derive(Clone)]
pub struct Auth {
    pub store: Arc<dyn Store>,
    pub host: Arc<dyn Host>,
    pub mailer: Arc<dyn Mailer>,
    pub http: Arc<dyn HttpClient>,
    pub issuer: Arc<JwtIssuer>,
    pub clock: Arc<dyn Clock>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActorKind {
    User,
    Enroll,
}

struct Actor {
    user: UserRow,
    kind: ActorKind,
}

fn bad(message: &str) -> AuthError {
    AuthError::bad(message)
}

fn denied() -> AuthError {
    AuthError::unauthorized("invalid credentials")
}

fn expired_token() -> AuthError {
    AuthError::unauthorized("invalid or expired token")
}

fn too_many() -> AuthError {
    AuthError::new(StatusCode::TOO_MANY_REQUESTS, "too many requests")
}

fn store_err(err: StoreError) -> AuthError {
    match err {
        StoreError::Conflict => AuthError::new(StatusCode::CONFLICT, "email exists"),
        _ => AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

fn ok_body() -> Response {
    Json(json!({"ok": true})).into_response()
}

fn email_of(value: &str) -> Result<String, AuthError> {
    let email = value.trim().to_ascii_lowercase();
    if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        return Err(bad("invalid email"));
    }
    Ok(email)
}

fn field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(Value::as_str).unwrap_or("")
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-authrs-client-ip")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

fn origin_header(headers: &HeaderMap) -> Result<String, AuthError> {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| bad("origin required for passkeys"))
}

fn redirect_to(url: &str, key: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{key}={}", encode(value))
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn found(url: String) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url)]).into_response()
}

impl Auth {
    pub fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    async fn limit(&self, headers: &HeaderMap, tenant: Uuid, kind: &str, max: i64) -> Result<(), AuthError> {
        let count = self
            .store
            .record_attempt(Uuid::new_v4(), tenant, &client_ip(headers), kind, self.now())
            .await.map_err(store_err)?;
        if count >= max {
            return Err(too_many());
        }
        Ok(())
    }

    async fn flags(&self, tenant: Uuid) -> Result<Flags, AuthError> {
        self.store.flags(tenant).await.map_err(store_err)
    }

    pub async fn provision(&self, tenant: Uuid, name: &str) -> Result<(), AuthError> {
        self.store.ensure_tenant(tenant, name).await.map_err(store_err)
    }

    pub async fn set_flags(&self, tenant: Uuid, require_email_verification: bool, require_mfa: bool) -> Result<(), AuthError> {
        self.store
            .ensure_tenant(tenant, "")
            .await.map_err(store_err)?;
        self.store
            .set_flags(
                tenant,
                Flags {
                    require_email_verification,
                    require_mfa,
                },
            )
            .await
            .map_err(store_err)
    }

    pub async fn put_email(&self, tenant: Uuid, settings: EmailSettings) -> Result<(), AuthError> {
        let mut settings = settings;
        if !settings.password_enc.is_empty() {
            settings.password_enc = crypto::seal(self.issuer.seal_key(), settings.password_enc.as_bytes()).map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        }
        self.store.set_email(tenant, settings).await.map_err(store_err)
    }

    pub async fn email_view(&self, tenant: Uuid) -> Result<Value, AuthError> {
        let Some(settings) = self.store.email_settings(tenant).await.map_err(store_err)? else {
            return Ok(json!({"configured": false}));
        };
        Ok(json!({
            "configured": true,
            "host": settings.host,
            "port": settings.port,
            "username": settings.username,
            "from_address": settings.from_address,
            "tls": settings.tls,
            "link_base": settings.link_base,
            "password_set": !settings.password_enc.is_empty()
        }))
    }

    pub async fn put_template(&self, tenant: Uuid, name: &str, row: TemplateRow) -> Result<(), AuthError> {
        self.store.set_template(tenant, name, row).await.map_err(store_err)
    }

    pub async fn delete_template(&self, tenant: Uuid, name: &str) -> Result<(), AuthError> {
        self.store.delete_template(tenant, name).await.map_err(store_err)
    }

    pub async fn put_provider(&self, tenant: Uuid, name: &str, mut row: ProviderRow) -> Result<(), AuthError> {
        if oauth::known(name).is_none() {
            return Err(AuthError::new(StatusCode::NOT_FOUND, "unknown provider"));
        }
        if !row.secret_enc.is_empty() {
            row.secret_enc = crypto::seal(self.issuer.seal_key(), row.secret_enc.as_bytes()).map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        }
        self.store.upsert_provider(tenant, name, row).await.map_err(store_err)
    }

    pub async fn delete_provider(&self, tenant: Uuid, name: &str) -> Result<(), AuthError> {
        self.store.delete_provider(tenant, name).await.map_err(store_err)
    }

    async fn issue(&self, user: &UserRow) -> Result<Response, AuthError> {
        let refresh = crypto::random_token();
        let expires = self.now() + REFRESH_MS;
        self.store
            .insert_session(Uuid::new_v4(), user.id, &crypto::token_hash(&refresh), expires)
            .await.map_err(store_err)?;
        let access = self
            .issuer
            .sign(
                &user.id.to_string(),
                "authenticated",
                &self.host.claims(user.tenant_id, user.id),
                ACCESS_TTL,
            ).map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        Ok(Json(json!({
            "access_token": access,
            "refresh_token": refresh,
            "user": {"id": user.id, "email": user.email}
        }))
        .into_response())
    }

    async fn deliver(
        &self,
        tenant: Uuid,
        to: &str,
        template: &str,
        token: &str,
        code: &str,
    ) -> Result<(), DeliverError> {
        let Some(settings) = self.store.email_settings(tenant).await.map_err(|_| DeliverError::Failed)? else {
            return Err(DeliverError::Unconfigured);
        };
        if settings.host.is_empty() {
            return Err(DeliverError::Unconfigured);
        }
        let custom = self
            .store
            .template(tenant, template)
            .await.map_err(|_| DeliverError::Failed)?;
        let (subject, text, html) = if let Some(row) = custom {
            (row.subject, row.body_text, row.body_html)
        } else if let Some(row) = mail::reserved_template(template) {
            (row.subject.to_string(), row.body_text.to_string(), row.body_html.to_string())
        } else {
            return Err(DeliverError::Failed);
        };
        let link = mail::auth_link(&settings.link_base, token);
        let text = mail::fill(&text, to, token, &link, code);
        let html = mail::fill(&html, to, token, &link, code);
        let subject = mail::fill(&subject, to, token, &link, code);
        let password = if settings.password_enc.is_empty() {
            String::new()
        } else {
            let bytes = crypto::unseal(self.issuer.seal_key(), &settings.password_enc).map_err(|_| DeliverError::Failed)?;
            String::from_utf8(bytes).map_err(|_| DeliverError::Failed)?
        };
        self.mailer.send(&Outgoing {
            to: to.to_string(),
            subject,
            text,
            html,
            from: settings.from_address,
            host: settings.host,
            port: settings.port as u16,
            username: settings.username,
            password,
            tls: settings.tls,
        })
    }

    pub async fn signup(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        self.store.ensure_tenant(tenant, "").await.map_err(store_err)?;
        self.limit(headers, tenant, "signup", 30).await?;
        let email = email_of(field(body, "email"))?;
        let password = field(body, "password");
        if password.len() < 8 {
            return Err(bad("password too short"));
        }
        if self.store.user_by_email(tenant, &email).await.map_err(store_err)?.is_some() {
            return Err(AuthError::new(StatusCode::CONFLICT, "email exists"));
        }
        let hash = crypto::hash_password(password).map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        let now = self.now();
        let flags = self.flags(tenant).await?;
        let user = NewUser {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            email: email.clone(),
            password_hash: Some(hash),
            email_verified_at: if flags.require_email_verification { None } else { Some(now) },
            created_at: now,
        };
        self.store.insert_user(user.clone()).await.map_err(store_err)?;
        if !flags.require_email_verification {
            let row = self.store.user_by_id(user.id).await.map_err(store_err)?.expect("user");
            return self.issue(&row).await;
        }
        let token = crypto::random_token();
        let code = crypto::code();
        let id = Uuid::new_v4();
        self.store
            .insert_challenge(
                id,
                tenant,
                Some(user.id),
                &email,
                "confirm_email",
                Some(&crypto::token_hash(&token)),
                Some(&crypto::token_hash(&code)),
                now + 24 * 60 * MINUTE,
                now,
            )
            .await.map_err(store_err)?;
        match self.deliver(tenant, &email, "confirm_email", &token, &code).await {
            Ok(()) => Ok(Json(json!({
                "verification_required": true,
                "user": {"id": user.id, "email": email}
            }))
            .into_response()),
            Err(DeliverError::Unconfigured) => {
                self.store.delete_user(user.id).await.map_err(store_err)?;
                Err(AuthError::new(StatusCode::SERVICE_UNAVAILABLE, "email is not configured"))
            }
            Err(DeliverError::Failed) => {
                self.store.delete_user(user.id).await.map_err(store_err)?;
                Err(AuthError::new(StatusCode::BAD_GATEWAY, "email could not be sent"))
            }
        }
    }

    pub async fn token(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        if let Some(refresh) = body.get("refresh_token").and_then(Value::as_str) {
            return self.refresh(refresh).await;
        }
        if let Some(code) = body.get("code").and_then(Value::as_str) {
            return self.exchange_code(headers, code).await;
        }
        self.password_login(headers, body).await
    }

    async fn refresh(&self, refresh: &str) -> Result<Response, AuthError> {
        let next = crypto::random_token();
        let now = self.now();
        let user = self
            .store
            .rotate_session(&crypto::token_hash(refresh), Uuid::new_v4(), &crypto::token_hash(&next), now, now + REFRESH_MS)
            .await
            .map_err(store_err)?
            .ok_or_else(expired_token)?;
        let access = self
            .issuer
            .sign(&user.id.to_string(), "authenticated", &self.host.claims(user.tenant_id, user.id), ACCESS_TTL).map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        Ok(Json(json!({
            "access_token": access,
            "refresh_token": next,
            "user": {"id": user.id, "email": user.email}
        }))
        .into_response())
    }

    async fn exchange_code(&self, headers: &HeaderMap, code: &str) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        let row = self
            .store
            .consume_token(tenant, &crypto::token_hash(code), "oauth_code", self.now())
            .await
            .map_err(store_err)?
            .ok_or_else(expired_token)?;
        let user_id = row.user_id.ok_or_else(expired_token)?;
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        self.issue(&user).await
    }

    async fn password_login(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        self.store.ensure_tenant(tenant, "").await.map_err(store_err)?;
        self.limit(headers, tenant, "token", 60).await?;
        let email = email_of(field(body, "email")).unwrap_or_default();
        let password = field(body, "password");
        let Some(user) = self.store.user_by_email(tenant, &email).await.map_err(store_err)? else {
            return Err(denied());
        };
        let Some(hash) = user.password_hash.as_deref() else {
            return Err(denied());
        };
        if !crypto::verify_password(password, hash) {
            return Err(denied());
        }
        let flags = self.flags(tenant).await?;
        if flags.require_email_verification && user.email_verified_at.is_none() {
            return Ok(Json(json!({
                "verification_required": true,
                "user": {"id": user.id, "email": user.email}
            }))
            .into_response());
        }
        if flags.require_mfa {
            return self.after_password(&user).await;
        }
        self.issue(&user).await
    }

    async fn after_password(&self, user: &UserRow) -> Result<Response, AuthError> {
        let names = self.factor_names(user.id).await?;
        let token = crypto::random_token();
        let kind = if names.is_empty() { "enroll" } else { "mfa" };
        let now = self.now();
        self.store
            .insert_challenge(
                Uuid::new_v4(),
                user.tenant_id,
                Some(user.id),
                &user.email,
                kind,
                Some(&crypto::token_hash(&token)),
                None,
                now + 5 * MINUTE,
                now,
            )
            .await.map_err(store_err)?;
        if names.is_empty() {
            Ok(Json(json!({"enrollment_required": true, "enroll_token": token, "factors": names})).into_response())
        } else {
            Ok(Json(json!({"mfa_required": true, "mfa_token": token, "factors": names})).into_response())
        }
    }

    async fn factor_names(&self, user: Uuid) -> Result<Vec<&'static str>, AuthError> {
        let rows = self.store.factors(user).await.map_err(store_err)?;
        let mut names = Vec::new();
        for row in rows {
            if row.kind == "totp" && row.secret.is_some() {
                names.push("totp");
            }
            if row.kind == "passkey" && row.credential.is_some() {
                names.push("passkey");
            }
        }
        names.sort();
        Ok(names)
    }

    pub async fn logout(&self, body: &Value) -> Result<Response, AuthError> {
        if let Some(refresh) = body.get("refresh_token").and_then(Value::as_str) {
            self.store
                .delete_session(&crypto::token_hash(refresh))
                .await.map_err(store_err)?;
        }
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    pub async fn user(&self, headers: &HeaderMap) -> Result<Response, AuthError> {
        let token = bearer(headers).ok_or_else(|| AuthError::unauthorized("invalid credentials"))?;
        let (sub, role) = self.issuer.subject_role(&token).map_err(|_| AuthError::unauthorized("invalid credentials"))?;
        if role != "authenticated" {
            return Err(AuthError::unauthorized("invalid credentials"));
        }
        let id = Uuid::parse_str(&sub).map_err(|_| AuthError::unauthorized("invalid credentials"))?;
        let user = self.store.user_by_id(id).await.map_err(store_err)?.ok_or_else(|| AuthError::unauthorized("invalid credentials"))?;
        Ok(Json(json!({
            "id": user.id,
            "email": user.email,
            "email_verified_at": user.email_verified_at
        }))
        .into_response())
    }

    pub async fn verify_email(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        if let Some(token) = body.get("token").and_then(Value::as_str).filter(|value| !value.is_empty()) {
            let row = self
                .store
                .consume_token(tenant, &crypto::token_hash(token), "confirm_email", self.now())
                .await
                .map_err(store_err)?
                .ok_or_else(expired_token)?;
            return self.finish_verify(row.user_id).await;
        }
        let email = email_of(field(body, "email"))?;
        let code = field(body, "code");
        let Some(open) = self
            .store
            .latest_open(tenant, &email, "confirm_email", self.now())
            .await
            .map_err(store_err)?
        else {
            return Err(expired_token());
        };
        if open.code_hash.as_deref() != Some(crypto::token_hash(code).as_str()) {
            let next = open.attempts + 1;
            let consume = if next >= 5 { Some(self.now()) } else { None };
            self.store.set_attempts(open.id, next, consume).await.map_err(store_err)?;
            return Err(expired_token());
        }
        self.store
            .set_attempts(open.id, open.attempts, Some(self.now()))
            .await.map_err(store_err)?;
        self.finish_verify(open.user_id).await
    }

    async fn finish_verify(&self, user_id: Option<Uuid>) -> Result<Response, AuthError> {
        let user_id = user_id.ok_or_else(expired_token)?;
        self.store.mark_verified(user_id, self.now()).await.map_err(store_err)?;
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        self.issue(&user).await
    }

    pub async fn resend(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        let Ok(email) = email_of(field(body, "email")) else {
            return Ok(ok_body());
        };
        let Some(user) = self.store.user_by_email(tenant, &email).await.map_err(store_err)? else {
            return Ok(ok_body());
        };
        if user.email_verified_at.is_some() {
            return Ok(ok_body());
        }
        let now = self.now();
        let (minute, _, _) = self
            .store
            .count_email_kind_window(tenant, &email, "confirm_email", now - MINUTE, now - MINUTE, now - MINUTE)
            .await.map_err(store_err)?;
        if minute > 0 {
            return Ok(ok_body());
        }
        while let Some(open) = self
            .store
            .latest_open(tenant, &email, "confirm_email", now)
            .await
            .map_err(store_err)?
        {
            self.store
                .set_attempts(open.id, open.attempts, Some(now))
                .await.map_err(store_err)?;
        }
        let token = crypto::random_token();
        let code = crypto::code();
        self.store
            .insert_challenge(
                Uuid::new_v4(),
                tenant,
                Some(user.id),
                &email,
                "confirm_email",
                Some(&crypto::token_hash(&token)),
                Some(&crypto::token_hash(&code)),
                now + 24 * 60 * MINUTE,
                now,
            )
            .await.map_err(store_err)?;
        let _ = self.deliver(tenant, &email, "confirm_email", &token, &code).await;
        Ok(ok_body())
    }

    pub async fn magic_link(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        self.store.ensure_tenant(tenant, "").await.map_err(store_err)?;
        self.limit(headers, tenant, "magic_link", 30).await?;
        let Ok(email) = email_of(field(body, "email")) else {
            return Ok(ok_body());
        };
        let now = self.now();
        if self
            .store
            .count_recent(tenant, &email, "magic_link", now - MINUTE)
            .await
            .map_err(store_err)?
            > 0
        {
            return Ok(ok_body());
        }
        let existing = self.store.user_by_email(tenant, &email).await.map_err(store_err)?;
        let created = existing.is_none();
        let user_id = if let Some(user) = existing {
            user.id
        } else {
            let id = Uuid::new_v4();
            self.store
                .insert_user(NewUser {
                    id,
                    tenant_id: tenant,
                    email: email.clone(),
                    password_hash: None,
                    email_verified_at: None,
                    created_at: now,
                })
                .await.map_err(store_err)?;
            id
        };
        let token = crypto::random_token();
        let challenge = Uuid::new_v4();
        self.store
            .insert_challenge(
                challenge,
                tenant,
                Some(user_id),
                &email,
                "magic_link",
                Some(&crypto::token_hash(&token)),
                None,
                now + 15 * MINUTE,
                now,
            )
            .await.map_err(store_err)?;
        if self.deliver(tenant, &email, "magic_link", &token, "").await.is_err() {
            self.store.delete_challenge(challenge).await.map_err(store_err)?;
            if created {
                self.store.delete_user(user_id).await.map_err(store_err)?;
            }
        }
        Ok(ok_body())
    }

    pub async fn verify_magic(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        let token = field(body, "token");
        let row = self
            .store
            .consume_token(tenant, &crypto::token_hash(token), "magic_link", self.now())
            .await
            .map_err(store_err)?
            .ok_or_else(expired_token)?;
        self.finish_verify(row.user_id).await
    }

    pub async fn recover(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        self.store.ensure_tenant(tenant, "").await.map_err(store_err)?;
        self.limit(headers, tenant, "recover", 30).await?;
        let Ok(email) = email_of(field(body, "email")) else {
            return Ok(ok_body());
        };
        let Some(user) = self.store.user_by_email(tenant, &email).await.map_err(store_err)? else {
            return Ok(ok_body());
        };
        let now = self.now();
        if self
            .store
            .count_recent(tenant, &email, "recovery", now - MINUTE)
            .await
            .map_err(store_err)?
            > 0
        {
            return Ok(ok_body());
        }
        let token = crypto::random_token();
        let challenge = Uuid::new_v4();
        self.store
            .insert_challenge(
                challenge,
                tenant,
                Some(user.id),
                &email,
                "recovery",
                Some(&crypto::token_hash(&token)),
                None,
                now + 15 * MINUTE,
                now,
            )
            .await.map_err(store_err)?;
        if self.deliver(tenant, &email, "recovery", &token, "").await.is_err() {
            self.store.delete_challenge(challenge).await.map_err(store_err)?;
        }
        Ok(ok_body())
    }

    pub async fn recover_complete(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        let password = field(body, "password");
        if password.len() < 8 {
            return Err(bad("password too short"));
        }
        let row = self
            .store
            .consume_token(tenant, &crypto::token_hash(field(body, "token")), "recovery", self.now())
            .await
            .map_err(store_err)?
            .ok_or_else(expired_token)?;
        self.finish_password(row.user_id, password).await
    }

    async fn finish_password(&self, user_id: Option<Uuid>, password: &str) -> Result<Response, AuthError> {
        let user_id = user_id.ok_or_else(expired_token)?;
        let hash = crypto::hash_password(password).map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        self.store.set_password(user_id, &hash).await.map_err(store_err)?;
        self.store.mark_verified(user_id, self.now()).await.map_err(store_err)?;
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        self.issue(&user).await
    }

    pub async fn invite(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        if !self.host.invite_allowed(headers) {
            return Err(AuthError::unauthorized("unauthorized"));
        }
        let tenant = self.host.tenant(headers);
        self.store.ensure_tenant(tenant, "").await.map_err(store_err)?;
        self.limit(headers, tenant, "invite", 30).await?;
        let email = email_of(field(body, "email"))?;
        if self.store.user_by_email(tenant, &email).await.map_err(store_err)?.is_some() {
            return Err(AuthError::new(StatusCode::CONFLICT, "email exists"));
        }
        let now = self.now();
        let user_id = Uuid::new_v4();
        self.store
            .insert_user(NewUser {
                id: user_id,
                tenant_id: tenant,
                email: email.clone(),
                password_hash: None,
                email_verified_at: None,
                created_at: now,
            })
            .await.map_err(store_err)?;
        let token = crypto::random_token();
        let challenge = Uuid::new_v4();
        self.store
            .insert_challenge(
                challenge,
                tenant,
                Some(user_id),
                &email,
                "invite",
                Some(&crypto::token_hash(&token)),
                None,
                now + 7 * 24 * 60 * MINUTE,
                now,
            )
            .await.map_err(store_err)?;
        match self.deliver(tenant, &email, "invite", &token, "").await {
            Ok(()) => Ok(ok_body()),
            Err(DeliverError::Unconfigured) => {
                self.store.delete_user(user_id).await.map_err(store_err)?;
                Err(AuthError::new(StatusCode::SERVICE_UNAVAILABLE, "email is not configured"))
            }
            Err(DeliverError::Failed) => {
                self.store.delete_user(user_id).await.map_err(store_err)?;
                Err(AuthError::new(StatusCode::BAD_GATEWAY, "email could not be sent"))
            }
        }
    }

    pub async fn invite_accept(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let password = field(body, "password");
        if password.len() < 8 {
            return Err(bad("password too short"));
        }
        let tenant = self.host.tenant(headers);
        let row = self
            .store
            .consume_token(tenant, &crypto::token_hash(field(body, "token")), "invite", self.now())
            .await
            .map_err(store_err)?
            .ok_or_else(expired_token)?;
        self.finish_password(row.user_id, password).await
    }

    pub async fn otp(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        self.store.ensure_tenant(tenant, "").await.map_err(store_err)?;
        let email = email_of(field(body, "email"))?;
        self.limit(headers, tenant, "otp", 20).await?;
        let now = self.now();
        let code = crypto::code();
        let id = Uuid::new_v4();
        let hold = self
            .store
            .hold_otp(
                tenant,
                &email,
                id,
                &crypto::token_hash(&crypto::random_token()),
                &crypto::token_hash(&code),
                now,
                now + 10 * MINUTE,
            )
            .await.map_err(store_err)?;
        match hold {
            Hold::Cooldown => Ok(ok_body()),
            Hold::Limited => Err(too_many()),
            Hold::Created => {
                if self.deliver(tenant, &email, "otp", "", &code).await.is_err() {
                    self.store.delete_challenge(id).await.map_err(store_err)?;
                } else {
                    self.store.supersede_otp(tenant, &email, id, now).await.map_err(store_err)?;
                }
                Ok(ok_body())
            }
        }
    }

    pub async fn otp_verify(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        self.limit(headers, tenant, "otp_verify", 30).await?;
        let email = email_of(field(body, "email"))?;
        let code = field(body, "code");
        match self
            .store
            .check_otp(tenant, &email, &crypto::token_hash(code), self.now(), 5)
            .await
            .map_err(store_err)?
        {
            OtpCheck::Limited => Err(too_many()),
            OtpCheck::Invalid => Err(bad("invalid or expired code")),
            OtpCheck::User(id) => {
                let user = self.store.user_by_id(id).await.map_err(store_err)?.ok_or_else(|| bad("invalid or expired code"))?;
                self.issue(&user).await
            }
        }
    }

    pub async fn authorize(&self, headers: &HeaderMap, provider: &str, redirect: &str) -> Result<Response, AuthError> {
        let catalog = oauth::known(provider).ok_or_else(|| AuthError::new(StatusCode::NOT_FOUND, "unknown provider"))?;
        let tenant = self.host.tenant(headers);
        let row = self
            .store
            .provider(tenant, provider)
            .await
            .map_err(store_err)?
            .filter(|row| row.enabled)
            .ok_or_else(|| AuthError::new(StatusCode::NOT_FOUND, "not found"))?;
        if !row.redirects.iter().any(|item| item == redirect) {
            return Err(bad("redirect is not allowed"));
        }
        let extra: Map<String, Value> = serde_json::from_str(&row.extra).unwrap_or_default();
        let verifier = crypto::random_token();
        let challenge = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(verifier.as_bytes()),
        );
        let state = crypto::random_token();
        let now = self.now();
        self.store
            .insert_oauth_tx(&state, tenant, provider, &verifier, redirect, now + 10 * MINUTE)
            .await.map_err(store_err)?;
        let callback = format!("{}/auth/v1/callback/{provider}", self.host.public_base().trim_end_matches('/'));
        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&scope={}",
            oauth::endpoint(catalog.authorize_url, &extra, "authorize_url"),
            encode(&row.client_id),
            encode(&callback),
            encode(&state),
            encode(&challenge),
            encode(catalog.scopes)
        );
        if provider == "apple" {
            url.push_str("&response_mode=form_post");
        }
        Ok(found(url))
    }

    pub async fn callback(&self, provider: &str, code: &str, state: &str, provider_error: &str) -> Result<Response, AuthError> {
        let now = self.now();
        let Some(tx) = self.store.take_oauth_tx(state, now).await.map_err(store_err)? else {
            return Err(bad("invalid or expired state"));
        };
        if !provider_error.is_empty() || code.is_empty() {
            return Ok(found(redirect_to(&tx.redirect_to, "error", "access_denied")));
        }
        let catalog = oauth::known(provider).ok_or_else(|| AuthError::new(StatusCode::NOT_FOUND, "unknown provider"))?;
        let row = self
            .store
            .provider(tx.tenant_id, provider)
            .await
            .map_err(store_err)?
            .ok_or_else(|| AuthError::new(StatusCode::NOT_FOUND, "not found"))?;
        let extra: Map<String, Value> = serde_json::from_str(&row.extra).unwrap_or_default();
        let secret = if row.secret_enc.is_empty() {
            String::new()
        } else {
            match crypto::unseal(self.issuer.seal_key(), &row.secret_enc) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
                Err(_) => return Ok(found(redirect_to(&tx.redirect_to, "error", "provider"))),
            }
        };
        let client_secret = match oauth::client_secret(provider, &secret, &row.client_id, &extra) {
            Ok(value) => value,
            Err(_) => return Ok(found(redirect_to(&tx.redirect_to, "error", "provider"))),
        };
        let callback = format!(
            "{}/auth/v1/callback/{provider}",
            self.host.public_base().trim_end_matches('/')
        );
        let token = match self.http.post_form(
            &oauth::endpoint(catalog.token_url, &extra, "token_url"),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &callback),
                ("client_id", &row.client_id),
                ("client_secret", &client_secret),
                ("code_verifier", &tx.verifier),
            ],
        ) {
            Ok(value) => value,
            Err(_) => return Ok(found(redirect_to(&tx.redirect_to, "error", "provider"))),
        };
        let profile = match oauth::read_profile(
            provider,
            &token,
            self.http.as_ref(),
            &oauth::endpoint(catalog.userinfo_url, &extra, "userinfo_url"),
        ) {
            Ok(value) => value,
            Err(_) => return Ok(found(redirect_to(&tx.redirect_to, "error", "provider"))),
        };
        if profile.provider_user.is_empty() {
            return Ok(found(redirect_to(&tx.redirect_to, "error", "provider")));
        }
        let email = profile.email.as_deref().unwrap_or("").trim().to_ascii_lowercase();
        let user_id = if let Some(existing) = self
            .store
            .find_identity(tx.tenant_id, provider, &profile.provider_user)
            .await
            .map_err(store_err)?
        {
            existing
        } else if profile.verified && !email.is_empty() {
            if let Some(user) = self.store.user_by_email(tx.tenant_id, &email).await.map_err(store_err)? {
                self.store
                    .insert_identity(Uuid::new_v4(), tx.tenant_id, user.id, provider, &profile.provider_user, &email, now)
                    .await.map_err(store_err)?;
                user.id
            } else {
                let id = Uuid::new_v4();
                self.store
                    .insert_user(NewUser {
                        id,
                        tenant_id: tx.tenant_id,
                        email: email.clone(),
                        password_hash: None,
                        email_verified_at: Some(now),
                        created_at: now,
                    })
                    .await.map_err(store_err)?;
                self.store
                    .insert_identity(Uuid::new_v4(), tx.tenant_id, id, provider, &profile.provider_user, &email, now)
                    .await.map_err(store_err)?;
                id
            }
        } else {
            return Ok(found(redirect_to(&tx.redirect_to, "error", "email_not_verified")));
        };
        let one_time = crypto::random_token();
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        self.store
            .insert_challenge(
                Uuid::new_v4(),
                tx.tenant_id,
                Some(user_id),
                &user.email,
                "oauth_code",
                Some(&crypto::token_hash(&one_time)),
                None,
                now + 10 * MINUTE,
                now,
            )
            .await.map_err(store_err)?;
        Ok(found(redirect_to(&tx.redirect_to, "code", &one_time)))
    }

    async fn actor(&self, headers: &HeaderMap) -> Result<Actor, AuthError> {
        let token = bearer(headers).ok_or_else(expired_token)?;
        if let Ok((sub, role)) = self.issuer.subject_role(&token) {
            if role == "authenticated" {
                let id = Uuid::parse_str(&sub).map_err(|_| expired_token())?;
                let user = self.store.user_by_id(id).await.map_err(store_err)?.ok_or_else(expired_token)?;
                return Ok(Actor {
                    user,
                    kind: ActorKind::User,
                });
            }
            return Err(AuthError::unauthorized("invalid credentials"));
        }
        let tenant = self.host.tenant(headers);
        let row = self
            .store
            .consume_token(tenant, &crypto::token_hash(&token), "enroll", self.now())
            .await
            .map_err(store_err)?
            .ok_or_else(expired_token)?;
        let user_id = row.user_id.ok_or_else(expired_token)?;
        self.store
            .insert_challenge(
                Uuid::new_v4(),
                tenant,
                Some(user_id),
                &row.email,
                "enroll",
                Some(&crypto::token_hash(&token)),
                None,
                self.now() + 5 * MINUTE,
                self.now(),
            )
            .await.map_err(store_err)?;
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        Ok(Actor {
            user,
            kind: ActorKind::Enroll,
        })
    }

    fn totp_for(&self, secret: &str, email: &str) -> Result<TOTP, AuthError> {
        let raw = crypto::unseal(self.issuer.seal_key(), secret).map_err(|_| AuthError::unauthorized("invalid code"))?;
        TOTP::new(Algorithm::SHA1, 6, 1, 30, raw, Some(self.host.display_name()), email.to_string())
            .map_err(|_| AuthError::unauthorized("invalid code"))
    }

    pub async fn totp_start(&self, headers: &HeaderMap) -> Result<Response, AuthError> {
        let actor = self.actor(headers).await?;
        let secret = Secret::generate_secret();
        let bytes = secret.to_bytes().map_err(|_| bad("invalid code"))?;
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            bytes.clone(),
            Some(self.host.display_name()),
            actor.user.email.clone(),
        ).map_err(|_| bad("invalid code"))?;
        let sealed = crypto::seal(self.issuer.seal_key(), &bytes).map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?;
        self.store
            .save_user_challenge(actor.user.id, "totp", &sealed, self.now() + 10 * MINUTE)
            .await.map_err(store_err)?;
        Ok(Json(json!({"secret": totp.get_secret_base32(), "url": totp.get_url()})).into_response())
    }

    pub async fn totp_confirm(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let actor = self.actor(headers).await?;
        let Some(state) = self
            .store
            .take_user_challenge(actor.user.id, "totp", self.now())
            .await
            .map_err(store_err)?
        else {
            return Err(AuthError::unauthorized("invalid code"));
        };
        let totp = self.totp_for(&state, &actor.user.email);
        let ok = totp.as_ref().ok().and_then(|totp| totp.check_current(field(body, "code")).ok()).unwrap_or(false);
        if !ok {
            self.store
                .save_user_challenge(actor.user.id, "totp", &state, self.now() + 10 * MINUTE)
                .await.map_err(store_err)?;
            return Err(AuthError::unauthorized("invalid code"));
        }
        self.store
            .upsert_factor(actor.user.id, "totp", Some(&state), None, self.now())
            .await.map_err(store_err)?;
        Ok(Json(json!({"ok": true})).into_response())
    }

    fn webauthn(&self, origin: &str) -> Result<webauthn_rs::Webauthn, AuthError> {
        let url = Url::parse(origin).map_err(|_| bad("origin required for passkeys"))?;
        let rp_id = url.domain().ok_or_else(|| bad("origin required for passkeys"))?;
        let name = self.host.display_name();
        WebauthnBuilder::new(rp_id, &url)
            .map_err(|_| bad("origin required for passkeys"))?
            .rp_name(&name)
            .allow_any_port(true)
            .build()
            .map_err(|_| bad("origin required for passkeys"))
    }

    pub async fn passkey_register_options(&self, headers: &HeaderMap) -> Result<Response, AuthError> {
        let origin = origin_header(headers)?;
        let actor = self.actor(headers).await?;
        let webauthn = self.webauthn(&origin)?;
        let (options, state) = webauthn
            .start_passkey_registration(actor.user.id, &actor.user.email, &actor.user.email, None).map_err(|_| bad("passkey registration failed"))?;
        let saved = serde_json::to_string(&state).map_err(|_| bad("passkey registration failed"))?;
        self.store
            .save_user_challenge(actor.user.id, "passkey_register", &saved, self.now() + 5 * MINUTE)
            .await.map_err(store_err)?;
        Ok(Json(json!(options)).into_response())
    }

    pub async fn passkey_register(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let origin = origin_header(headers)?;
        let actor = self.actor(headers).await?;
        let Some(saved) = self
            .store
            .take_user_challenge(actor.user.id, "passkey_register", self.now())
            .await
            .map_err(store_err)?
        else {
            return Err(bad("passkey registration failed"));
        };
        let state: PasskeyRegistration = serde_json::from_str(&saved).map_err(|_| bad("passkey registration failed"))?;
        let credential: RegisterPublicKeyCredential = serde_json::from_value(body.clone()).map_err(|_| {
            let _ = saved;
            bad("passkey registration failed")
        })?;
        let webauthn = self.webauthn(&origin)?;
        let passkey = webauthn
            .finish_passkey_registration(&credential, &state).map_err(|_| bad("passkey registration failed"))?;
        let stored = serde_json::to_string(&passkey).map_err(|_| bad("passkey registration failed"))?;
        self.store
            .upsert_factor(actor.user.id, "passkey", None, Some(&stored), self.now())
            .await.map_err(store_err)?;
        Ok(Json(json!({"ok": true})).into_response())
    }

    pub async fn finish_enroll(&self, headers: &HeaderMap) -> Result<Response, AuthError> {
        let actor = self.actor(headers).await?;
        if actor.kind == ActorKind::Enroll {
            let token = bearer(headers).unwrap_or_default();
            let consumed = self
                .store
                .consume_enroll(actor.user.tenant_id, &crypto::token_hash(&token), self.now())
                .await.map_err(store_err)?;
            if !consumed {
                return Err(expired_token());
            }
        }
        let names = self.factor_names(actor.user.id).await?;
        if names.is_empty() {
            return Err(bad("a factor is required"));
        }
        let (response, codes) = self.session_with_codes(&actor.user).await?;
        let mut body = body_json(response).await;
        body["recovery_codes"] = json!(codes);
        Ok(Json(body).into_response())
    }

    pub async fn regenerate(&self, headers: &HeaderMap) -> Result<Response, AuthError> {
        let actor = self.actor(headers).await?;
        if actor.kind != ActorKind::User {
            return Err(AuthError::unauthorized("invalid credentials"));
        }
        let codes = self.recovery_codes(actor.user.id).await?;
        Ok(Json(json!({"recovery_codes": codes})).into_response())
    }

    async fn recovery_codes(&self, user: Uuid) -> Result<Vec<String>, AuthError> {
        const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
        let mut codes = Vec::new();
        let mut hashes = Vec::new();
        for _ in 0..8 {
            let mut raw = String::new();
            for index in 0..8 {
                if index == 4 {
                    raw.push('-');
                }
                let pick = rand::random::<usize>() % ALPHABET.len();
                raw.push(ALPHABET[pick] as char);
            }
            hashes.push(crypto::token_hash(&raw));
            codes.push(raw);
        }
        self.store.replace_recovery(user, &hashes).await.map_err(store_err)?;
        Ok(codes)
    }

    async fn session_with_codes(&self, user: &UserRow) -> Result<(Response, Vec<String>), AuthError> {
        let codes = self.recovery_codes(user.id).await?;
        let response = self.issue(user).await?;
        Ok((response, codes))
    }

    async fn mfa_row(&self, tenant: Uuid, token: &str) -> Result<authrs_store::ChallengeRow, AuthError> {
        self.store
            .consume_token(tenant, &crypto::token_hash(token), "mfa", self.now())
            .await
            .map_err(store_err)?
            .ok_or_else(expired_token)
    }

    async fn fail_mfa(&self, tenant: Uuid, token: &str, row: &authrs_store::ChallengeRow) -> Result<(), AuthError> {
        let next = row.attempts + 1;
        if next >= 5 {
            return Ok(());
        }
        let id = Uuid::new_v4();
        self.store
            .insert_challenge(
                id,
                tenant,
                row.user_id,
                &row.email,
                "mfa",
                Some(&crypto::token_hash(token)),
                None,
                self.now() + 5 * MINUTE,
                self.now(),
            )
            .await.map_err(store_err)?;
        self.store.set_attempts(id, next, None).await.map_err(store_err)?;
        Ok(())
    }

    pub async fn totp_verify(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        let token = field(body, "mfa_token");
        let row = self.mfa_row(tenant, token).await?;
        let user_id = row.user_id.ok_or_else(expired_token)?;
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        let factors = self.store.factors(user.id).await.map_err(store_err)?;
        let secret = factors.into_iter().find(|factor| factor.kind == "totp").and_then(|factor| factor.secret);
        let ok = secret
            .as_deref()
            .and_then(|secret| self.totp_for(secret, &user.email).ok())
            .and_then(|totp| totp.check_current(field(body, "code")).ok())
            .unwrap_or(false);
        if !ok {
            self.fail_mfa(tenant, token, &row).await?;
            return Err(AuthError::unauthorized("invalid code"));
        }
        self.issue(&user).await
    }

    pub async fn passkey_auth_options(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let origin = origin_header(headers)?;
        let tenant = self.host.tenant(headers);
        let token = field(body, "mfa_token");
        let row = self.mfa_row(tenant, token).await?;
        let user_id = row.user_id.ok_or_else(expired_token)?;
        let factors = self.store.factors(user_id).await.map_err(store_err)?;
        let Some(stored) = factors.into_iter().find(|factor| factor.kind == "passkey").and_then(|factor| factor.credential) else {
            self.fail_mfa(tenant, token, &row).await?;
            return Err(bad("passkey required"));
        };
        let passkey: Passkey = serde_json::from_str(&stored).map_err(|_| bad("passkey required"))?;
        let webauthn = self.webauthn(&origin)?;
        let (options, state) = webauthn
            .start_passkey_authentication(&[passkey]).map_err(|_| bad("passkey required"))?;
        let id = Uuid::new_v4();
        self.store
            .insert_challenge(
                id,
                tenant,
                Some(user_id),
                &row.email,
                "mfa",
                Some(&crypto::token_hash(token)),
                None,
                self.now() + 5 * MINUTE,
                self.now(),
            )
            .await.map_err(store_err)?;
        self.store.set_attempts(id, row.attempts, None).await.map_err(store_err)?;
        let saved = serde_json::to_string(&state).map_err(|_| bad("passkey required"))?;
        self.store
            .save_user_challenge(user_id, "passkey_auth", &saved, self.now() + 5 * MINUTE)
            .await.map_err(store_err)?;
        Ok(Json(json!(options)).into_response())
    }

    pub async fn passkey_verify(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let origin = origin_header(headers)?;
        let tenant = self.host.tenant(headers);
        let token = field(body, "mfa_token");
        let row = self.mfa_row(tenant, token).await?;
        let user_id = row.user_id.ok_or_else(expired_token)?;
        let Some(saved) = self
            .store
            .take_user_challenge(user_id, "passkey_auth", self.now())
            .await
            .map_err(store_err)?
        else {
            self.fail_mfa(tenant, token, &row).await?;
            return Err(AuthError::unauthorized("invalid or expired token"));
        };
        let state: PasskeyAuthentication = serde_json::from_str(&saved).map_err(|_| AuthError::unauthorized("invalid or expired token"))?;
        let credential: PublicKeyCredential = serde_json::from_value(body.get("credential").cloned().unwrap_or(Value::Null)).map_err(|_| AuthError::unauthorized("invalid or expired token"))?;
        let webauthn = self.webauthn(&origin)?;
        if webauthn.finish_passkey_authentication(&credential, &state).is_err() {
            self.fail_mfa(tenant, token, &row).await?;
            return Err(AuthError::unauthorized("invalid or expired token"));
        }
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        self.issue(&user).await
    }

    pub async fn recovery_verify(&self, headers: &HeaderMap, body: &Value) -> Result<Response, AuthError> {
        let tenant = self.host.tenant(headers);
        let token = field(body, "mfa_token");
        let row = self.mfa_row(tenant, token).await?;
        let user_id = row.user_id.ok_or_else(expired_token)?;
        let used = self
            .store
            .take_recovery(user_id, &crypto::token_hash(field(body, "code")), self.now())
            .await.map_err(store_err)?;
        if !used {
            self.fail_mfa(tenant, token, &row).await?;
            return Err(AuthError::unauthorized("invalid code"));
        }
        let user = self.store.user_by_id(user_id).await.map_err(store_err)?.ok_or_else(expired_token)?;
        self.issue(&user).await
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn store_errors_map() {
        assert_eq!(store_err(StoreError::Conflict).status, StatusCode::CONFLICT);
        assert_eq!(store_err(StoreError::BadKey).status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(store_err(StoreError::Other("nope".into())).message, "internal");
    }

    #[test]
    fn system_clock_is_positive() {
        assert!(SystemClock.now_ms() > 1_000_000);
    }
}

async fn body_json(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(json!({}))
}
