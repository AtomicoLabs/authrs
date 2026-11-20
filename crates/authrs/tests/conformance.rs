use std::sync::Arc;
use webauthn_authenticator_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::WebauthnAuthenticator;

use authrs::testkit::{HeaderHost, Inbox, ManualClock, StaticHttp};
use authrs::{router, Auth, JwtIssuer};
use authrs_store::{EmailSettings, ProviderRow, Store, StoreError};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const NOW: i64 = 1_700_000_000_000;

struct Env {
    auth: Auth,
    inbox: Arc<Inbox>,
    clock: Arc<ManualClock>,
    http: Arc<StaticHttp>,
    tenant: Uuid,
}

fn env(store: Arc<dyn Store>) -> Env {
    let tenant = Uuid::new_v4();
    let inbox = Arc::new(Inbox::new());
    let clock = Arc::new(ManualClock::new(NOW));
    let http = Arc::new(StaticHttp {
        token: std::sync::Mutex::new(json!({"access_token": "provider-token"})),
        profile: std::sync::Mutex::new(json!({"sub": "sub-1", "email": "ada@example.com", "email_verified": true})),
        fail: std::sync::atomic::AtomicBool::new(false),
    });
    let host = Arc::new(HeaderHost {
        default_tenant: tenant,
        public_base: "http://localhost".into(),
        display_name: "Authrs".into(),
    });
    let auth = Auth {
        store,
        host,
        mailer: inbox.clone(),
        http: http.clone(),
        issuer: Arc::new(JwtIssuer::generate().unwrap()),
        clock: clock.clone(),
    };
    Env {
        auth,
        inbox,
        clock,
        http,
        tenant,
    }
}

async fn call(auth: &Auth, method: &str, path: &str, headers: &[(&str, &str)], body: Option<Value>) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder().method(method).uri(path);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    let payload = body.map(|value| serde_json::to_vec(&value).unwrap()).unwrap_or_default();
    let response = router(auth.clone())
        .oneshot(builder.body(Body::from(payload)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json, location)
}

fn token_from(text: &str) -> String {
    let marker = "token=";
    let start = text.find(marker).expect("token") + marker.len();
    text[start..].split_whitespace().next().unwrap().trim_matches('"').to_string()
}

fn code_from(text: &str) -> String {
    let marker = "Code: ";
    let start = text.find(marker).expect("code") + marker.len();
    text[start..].chars().take(6).collect()
}

async fn configure_mail(env: &Env) {
    env.auth
        .put_email(
            env.tenant,
            EmailSettings {
                host: "127.0.0.1".into(),
                port: 2525,
                username: "user".into(),
                password_enc: "secret".into(),
                from_address: "auth@example.com".into(),
                tls: "none".into(),
                link_base: "https://app.example/cb".into(),
            },
        )
        .await
        .unwrap();
}

async fn run(store: Arc<dyn Store>) {
    let env = env(store);
    let dup = authrs_store::NewUser {
        id: Uuid::new_v4(),
        tenant_id: env.tenant,
        email: "dup@example.com".into(),
        password_hash: None,
        email_verified_at: None,
        created_at: NOW,
    };
    env.auth.store.insert_user(dup.clone()).await.unwrap();
    let err = env.auth
        .store
        .insert_user(authrs_store::NewUser { id: Uuid::new_v4(), ..dup })
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict), "{err:?}");
    configure_mail(&env).await;
    let view = env.auth.email_view(env.tenant).await.unwrap();
    assert_eq!(view["password_set"], true);
    assert!(view.get("password_enc").is_none());

    let headers = [("x-authrs-client-ip", "signup")];
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &headers,
        Some(json!({"email": "ada@example.com", "password": "short"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "password too short");

    let (status, created, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &headers,
        Some(json!({"email": " Ada@Example.com ", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["verification_required"], true);
    assert_eq!(created["user"]["email"], "ada@example.com");
    let user_id = created["user"]["id"].as_str().unwrap().to_string();

    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &headers,
        Some(json!({"email": "ada@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "email exists");

    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "login")],
        Some(json!({"email": "missing@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid credentials");
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "login")],
        Some(json!({"email": "ada@example.com", "password": "wrong-password"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid credentials");

    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "login")],
        Some(json!({"email": "ada@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verification_required"], true);
    assert!(body.get("access_token").is_none());
    assert_eq!(env.inbox.sent.lock().unwrap().len(), 1);

    let before = env.inbox.sent.lock().unwrap().len();
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email/send",
        &[],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(env.inbox.sent.lock().unwrap().len(), before);

    let text = env.inbox.last_text();
    let good_code = code_from(&text);
    let link_token = token_from(&text);
    for _ in 0..4 {
        let (status, body, _) = call(
            &env.auth,
            "POST",
            "/auth/v1/verify-email",
            &[],
            Some(json!({"email": "ada@example.com", "code": "000000"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid or expired token");
    }
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email",
        &[],
        Some(json!({"email": "ada@example.com", "code": "000000"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email",
        &[],
        Some(json!({"token": link_token})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    env.clock.advance(61_000);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email/send",
        &[],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = env.inbox.last_text();
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email",
        &[],
        Some(json!({"email": "ada@example.com", "code": code_from(&text)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let access = session["access_token"].as_str().unwrap().to_string();
    let refresh = session["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(session["user"]["id"], user_id);

    let (status, body, _) = call(&env.auth, "GET", "/auth/v1/user", &[("authorization", &format!("Bearer {access}"))], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "ada@example.com");
    assert!(body["email_verified_at"].is_number());

    let anon = env.auth.issuer.sign("anon", "anon", &serde_json::Map::new(), 60).unwrap();
    let (status, _, _) = call(&env.auth, "GET", "/auth/v1/user", &[("authorization", &format!("Bearer {anon}"))], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, rotated, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[],
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let refresh2 = rotated["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh2, refresh);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[],
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = call(&env.auth, "POST", "/auth/v1/logout", &[], Some(json!({"refresh_token": refresh2}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = call(&env.auth, "POST", "/auth/v1/logout", &[], Some(json!({"refresh_token": "missing"}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let _ = good_code;
    magic_recovery_invite(&env).await;
    otp(&env).await;
    mfa(&env).await;
    oauth(&env).await;
    mail_failures(&env).await;
    limits(&env).await;
    edges(&env).await;
}

async fn magic_recovery_invite(env: &Env) {
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/magic-link",
        &[("x-authrs-client-ip", "magic")],
        Some(json!({"email": "mag@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let again = env.inbox.sent.lock().unwrap().len();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/magic-link",
        &[("x-authrs-client-ip", "magic")],
        Some(json!({"email": "mag@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(env.inbox.sent.lock().unwrap().len(), again);
    env.clock.advance(61_000);
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify",
        &[],
        Some(json!({"token": token_from(&env.inbox.last_text())})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert!(session["access_token"].is_string());

    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/recover",
        &[("x-authrs-client-ip", "recover")],
        Some(json!({"email": "nobody@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/recover",
        &[("x-authrs-client-ip", "recover")],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/recover/complete",
        &[],
        Some(json!({"token": token_from(&env.inbox.last_text()), "password": "password2"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");

    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/invite",
        &[("x-authrs-client-ip", "invite")],
        Some(json!({"email": "new@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/invite",
        &[("x-authrs-client-ip", "invite"), ("x-authrs-invite", "allow")],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "email exists");
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/invite",
        &[("x-authrs-client-ip", "invite"), ("x-authrs-invite", "allow")],
        Some(json!({"email": "guest@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/invite/accept",
        &[],
        Some(json!({"token": token_from(&env.inbox.last_text()), "password": "short"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/invite/accept",
        &[],
        Some(json!({"token": token_from(&env.inbox.last_text()), "password": "password3"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
}

async fn otp(env: &Env) {
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "otp")],
        Some(json!({"email": "not-an-email"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "otp")],
        Some(json!({"email": "otp@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let code = code_from(&env.inbox.last_text());
    let sent = env.inbox.sent.lock().unwrap().len();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "otp")],
        Some(json!({"email": "otp@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(env.inbox.sent.lock().unwrap().len(), sent);
    for _ in 0..5 {
        let (status, body, _) = call(
            &env.auth,
            "POST",
            "/auth/v1/otp/verify",
            &[("x-authrs-client-ip", "otp-verify")],
            Some(json!({"email": "otp@example.com", "code": "111111"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid or expired code");
    }
    env.clock.advance(61_000);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "otp")],
        Some(json!({"email": "otp@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..5 {
        let (status, _, _) = call(
            &env.auth,
            "POST",
            "/auth/v1/otp/verify",
            &[("x-authrs-client-ip", "otp-verify")],
            Some(json!({"email": "otp@example.com", "code": "111111"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    env.clock.advance(61_000);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "otp")],
        Some(json!({"email": "otp@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fresh = code_from(&env.inbox.last_text());
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp/verify",
        &[("x-authrs-client-ip", "otp-verify")],
        Some(json!({"email": "otp@example.com", "code": fresh})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "too many requests");

    env.clock.advance(3_600_000);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "otp-b")],
        Some(json!({"email": "fresh@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp/verify",
        &[("x-authrs-client-ip", "otp-b")],
        Some(json!({"email": "fresh@example.com", "code": code_from(&env.inbox.last_text())})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let _ = code;
}

async fn mfa(env: &Env) {
    env.auth.set_flags(env.tenant, false, false).await.unwrap();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "mfa-signup")],
        Some(json!({"email": "factor@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    env.auth.set_flags(env.tenant, true, true).await.unwrap();
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "mfa-login")],
        Some(json!({"email": "factor@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enrollment_required"], true);
    let enroll = body["enroll_token"].as_str().unwrap().to_string();
    let (status, started, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp/start",
        &[("authorization", &format!("Bearer {enroll}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let secret = started["secret"].as_str().unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.into()).to_bytes().unwrap(),
        Some("Authrs".into()),
        "factor@example.com".into(),
    )
    .unwrap();
    let (status, bad, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp/confirm",
        &[("authorization", &format!("Bearer {enroll}"))],
        Some(json!({"code": "000000"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad["error"], "invalid code");
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp/confirm",
        &[("authorization", &format!("Bearer {enroll}"))],
        Some(json!({"code": totp.generate_current().unwrap()})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/register/options",
        &[("authorization", &format!("Bearer {enroll}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut soft = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let origin = Url::parse("http://localhost").unwrap();
    let (status, options, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/register/options",
        &[("authorization", &format!("Bearer {enroll}")), ("origin", "http://localhost")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let challenge: CreationChallengeResponse = serde_json::from_value(options).unwrap();
    let registered = soft.do_registration(origin.clone(), challenge).expect("soft passkey register");
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/register",
        &[("authorization", &format!("Bearer {enroll}")), ("origin", "http://localhost")],
        Some(serde_json::to_value(&registered).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, finished, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/finish",
        &[("authorization", &format!("Bearer {enroll}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{finished}");
    assert_eq!(finished["recovery_codes"].as_array().unwrap().len(), 8);
    let access = finished["access_token"].as_str().unwrap().to_string();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/recovery/regenerate",
        &[("authorization", &format!("Bearer {enroll}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, codes, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/recovery/regenerate",
        &[("authorization", &format!("Bearer {access}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let backup = codes["recovery_codes"][0].as_str().unwrap().to_string();

    let (status, challenge, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "mfa-login")],
        Some(json!({"email": "factor@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(challenge["mfa_required"], true);
    assert!(challenge["factors"].as_array().unwrap().iter().any(|item| item == "totp"));
    let mfa = challenge["mfa_token"].as_str().unwrap().to_string();
    for _ in 0..4 {
        let (status, _, _) = call(
            &env.auth,
            "POST",
            "/auth/v1/factors/totp",
            &[],
            Some(json!({"mfa_token": mfa, "code": "000000"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp",
        &[],
        Some(json!({"mfa_token": mfa, "code": "000000"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp",
        &[],
        Some(json!({"mfa_token": mfa, "code": totp.generate_current().unwrap()})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, challenge, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "mfa-login-2")],
        Some(json!({"email": "factor@example.com", "password": "password1"})),
    )
    .await;
    let mfa = challenge["mfa_token"].as_str().unwrap();
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/recovery",
        &[],
        Some(json!({"mfa_token": mfa, "code": backup})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let (status, challenge, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "mfa-passkey")],
        Some(json!({"email": "factor@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    assert!(challenge["factors"].as_array().unwrap().iter().any(|item| item == "passkey"));
    let mfa = challenge["mfa_token"].as_str().unwrap();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/options",
        &[],
        Some(json!({"mfa_token": mfa})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, options, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/options",
        &[("origin", "http://localhost")],
        Some(json!({"mfa_token": mfa})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let request: RequestChallengeResponse = serde_json::from_value(options).unwrap();
    let assertion = soft.do_authentication(origin, request).expect("soft passkey auth");
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/verify",
        &[("origin", "http://localhost")],
        Some(json!({"mfa_token": mfa, "credential": assertion})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert!(session["access_token"].is_string());
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "mfa-login-3")],
        Some(json!({"email": "factor@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

async fn oauth(env: &Env) {
    let (status, body, _) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=nope&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "unknown provider");
    env.auth
        .put_provider(
            env.tenant,
            "google",
            ProviderRow {
                client_id: "cid".into(),
                secret_enc: "sek".into(),
                extra: json!({"token_url": "http://provider/token", "userinfo_url": "http://provider/user"}).to_string(),
                enabled: false,
                redirects: vec!["https://app.example/cb".into()],
            },
        )
        .await
        .unwrap();
    let (status, body, _) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=google&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not found");
    env.auth
        .put_provider(
            env.tenant,
            "google",
            ProviderRow {
                client_id: "cid".into(),
                secret_enc: "sek".into(),
                extra: json!({"token_url": "http://provider/token", "userinfo_url": "http://provider/user", "authorize_url": "https://idp.example/auth"}).to_string(),
                enabled: true,
                redirects: vec!["https://app.example/cb".into()],
            },
        )
        .await
        .unwrap();
    let (status, body, _) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=google&redirect_to=https://evil.example",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "redirect is not allowed");
    let (status, _, location) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=google&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = location.unwrap();
    assert!(location.contains("code_challenge_method=S256"));
    let state = query_param(&location, "state");

    *env.http.profile.lock().unwrap() = json!({"sub": "sub-unverified", "email": "ada@example.com", "email_verified": false});
    let (status, _, location) = call(
        &env.auth,
        "GET",
        &format!("/auth/v1/callback/google?code=abc&state={state}"),
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location.unwrap().contains("error=email_not_verified"));

    let (status, _, location) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=google&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    let state = query_param(&location.unwrap(), "state");
    *env.http.profile.lock().unwrap() = json!({"sub": "sub-ada", "email": "ada@example.com", "email_verified": true});
    let (status, _, location) = call(
        &env.auth,
        "GET",
        &format!("/auth/v1/callback/google?code=abc&state={state}"),
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "{status}");
    let location = location.unwrap();
    assert!(location.contains("code="));
    let code = query_param(&location, "code");
    let (status, session, _) = call(&env.auth, "POST", "/auth/v1/token", &[], Some(json!({"code": code}))).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["user"]["email"], "ada@example.com");
    let (status, _, _) = call(&env.auth, "POST", "/auth/v1/token", &[], Some(json!({"code": code}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, location) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=google&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    let state = query_param(&location.unwrap(), "state");
    *env.http.profile.lock().unwrap() = json!({"sub": "sub-new", "email": "oauth@example.com", "email_verified": true});
    let (status, _, location) = call(
        &env.auth,
        "POST",
        &format!("/auth/v1/callback/google"),
        &[("content-type", "application/x-www-form-urlencoded")],
        None,
    )
    .await;
    let _ = (status, location);
    let (status, _, location) = call_raw(
        &env.auth,
        "POST",
        "/auth/v1/callback/google",
        "application/x-www-form-urlencoded",
        format!("code=abc&state={state}"),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location.unwrap().contains("code="));
    let (status, _, location) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=google&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    let state = query_param(&location.unwrap(), "state");
    let (status, _, location) = call_raw(
        &env.auth,
        "POST",
        "/auth/v1/callback/google",
        "application/json",
        format!(r#"{{"code":"abc","state":"{state}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location.unwrap().contains("code="));
}

fn query_param(url: &str, key: &str) -> String {
    let query = url.split('?').nth(1).unwrap_or("");
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next() == Some(key) {
            return parts.next().unwrap_or("").to_string();
        }
    }
    panic!("missing {key} in {url}");
}

async fn call_raw(auth: &Auth, method: &str, path: &str, content_type: &str, body: String) -> (StatusCode, Value, Option<String>) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", content_type)
        .body(Body::from(body))
        .unwrap();
    let response = router(auth.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let location = response.headers().get("location").and_then(|value| value.to_str().ok()).map(str::to_string);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, location)
}

async fn mail_failures(env: &Env) {
    env.inbox.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "mail-fail")],
        Some(json!({"email": "bounce@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "email could not be sent");
    env.inbox.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "mail-fail")],
        Some(json!({"email": "bounce@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    env.inbox.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/magic-link",
        &[("x-authrs-client-ip", "mail-magic")],
        Some(json!({"email": "ghost@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    env.inbox.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    env.clock.advance(61_000);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "mail-magic")],
        Some(json!({"email": "ghost@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    env.auth
        .put_email(
            env.tenant,
            EmailSettings {
                host: "".into(),
                port: 587,
                username: "".into(),
                password_enc: "".into(),
                from_address: "auth@example.com".into(),
                tls: "starttls".into(),
                link_base: "".into(),
            },
        )
        .await
        .unwrap();
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "no-smtp")],
        Some(json!({"email": "nosmtp@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "email is not configured");
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/invite",
        &[("x-authrs-invite", "allow"), ("x-authrs-client-ip", "no-smtp")],
        Some(json!({"email": "nosmtp-invite@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "email is not configured");
    configure_mail(env).await;
}

async fn limits(env: &Env) {
    for _ in 0..30 {
        let (status, _, _) = call(
            &env.auth,
            "POST",
            "/auth/v1/signup",
            &[("x-authrs-client-ip", "limit-signup")],
            Some(json!({"email": "limit@example.com", "password": "short"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "limit-signup")],
        Some(json!({"email": "limit@example.com", "password": "short"})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "too many requests");
}

async fn edges(env: &Env) {
    let unseen = env.auth.store.flags(Uuid::new_v4()).await.unwrap();
    assert!(unseen.require_email_verification);
    env.auth.provision(env.tenant, "Acme").await.unwrap();
    env.auth
        .put_template(
            env.tenant,
            "otp",
            authrs_store::TemplateRow {
                subject: "Code {{code}}".into(),
                body_text: "Code: {{code}}".into(),
                body_html: "<p>{{code}}</p>".into(),
            },
        )
        .await
        .unwrap();
    env.auth.delete_template(env.tenant, "otp").await.unwrap();
    let err = env
        .auth
        .put_provider(
            env.tenant,
            "nope",
            ProviderRow {
                client_id: "c".into(),
                secret_enc: "s".into(),
                extra: "{}".into(),
                enabled: true,
                redirects: vec![],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.message, "unknown provider");
    env.auth.delete_provider(env.tenant, "google").await.unwrap();

    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email/send",
        &[],
        Some(json!({"email": "nobody-resend@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email/send",
        &[],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/magic-link",
        &[("x-authrs-client-ip", "edges-magic")],
        Some(json!({"email": "not-an-email"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/recover",
        &[("x-authrs-client-ip", "edges-recover")],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sent = env.inbox.sent.lock().unwrap().len();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/recover",
        &[("x-authrs-client-ip", "edges-recover")],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(env.inbox.sent.lock().unwrap().len(), sent);

    env.auth.set_flags(env.tenant, false, false).await.unwrap();
    for index in 0..5 {
        env.clock.advance(61_000);
        let (status, _, _) = call(
            &env.auth,
            "POST",
            "/auth/v1/otp",
            &[("x-authrs-client-ip", "edges-otp")],
            Some(json!({"email": "capped@example.com"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "send {index}");
    }
    env.clock.advance(61_000);
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "edges-otp")],
        Some(json!({"email": "capped@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    env.inbox.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/invite",
        &[("x-authrs-invite", "allow"), ("x-authrs-client-ip", "edges-invite")],
        Some(json!({"email": "fail-invite@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    env.inbox.fail.store(false, std::sync::atomic::Ordering::SeqCst);

    env.auth
        .put_provider(
            env.tenant,
            "apple",
            ProviderRow {
                client_id: "app.example".into(),
                secret_enc: "not-a-key".into(),
                extra: json!({"team_id": "TEAM", "key_id": "KEY", "authorize_url": "https://apple.example/auth", "token_url": "http://127.0.0.1:1/token"}).to_string(),
                enabled: true,
                redirects: vec!["https://app.example/cb".into()],
            },
        )
        .await
        .unwrap();
    let (status, _, location) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=apple&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = location.unwrap();
    assert!(location.contains("response_mode=form_post"));
    let state = query_param(&location, "state");
    let (status, _, location) = call(
        &env.auth,
        "GET",
        &format!("/auth/v1/callback/apple?error=access_denied&state={state}"),
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location.unwrap().contains("error=access_denied"));
    let (status, _, _) = call(&env.auth, "GET", "/auth/v1/callback/apple?code=x&state=missing", &[], None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _, location) = call(
        &env.auth,
        "GET",
        "/auth/v1/authorize?provider=apple&redirect_to=https://app.example/cb",
        &[],
        None,
    )
    .await;
    let state = query_param(&location.unwrap(), "state");
    let (status, _, location) = call(
        &env.auth,
        "GET",
        &format!("/auth/v1/callback/apple?code=abc&state={state}"),
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location.unwrap().contains("error=provider"));

    let unseen = env.auth.email_view(Uuid::new_v4()).await.unwrap();
    assert_eq!(unseen["configured"], false);
    env.auth.set_flags(env.tenant, true, false).await.unwrap();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "edges-token")],
        Some(json!({"email": "token@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/verify-email",
        &[],
        Some(json!({"token": token_from(&env.inbox.last_text())})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "edges-nopw")],
        Some(json!({"email": "mag@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    env.auth
        .put_template(
            env.tenant,
            "otp",
            authrs_store::TemplateRow {
                subject: "Custom {{code}}".into(),
                body_text: "Code: {{code}}".into(),
                body_html: "<p>{{code}}</p>".into(),
            },
        )
        .await
        .unwrap();
    env.clock.advance(61_000);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "edges-template")],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(env.inbox.sent.lock().unwrap().last().unwrap().subject.starts_with("Custom"));
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp/verify",
        &[("x-authrs-client-ip", "edges-template")],
        Some(json!({"email": "ada@example.com", "code": code_from(&env.inbox.last_text())})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    env.auth.delete_template(env.tenant, "otp").await.unwrap();
    let now = env.clock.now.load(std::sync::atomic::Ordering::SeqCst);
    let first = authrs_store::NewUser {
        id: Uuid::new_v4(),
        tenant_id: env.tenant,
        email: "dup-store@example.com".into(),
        password_hash: None,
        email_verified_at: None,
        created_at: now,
    };
    env.auth.store.insert_user(first.clone()).await.unwrap();
    let mut second = first;
    second.id = Uuid::new_v4();
    let err = env.auth.store.insert_user(second).await.unwrap_err();
    assert!(matches!(err, StoreError::Conflict));
    env.inbox.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/recover",
        &[("x-authrs-client-ip", "edges-recover-fail")],
        Some(json!({"email": "ada@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    env.clock.advance(61_000);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/otp",
        &[("x-authrs-client-ip", "edges-otp-fail")],
        Some(json!({"email": "silent@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    env.inbox.fail.store(false, std::sync::atomic::Ordering::SeqCst);

    env.auth.set_flags(env.tenant, false, false).await.unwrap();
    let (status, created, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/signup",
        &[("x-authrs-client-ip", "edges-pass")],
        Some(json!({"email": "pass@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    env.auth.set_flags(env.tenant, true, true).await.unwrap();
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "edges-pass")],
        Some(json!({"email": "pass@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(body["enrollment_required"], true, "{body}");
    let enroll = body["enroll_token"].as_str().unwrap();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/register",
        &[("authorization", &format!("Bearer {enroll}")), ("origin", "http://localhost")],
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/recovery/regenerate",
        &[("authorization", &format!("Bearer {enroll}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, started, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp/start",
        &[("authorization", &format!("Bearer {enroll}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(started["secret"].as_str().unwrap().into()).to_bytes().unwrap(),
        Some("Authrs".into()),
        "pass@example.com".into(),
    )
    .unwrap();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp/confirm",
        &[("authorization", &format!("Bearer {enroll}"))],
        Some(json!({"code": totp.generate_current().unwrap()})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, options, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/register/options",
        &[("authorization", &format!("Bearer {enroll}")), ("origin", "http://localhost")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/register",
        &[("authorization", &format!("Bearer {enroll}")), ("origin", "http://localhost")],
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/finish",
        &[("authorization", &format!("Bearer {enroll}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, challenge, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "edges-pass-2")],
        Some(json!({"email": "pass@example.com", "password": "password1"})),
    )
    .await;
    assert_eq!(challenge["mfa_required"], true, "{challenge}");
    let mfa = challenge["mfa_token"].as_str().unwrap();
    let (status, session, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/totp",
        &[],
        Some(json!({"mfa_token": mfa, "code": totp.generate_current().unwrap()})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let (status, challenge, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "edges-pass-3")],
        Some(json!({"email": "pass@example.com", "password": "password1"})),
    )
    .await;
    let mfa = challenge["mfa_token"].as_str().unwrap();
    let (status, body, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/options",
        &[("origin", "http://localhost")],
        Some(json!({"mfa_token": mfa})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, challenge, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "edges-pass-4")],
        Some(json!({"email": "pass@example.com", "password": "password1"})),
    )
    .await;
    let mfa = challenge["mfa_token"].as_str().unwrap();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/passkey/verify",
        &[("origin", "http://localhost")],
        Some(json!({"mfa_token": mfa, "credential": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, challenge, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/token",
        &[("x-authrs-client-ip", "edges-pass-5")],
        Some(json!({"email": "pass@example.com", "password": "password1"})),
    )
    .await;
    let mfa = challenge["mfa_token"].as_str().unwrap();
    let (status, _, _) = call(
        &env.auth,
        "POST",
        "/auth/v1/factors/recovery",
        &[],
        Some(json!({"mfa_token": mfa, "code": "nope-nope"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let _ = status;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_conformance_and_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.db");
    let store = authrs_store_sqlite::open(&path, "test-key").unwrap();
    run(Arc::new(store)).await;
    let mounted = authrs::mount(
        Arc::new(authrs_store_sqlite::open(&path, "test-key").unwrap()),
        Arc::new(HeaderHost {
            default_tenant: Uuid::new_v4(),
            public_base: "http://localhost".into(),
            display_name: "Authrs".into(),
        }),
        Arc::new(Inbox::new()),
        Arc::new(StaticHttp {
            token: std::sync::Mutex::new(json!({})),
            profile: std::sync::Mutex::new(json!({})),
            fail: std::sync::atomic::AtomicBool::new(false),
        }),
        Arc::new(JwtIssuer::generate().unwrap()),
    );
    let response = mounted
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/signup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"email":"clock@example.com","password":"short"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    match authrs_store_sqlite::open(&path, "other-key") {
        Err(err) => assert!(matches!(err, StoreError::BadKey), "{err:?}"),
        Ok(_) => panic!("wrong key opened the database"),
    }
    let err = match authrs_store_sqlite::open(&path, "") {
        Err(err) => err,
        Ok(_) => panic!("empty key opened the database"),
    };
    assert!(matches!(err, StoreError::Other(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_conformance() {
    let url = std::env::var("AUTHR_TEST_DATABASE_URL").unwrap_or_default();
    if url.is_empty() {
        use testcontainers::runners::AsyncRunner;
        let node = testcontainers_modules::postgres::Postgres::default()
            .start()
            .await
            .expect("postgres container");
        let port = node.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let store = authrs_store_postgres::connect(&url).expect("postgres");
        run(Arc::new(store)).await;
        return;
    }
    let store = authrs_store_postgres::connect(&url).expect("postgres");
    run(Arc::new(store)).await;
}
