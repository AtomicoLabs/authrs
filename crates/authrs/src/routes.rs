use crate::service::Auth;
use crate::error::AuthError;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;

pub fn router(auth: Auth) -> Router {
    Router::new()
        .route("/auth/v1/signup", post(signup))
        .route("/auth/v1/token", post(token))
        .route("/auth/v1/logout", post(logout))
        .route("/auth/v1/user", get(user))
        .route("/auth/v1/verify-email", post(verify_email))
        .route("/auth/v1/verify-email/send", post(resend))
        .route("/auth/v1/magic-link", post(magic_link))
        .route("/auth/v1/verify", post(verify_magic))
        .route("/auth/v1/recover", post(recover))
        .route("/auth/v1/recover/complete", post(recover_complete))
        .route("/auth/v1/invite", post(invite))
        .route("/auth/v1/invite/accept", post(invite_accept))
        .route("/auth/v1/otp", post(otp))
        .route("/auth/v1/otp/verify", post(otp_verify))
        .route("/auth/v1/authorize", get(authorize))
        .route("/auth/v1/callback/{provider}", get(callback_get).post(callback_post))
        .route("/auth/v1/factors/totp/start", post(totp_start))
        .route("/auth/v1/factors/totp/confirm", post(totp_confirm))
        .route("/auth/v1/factors/passkey/register/options", post(passkey_register_options))
        .route("/auth/v1/factors/passkey/register", post(passkey_register))
        .route("/auth/v1/factors/finish", post(finish))
        .route("/auth/v1/factors/recovery/regenerate", post(regenerate))
        .route("/auth/v1/factors/totp", post(totp_verify))
        .route("/auth/v1/factors/passkey/options", post(passkey_options))
        .route("/auth/v1/factors/passkey/verify", post(passkey_verify))
        .route("/auth/v1/factors/recovery", post(recovery))
        .with_state(auth)
}

async fn signup(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.signup(&headers, &json_body(body)).await
}
async fn token(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.token(&headers, &json_body(body)).await
}
async fn logout(State(auth): State<Auth>, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.logout(&json_body(body)).await
}
async fn user(State(auth): State<Auth>, headers: HeaderMap) -> Result<Response, AuthError> {
    auth.user(&headers).await
}
async fn verify_email(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.verify_email(&headers, &json_body(body)).await
}
async fn resend(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.resend(&headers, &json_body(body)).await
}
async fn magic_link(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.magic_link(&headers, &json_body(body)).await
}
async fn verify_magic(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.verify_magic(&headers, &json_body(body)).await
}
async fn recover(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.recover(&headers, &json_body(body)).await
}
async fn recover_complete(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.recover_complete(&headers, &json_body(body)).await
}
async fn invite(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.invite(&headers, &json_body(body)).await
}
async fn invite_accept(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.invite_accept(&headers, &json_body(body)).await
}
async fn otp(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.otp(&headers, &json_body(body)).await
}
async fn otp_verify(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.otp_verify(&headers, &json_body(body)).await
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    provider: String,
    redirect_to: String,
}

async fn authorize(State(auth): State<Auth>, headers: HeaderMap, Query(query): Query<AuthorizeQuery>) -> Result<Response, AuthError> {
    auth.authorize(&headers, &query.provider, &query.redirect_to).await
}

#[derive(Deserialize, Default)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback_get(
    State(auth): State<Auth>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AuthError> {
    auth.callback(
        &provider,
        query.code.as_deref().unwrap_or(""),
        query.state.as_deref().unwrap_or(""),
        query.error.as_deref().unwrap_or(""),
    )
    .await
}

async fn callback_post(
    State(auth): State<Auth>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AuthError> {
    let text = String::from_utf8_lossy(&body);
    let content = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let (code, state, error) = if content.contains("json") {
        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (
            value.get("code").and_then(Value::as_str).unwrap_or("").to_string(),
            value.get("state").and_then(Value::as_str).unwrap_or("").to_string(),
            value.get("error").and_then(Value::as_str).unwrap_or("").to_string(),
        )
    } else {
        (
            form_value(&text, "code"),
            form_value(&text, "state"),
            form_value(&text, "error"),
        )
    };
    auth.callback(&provider, &code, &state, &error).await
}

fn form_value(body: &str, key: &str) -> String {
    for pair in body.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next() == Some(key) {
            return parts.next().unwrap_or("").replace('+', " ");
        }
    }
    String::new()
}

async fn totp_start(State(auth): State<Auth>, headers: HeaderMap) -> Result<Response, AuthError> {
    auth.totp_start(&headers).await
}
async fn totp_confirm(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.totp_confirm(&headers, &json_body(body)).await
}
async fn passkey_register_options(State(auth): State<Auth>, headers: HeaderMap) -> Result<Response, AuthError> {
    auth.passkey_register_options(&headers).await
}
async fn passkey_register(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.passkey_register(&headers, &json_body(body)).await
}
async fn finish(State(auth): State<Auth>, headers: HeaderMap) -> Result<Response, AuthError> {
    auth.finish_enroll(&headers).await
}
async fn regenerate(State(auth): State<Auth>, headers: HeaderMap) -> Result<Response, AuthError> {
    auth.regenerate(&headers).await
}
async fn totp_verify(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.totp_verify(&headers, &json_body(body)).await
}
async fn passkey_options(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.passkey_auth_options(&headers, &json_body(body)).await
}
async fn passkey_verify(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.passkey_verify(&headers, &json_body(body)).await
}
async fn recovery(State(auth): State<Auth>, headers: HeaderMap, body: Option<Json<Value>>) -> Result<Response, AuthError> {
    auth.recovery_verify(&headers, &json_body(body)).await
}

fn json_body(body: Option<Json<Value>>) -> Value {
    body.map(|Json(value)| value).unwrap_or(Value::Null)
}
