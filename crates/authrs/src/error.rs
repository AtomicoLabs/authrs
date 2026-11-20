use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct AuthError {
    pub status: StatusCode,
    pub message: String,
}

impl AuthError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(json!({"error": self.message}))).into_response();
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        response
    }
}

#[derive(Debug)]
pub enum DeliverError {
    Unconfigured,
    Failed,
}
