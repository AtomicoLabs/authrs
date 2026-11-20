//! Human login mounted on an axum host.
//!
//! [`mount`] returns the `/auth/v1` router. The host supplies a [`Store`](authrs_store::Store),
//! a [`Host`], a [`Mailer`], an [`HttpClient`], and a [`JwtIssuer`]. Postgres and SQLCipher
//! adapters implement `Store` in `authrs-store-postgres` and `authrs-store-sqlite`.

mod crypto;
mod error;
mod http;
mod mail;
mod oauth;
mod routes;
mod service;

#[cfg(feature = "testkit")]
pub mod testkit;

pub use crypto::JwtIssuer;
pub use error::AuthError;
pub use http::{HttpClient, ReqwestClient};
pub use mail::{Mailer, SmtpMailer};
pub use routes::router;
pub use service::{Auth, Clock, Host, SystemClock};

use authrs_store::Store;
use std::sync::Arc;

/// Build the `/auth/v1` router.
///
/// `host` resolves the tenant, extra access-token claims, and whether this request may invite.
/// SMTP passwords and OAuth client secrets are sealed in `store`.
pub fn mount(store: Arc<dyn Store>, host: Arc<dyn Host>, mailer: Arc<dyn Mailer>, http: Arc<dyn HttpClient>, issuer: Arc<JwtIssuer>) -> axum::Router {
    router(Auth {
        store,
        host,
        mailer,
        http,
        issuer,
        clock: Arc::new(SystemClock),
    })
}
