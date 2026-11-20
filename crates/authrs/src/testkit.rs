use crate::http::HttpClient;
use crate::mail::{Mailer, Outgoing};
use crate::service::{Clock, Host};
use crate::error::DeliverError;
use axum::http::HeaderMap;
use serde_json::{Map, Value};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Mutex;
use uuid::Uuid;

pub struct HeaderHost {
    pub default_tenant: Uuid,
    pub public_base: String,
    pub display_name: String,
}

impl Host for HeaderHost {
    fn tenant(&self, headers: &HeaderMap) -> Uuid {
        headers
            .get("x-authrs-tenant")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Uuid::parse_str(value).ok())
            .unwrap_or(self.default_tenant)
    }

    fn claims(&self, tenant: Uuid, user: Uuid) -> Map<String, Value> {
        let mut claims = Map::new();
        claims.insert("ref".into(), Value::String(tenant.to_string()));
        claims.insert("user_id".into(), Value::String(user.to_string()));
        claims
    }

    fn invite_allowed(&self, headers: &HeaderMap) -> bool {
        headers.get("x-authrs-invite").and_then(|value| value.to_str().ok()) == Some("allow")
    }

    fn public_base(&self) -> String {
        self.public_base.clone()
    }

    fn display_name(&self) -> String {
        self.display_name.clone()
    }
}

pub struct Inbox {
    pub sent: Mutex<Vec<Outgoing>>,
    pub fail: AtomicBool,
}

impl Inbox {
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
        }
    }

    pub fn last_text(&self) -> String {
        self.sent.lock().expect("inbox").last().map(|mail| mail.text.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpClient;
    use std::sync::atomic::Ordering;

    #[test]
    fn inbox_default_and_http_failure() {
        let inbox = Inbox::default();
        inbox.fail.store(true, Ordering::SeqCst);
        assert!(inbox
            .send(&Outgoing {
                to: "a@b.co".into(),
                subject: "s".into(),
                text: "t".into(),
                html: "h".into(),
                from: "f@b.co".into(),
                host: "h".into(),
                port: 1,
                username: "u".into(),
                password: "p".into(),
                tls: "none".into(),
            })
            .is_err());
        let http = StaticHttp {
            token: Mutex::new(Value::Null),
            profile: Mutex::new(Value::Null),
            fail: AtomicBool::new(true),
        };
        assert!(http.post_form("http://example", &[]).is_err());
        assert!(http.get_json("http://example", "t").is_err());
    }
}

impl Default for Inbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailer for Inbox {
    fn send(&self, mail: &Outgoing) -> Result<(), DeliverError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(DeliverError::Failed);
        }
        self.sent.lock().expect("inbox").push(mail.clone());
        Ok(())
    }
}

pub struct ManualClock {
    pub now: AtomicI64,
}

impl ManualClock {
    pub fn new(now: i64) -> Self {
        Self {
            now: AtomicI64::new(now),
        }
    }

    pub fn advance(&self, ms: i64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

pub struct StaticHttp {
    pub token: Mutex<Value>,
    pub profile: Mutex<Value>,
    pub fail: AtomicBool,
}

impl HttpClient for StaticHttp {
    fn post_form(&self, _: &str, _: &[(&str, &str)]) -> Result<Value, String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("down".into());
        }
        Ok(self.token.lock().expect("token").clone())
    }

    fn get_json(&self, _: &str, _: &str) -> Result<Value, String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("down".into());
        }
        Ok(self.profile.lock().expect("profile").clone())
    }
}
