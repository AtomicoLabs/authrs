mod logic;

use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const SCHEMA: &str = include_str!("schema.sql");

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("conflict")]
    Conflict,
    #[error("bad key")]
    BadKey,
    #[error("{0}")]
    Other(String),
}

#[derive(Clone, Debug)]
pub enum SqlVal {
    Null,
    Text(String),
    Int(i64),
}

impl SqlVal {
    pub fn text(&self) -> Option<&str> {
        match self {
            SqlVal::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn int(&self) -> Option<i64> {
        match self {
            SqlVal::Int(value) => Some(*value),
            _ => None,
        }
    }
}

pub trait Tx {
    fn exec(&mut self, sql: &str, params: &[SqlVal]) -> Result<u64, StoreError>;
    fn query(&mut self, sql: &str, params: &[SqlVal]) -> Result<Vec<Vec<SqlVal>>, StoreError>;
}

pub trait Database: Send {
    fn with_tx<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut dyn Tx) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError>;
}

#[derive(Clone)]
pub struct Engine<D> {
    db: Arc<Mutex<D>>,
}

impl<D> Engine<D> {
    pub fn new(db: D) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
        }
    }

    fn block<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut dyn Tx) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError>
    where
        D: Database,
    {
        let run = || {
            let mut guard = self
                .db
                .lock().map_err(|err| StoreError::Other(err.to_string()))?;
            guard.with_tx(f)
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::scope(|scope| {
                scope
                    .spawn(run)
                    .join()
                    .unwrap_or_else(|_| Err(StoreError::Other("store thread panicked".into())))
            })
        } else {
            run()
        }
    }
}

#[derive(Clone, Debug)]
pub struct NewUser {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct UserRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct Flags {
    pub require_email_verification: bool,
    pub require_mfa: bool,
}

#[derive(Clone, Debug)]
pub struct ChallengeRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub email: String,
    pub attempts: i32,
    pub code_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    Cooldown,
    Limited,
    Created,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OtpCheck {
    Limited,
    Invalid,
    User(Uuid),
}

#[derive(Clone, Debug)]
pub struct EmailSettings {
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password_enc: String,
    pub from_address: String,
    pub tls: String,
    pub link_base: String,
}

#[derive(Clone, Debug)]
pub struct TemplateRow {
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
}

#[derive(Clone, Debug)]
pub struct ProviderRow {
    pub client_id: String,
    pub secret_enc: String,
    pub extra: String,
    pub enabled: bool,
    pub redirects: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OAuthTx {
    pub tenant_id: Uuid,
    pub provider: String,
    pub verifier: String,
    pub redirect_to: String,
}

#[derive(Clone, Debug)]
pub struct FactorRow {
    pub kind: String,
    pub secret: Option<String>,
    pub credential: Option<String>,
}

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn ensure_tenant(&self, id: Uuid, name: &str) -> Result<(), StoreError>;
    async fn flags(&self, tenant: Uuid) -> Result<Flags, StoreError>;
    async fn set_flags(&self, tenant: Uuid, flags: Flags) -> Result<(), StoreError>;
    async fn insert_user(&self, user: NewUser) -> Result<(), StoreError>;
    async fn user_by_email(&self, tenant: Uuid, email: &str) -> Result<Option<UserRow>, StoreError>;
    async fn user_by_id(&self, id: Uuid) -> Result<Option<UserRow>, StoreError>;
    async fn set_password(&self, id: Uuid, hash: &str) -> Result<(), StoreError>;
    async fn mark_verified(&self, id: Uuid, at: i64) -> Result<(), StoreError>;
    async fn delete_user(&self, id: Uuid) -> Result<(), StoreError>;
    async fn insert_session(
        &self,
        id: Uuid,
        user_id: Uuid,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<(), StoreError>;
    async fn rotate_session(
        &self,
        old_hash: &str,
        new_id: Uuid,
        new_hash: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<Option<UserRow>, StoreError>;
    async fn delete_session(&self, token_hash: &str) -> Result<(), StoreError>;
    async fn insert_challenge(
        &self,
        id: Uuid,
        tenant: Uuid,
        user_id: Option<Uuid>,
        email: &str,
        kind: &str,
        token_hash: Option<&str>,
        code_hash: Option<&str>,
        expires_at: i64,
        created_at: i64,
    ) -> Result<(), StoreError>;
    async fn count_recent(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        since: i64,
    ) -> Result<i64, StoreError>;
    async fn consume_token(
        &self,
        tenant: Uuid,
        token_hash: &str,
        kind: &str,
        now: i64,
    ) -> Result<Option<ChallengeRow>, StoreError>;
    async fn latest_open(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        now: i64,
    ) -> Result<Option<ChallengeRow>, StoreError>;
    async fn set_attempts(
        &self,
        id: Uuid,
        attempts: i32,
        consume_at: Option<i64>,
    ) -> Result<(), StoreError>;
    async fn delete_challenge(&self, id: Uuid) -> Result<(), StoreError>;
    async fn count_kind_since(
        &self,
        tenant: Uuid,
        kind: &str,
        since: i64,
    ) -> Result<i64, StoreError>;
    async fn count_email_kind_window(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        minute_since: i64,
        hour_since: i64,
        day_since: i64,
    ) -> Result<(i64, i64, i64), StoreError>;
    async fn sum_attempts_since(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        since: i64,
    ) -> Result<i64, StoreError>;
    async fn hold_otp(
        &self,
        tenant: Uuid,
        email: &str,
        id: Uuid,
        token_hash: &str,
        code_hash: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<Hold, StoreError>;
    async fn check_otp(
        &self,
        tenant: Uuid,
        email: &str,
        code_hash: &str,
        now: i64,
        max_attempts: i32,
    ) -> Result<OtpCheck, StoreError>;
    async fn supersede_otp(
        &self,
        tenant: Uuid,
        email: &str,
        keep: Uuid,
        now: i64,
    ) -> Result<(), StoreError>;
    async fn record_attempt(
        &self,
        id: Uuid,
        tenant: Uuid,
        ip: &str,
        kind: &str,
        at: i64,
    ) -> Result<i64, StoreError>;
    async fn save_user_challenge(
        &self,
        user: Uuid,
        kind: &str,
        state: &str,
        expires_at: i64,
    ) -> Result<(), StoreError>;
    async fn take_user_challenge(
        &self,
        user: Uuid,
        kind: &str,
        now: i64,
    ) -> Result<Option<String>, StoreError>;
    async fn upsert_factor(
        &self,
        user: Uuid,
        kind: &str,
        secret: Option<&str>,
        credential: Option<&str>,
        at: i64,
    ) -> Result<(), StoreError>;
    async fn factors(&self, user: Uuid) -> Result<Vec<FactorRow>, StoreError>;
    async fn replace_recovery(&self, user: Uuid, hashes: &[String]) -> Result<(), StoreError>;
    async fn take_recovery(&self, user: Uuid, hash: &str, now: i64) -> Result<bool, StoreError>;
    async fn find_identity(
        &self,
        tenant: Uuid,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Uuid>, StoreError>;
    async fn insert_identity(
        &self,
        id: Uuid,
        tenant: Uuid,
        user: Uuid,
        provider: &str,
        subject: &str,
        email: &str,
        at: i64,
    ) -> Result<(), StoreError>;
    async fn email_settings(&self, tenant: Uuid) -> Result<Option<EmailSettings>, StoreError>;
    async fn set_email(&self, tenant: Uuid, settings: EmailSettings) -> Result<(), StoreError>;
    async fn template(
        &self,
        tenant: Uuid,
        name: &str,
    ) -> Result<Option<TemplateRow>, StoreError>;
    async fn set_template(
        &self,
        tenant: Uuid,
        name: &str,
        row: TemplateRow,
    ) -> Result<(), StoreError>;
    async fn delete_template(&self, tenant: Uuid, name: &str) -> Result<(), StoreError>;
    async fn provider(
        &self,
        tenant: Uuid,
        name: &str,
    ) -> Result<Option<ProviderRow>, StoreError>;
    async fn upsert_provider(
        &self,
        tenant: Uuid,
        name: &str,
        row: ProviderRow,
    ) -> Result<(), StoreError>;
    async fn delete_provider(&self, tenant: Uuid, name: &str) -> Result<(), StoreError>;
    async fn insert_oauth_tx(
        &self,
        state: &str,
        tenant: Uuid,
        provider: &str,
        verifier: &str,
        redirect_to: &str,
        expires_at: i64,
    ) -> Result<(), StoreError>;
    async fn take_oauth_tx(&self, state: &str, now: i64) -> Result<Option<OAuthTx>, StoreError>;
    async fn consume_enroll(
        &self,
        tenant: Uuid,
        token_hash: &str,
        now: i64,
    ) -> Result<bool, StoreError>;
    async fn bump_mfa(&self, id: Uuid, now: i64, max: i32) -> Result<i32, StoreError>;
}

#[async_trait::async_trait]
impl<D: Database + 'static> Store for Engine<D> {
    async fn ensure_tenant(&self, id: Uuid, name: &str) -> Result<(), StoreError> {
        let name = name.to_string();
        self.block(move |tx| logic::ensure_tenant(tx, id, &name))
    }
    async fn flags(&self, tenant: Uuid) -> Result<Flags, StoreError> {
        self.block(move |tx| logic::flags(tx, tenant))
    }
    async fn set_flags(&self, tenant: Uuid, flags: Flags) -> Result<(), StoreError> {
        self.block(move |tx| logic::set_flags(tx, tenant, flags))
    }
    async fn insert_user(&self, user: NewUser) -> Result<(), StoreError> {
        self.block(move |tx| logic::insert_user(tx, &user))
    }
    async fn user_by_email(&self, tenant: Uuid, email: &str) -> Result<Option<UserRow>, StoreError> {
        let email = email.to_string();
        self.block(move |tx| logic::user_by_email(tx, tenant, &email))
    }
    async fn user_by_id(&self, id: Uuid) -> Result<Option<UserRow>, StoreError> {
        self.block(move |tx| logic::user_by_id(tx, id))
    }
    async fn set_password(&self, id: Uuid, hash: &str) -> Result<(), StoreError> {
        let hash = hash.to_string();
        self.block(move |tx| logic::set_password(tx, id, &hash))
    }
    async fn mark_verified(&self, id: Uuid, at: i64) -> Result<(), StoreError> {
        self.block(move |tx| logic::mark_verified(tx, id, at))
    }
    async fn delete_user(&self, id: Uuid) -> Result<(), StoreError> {
        self.block(move |tx| logic::delete_user(tx, id))
    }
    async fn insert_session(
        &self,
        id: Uuid,
        user_id: Uuid,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        let token_hash = token_hash.to_string();
        self.block(move |tx| logic::insert_session(tx, id, user_id, &token_hash, expires_at))
    }
    async fn rotate_session(
        &self,
        old_hash: &str,
        new_id: Uuid,
        new_hash: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<Option<UserRow>, StoreError> {
        let old_hash = old_hash.to_string();
        let new_hash = new_hash.to_string();
        self.block(move |tx| logic::rotate_session(tx, &old_hash, new_id, &new_hash, now, expires_at))
    }
    async fn delete_session(&self, token_hash: &str) -> Result<(), StoreError> {
        let token_hash = token_hash.to_string();
        self.block(move |tx| logic::delete_session(tx, &token_hash))
    }
    async fn insert_challenge(
        &self,
        id: Uuid,
        tenant: Uuid,
        user_id: Option<Uuid>,
        email: &str,
        kind: &str,
        token_hash: Option<&str>,
        code_hash: Option<&str>,
        expires_at: i64,
        created_at: i64,
    ) -> Result<(), StoreError> {
        let email = email.to_string();
        let kind = kind.to_string();
        let token_hash = token_hash.map(str::to_string);
        let code_hash = code_hash.map(str::to_string);
        self.block(move |tx| {
            logic::insert_challenge(
                tx,
                id,
                tenant,
                user_id,
                &email,
                &kind,
                token_hash.as_deref(),
                code_hash.as_deref(),
                expires_at,
                created_at,
            )
        })
    }
    async fn count_recent(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        since: i64,
    ) -> Result<i64, StoreError> {
        let email = email.to_string();
        let kind = kind.to_string();
        self.block(move |tx| logic::count_recent(tx, tenant, &email, &kind, since))
    }
    async fn consume_token(
        &self,
        tenant: Uuid,
        token_hash: &str,
        kind: &str,
        now: i64,
    ) -> Result<Option<ChallengeRow>, StoreError> {
        let token_hash = token_hash.to_string();
        let kind = kind.to_string();
        self.block(move |tx| logic::consume_token(tx, tenant, &token_hash, &kind, now))
    }
    async fn latest_open(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        now: i64,
    ) -> Result<Option<ChallengeRow>, StoreError> {
        let email = email.to_string();
        let kind = kind.to_string();
        self.block(move |tx| logic::latest_open(tx, tenant, &email, &kind, now))
    }
    async fn set_attempts(
        &self,
        id: Uuid,
        attempts: i32,
        consume_at: Option<i64>,
    ) -> Result<(), StoreError> {
        self.block(move |tx| logic::set_attempts(tx, id, attempts, consume_at))
    }
    async fn delete_challenge(&self, id: Uuid) -> Result<(), StoreError> {
        self.block(move |tx| logic::delete_challenge(tx, id))
    }
    async fn count_kind_since(&self, tenant: Uuid, kind: &str, since: i64) -> Result<i64, StoreError> {
        let kind = kind.to_string();
        self.block(move |tx| logic::count_kind_since(tx, tenant, &kind, since))
    }
    async fn count_email_kind_window(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        minute_since: i64,
        hour_since: i64,
        day_since: i64,
    ) -> Result<(i64, i64, i64), StoreError> {
        let email = email.to_string();
        let kind = kind.to_string();
        self.block(move |tx| {
            logic::count_email_kind_window(tx, tenant, &email, &kind, minute_since, hour_since, day_since)
        })
    }
    async fn sum_attempts_since(
        &self,
        tenant: Uuid,
        email: &str,
        kind: &str,
        since: i64,
    ) -> Result<i64, StoreError> {
        let email = email.to_string();
        let kind = kind.to_string();
        self.block(move |tx| logic::sum_attempts_since(tx, tenant, &email, &kind, since))
    }
    async fn hold_otp(
        &self,
        tenant: Uuid,
        email: &str,
        id: Uuid,
        token_hash: &str,
        code_hash: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<Hold, StoreError> {
        let email = email.to_string();
        let token_hash = token_hash.to_string();
        let code_hash = code_hash.to_string();
        self.block(move |tx| {
            logic::hold_otp(tx, tenant, &email, id, &token_hash, &code_hash, now, expires_at)
        })
    }
    async fn check_otp(
        &self,
        tenant: Uuid,
        email: &str,
        code_hash: &str,
        now: i64,
        max_attempts: i32,
    ) -> Result<OtpCheck, StoreError> {
        let email = email.to_string();
        let code_hash = code_hash.to_string();
        self.block(move |tx| logic::check_otp(tx, tenant, &email, &code_hash, now, max_attempts))
    }
    async fn supersede_otp(
        &self,
        tenant: Uuid,
        email: &str,
        keep: Uuid,
        now: i64,
    ) -> Result<(), StoreError> {
        let email = email.to_string();
        self.block(move |tx| logic::supersede_otp(tx, tenant, &email, keep, now))
    }
    async fn record_attempt(
        &self,
        id: Uuid,
        tenant: Uuid,
        ip: &str,
        kind: &str,
        at: i64,
    ) -> Result<i64, StoreError> {
        let ip = ip.to_string();
        let kind = kind.to_string();
        self.block(move |tx| logic::record_attempt(tx, id, tenant, &ip, &kind, at))
    }
    async fn save_user_challenge(
        &self,
        user: Uuid,
        kind: &str,
        state: &str,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        let kind = kind.to_string();
        let state = state.to_string();
        self.block(move |tx| logic::save_user_challenge(tx, user, &kind, &state, expires_at))
    }
    async fn take_user_challenge(
        &self,
        user: Uuid,
        kind: &str,
        now: i64,
    ) -> Result<Option<String>, StoreError> {
        let kind = kind.to_string();
        self.block(move |tx| logic::take_user_challenge(tx, user, &kind, now))
    }
    async fn upsert_factor(
        &self,
        user: Uuid,
        kind: &str,
        secret: Option<&str>,
        credential: Option<&str>,
        at: i64,
    ) -> Result<(), StoreError> {
        let kind = kind.to_string();
        let secret = secret.map(str::to_string);
        let credential = credential.map(str::to_string);
        self.block(move |tx| {
            logic::upsert_factor(tx, user, &kind, secret.as_deref(), credential.as_deref(), at)
        })
    }
    async fn factors(&self, user: Uuid) -> Result<Vec<FactorRow>, StoreError> {
        self.block(move |tx| logic::factors(tx, user))
    }
    async fn replace_recovery(&self, user: Uuid, hashes: &[String]) -> Result<(), StoreError> {
        let hashes = hashes.to_vec();
        self.block(move |tx| logic::replace_recovery(tx, user, &hashes))
    }
    async fn take_recovery(&self, user: Uuid, hash: &str, now: i64) -> Result<bool, StoreError> {
        let hash = hash.to_string();
        self.block(move |tx| logic::take_recovery(tx, user, &hash, now))
    }
    async fn find_identity(
        &self,
        tenant: Uuid,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Uuid>, StoreError> {
        let provider = provider.to_string();
        let subject = subject.to_string();
        self.block(move |tx| logic::find_identity(tx, tenant, &provider, &subject))
    }
    async fn insert_identity(
        &self,
        id: Uuid,
        tenant: Uuid,
        user: Uuid,
        provider: &str,
        subject: &str,
        email: &str,
        at: i64,
    ) -> Result<(), StoreError> {
        let provider = provider.to_string();
        let subject = subject.to_string();
        let email = email.to_string();
        self.block(move |tx| {
            logic::insert_identity(tx, id, tenant, user, &provider, &subject, &email, at)
        })
    }
    async fn email_settings(&self, tenant: Uuid) -> Result<Option<EmailSettings>, StoreError> {
        self.block(move |tx| logic::email_settings(tx, tenant))
    }
    async fn set_email(&self, tenant: Uuid, settings: EmailSettings) -> Result<(), StoreError> {
        self.block(move |tx| logic::set_email(tx, tenant, &settings))
    }
    async fn template(&self, tenant: Uuid, name: &str) -> Result<Option<TemplateRow>, StoreError> {
        let name = name.to_string();
        self.block(move |tx| logic::template(tx, tenant, &name))
    }
    async fn set_template(
        &self,
        tenant: Uuid,
        name: &str,
        row: TemplateRow,
    ) -> Result<(), StoreError> {
        let name = name.to_string();
        self.block(move |tx| logic::set_template(tx, tenant, &name, &row))
    }
    async fn delete_template(&self, tenant: Uuid, name: &str) -> Result<(), StoreError> {
        let name = name.to_string();
        self.block(move |tx| logic::delete_template(tx, tenant, &name))
    }
    async fn provider(&self, tenant: Uuid, name: &str) -> Result<Option<ProviderRow>, StoreError> {
        let name = name.to_string();
        self.block(move |tx| logic::provider(tx, tenant, &name))
    }
    async fn upsert_provider(
        &self,
        tenant: Uuid,
        name: &str,
        row: ProviderRow,
    ) -> Result<(), StoreError> {
        let name = name.to_string();
        self.block(move |tx| logic::upsert_provider(tx, tenant, &name, &row))
    }
    async fn delete_provider(&self, tenant: Uuid, name: &str) -> Result<(), StoreError> {
        let name = name.to_string();
        self.block(move |tx| logic::delete_provider(tx, tenant, &name))
    }
    async fn insert_oauth_tx(
        &self,
        state: &str,
        tenant: Uuid,
        provider: &str,
        verifier: &str,
        redirect_to: &str,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        let state = state.to_string();
        let provider = provider.to_string();
        let verifier = verifier.to_string();
        let redirect_to = redirect_to.to_string();
        self.block(move |tx| {
            logic::insert_oauth_tx(tx, &state, tenant, &provider, &verifier, &redirect_to, expires_at)
        })
    }
    async fn take_oauth_tx(&self, state: &str, now: i64) -> Result<Option<OAuthTx>, StoreError> {
        let state = state.to_string();
        self.block(move |tx| logic::take_oauth_tx(tx, &state, now))
    }
    async fn consume_enroll(&self, tenant: Uuid, token_hash: &str, now: i64) -> Result<bool, StoreError> {
        let token_hash = token_hash.to_string();
        self.block(move |tx| logic::consume_enroll(tx, tenant, &token_hash, now))
    }
    async fn bump_mfa(&self, id: Uuid, now: i64, max: i32) -> Result<i32, StoreError> {
        self.block(move |tx| logic::bump_mfa(tx, id, now, max))
    }
}
