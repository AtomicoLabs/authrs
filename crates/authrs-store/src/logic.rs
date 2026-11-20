use crate::{
    ChallengeRow, EmailSettings, FactorRow, Flags, Hold, NewUser, OAuthTx, OtpCheck, ProviderRow,
    SqlVal, StoreError, TemplateRow, Tx, UserRow,
};
use uuid::Uuid;

fn t(value: &str) -> SqlVal {
    SqlVal::Text(value.to_string())
}

fn key(value: Uuid) -> SqlVal {
    SqlVal::Text(value.to_string())
}

fn opt_text(value: Option<&str>) -> SqlVal {
    match value {
        Some(value) => SqlVal::Text(value.to_string()),
        None => SqlVal::Null,
    }
}

fn opt_i64(value: Option<i64>) -> SqlVal {
    match value {
        Some(value) => SqlVal::Int(value),
        None => SqlVal::Null,
    }
}

fn uuid_of(row: &[SqlVal], index: usize) -> Result<Uuid, StoreError> {
    let text = row
        .get(index)
        .and_then(SqlVal::text)
        .ok_or_else(|| StoreError::Other("expected text".into()))?;
    Uuid::parse_str(text).map_err(|err| StoreError::Other(err.to_string()))
}

fn opt_uuid(row: &[SqlVal], index: usize) -> Result<Option<Uuid>, StoreError> {
    match row.get(index) {
        Some(SqlVal::Null) | None => Ok(None),
        Some(SqlVal::Text(value)) if value.is_empty() => Ok(None),
        Some(_) => Ok(Some(uuid_of(row, index)?)),
    }
}

fn text_of<'a>(row: &'a [SqlVal], index: usize) -> Result<&'a str, StoreError> {
    row.get(index)
        .and_then(SqlVal::text)
        .ok_or_else(|| StoreError::Other("expected text".into()))
}

fn opt_text_owned(row: &[SqlVal], index: usize) -> Option<String> {
    match row.get(index) {
        Some(SqlVal::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

fn int_of(row: &[SqlVal], index: usize) -> Result<i64, StoreError> {
    row.get(index)
        .and_then(SqlVal::int)
        .ok_or_else(|| StoreError::Other("expected int".into()))
}

fn one(tx: &mut dyn Tx, sql: &str, params: &[SqlVal]) -> Result<Option<Vec<SqlVal>>, StoreError> {
    Ok(tx.query(sql, params)?.into_iter().next())
}

fn count_of(row: &[SqlVal]) -> Result<i64, StoreError> {
    int_of(row, 0)
}

fn user_from(row: &[SqlVal]) -> Result<UserRow, StoreError> {
    Ok(UserRow {
        id: uuid_of(row, 0)?,
        tenant_id: uuid_of(row, 1)?,
        email: text_of(row, 2)?.to_string(),
        password_hash: opt_text_owned(row, 3),
        email_verified_at: row.get(4).and_then(SqlVal::int),
    })
}

const USER_COLS: &str = "id, tenant_id, email, password_hash, email_verified_at";

pub fn ensure_tenant(tx: &mut dyn Tx, id: Uuid, name: &str) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name",
        &[key(id), t(name)],)?;
    tx.exec(
        "INSERT INTO flags (tenant_id, require_email_verification, require_mfa) VALUES ($1, 1, 0) ON CONFLICT (tenant_id) DO NOTHING",
        &[key(id)],)?;
    Ok(())
}

pub fn flags(tx: &mut dyn Tx, tenant: Uuid) -> Result<Flags, StoreError> {
    let row = one(
        tx,
        "SELECT require_email_verification, require_mfa FROM flags WHERE tenant_id = $1",
        &[key(tenant)],)?;
    let Some(row) = row else {
        return Ok(Flags {
            require_email_verification: true,
            require_mfa: false,
        });
    };
    Ok(Flags {
        require_email_verification: int_of(&row, 0)? != 0,
        require_mfa: int_of(&row, 1)? != 0,
    })
}

pub fn set_flags(tx: &mut dyn Tx, tenant: Uuid, flags: Flags) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO flags (tenant_id, require_email_verification, require_mfa) VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id) DO UPDATE SET require_email_verification = EXCLUDED.require_email_verification, \
         require_mfa = EXCLUDED.require_mfa",
        &[
            key(tenant),
            SqlVal::Int(if flags.require_email_verification { 1 } else { 0 }),
            SqlVal::Int(if flags.require_mfa { 1 } else { 0 }),
        ],)?;
    Ok(())
}

pub fn insert_user(tx: &mut dyn Tx, user: &NewUser) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO users (id, tenant_id, email, password_hash, email_verified_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            key(user.id),
            key(user.tenant_id),
            t(&user.email),
            opt_text(user.password_hash.as_deref()),
            opt_i64(user.email_verified_at),
            SqlVal::Int(user.created_at),
        ],)?;
    Ok(())
}

pub fn user_by_email(tx: &mut dyn Tx, tenant: Uuid, email: &str) -> Result<Option<UserRow>, StoreError> {
    let row = one(
        tx,
        &format!("SELECT {USER_COLS} FROM users WHERE tenant_id = $1 AND email = $2"),
        &[key(tenant), t(email)],)?;
    row.map(|row| user_from(&row)).transpose()
}

pub fn user_by_id(tx: &mut dyn Tx, id_value: Uuid) -> Result<Option<UserRow>, StoreError> {
    let row = one(
        tx,
        &format!("SELECT {USER_COLS} FROM users WHERE id = $1"),
        &[key(id_value)],)?;
    row.map(|row| user_from(&row)).transpose()
}

pub fn set_password(tx: &mut dyn Tx, user: Uuid, hash: &str) -> Result<(), StoreError> {
    tx.exec(
        "UPDATE users SET password_hash = $2 WHERE id = $1",
        &[key(user), t(hash)],)?;
    Ok(())
}

pub fn mark_verified(tx: &mut dyn Tx, user: Uuid, at: i64) -> Result<(), StoreError> {
    tx.exec(
        "UPDATE users SET email_verified_at = COALESCE(email_verified_at, $2) WHERE id = $1",
        &[key(user), SqlVal::Int(at)],)?;
    Ok(())
}

pub fn delete_user(tx: &mut dyn Tx, user: Uuid) -> Result<(), StoreError> {
    for sql in [
        "DELETE FROM sessions WHERE user_id = $1",
        "DELETE FROM challenges WHERE user_id = $1",
        "DELETE FROM factors WHERE user_id = $1",
        "DELETE FROM user_challenges WHERE user_id = $1",
        "DELETE FROM recovery_codes WHERE user_id = $1",
        "DELETE FROM identities WHERE user_id = $1",
        "DELETE FROM users WHERE id = $1",
    ] {
        tx.exec(sql, &[key(user)])?;
    }
    Ok(())
}

pub fn insert_session(
    tx: &mut dyn Tx,
    session: Uuid,
    user: Uuid,
    token_hash: &str,
    expires_at: i64,
) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
        &[key(session), key(user), t(token_hash), SqlVal::Int(expires_at)],)?;
    Ok(())
}

pub fn rotate_session(
    tx: &mut dyn Tx,
    old_hash: &str,
    new_id: Uuid,
    new_hash: &str,
    now: i64,
    expires_at: i64,
) -> Result<Option<UserRow>, StoreError> {
    let row = one(
        tx,
        &format!(
            "SELECT u.id, u.tenant_id, u.email, u.password_hash, u.email_verified_at \
             FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.token_hash = $1 AND s.expires_at > $2"
        ),
        &[t(old_hash), SqlVal::Int(now)],)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let user = user_from(&row)?;
    let deleted = tx.exec("DELETE FROM sessions WHERE token_hash = $1", &[t(old_hash)])?;
    if deleted == 0 {
        return Ok(None);
    }
    insert_session(tx, new_id, user.id, new_hash, expires_at)?;
    Ok(Some(user))
}

pub fn delete_session(tx: &mut dyn Tx, token_hash: &str) -> Result<(), StoreError> {
    tx.exec("DELETE FROM sessions WHERE token_hash = $1", &[t(token_hash)])?;
    Ok(())
}

pub fn insert_challenge(
    tx: &mut dyn Tx,
    challenge: Uuid,
    tenant: Uuid,
    user_id: Option<Uuid>,
    email: &str,
    kind: &str,
    token_hash: Option<&str>,
    code_hash: Option<&str>,
    expires_at: i64,
    created_at: i64,
) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO challenges (id, tenant_id, user_id, email, kind, token_hash, code_hash, attempts, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, $9)",
        &[
            key(challenge),
            key(tenant),
            user_id.map(key).unwrap_or(SqlVal::Null),
            t(email),
            t(kind),
            opt_text(token_hash),
            opt_text(code_hash),
            SqlVal::Int(expires_at),
            SqlVal::Int(created_at),
        ],)?;
    Ok(())
}

pub fn count_recent(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    kind: &str,
    since: i64,
) -> Result<i64, StoreError> {
    let row = one(
        tx,
        "SELECT COUNT(*) FROM challenges WHERE tenant_id = $1 AND email = $2 AND kind = $3 AND consumed_at IS NULL AND created_at > $4",
        &[key(tenant), t(email), t(kind), SqlVal::Int(since)],)?
    .ok_or_else(|| StoreError::Other("count missing".into()))?;
    count_of(&row)
}

pub fn consume_token(
    tx: &mut dyn Tx,
    tenant: Uuid,
    token_hash: &str,
    kind: &str,
    now: i64,
) -> Result<Option<ChallengeRow>, StoreError> {
    let row = one(
        tx,
        "SELECT id, user_id, email, attempts, code_hash FROM challenges \
         WHERE tenant_id = $1 AND token_hash = $2 AND kind = $3 AND consumed_at IS NULL AND expires_at > $4",
        &[key(tenant), t(token_hash), t(kind), SqlVal::Int(now)],)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let challenge = challenge_from(&row)?;
    let updated = tx.exec(
        "UPDATE challenges SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL",
        &[key(challenge.id), SqlVal::Int(now)],)?;
    if updated == 0 {
        return Ok(None);
    }
    Ok(Some(challenge))
}

fn challenge_from(row: &[SqlVal]) -> Result<ChallengeRow, StoreError> {
    Ok(ChallengeRow {
        id: uuid_of(row, 0)?,
        user_id: opt_uuid(row, 1)?,
        email: text_of(row, 2)?.to_string(),
        attempts: int_of(row, 3)? as i32,
        code_hash: opt_text_owned(row, 4),
    })
}

pub fn latest_open(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    kind: &str,
    now: i64,
) -> Result<Option<ChallengeRow>, StoreError> {
    let row = one(
        tx,
        "SELECT id, user_id, email, attempts, code_hash FROM challenges \
         WHERE tenant_id = $1 AND email = $2 AND kind = $3 AND consumed_at IS NULL AND expires_at > $4 \
         ORDER BY created_at DESC LIMIT 1",
        &[key(tenant), t(email), t(kind), SqlVal::Int(now)],)?;
    row.map(|row| challenge_from(&row)).transpose()
}

pub fn set_attempts(
    tx: &mut dyn Tx,
    challenge: Uuid,
    attempts: i32,
    consume_at: Option<i64>,
) -> Result<(), StoreError> {
    tx.exec(
        "UPDATE challenges SET attempts = $2, consumed_at = COALESCE($3, consumed_at) WHERE id = $1",
        &[key(challenge), SqlVal::Int(i64::from(attempts)), opt_i64(consume_at)],)?;
    Ok(())
}

pub fn delete_challenge(tx: &mut dyn Tx, challenge: Uuid) -> Result<(), StoreError> {
    tx.exec("DELETE FROM challenges WHERE id = $1", &[key(challenge)])?;
    Ok(())
}

pub fn count_kind_since(tx: &mut dyn Tx, tenant: Uuid, kind: &str, since: i64) -> Result<i64, StoreError> {
    let row = one(
        tx,
        "SELECT COUNT(*) FROM challenges WHERE tenant_id = $1 AND kind = $2 AND created_at > $3",
        &[key(tenant), t(kind), SqlVal::Int(since)],)?
    .ok_or_else(|| StoreError::Other("count missing".into()))?;
    count_of(&row)
}

fn count_created(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    kind: &str,
    since: i64,
) -> Result<i64, StoreError> {
    let row = one(
        tx,
        "SELECT COUNT(*) FROM challenges WHERE tenant_id = $1 AND email = $2 AND kind = $3 AND created_at > $4",
        &[key(tenant), t(email), t(kind), SqlVal::Int(since)],)?
    .ok_or_else(|| StoreError::Other("count missing".into()))?;
    count_of(&row)
}

pub fn count_email_kind_window(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    kind: &str,
    minute_since: i64,
    hour_since: i64,
    day_since: i64,
) -> Result<(i64, i64, i64), StoreError> {
    Ok((
        count_created(tx, tenant, email, kind, minute_since)?,
        count_created(tx, tenant, email, kind, hour_since)?,
        count_created(tx, tenant, email, kind, day_since)?,
    ))
}

pub fn sum_attempts_since(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    kind: &str,
    since: i64,
) -> Result<i64, StoreError> {
    let row = one(
        tx,
        "SELECT CAST(COALESCE(SUM(attempts), 0) AS BIGINT) FROM challenges WHERE tenant_id = $1 AND email = $2 AND kind = $3 AND created_at > $4",
        &[key(tenant), t(email), t(kind), SqlVal::Int(since)],)?
    .ok_or_else(|| StoreError::Other("sum missing".into()))?;
    count_of(&row)
}

pub fn hold_otp(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    challenge: Uuid,
    token_hash: &str,
    code_hash: &str,
    now: i64,
    expires_at: i64,
) -> Result<Hold, StoreError> {
    let (minute, hour, day) = count_email_kind_window(
        tx,
        tenant,
        email,
        "otp",
        now - 60_000,
        now - 3_600_000,
        now - 86_400_000,)?;
    if minute > 0 {
        return Ok(Hold::Cooldown);
    }
    if hour >= 5 || day >= 10 {
        return Ok(Hold::Limited);
    }
    let tenant_hour = count_kind_since(tx, tenant, "otp", now - 3_600_000)?;
    if tenant_hour >= 100 {
        return Ok(Hold::Limited);
    }
    insert_challenge(
        tx,
        challenge,
        tenant,
        None,
        email,
        "otp",
        Some(token_hash),
        Some(code_hash),
        expires_at,
        now,)?;
    Ok(Hold::Created)
}

pub fn check_otp(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    code_hash: &str,
    now: i64,
    max_attempts: i32,
) -> Result<OtpCheck, StoreError> {
    let failures = sum_attempts_since(tx, tenant, email, "otp", now - 3_600_000)?;
    if failures >= 10 {
        return Ok(OtpCheck::Limited);
    }
    let Some(open) = latest_open(tx, tenant, email, "otp", now)? else {
        return Ok(OtpCheck::Invalid);
    };
    if open.code_hash.as_deref() != Some(code_hash) {
        let next = open.attempts + 1;
        let consume = if next >= max_attempts { Some(now) } else { None };
        set_attempts(tx, open.id, next, consume)?;
        return Ok(OtpCheck::Invalid);
    }
    let updated = tx.exec(
        "UPDATE challenges SET consumed_at = $2, user_id = COALESCE(user_id, user_id) WHERE id = $1 AND consumed_at IS NULL",
        &[key(open.id), SqlVal::Int(now)],)?;
    if updated == 0 {
        return Ok(OtpCheck::Invalid);
    }
    let existing = user_by_email(tx, tenant, email)?;
    let user_id = if let Some(user) = existing {
        mark_verified(tx, user.id, now)?;
        user.id
    } else {
        let user_id = Uuid::new_v4();
        insert_user(
            tx,
            &NewUser {
                id: user_id,
                tenant_id: tenant,
                email: email.to_string(),
                password_hash: None,
                email_verified_at: Some(now),
                created_at: now,
            },)?;
        user_id
    };
    tx.exec(
        "UPDATE challenges SET user_id = $2 WHERE id = $1",
        &[key(open.id), key(user_id)],)?;
    Ok(OtpCheck::User(user_id))
}

pub fn supersede_otp(
    tx: &mut dyn Tx,
    tenant: Uuid,
    email: &str,
    keep: Uuid,
    now: i64,
) -> Result<(), StoreError> {
    tx.exec(
        "UPDATE challenges SET consumed_at = $4 WHERE tenant_id = $1 AND email = $2 AND kind = 'otp' AND consumed_at IS NULL AND id <> $3",
        &[key(tenant), t(email), key(keep), SqlVal::Int(now)],)?;
    Ok(())
}

pub fn record_attempt(
    tx: &mut dyn Tx,
    attempt: Uuid,
    tenant: Uuid,
    ip: &str,
    kind: &str,
    at: i64,
) -> Result<i64, StoreError> {
    let row = one(
        tx,
        "SELECT COUNT(*) FROM attempts WHERE tenant_id = $1 AND ip = $2 AND kind = $3 AND created_at > $4",
        &[key(tenant), t(ip), t(kind), SqlVal::Int(at - 60_000)],)?
    .ok_or_else(|| StoreError::Other("count missing".into()))?;
    let count = count_of(&row)?;
    tx.exec(
        "INSERT INTO attempts (id, tenant_id, ip, kind, created_at) VALUES ($1, $2, $3, $4, $5)",
        &[key(attempt), key(tenant), t(ip), t(kind), SqlVal::Int(at)],)?;
    Ok(count)
}

pub fn save_user_challenge(
    tx: &mut dyn Tx,
    user: Uuid,
    kind: &str,
    state: &str,
    expires_at: i64,
) -> Result<(), StoreError> {
    tx.exec("DELETE FROM user_challenges WHERE user_id = $1 AND kind = $2", &[key(user), t(kind)])?;
    tx.exec(
        "INSERT INTO user_challenges (user_id, kind, state, expires_at) VALUES ($1, $2, $3, $4)",
        &[key(user), t(kind), t(state), SqlVal::Int(expires_at)],)?;
    Ok(())
}

pub fn take_user_challenge(
    tx: &mut dyn Tx,
    user: Uuid,
    kind: &str,
    now: i64,
) -> Result<Option<String>, StoreError> {
    let row = one(
        tx,
        "SELECT state FROM user_challenges WHERE user_id = $1 AND kind = $2 AND expires_at > $3",
        &[key(user), t(kind), SqlVal::Int(now)],)?;
    tx.exec(
        "DELETE FROM user_challenges WHERE user_id = $1 AND kind = $2",
        &[key(user), t(kind)],)?;
    Ok(row.and_then(|row| opt_text_owned(&row, 0)))
}

pub fn upsert_factor(
    tx: &mut dyn Tx,
    user: Uuid,
    kind: &str,
    secret: Option<&str>,
    credential: Option<&str>,
    at: i64,
) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO factors (user_id, kind, secret, credential, created_at) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (user_id, kind) DO UPDATE SET secret = COALESCE(EXCLUDED.secret, factors.secret), \
         credential = COALESCE(EXCLUDED.credential, factors.credential)",
        &[key(user), t(kind), opt_text(secret), opt_text(credential), SqlVal::Int(at)],)?;
    Ok(())
}

pub fn factors(tx: &mut dyn Tx, user: Uuid) -> Result<Vec<FactorRow>, StoreError> {
    let rows = tx.query(
        "SELECT kind, secret, credential FROM factors WHERE user_id = $1",
        &[key(user)],)?;
    rows.into_iter()
        .map(|row| {
            Ok(FactorRow {
                kind: text_of(&row, 0)?.to_string(),
                secret: opt_text_owned(&row, 1),
                credential: opt_text_owned(&row, 2),
            })
        })
        .collect()
}

pub fn replace_recovery(tx: &mut dyn Tx, user: Uuid, hashes: &[String]) -> Result<(), StoreError> {
    tx.exec("DELETE FROM recovery_codes WHERE user_id = $1", &[key(user)])?;
    for hash in hashes {
        tx.exec(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)",
            &[key(user), t(hash)],)?;
    }
    Ok(())
}

pub fn take_recovery(tx: &mut dyn Tx, user: Uuid, hash: &str, now: i64) -> Result<bool, StoreError> {
    let row = one(
        tx,
        "SELECT code_hash FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
        &[key(user), t(hash)],)?;
    if row.is_none() {
        return Ok(false);
    }
    tx.exec(
        "UPDATE recovery_codes SET used_at = $3 WHERE user_id = $1 AND code_hash = $2",
        &[key(user), t(hash), SqlVal::Int(now)],)?;
    Ok(true)
}

pub fn find_identity(
    tx: &mut dyn Tx,
    tenant: Uuid,
    provider: &str,
    subject: &str,
) -> Result<Option<Uuid>, StoreError> {
    let row = one(
        tx,
        "SELECT user_id FROM identities WHERE tenant_id = $1 AND provider = $2 AND subject = $3",
        &[key(tenant), t(provider), t(subject)],)?;
    row.map(|row| uuid_of(&row, 0)).transpose()
}

pub fn insert_identity(
    tx: &mut dyn Tx,
    identity: Uuid,
    tenant: Uuid,
    user: Uuid,
    provider: &str,
    subject: &str,
    email: &str,
    at: i64,
) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO identities (id, tenant_id, user_id, provider, subject, email, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            key(identity),
            key(tenant),
            key(user),
            t(provider),
            t(subject),
            t(email),
            SqlVal::Int(at),
        ],)?;
    Ok(())
}

pub fn email_settings(tx: &mut dyn Tx, tenant: Uuid) -> Result<Option<EmailSettings>, StoreError> {
    let row = one(
        tx,
        "SELECT host, port, username, password_enc, from_address, tls, link_base FROM email_settings WHERE tenant_id = $1",
        &[key(tenant)],)?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(EmailSettings {
        host: text_of(&row, 0)?.to_string(),
        port: int_of(&row, 1)?,
        username: text_of(&row, 2)?.to_string(),
        password_enc: text_of(&row, 3)?.to_string(),
        from_address: text_of(&row, 4)?.to_string(),
        tls: text_of(&row, 5)?.to_string(),
        link_base: text_of(&row, 6)?.to_string(),
    }))
}

pub fn set_email(tx: &mut dyn Tx, tenant: Uuid, settings: &EmailSettings) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO email_settings (tenant_id, host, port, username, password_enc, from_address, tls, link_base) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (tenant_id) DO UPDATE SET host = EXCLUDED.host, port = EXCLUDED.port, username = EXCLUDED.username, \
         password_enc = EXCLUDED.password_enc, from_address = EXCLUDED.from_address, tls = EXCLUDED.tls, link_base = EXCLUDED.link_base",
        &[
            key(tenant),
            t(&settings.host),
            SqlVal::Int(settings.port),
            t(&settings.username),
            t(&settings.password_enc),
            t(&settings.from_address),
            t(&settings.tls),
            t(&settings.link_base),
        ],)?;
    Ok(())
}

pub fn template(tx: &mut dyn Tx, tenant: Uuid, name: &str) -> Result<Option<TemplateRow>, StoreError> {
    let row = one(
        tx,
        "SELECT subject, body_text, body_html FROM email_templates WHERE tenant_id = $1 AND name = $2",
        &[key(tenant), t(name)],)?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(TemplateRow {
        subject: text_of(&row, 0)?.to_string(),
        body_text: text_of(&row, 1)?.to_string(),
        body_html: text_of(&row, 2)?.to_string(),
    }))
}

pub fn set_template(
    tx: &mut dyn Tx,
    tenant: Uuid,
    name: &str,
    row: &TemplateRow,
) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO email_templates (tenant_id, name, subject, body_html, body_text) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id, name) DO UPDATE SET subject = EXCLUDED.subject, body_html = EXCLUDED.body_html, body_text = EXCLUDED.body_text",
        &[key(tenant), t(name), t(&row.subject), t(&row.body_html), t(&row.body_text)],)?;
    Ok(())
}

pub fn delete_template(tx: &mut dyn Tx, tenant: Uuid, name: &str) -> Result<(), StoreError> {
    tx.exec(
        "DELETE FROM email_templates WHERE tenant_id = $1 AND name = $2",
        &[key(tenant), t(name)],)?;
    Ok(())
}

pub fn provider(tx: &mut dyn Tx, tenant: Uuid, name: &str) -> Result<Option<ProviderRow>, StoreError> {
    let row = one(
        tx,
        "SELECT client_id, secret_enc, extra, enabled, redirects FROM oauth_clients WHERE tenant_id = $1 AND provider = $2",
        &[key(tenant), t(name)],)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let redirects = serde_json::from_str(text_of(&row, 4)?).unwrap_or_default();
    Ok(Some(ProviderRow {
        client_id: text_of(&row, 0)?.to_string(),
        secret_enc: text_of(&row, 1)?.to_string(),
        extra: text_of(&row, 2)?.to_string(),
        enabled: int_of(&row, 3)? != 0,
        redirects,
    }))
}

pub fn upsert_provider(
    tx: &mut dyn Tx,
    tenant: Uuid,
    name: &str,
    row: &ProviderRow,
) -> Result<(), StoreError> {
    let redirects = serde_json::to_string(&row.redirects).map_err(|err| StoreError::Other(err.to_string()))?;
    tx.exec(
        "INSERT INTO oauth_clients (tenant_id, provider, client_id, secret_enc, extra, enabled, redirects) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, provider) DO UPDATE SET client_id = EXCLUDED.client_id, secret_enc = EXCLUDED.secret_enc, \
         extra = EXCLUDED.extra, enabled = EXCLUDED.enabled, redirects = EXCLUDED.redirects",
        &[
            key(tenant),
            t(name),
            t(&row.client_id),
            t(&row.secret_enc),
            t(&row.extra),
            SqlVal::Int(i64::from(row.enabled)),
            t(&redirects),
        ],)?;
    Ok(())
}

pub fn delete_provider(tx: &mut dyn Tx, tenant: Uuid, name: &str) -> Result<(), StoreError> {
    tx.exec(
        "DELETE FROM oauth_clients WHERE tenant_id = $1 AND provider = $2",
        &[key(tenant), t(name)],)?;
    Ok(())
}

pub fn insert_oauth_tx(
    tx: &mut dyn Tx,
    state: &str,
    tenant: Uuid,
    provider: &str,
    verifier: &str,
    redirect_to: &str,
    expires_at: i64,
) -> Result<(), StoreError> {
    tx.exec(
        "INSERT INTO oauth_tx (state, tenant_id, provider, verifier, redirect_to, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
        &[t(state), key(tenant), t(provider), t(verifier), t(redirect_to), SqlVal::Int(expires_at)],)?;
    Ok(())
}

pub fn take_oauth_tx(tx: &mut dyn Tx, state: &str, now: i64) -> Result<Option<OAuthTx>, StoreError> {
    let row = one(
        tx,
        "SELECT tenant_id, provider, verifier, redirect_to FROM oauth_tx WHERE state = $1 AND expires_at > $2",
        &[t(state), SqlVal::Int(now)],)?;
    let Some(row) = row else {
        return Ok(None);
    };
    tx.exec("DELETE FROM oauth_tx WHERE state = $1", &[t(state)])?;
    Ok(Some(OAuthTx {
        tenant_id: uuid_of(&row, 0)?,
        provider: text_of(&row, 1)?.to_string(),
        verifier: text_of(&row, 2)?.to_string(),
        redirect_to: text_of(&row, 3)?.to_string(),
    }))
}

pub fn consume_enroll(
    tx: &mut dyn Tx,
    tenant: Uuid,
    token_hash: &str,
    now: i64,
) -> Result<bool, StoreError> {
    let updated = tx.exec(
        "UPDATE challenges SET consumed_at = $4 WHERE tenant_id = $1 AND token_hash = $2 AND kind = 'enroll' AND consumed_at IS NULL AND expires_at > $3",
        &[key(tenant), t(token_hash), SqlVal::Int(now), SqlVal::Int(now)],)?;
    Ok(updated > 0)
}

pub fn bump_mfa(tx: &mut dyn Tx, challenge: Uuid, now: i64, max: i32) -> Result<i32, StoreError> {
    let row = one(tx, "SELECT attempts FROM challenges WHERE id = $1", &[key(challenge)])?
        .ok_or_else(|| StoreError::Other("challenge missing".into()))?;
    let next = int_of(&row, 0)? as i32 + 1;
    let consume = if next >= max { Some(now) } else { None };
    set_attempts(tx, challenge, next, consume)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Script {
        values: Vec<i64>,
    }

    impl Tx for Script {
        fn exec(&mut self, _: &str, _: &[SqlVal]) -> Result<u64, StoreError> {
            Ok(1)
        }

        fn query(&mut self, _: &str, _: &[SqlVal]) -> Result<Vec<Vec<SqlVal>>, StoreError> {
            let value = if self.values.is_empty() { 0 } else { self.values.remove(0) };
            Ok(vec![vec![SqlVal::Int(value)]])
        }
    }

    struct Empty;

    impl Tx for Empty {
        fn exec(&mut self, _: &str, _: &[SqlVal]) -> Result<u64, StoreError> {
            Ok(0)
        }

        fn query(&mut self, _: &str, _: &[SqlVal]) -> Result<Vec<Vec<SqlVal>>, StoreError> {
            Ok(vec![])
        }
    }

    #[test]
    fn defaults_limits_and_bump() {
        let mut empty = Empty;
        let flags = flags(&mut empty, Uuid::new_v4()).unwrap();
        assert!(flags.require_email_verification);
        assert!(!flags.require_mfa);
        assert!(user_by_email(&mut empty, Uuid::new_v4(), "a@b.co").unwrap().is_none());
        assert!(template(&mut empty, Uuid::new_v4(), "otp").unwrap().is_none());
        assert!(provider(&mut empty, Uuid::new_v4(), "google").unwrap().is_none());
        assert!(email_settings(&mut empty, Uuid::new_v4()).unwrap().is_none());
        assert!(!take_recovery(&mut empty, Uuid::new_v4(), "hash", 1).unwrap());

        let mut hour = Script { values: vec![0, 5, 0] };
        assert_eq!(
            hold_otp(&mut hour, Uuid::new_v4(), "a@b.co", Uuid::new_v4(), "t", "c", 10, 20).unwrap(),
            Hold::Limited
        );
        let mut day = Script { values: vec![0, 0, 10] };
        assert_eq!(
            hold_otp(&mut day, Uuid::new_v4(), "a@b.co", Uuid::new_v4(), "t", "c", 10, 20).unwrap(),
            Hold::Limited
        );
        let mut tenant = Script { values: vec![0, 0, 0, 100] };
        assert_eq!(
            hold_otp(&mut tenant, Uuid::new_v4(), "a@b.co", Uuid::new_v4(), "t", "c", 10, 20).unwrap(),
            Hold::Limited
        );
        let mut bump = Script { values: vec![4] };
        assert_eq!(bump_mfa(&mut bump, Uuid::new_v4(), 9, 5).unwrap(), 5);
        set_template(
            &mut bump,
            Uuid::new_v4(),
            "otp",
            &TemplateRow { subject: "s".into(), body_text: "t".into(), body_html: "h".into() },
        )
        .unwrap();
        delete_template(&mut bump, Uuid::new_v4(), "otp").unwrap();
        delete_provider(&mut bump, Uuid::new_v4(), "google").unwrap();
    }

    struct Rows {
        count: i64,
        counts: Vec<i64>,
        hide_user: bool,
        zero: bool,
        bad_json: bool,
    }

    impl Default for Rows {
        fn default() -> Self {
            Self { count: 0, counts: Vec::new(), hide_user: false, zero: false, bad_json: false }
        }
    }

    fn nil() -> SqlVal {
        SqlVal::Text(Uuid::nil().to_string())
    }

    fn text(value: &str) -> SqlVal {
        SqlVal::Text(value.to_string())
    }

    impl Tx for Rows {
        fn exec(&mut self, _: &str, _: &[SqlVal]) -> Result<u64, StoreError> {
            Ok(if self.zero { 0 } else { 1 })
        }

        fn query(&mut self, sql: &str, _: &[SqlVal]) -> Result<Vec<Vec<SqlVal>>, StoreError> {
            if sql.contains("COUNT(*)") || sql.contains("SUM(") {
                let value = if self.counts.is_empty() { self.count } else { self.counts.remove(0) };
                return Ok(vec![vec![SqlVal::Int(value)]]);
            }
            if sql.contains("SELECT attempts") {
                return Ok(vec![vec![SqlVal::Int(4)]]);
            }
            if sql.contains("FROM flags") {
                return Ok(vec![vec![SqlVal::Int(0), SqlVal::Int(1)]]);
            }
            if sql.contains("FROM users") || sql.contains("JOIN users") {
                if self.hide_user {
                    return Ok(vec![]);
                }
                return Ok(vec![vec![nil(), nil(), text("a@b.co"), text("hash"), SqlVal::Int(1)]]);
            }
            if sql.contains("SELECT id, user_id") {
                return Ok(vec![vec![nil(), SqlVal::Null, text("a@b.co"), SqlVal::Int(0), text("code")]]);
            }
            if sql.contains("FROM factors") {
                return Ok(vec![vec![text("totp"), text("sec"), SqlVal::Null]]);
            }
            if sql.contains("FROM recovery_codes") {
                return Ok(vec![vec![text("hash")]]);
            }
            if sql.contains("FROM identities") {
                return Ok(vec![vec![nil()]]);
            }
            if sql.contains("FROM email_settings") {
                return Ok(vec![vec![
                    text("localhost"),
                    SqlVal::Int(25),
                    text("user"),
                    text("secret"),
                    text("from@example.com"),
                    text("none"),
                    text("http://localhost"),
                ]]);
            }
            if sql.contains("FROM email_templates") {
                return Ok(vec![vec![text("s"), text("t"), text("h")]]);
            }
            if sql.contains("FROM oauth_clients") {
                let redirects = if self.bad_json { "nope" } else { "[\"https://app.example/cb\"]" };
                return Ok(vec![vec![text("id"), text("sec"), text("{}"), SqlVal::Int(1), text(redirects)]]);
            }
            if sql.contains("FROM oauth_tx") {
                return Ok(vec![vec![nil(), text("google"), text("verifier"), text("https://app.example/cb")]]);
            }
            if sql.contains("FROM user_challenges") {
                return Ok(vec![vec![text("state")]]);
            }
            Ok(vec![])
        }
    }

    struct Gate {
        calls: i32,
        fail_at: i32,
        inner: Rows,
    }

    impl Tx for Gate {
        fn exec(&mut self, sql: &str, params: &[SqlVal]) -> Result<u64, StoreError> {
            self.bump()?;
            self.inner.exec(sql, params)
        }

        fn query(&mut self, sql: &str, params: &[SqlVal]) -> Result<Vec<Vec<SqlVal>>, StoreError> {
            self.bump()?;
            self.inner.query(sql, params)
        }
    }

    impl Gate {
        fn bump(&mut self) -> Result<(), StoreError> {
            let current = self.calls;
            self.calls += 1;
            if current == self.fail_at {
                Err(StoreError::Other("fail".into()))
            } else {
                Ok(())
            }
        }
    }

    fn sample_user() -> NewUser {
        NewUser {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            email: "a@b.co".into(),
            password_hash: Some("hash".into()),
            email_verified_at: Some(1),
            created_at: 1,
        }
    }

    fn sample_settings() -> EmailSettings {
        EmailSettings {
            host: "localhost".into(),
            port: 25,
            username: "user".into(),
            password_enc: "secret".into(),
            from_address: "from@example.com".into(),
            tls: "none".into(),
            link_base: "http://localhost".into(),
        }
    }

    fn touch(tx: &mut dyn Tx) {
        let id = Uuid::nil();
        let _ = ensure_tenant(tx, id, "n");
        let _ = flags(tx, id);
        let _ = set_flags(tx, id, Flags { require_email_verification: false, require_mfa: true });
        let _ = insert_user(tx, &sample_user());
        let _ = user_by_email(tx, id, "a@b.co");
        let _ = user_by_id(tx, id);
        let _ = set_password(tx, id, "hash");
        let _ = mark_verified(tx, id, 1);
        let _ = delete_user(tx, id);
        let _ = insert_session(tx, id, id, "hash", 10);
        let _ = rotate_session(tx, "hash", id, "next", 1, 10);
        let _ = delete_session(tx, "hash");
        let _ = insert_challenge(tx, id, id, Some(id), "a@b.co", "otp", Some("t"), Some("c"), 10, 1);
        let _ = count_recent(tx, id, "a@b.co", "otp", 1);
        let _ = consume_token(tx, id, "t", "magic_link", 1);
        let _ = latest_open(tx, id, "a@b.co", "otp", 1);
        let _ = set_attempts(tx, id, 2, Some(1));
        let _ = set_attempts(tx, id, 2, None);
        let _ = delete_challenge(tx, id);
        let _ = count_kind_since(tx, id, "otp", 1);
        let _ = count_email_kind_window(tx, id, "a@b.co", "otp", 1, 1, 1);
        let _ = sum_attempts_since(tx, id, "a@b.co", "otp", 1);
        let _ = hold_otp(tx, id, "a@b.co", id, "t", "c", 10, 20);
        let _ = check_otp(tx, id, "a@b.co", "code", 1, 5);
        let _ = supersede_otp(tx, id, "a@b.co", id, 1);
        let _ = record_attempt(tx, id, id, "127.0.0.1", "signup", 60_000);
        let _ = save_user_challenge(tx, id, "totp", "state", 10);
        let _ = take_user_challenge(tx, id, "totp", 1);
        let _ = upsert_factor(tx, id, "totp", Some("sec"), None, 1);
        let _ = factors(tx, id);
        let _ = replace_recovery(tx, id, &["hash".into()]);
        let _ = take_recovery(tx, id, "hash", 1);
        let _ = find_identity(tx, id, "google", "sub");
        let _ = insert_identity(tx, id, id, id, "google", "sub", "a@b.co", 1);
        let _ = email_settings(tx, id);
        let _ = set_email(tx, id, &sample_settings());
        let _ = template(tx, id, "otp");
        let _ = set_template(
            tx,
            id,
            "otp",
            &TemplateRow { subject: "s".into(), body_text: "t".into(), body_html: "h".into() },
        );
        let _ = delete_template(tx, id, "otp");
        let _ = provider(tx, id, "google");
        let _ = upsert_provider(
            tx,
            id,
            "google",
            &ProviderRow {
                client_id: "id".into(),
                secret_enc: "sec".into(),
                extra: "{}".into(),
                enabled: true,
                redirects: vec!["https://app.example/cb".into()],
            },
        );
        let _ = delete_provider(tx, id, "google");
        let _ = insert_oauth_tx(tx, "state", id, "google", "verifier", "https://app.example/cb", 10);
        let _ = take_oauth_tx(tx, "state", 1);
        let _ = consume_enroll(tx, id, "hash", 1);
        let _ = bump_mfa(tx, id, 1, 5);
    }

    #[test]
    fn rows_round_trip_and_every_error() {
        let mut ok = Rows::default();
        touch(&mut ok);
        assert!(flags(&mut ok, Uuid::nil()).unwrap().require_mfa);
        assert!(user_by_id(&mut ok, Uuid::nil()).unwrap().is_some());
        assert!(rotate_session(&mut ok, "hash", Uuid::nil(), "next", 1, 10).unwrap().is_some());
        assert!(matches!(check_otp(&mut ok, Uuid::nil(), "a@b.co", "code", 1, 5).unwrap(), OtpCheck::User(_)));
        ok.hide_user = true;
        assert!(matches!(check_otp(&mut ok, Uuid::nil(), "a@b.co", "code", 1, 5).unwrap(), OtpCheck::User(_)));
        ok.hide_user = false;
        ok.count = 10;
        assert!(matches!(check_otp(&mut ok, Uuid::nil(), "a@b.co", "code", 1, 5).unwrap(), OtpCheck::Limited));
        ok.count = 0;
        ok.counts = vec![0, 5, 0];
        assert!(matches!(hold_otp(&mut ok, Uuid::nil(), "a@b.co", Uuid::nil(), "t", "c", 10, 20).unwrap(), Hold::Limited));
        ok.counts = vec![0, 0, 0, 100];
        assert!(matches!(hold_otp(&mut ok, Uuid::nil(), "a@b.co", Uuid::nil(), "t", "c", 10, 20).unwrap(), Hold::Limited));
        ok.counts.clear();
        assert!(matches!(check_otp(&mut ok, Uuid::nil(), "a@b.co", "nope", 1, 5).unwrap(), OtpCheck::Invalid));
        assert!(matches!(hold_otp(&mut ok, Uuid::nil(), "a@b.co", Uuid::nil(), "t", "c", 10, 20).unwrap(), Hold::Created));
        assert!(email_settings(&mut ok, Uuid::nil()).unwrap().is_some());
        assert!(take_oauth_tx(&mut ok, "state", 1).unwrap().is_some());
        assert!(factors(&mut ok, Uuid::nil()).unwrap().len() == 1);
        ok.zero = true;
        assert!(rotate_session(&mut ok, "hash", Uuid::nil(), "next", 1, 10).unwrap().is_none());
        assert!(!consume_enroll(&mut ok, Uuid::nil(), "hash", 1).unwrap());
        ok.zero = false;
        ok.bad_json = true;
        assert!(provider(&mut ok, Uuid::nil(), "google").unwrap().unwrap().redirects.is_empty());
        for fail_at in 0..90 {
            touch(&mut Gate { calls: 0, fail_at, inner: Rows::default() });
        }
    }
}
