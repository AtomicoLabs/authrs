CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS flags (
  tenant_id TEXT PRIMARY KEY,
  require_email_verification BIGINT NOT NULL DEFAULT 1,
  require_mfa BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT,
  email_verified_at BIGINT,
  created_at BIGINT NOT NULL,
  UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  user_id TEXT,
  email TEXT NOT NULL,
  kind TEXT NOT NULL,
  token_hash TEXT,
  code_hash TEXT,
  attempts BIGINT NOT NULL DEFAULT 0,
  expires_at BIGINT NOT NULL,
  consumed_at BIGINT,
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS challenges_email ON challenges (tenant_id, email, kind, created_at);
CREATE INDEX IF NOT EXISTS challenges_token ON challenges (token_hash);

CREATE TABLE IF NOT EXISTS attempts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  kind TEXT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts (tenant_id, ip, kind, created_at);

CREATE TABLE IF NOT EXISTS factors (
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  secret TEXT,
  credential TEXT,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, kind)
);

CREATE TABLE IF NOT EXISTS user_challenges (
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, kind)
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  used_at BIGINT,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE IF NOT EXISTS identities (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL,
  UNIQUE (tenant_id, provider, subject)
);

CREATE TABLE IF NOT EXISTS email_settings (
  tenant_id TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  port BIGINT NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  password_enc TEXT NOT NULL DEFAULT '',
  from_address TEXT NOT NULL,
  tls TEXT NOT NULL DEFAULT 'starttls',
  link_base TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS email_templates (
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  subject TEXT NOT NULL,
  body_html TEXT NOT NULL DEFAULT '',
  body_text TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  tenant_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  client_id TEXT NOT NULL,
  secret_enc TEXT NOT NULL DEFAULT '',
  extra TEXT NOT NULL DEFAULT '{}',
  enabled BIGINT NOT NULL DEFAULT 1,
  redirects TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (tenant_id, provider)
);

CREATE TABLE IF NOT EXISTS oauth_tx (
  state TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  verifier TEXT NOT NULL,
  redirect_to TEXT NOT NULL,
  expires_at BIGINT NOT NULL
);
