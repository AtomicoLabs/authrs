# authrs

[![CI](https://github.com/atomicolabs/authrs/actions/workflows/ci.yml/badge.svg)](https://github.com/atomicolabs/authrs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Human login for an [axum](https://github.com/tokio-rs/axum) host. `mount` returns a router for `/auth/v1`. The host keeps its own users, projects, and agent tokens. This crate owns the human session.

Password signup, email verification, magic link, recovery, invite, one-time codes, ten OAuth providers, TOTP, passkeys, and recovery codes. Access tokens are Ed25519 JWTs (15 minutes). Refresh tokens rotate and last 30 days.

## Install

```toml
[dependencies]
authrs = { git = "https://github.com/atomicolabs/authrs" }
authrs-store-postgres = { git = "https://github.com/atomicolabs/authrs" }
# or
authrs-store-sqlite = { git = "https://github.com/atomicolabs/authrs" }
```

| Crate | Role |
| --- | --- |
| `authrs` | `/auth/v1` routes, passwords, mail, OAuth, JWT |
| `authrs-store` | `Store` trait and the SQL both adapters share |
| `authrs-store-postgres` | Postgres, schema `auth` |
| `authrs-store-sqlite` | SQLCipher file. The key is passed in and never stored |

## Mount

```rust
pub fn mount(
    store: Arc<dyn Store>,
    host: Arc<dyn Host>,
    mailer: Arc<dyn Mailer>,
    http: Arc<dyn HttpClient>,
    issuer: Arc<JwtIssuer>,
) -> axum::Router
```

```rust
let store = authrs_store_postgres::connect(&database_url)?;
let issuer = Arc::new(authrs::JwtIssuer::generate()?);
let router = authrs::mount(
    Arc::new(store),
    host,
    Arc::new(authrs::SmtpMailer),
    Arc::new(authrs::ReqwestClient::new()),
    issuer,
);
let app = axum::Router::new().merge(router);
```

Nest `router` on the host app. Paths are already `/auth/v1/...`.

`Host` is the only product-specific seam:

| Method | Decides |
| --- | --- |
| `tenant` | Which tenant this request belongs to |
| `claims` | Extra access-token claims. `sub`, `role`, `exp`, and `iat` are stripped |
| `invite_allowed` | Whether `POST /auth/v1/invite` is allowed. Otherwise 401 |
| `public_base` | Origin used in links |
| `display_name` | Name on mail and the passkey relying party |

SMTP settings and OAuth client secrets are sealed in the store. The seal key is the SHA-256 of the JWT private key.

### Multi-tenant host

Resolve the project, pass that id from `tenant`, and add `ref` plus `role` from `claims`. Allow invite when the caller holds the service key.

### Single-tenant host

Pass one account id from `tenant`. `claims` carries the human user id. Allow invite from an admin session. Agent and client tokens stay in the host and are issued after this session exists.

## Stores

Both adapters use the same tables: text ids, integer milliseconds, no foreign key into a host table. A unique `(tenant, email)` violation is `StoreError::Conflict`.

```rust
let store = authrs_store_postgres::connect("postgres://localhost/auth")?;
```

```rust
let store = authrs_store_sqlite::open(Path::new("auth.db"), &key)?;
```

`open` runs `PRAGMA key` and then reads `sqlite_master`. A wrong key is `StoreError::BadKey`. An empty key is refused. The key is not written into the file.

## Routes

| Method | Path | Result |
| --- | --- | --- |
| POST | `/auth/v1/signup` | Creates the user. Sends a confirm mail when verification is required |
| POST | `/auth/v1/token` | Password, refresh, or one-time OAuth code |
| POST | `/auth/v1/logout` | 204, including an unknown refresh token |
| GET | `/auth/v1/user` | `id`, `email`, `email_verified_at` |
| POST | `/auth/v1/verify-email` | Token or `{email, code}` |
| POST | `/auth/v1/verify-email/send` | Resend. Always `{ok: true}` |
| POST | `/auth/v1/magic-link` | Always `{ok: true}` |
| POST | `/auth/v1/verify` | Consumes the magic link |
| POST | `/auth/v1/recover` | Always `{ok: true}` |
| POST | `/auth/v1/recover/complete` | Sets the password and opens a session |
| POST | `/auth/v1/invite` | Host must allow it |
| POST | `/auth/v1/invite/accept` | Sets the password |
| POST | `/auth/v1/otp` | Six-digit code, 10 minutes |
| POST | `/auth/v1/otp/verify` | Creates the user when the address is new |
| GET | `/auth/v1/authorize` | OAuth redirect, PKCE S256 |
| GET, POST | `/auth/v1/callback/{provider}` | Returns to `redirect_to` with `?code=` |
| POST | `/auth/v1/factors/...` | TOTP, passkey, and recovery codes |

Unknown email and a wrong password both return `401 {"error":"invalid credentials"}`. Passwords shorter than 8 characters return `400 {"error":"password too short"}`. A duplicate email returns `409 {"error":"email exists"}`.

OAuth providers: Google, Microsoft, Apple, GitHub, Facebook, Discord, X, LinkedIn, Slack, GitLab. Apple client secrets are an ES256 JWT built from `team_id`, `key_id`, and the PKCS#8 PEM stored as the client secret.

Admin changes are Rust methods on `Auth`, not HTTP routes: `provision`, `set_flags`, `put_email`, `put_template`, `put_provider`, and the matching deletes. `require_email_verification` defaults on. `require_mfa` defaults off.

## Tests

```sh
cargo test --workspace
```

The suite runs the same cases against Postgres (Testcontainers) and a temporary SQLCipher file, including a wrong key. Docker must be running for the Postgres test.

```sh
./scripts/coverage.sh
```

needs `llvm-cov` and `llvm-profdata` on `PATH` (or `LLVM_COV` and `LLVM_PROFDATA`) and checks a 95% line floor.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Atomico Labs.
