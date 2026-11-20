use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::rand_core::OsRng as ArgonRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use pkcs8::LineEnding;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct JwtIssuer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    seal_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl JwtIssuer {
    pub fn generate() -> anyhow::Result<Self> {
        let seed: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&seed);
        let private_pem = signing.to_pkcs8_pem(LineEnding::LF)?;
        let public_pem = signing.verifying_key().to_public_key_pem(LineEnding::LF)?;
        Self::from_pem(private_pem.as_bytes(), public_pem.as_bytes())
    }

    pub fn from_pem(private_pem: &[u8], public_pem: &[u8]) -> anyhow::Result<Self> {
        let digest = Sha256::digest(private_pem);
        let mut seal_key = [0u8; 32];
        seal_key.copy_from_slice(&digest);
        Ok(Self {
            encoding: EncodingKey::from_ed_pem(private_pem)?,
            decoding: DecodingKey::from_ed_pem(public_pem)?,
            seal_key,
        })
    }

    pub fn from_private_pem(pem: &str) -> anyhow::Result<Self> {
        let signing = SigningKey::from_pkcs8_pem(pem)?;
        let public_pem = signing.verifying_key().to_public_key_pem(LineEnding::LF)?;
        Self::from_pem(pem.as_bytes(), public_pem.as_bytes())
    }

    pub fn seal_key(&self) -> &[u8; 32] {
        &self.seal_key
    }

    pub fn sign(&self, sub: &str, role: &str, extra: &Map<String, Value>, ttl_secs: u64) -> anyhow::Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;
        let mut extra = extra.clone();
        extra.remove("sub");
        extra.remove("role");
        extra.remove("exp");
        extra.remove("iat");
        let claims = Claims {
            sub: sub.to_string(),
            role: role.to_string(),
            iat: now,
            exp: now + ttl_secs as usize,
            extra,
        };
        Ok(encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)?)
    }

    pub fn decode(&self, token: &str) -> anyhow::Result<Claims> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_required_spec_claims(&["exp"]);
        validation.validate_exp = true;
        validation.validate_aud = false;
        Ok(decode::<Claims>(token, &self.decoding, &validation)?.claims)
    }

    pub fn subject_role(&self, token: &str) -> anyhow::Result<(String, String)> {
        let claims = self.decode(token)?;
        Ok((claims.sub, claims.role))
    }
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut ArgonRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn seal(key: &[u8; 32], plain: &[u8]) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plain).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let mut packed = nonce.to_vec();
    packed.extend(ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(packed))
}

pub fn unseal(key: &[u8; 32], packed: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(packed).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    if bytes.len() < 12 {
        anyhow::bail!("sealed value is too short");
    }
    let (nonce, ciphertext) = bytes.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

pub fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn code() -> String {
    format!("{:06}", rand::random::<u32>() % 1_000_000)
}

pub fn apple_client_secret(team_id: &str, key_id: &str, client_id: &str, pem: &str) -> anyhow::Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.to_string());
    let claims = serde_json::json!({
        "iss": team_id,
        "sub": client_id,
        "aud": "https://appleid.apple.com",
        "iat": now,
        "exp": now + 300
    });
    let key = EncodingKey::from_ec_pem(pem.as_bytes())?;
    Ok(encode(&header, &claims, &key)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_and_seal_round_trip() {
        let hash = hash_password("password123").unwrap();
        assert!(verify_password("password123", &hash));
        assert!(!verify_password("nope", &hash));
        assert!(!verify_password("password123", "not-a-hash"));
        let key = [9u8; 32];
        let sealed = seal(&key, b"secret").unwrap();
        assert_eq!(unseal(&key, &sealed).unwrap(), b"secret");
        assert!(unseal(&key, "aa").is_err());
    }

    #[test]
    fn jwt_keeps_host_claims() {
        let issuer = JwtIssuer::generate().unwrap();
        let pem_round = issuer.sign("user", "authenticated", &Map::new(), 60).unwrap();
        let (sub, role) = issuer.subject_role(&pem_round).unwrap();
        assert_eq!(sub, "user");
        assert_eq!(role, "authenticated");
        let mut extra = Map::new();
        extra.insert("ref".into(), Value::String("proj".into()));
        extra.insert("sub".into(), Value::String("ignored".into()));
        let token = issuer.sign("real", "authenticated", &extra, 60).unwrap();
        let claims = issuer.decode(&token).unwrap();
        assert_eq!(claims.sub, "real");
        assert_eq!(claims.extra.get("ref").and_then(Value::as_str), Some("proj"));
    }

    #[test]
    fn apple_secret_is_an_es256_jwt() {
        use p256::pkcs8::EncodePrivateKey;
        let key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let pem = key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
        let token = apple_client_secret("TEAMID", "KEYID", "com.example", pem.as_str()).unwrap();
        assert_eq!(token.split('.').count(), 3);
        assert!(apple_client_secret("TEAMID", "KEYID", "com.example", "not-a-pem").is_err());
    }

    #[test]
    fn private_pem_reloads() {
        let seed: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&seed);
        let pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap();
        let issuer = JwtIssuer::from_private_pem(pem.as_str()).unwrap();
        let token = issuer.sign("a", "authenticated", &Map::new(), 30).unwrap();
        assert!(issuer.decode(&token).is_ok());
    }
}
