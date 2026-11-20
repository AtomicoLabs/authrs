use crate::crypto::apple_client_secret;
use crate::http::HttpClient;
use serde_json::{Map, Value};

#[derive(Clone, Copy)]
pub struct Catalog {
    pub name: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub userinfo_url: &'static str,
    pub scopes: &'static str,
}

const CATALOG: &[Catalog] = &[
    Catalog {
        name: "google",
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
        scopes: "openid email profile",
    },
    Catalog {
        name: "microsoft",
        authorize_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        userinfo_url: "https://graph.microsoft.com/oidc/userinfo",
        scopes: "openid email profile",
    },
    Catalog {
        name: "apple",
        authorize_url: "https://appleid.apple.com/auth/authorize",
        token_url: "https://appleid.apple.com/auth/token",
        userinfo_url: "",
        scopes: "name email",
    },
    Catalog {
        name: "github",
        authorize_url: "https://github.com/login/oauth/authorize",
        token_url: "https://github.com/login/oauth/access_token",
        userinfo_url: "https://api.github.com/user",
        scopes: "read:user user:email",
    },
    Catalog {
        name: "facebook",
        authorize_url: "https://www.facebook.com/v18.0/dialog/oauth",
        token_url: "https://graph.facebook.com/v18.0/oauth/access_token",
        userinfo_url: "https://graph.facebook.com/me?fields=id,email,name",
        scopes: "email",
    },
    Catalog {
        name: "discord",
        authorize_url: "https://discord.com/oauth2/authorize",
        token_url: "https://discord.com/api/oauth2/token",
        userinfo_url: "https://discord.com/api/users/@me",
        scopes: "identify email",
    },
    Catalog {
        name: "x",
        authorize_url: "https://twitter.com/i/oauth2/authorize",
        token_url: "https://api.twitter.com/2/oauth2/token",
        userinfo_url: "https://api.twitter.com/2/users/me?user.fields=confirmed_email",
        scopes: "users.read tweet.read",
    },
    Catalog {
        name: "linkedin",
        authorize_url: "https://www.linkedin.com/oauth/v2/authorization",
        token_url: "https://www.linkedin.com/oauth/v2/accessToken",
        userinfo_url: "https://api.linkedin.com/v2/userinfo",
        scopes: "openid email profile",
    },
    Catalog {
        name: "slack",
        authorize_url: "https://slack.com/oauth/v2/authorize",
        token_url: "https://slack.com/api/oauth.v2.access",
        userinfo_url: "",
        scopes: "openid email profile",
    },
    Catalog {
        name: "gitlab",
        authorize_url: "https://gitlab.com/oauth/authorize",
        token_url: "https://gitlab.com/oauth/token",
        userinfo_url: "https://gitlab.com/oauth/userinfo",
        scopes: "openid email profile",
    },
];

pub fn known(name: &str) -> Option<Catalog> {
    CATALOG.iter().copied().find(|item| item.name == name)
}

pub fn names() -> Vec<&'static str> {
    CATALOG.iter().map(|item| item.name).collect()
}

fn extra_str(extra: &Map<String, Value>, key: &str) -> Option<String> {
    extra.get(key).and_then(Value::as_str).map(str::to_string)
}

pub fn endpoint(template: &str, extra: &Map<String, Value>, key: &str) -> String {
    if let Some(value) = extra_str(extra, key) {
        return value;
    }
    let tenant = extra_str(extra, "tenant").unwrap_or_else(|| "common".into());
    template.replace("{tenant}", &tenant)
}

pub struct Profile {
    pub provider_user: String,
    pub email: Option<String>,
    pub verified: bool,
}

pub fn read_profile(provider: &str, token: &Value, http: &dyn HttpClient, userinfo_url: &str) -> Result<Profile, String> {
    if provider == "apple" {
        let id_token = token.get("id_token").and_then(Value::as_str).unwrap_or("");
        let payload = id_token.split('.').nth(1).unwrap_or("");
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload,
        )
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, payload)
        }).map_err(|err| err.to_string())?;
        let claims: Value = serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;
        return Ok(Profile {
            provider_user: claims.get("sub").and_then(Value::as_str).unwrap_or("").into(),
            email: claims.get("email").and_then(Value::as_str).map(str::to_string),
            verified: claims
                .get("email_verified")
                .and_then(|value| value.as_bool().or_else(|| value.as_str().map(|text| text == "true")))
                .unwrap_or(false),
        });
    }
    let access = token
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "provider did not return an access token".to_string())?;
    let body = if provider == "slack" {
        token
            .get("authed_user")
            .cloned()
            .filter(|value| value.is_object())
            .ok_or_else(|| "provider did not return a profile".to_string())?
    } else if userinfo_url.is_empty() {
        return Err("provider did not return a profile".into());
    } else {
        http.get_json(userinfo_url, access)?
    };
    let email = body
        .get("email")
        .or_else(|| body.pointer("/data/confirmed_email"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let verified = match provider {
        "github" => body.get("email").and_then(Value::as_str).is_some(),
        "x" => email.is_some(),
        _ => body
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(email.is_some()),
    };
    let provider_user = body
        .get("sub")
        .or_else(|| body.get("id"))
        .and_then(|value| value.as_str().map(str::to_string).or_else(|| value.as_i64().map(|n| n.to_string())))
        .unwrap_or_default();
    if provider_user.is_empty() {
        return Err("provider did not return a profile".into());
    }
    Ok(Profile {
        provider_user,
        email,
        verified,
    })
}

pub fn client_secret(provider: &str, secret: &str, client_id: &str, extra: &Map<String, Value>) -> Result<String, String> {
    if provider != "apple" {
        return Ok(secret.to_string());
    }
    let team = extra_str(extra, "team_id").ok_or_else(|| "apple team_id is required".to_string())?;
    let key = extra_str(extra, "key_id").ok_or_else(|| "apple key_id is required".to_string())?;
    apple_client_secret(&team, &key, client_id, secret).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Stub {
        body: Value,
    }

    impl HttpClient for Stub {
        fn post_form(&self, _: &str, _: &[(&str, &str)]) -> Result<Value, String> {
            Ok(self.body.clone())
        }
        fn get_json(&self, _: &str, _: &str) -> Result<Value, String> {
            Ok(self.body.clone())
        }
    }

    #[test]
    fn catalog_covers_ten_providers() {
        assert_eq!(names().len(), 10);
        assert!(known("google").is_some());
        assert!(known("nope").is_none());
        let extra = json!({"tenant": "contoso", "token_url": "http://local/token"}).as_object().unwrap().clone();
        assert_eq!(
            endpoint(known("microsoft").unwrap().token_url, &extra, "token_url"),
            "http://local/token"
        );
        assert!(endpoint(known("microsoft").unwrap().authorize_url, &Map::new(), "authorize_url").contains("common"));
    }

    #[test]
    fn profiles_from_providers() {
        let google = read_profile(
            "google",
            &json!({"access_token": "t"}),
            &Stub { body: json!({"sub": "g", "email": "a@b.co", "email_verified": true}) },
            "http://user",
        )
        .unwrap();
        assert_eq!(google.provider_user, "g");
        assert!(google.verified);
        let github = read_profile(
            "github",
            &json!({"access_token": "t"}),
            &Stub { body: json!({"id": 7, "email": "a@b.co"}) },
            "http://user",
        )
        .unwrap();
        assert_eq!(github.provider_user, "7");
        let slack = read_profile(
            "slack",
            &json!({"access_token": "t", "authed_user": {"id": "U1", "email": "a@b.co"}}),
            &Stub { body: json!({}) },
            "",
        )
        .unwrap();
        assert_eq!(slack.provider_user, "U1");
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"sub":"apple","email":"a@b.co","email_verified":"true"}"#,
        );
        let apple = read_profile("apple", &json!({"id_token": format!("h.{payload}.s")}), &Stub { body: json!({}) }, "").unwrap();
        assert_eq!(apple.email.as_deref(), Some("a@b.co"));
        assert!(apple.verified);
        assert!(read_profile("google", &json!({}), &Stub { body: json!({}) }, "http://user").is_err());
        assert!(read_profile("slack", &json!({"access_token": "t"}), &Stub { body: json!({}) }, "").is_err());
        assert!(Stub { body: json!({}) }.post_form("http://token", &[("a", "b")]).is_ok());
        assert!(read_profile("gitlab", &json!({"access_token": "t"}), &Stub { body: json!({}) }, "").is_err());
        assert!(client_secret("google", "sek", "id", &Map::new()).is_ok());
        assert!(client_secret("apple", "not-a-key", "id", &Map::new()).is_err());
    }
}
