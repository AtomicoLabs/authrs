use serde_json::Value;
use std::time::Duration;

pub trait HttpClient: Send + Sync {
    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Value, String>;
    fn get_json(&self, url: &str, bearer: &str) -> Result<Value, String>;
}

#[derive(Clone)]
pub struct ReqwestClient {
    client: reqwest::blocking::Client,
}

impl ReqwestClient {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        Self { client }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let server = runtime.block_on(MockServer::start());
        runtime.block_on(async {
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"email": "a@b.co"})))
                .mount(&server)
                .await;
        });
        let client = ReqwestClient::default();
        assert!(client.post_form(&format!("{}/token", server.uri()), &[("a", "b")]).is_ok());
        assert!(client.get_json(&format!("{}/user", server.uri()), "token").is_ok());
        drop(server);
    }

    #[test]
    fn closed_port_fails() {
        let client = ReqwestClient::new();
        assert!(client.post_form("http://127.0.0.1:1", &[("a", "b")]).is_err());
        assert!(client.get_json("http://127.0.0.1:1", "token").is_err());
    }

    #[test]
    fn json_round_trip_and_bad_body() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for body in [br#"{"ok":true}"#.to_vec(), br#"{"ok":true}"#.to_vec(), b"nope".to_vec()] {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf);
                let header = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes());
                let _ = sock.write_all(&body);
            }
        });
        let client = ReqwestClient::default();
        let url = format!("http://127.0.0.1:{port}/token");
        assert_eq!(client.post_form(&url, &[("a", "b")]).unwrap()["ok"], true);
        assert_eq!(client.get_json(&url, "token").unwrap()["ok"], true);
        assert!(client.get_json(&url, "token").is_err());
    }
}

impl HttpClient for ReqwestClient {
    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Value, String> {
        self.client
            .post(url)
            .header("accept", "application/json")
            .form(form)
            .send()
            .map_err(|err| err.to_string())?
            .json()
            .map_err(|err| err.to_string())
    }

    fn get_json(&self, url: &str, bearer: &str) -> Result<Value, String> {
        self.client
            .get(url)
            .bearer_auth(bearer)
            .header("accept", "application/json")
            .header("user-agent", "authrs")
            .send()
            .map_err(|err| err.to_string())?
            .json()
            .map_err(|err| err.to_string())
    }
}
