use crate::error::DeliverError;
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, Message, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use std::time::Duration;

pub struct Template {
    pub name: &'static str,
    pub subject: &'static str,
    pub body_text: &'static str,
    pub body_html: &'static str,
}

pub fn reserved() -> &'static [Template] {
    &[
        Template {
            name: "magic_link",
            subject: "Sign in",
            body_text: "Sign in as {{email}}.\n\n{{link}}\n",
            body_html: "<p>Sign in as {{email}}.</p><p><a href=\"{{link}}\">{{link}}</a></p>",
        },
        Template {
            name: "recovery",
            subject: "Reset your password",
            body_text: "Reset the password for {{email}}.\n\n{{link}}\n",
            body_html: "<p>Reset the password for {{email}}.</p><p><a href=\"{{link}}\">{{link}}</a></p>",
        },
        Template {
            name: "invite",
            subject: "You are invited",
            body_text: "Accept the invite for {{email}}.\n\n{{link}}\n",
            body_html: "<p>Accept the invite for {{email}}.</p><p><a href=\"{{link}}\">{{link}}</a></p>",
        },
        Template {
            name: "confirm_email",
            subject: "Confirm your email",
            body_text: "Confirm {{email}}.\n\nCode: {{code}}\n\n{{link}}\n",
            body_html: "<p>Confirm {{email}}.</p><p>Code: {{code}}</p><p><a href=\"{{link}}\">{{link}}</a></p>",
        },
        Template {
            name: "otp",
            subject: "Your sign-in code",
            body_text: "Sign in as {{email}}.\n\nCode: {{code}}\n\nThe code expires in 10 minutes.\n",
            body_html: "<p>Sign in as {{email}}.</p><p>Code: {{code}}</p><p>The code expires in 10 minutes.</p>",
        },
    ]
}

pub fn reserved_template(name: &str) -> Option<&'static Template> {
    reserved().iter().find(|template| template.name == name)
}

pub fn fill(body: &str, email: &str, token: &str, link: &str, code: &str) -> String {
    body.replace("{{email}}", email)
        .replace("{{token}}", token)
        .replace("{{link}}", link)
        .replace("{{code}}", code)
}

pub fn auth_link(base: &str, token: &str) -> String {
    let base = base.trim();
    if base.is_empty() {
        return token.to_string();
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}token={token}")
}

#[derive(Clone, Debug)]
pub struct Outgoing {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
    pub from: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls: String,
}

pub trait Mailer: Send + Sync {
    fn send(&self, mail: &Outgoing) -> Result<(), DeliverError>;
}

pub struct SmtpMailer;

impl Mailer for SmtpMailer {
    fn send(&self, mail: &Outgoing) -> Result<(), DeliverError> {
        let from: Mailbox = mail.from.parse().map_err(|_| DeliverError::Failed)?;
        let to: Mailbox = mail.to.parse().map_err(|_| DeliverError::Failed)?;
        let message = Message::builder()
            .from(from)
            .to(to)
            .subject(&mail.subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(mail.text.clone()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(mail.html.clone()),
                    ),
            ).map_err(|_| DeliverError::Failed)?;
        let mut builder = match mail.tls.as_str() {
            "tls" => SmtpTransport::relay(&mail.host).map_err(|_| DeliverError::Failed)?.port(mail.port),
            "none" => SmtpTransport::builder_dangerous(&mail.host).port(mail.port),
            _ => SmtpTransport::starttls_relay(&mail.host)
                .map_err(|_| DeliverError::Failed)?
                .port(mail.port),
        };
        builder = builder.timeout(Some(Duration::from_secs(10)));
        if !mail.username.is_empty() {
            builder = builder.credentials(Credentials::new(mail.username.clone(), mail.password.clone()));
        }
        builder.build().send(&message).map_err(|_| DeliverError::Failed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_templates_and_links() {
        assert_eq!(fill("Hi {{email}} {{code}}", "a@b.co", "t", "l", "123456"), "Hi a@b.co 123456");
        assert_eq!(auth_link("https://app/cb", "tok"), "https://app/cb?token=tok");
        assert_eq!(auth_link("https://app/cb?next=1", "tok"), "https://app/cb?next=1&token=tok");
        assert_eq!(auth_link("", "tok"), "tok");
        assert!(reserved_template("otp").is_some());
        assert!(reserved_template("nope").is_none());
        assert_eq!(reserved().len(), 5);
    }

    #[test]
    fn smtp_reports_failure() {
        let mailer = SmtpMailer;
        let err = mailer.send(&Outgoing {
            to: "a@b.co".into(),
            subject: "s".into(),
            text: "t".into(),
            html: "<p>t</p>".into(),
            from: "from@b.co".into(),
            host: "127.0.0.1".into(),
            port: 1,
            username: "u".into(),
            password: "p".into(),
            tls: "none".into(),
        });
        assert!(err.is_err());
        assert!(mailer
            .send(&Outgoing {
                to: "not-an-email".into(),
                subject: "s".into(),
                text: "t".into(),
                html: "<p>t</p>".into(),
                from: "from@b.co".into(),
                host: "127.0.0.1".into(),
                port: 1,
                username: "".into(),
                password: "".into(),
                tls: "starttls".into(),
            })
            .is_err());
        assert!(mailer
            .send(&Outgoing {
                to: "a@b.co".into(),
                subject: "s".into(),
                text: "t".into(),
                html: "<p>t</p>".into(),
                from: "bad".into(),
                host: "127.0.0.1".into(),
                port: 1,
                username: "".into(),
                password: "".into(),
                tls: "tls".into(),
            })
            .is_err());
    }
}
