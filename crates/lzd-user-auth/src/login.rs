use crate::cipher::{Cipher, EncryptedContentAndKey};
use askama_axum::Template;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    Form,
};
use axum_login::{AuthSession, AuthUser, AuthnBackend, UserId};
use axum_messages::{Message, Messages};
use http::StatusCode;
use itertools::Itertools;
use rs_sha512::HasherContext;
use std::{hash::Hasher, string::FromUtf8Error, sync::Arc};

#[derive(Clone, Debug)]
pub struct BackEnd {
    db: lzd_db::Store,
    cipher: Arc<Cipher>,
}

pub(crate) fn create_backend(database: lzd_db::Store, cipher: Arc<Cipher>) -> BackEnd {
    BackEnd {
        db: database,
        cipher,
    }
}

#[derive(Clone, Debug)]
pub struct User {
    id: i32,
    session_auth_hash: [u8; 64],
}

impl AuthUser for User {
    type Id = i32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.session_auth_hash
    }
}

impl From<lzd_db::models::User> for User {
    fn from(
        lzd_db::models::User {
            id, pass_phrase, ..
        }: lzd_db::models::User,
    ) -> Self {
        let mut hasher = rs_sha512::Sha512Hasher::default();
        hasher.write(pass_phrase.as_bytes());
        let _ = hasher.finish();
        let session_hash = HasherContext::finish(&mut hasher);
        Self {
            id: id,
            session_auth_hash: session_hash.into(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("User database error: {0}")]
    UserDb(#[from] lzd_db::Error),
    #[error("Stored pass phrase is not valid utf8: {0}")]
    StoredPassPhraseInvalidUtf8(#[from] FromUtf8Error),
    #[error("Pass phrase could not be verified: {0}")]
    PassPhraseUnableToVerify(#[from] crate::cipher::Error),
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Credentials {
    logon_name: String,
    pass_phrase: String,
    next: Option<String>,
}

#[async_trait::async_trait]
impl AuthnBackend for BackEnd {
    type User = User;
    type Credentials = Credentials;
    type Error = Error;

    async fn authenticate(
        &self,
        credentials: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user = match self
            .db
            .load_user_by_logon_name(&credentials.logon_name)
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        self.cipher
            .verify_pass_phrase(&credentials.pass_phrase, &user.pass_phrase)
            .map(move |verified| if verified { Some(user.into()) } else { None })
            .map_err(Into::into)
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        self.db
            .load_user_by_id(*user_id)
            .await
            .map_err(Into::into)
            .map(|v| v.map(Into::into))
    }
}

pub mod register_new_user {
    use super::*;

    #[derive(Template)]
    #[template(path = "register.html")]
    pub struct RegisterTemplate {
        messages: Vec<Message>,
    }

    #[derive(serde::Deserialize, Debug)]
    pub struct RegistrationForm {
        user_name: String,
        pass_phrase: String,
        repeat_pass_phrase: String,
        email: String,
        repeat_email: String,
    }

    pub async fn get(messages: Messages) -> impl IntoResponse {
        Html(
            RegisterTemplate {
                messages: messages.into_iter().collect(),
            }
            .render()
            .unwrap(),
        )
    }

    pub async fn post(
        mut messages: Messages,
        State(app_state): State<crate::AppState>,
        Form(RegistrationForm {
            user_name,
            mut pass_phrase,
            repeat_pass_phrase,
            email,
            repeat_email,
        }): Form<RegistrationForm>,
    ) -> impl IntoResponse {
        let (user_name_valid, pass_phrase_valid, email_valid);
        (messages, user_name_valid) = validate_user_name(messages, &user_name);
        (messages, pass_phrase, pass_phrase_valid) =
            validate_pass_phrase(messages, pass_phrase, &repeat_pass_phrase);
        (_, email_valid) = validate_email(messages, &email, &repeat_email);
        if user_name_valid && pass_phrase_valid && email_valid {
            let hashed_pass_phrase = match app_state.cipher.hash_passphrase(pass_phrase.as_bytes())
            {
                Ok(hashed_pass_phrase) => hashed_pass_phrase,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let EncryptedContentAndKey {
                encrypted_content: encrypted_email_address,
                encrypted_key: encrypted_secret,
            } = match app_state
                .cipher
                .encrypt_content_with_new_key_and_supply_encrypted_content_and_key(email.as_bytes())
            {
                Ok(encrypted_content_and_key) => encrypted_content_and_key,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            match app_state
                .store
                .register_user(
                    user_name,
                    hashed_pass_phrase,
                    encrypted_email_address,
                    encrypted_secret,
                )
                .await
            {
                Ok((_, _)) => Redirect::to("/hello-logged-in").into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        } else {
            Redirect::to("/register").into_response()
        }
    }

    fn validate_user_name(mut messages: Messages, username: &str) -> (Messages, bool) {
        let mut valid = true;
        if username.contains(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-')) {
            valid = false;
            messages =
                messages.error("user name must only consist of letters, numbers, and '.' or '-'");
        }
        if username.chars().count() < 4 {
            valid = false;
            messages = messages.error("user name must be at least 4 characters in length");
        }
        if username.chars().count() > 64 {
            valid = false;
            messages = messages.error("user name must be no more than 64 characters in length");
        }
        (messages, valid)
    }

    fn validate_pass_phrase(
        mut messages: Messages,
        pass_phrase: String,
        repeat_pass_phrase: &str,
    ) -> (Messages, String, bool) {
        let mut valid = true;
        let stripped_pass_phrase = pass_phrase
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        if stripped_pass_phrase.chars().count() < 24 {
            valid = false;
            messages = messages
                .error("pass phrase must be at least 24 characters in length excluding spaces");
        }
        if stripped_pass_phrase.chars().count() > 512 {
            valid = false;
            messages = messages.error(
                "pass phrase must be shorter than 512 characters in length excluding spaces",
            );
        }
        if pass_phrase.split_whitespace().count() < 5 {
            valid = false;
            messages = messages.error("pass phrase must have at least 5 words separated by space (words may consist of any non-space character including letters, numbers, and punctuation)");
        }
        if stripped_pass_phrase.chars().unique().count() < 8 {
            valid = false;
            messages =
                messages.error("pass phrase must have at least 8 unique non-space characters");
        }
        if pass_phrase.split_whitespace().unique().count() < 4 {
            valid = false;
            messages =
                messages.error("pass phrase must have at least 4 unique, non-repeated words");
        }
        if pass_phrase != repeat_pass_phrase {
            valid = false;
            messages = messages.error("pass phrase entries don't match each other");
        }
        (messages, stripped_pass_phrase, valid)
    }

    fn validate_email(mut messages: Messages, email: &str, repeat_email: &str) -> (Messages, bool) {
        let mut valid = true;
        if let Some((_, domain)) = email.split_once('@') {
            if domain.contains(|c| c == '@') {
                valid = false;
                messages = messages
                    .error("email address is invalid - contains an '@' symbol in the domain name or '@' symbol in name");
            }
        } else {
            valid = false;
            messages = messages.error("email address must contain an '@' character")
        }
        if email != repeat_email {
            valid = false;
            messages = messages.error("email entries don't match each other");
        }
        (messages, valid)
    }
}

pub mod login {
    use super::*;

    #[derive(Template)]
    #[template(path = "login.html")]
    pub struct LoginTemplate {
        messages: Vec<Message>,
        next: Option<String>,
    }

    #[derive(Debug, serde::Deserialize)]
    pub struct NextUrl {
        next: Option<String>,
    }

    pub async fn get(
        messages: Messages,
        Query(NextUrl { next }): Query<NextUrl>,
    ) -> impl IntoResponse {
        Html(
            LoginTemplate {
                messages: messages.into_iter().collect(),
                next,
            }
            .render()
            .unwrap(),
        )
    }

    pub async fn post(
        mut auth_session: AuthSession<BackEnd>,
        messages: Messages,
        Form(creds): Form<Credentials>,
    ) -> impl IntoResponse {
        let user = match auth_session.authenticate(creds.clone()).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                messages.error("Invalid User Name or Pass Phrase");
                let mut login_url = "/login".to_string();
                if let Some(next) = creds.next {
                    login_url = format!("{}?next={}", login_url, next);
                };
                return Redirect::to(&login_url).into_response();
            }
            Err(_) => {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        if let Err(_) = auth_session.login(&user).await {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        messages.success("Successfully logged in");
        if let Some(ref next) = creds.next {
            Redirect::to(next)
        } else {
            Redirect::to("/hello-logged-in")
        }
        .into_response()
    }
}

pub mod logout {
    use super::*;

    pub async fn get() -> impl IntoResponse {
        todo!()
    }

    pub async fn post() -> impl IntoResponse {
        todo!()
    }
}
