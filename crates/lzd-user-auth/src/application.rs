use crate::login::BackEnd;
use askama::Template;
use axum::response::{Html, IntoResponse};
use axum_login::AuthSession;
use axum_messages::{Message, Messages};

pub mod main {
    use super::*;

    #[derive(Template)]
    #[template(path = "app-main.html")]
    pub struct RegisterTemplate {
        messages: Vec<Message>,
        logged_in: bool,
    }

    pub async fn get(messages: Messages, auth_session: AuthSession<BackEnd>) -> impl IntoResponse {
        Html(
            RegisterTemplate {
                messages: messages.into_iter().collect(),
                logged_in: auth_session.user.is_some(),
            }
            .render()
            .unwrap(),
        )
    }
}
