use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::client::{ClientError, Method, fetch_json};

pub const LOGIN_URL: &str = "https://auth.gog.com/auth?client_id=46899977096215655&redirect_uri=https://embed.gog.com/on_login_success?origin=client&response_type=code&layout=client2";

#[derive(Deserialize, Serialize, Clone)]
pub struct Auth {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i32,
    pub token_type: String,
    pub session_id: String,
    pub scope: Option<String>,
    pub user_id: String,
}
#[derive(Deserialize, Serialize, Clone)]
pub struct SavesAuth {
    pub access_token: String,
    pub user_id: String,
}

pub async fn refresh_token(refresh_token: &str, client: &Client) -> Result<Auth, ClientError> {
    let url = format!(
        "https://auth.gog.com/token?client_id=46899977096215655&client_secret=9d85c43b1482497dbbce61f6e4aa173a433796eeae2ca8c5f6129f2dc4de46d9&grant_type=refresh_token&refresh_token={}",
        refresh_token
    );
    let auth = fetch_json::<Auth, String>(&url, None, client, Method::Get, false, None).await?;
    Ok(auth)
}

pub async fn get_login_tokens(code: &str, client: &Client) -> Result<Auth, ClientError> {
    let url = format!(
        "https://auth.gog.com/token?client_id=46899977096215655&client_secret=9d85c43b1482497dbbce61f6e4aa173a433796eeae2ca8c5f6129f2dc4de46d9&grant_type=authorization_code&redirect_uri=https://embed.gog.com/on_login_success?origin=client&code={}",
        code
    );
    let auth = fetch_json::<Auth, String>(&url, None, client, Method::Get, false, None).await?;
    Ok(auth)
}

impl Auth {
    pub async fn get_cloud_saves_tokens(
        &self,
        client: &Client,
        client_id: &str,
        client_secret: &str,
    ) -> Result<SavesAuth, ClientError> {
        let url = format!(
            "https://auth.gog.com/token?client_id={}&client_secret={}&grant_type=refresh_token&refresh_token={}",
            client_id, client_secret, self.refresh_token
        );
        let auth =
            fetch_json::<SavesAuth, String>(&url, None, client, Method::Get, false, None).await?;
        Ok(auth)
    }
}
