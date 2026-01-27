use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{Auth, SavesAuth},
    client::{ClientError, fetch_json, fetch_plain},
    games::{BuildMetadata, get_game_builds},
};

#[derive(Serialize, Deserialize, Debug)]
struct CloudStorageLocation {
    name: String,
    location: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct CloudStorage {
    enabled: bool,
    locations: Vec<CloudStorageLocation>,
}

#[derive(Serialize, Deserialize, Debug)]
struct IsSupported {
    supported: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct OsData {
    overlay: IsSupported,
    #[serde(alias = "cloudStorage")]
    cloud_storage: CloudStorage,
}

#[derive(Serialize, Deserialize, Debug)]
struct RemoteConfigContent {
    #[serde(alias = "Windows")]
    windows: OsData,
    #[serde(alias = "MacOS")]
    macos: OsData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoteConfig {
    version: String,
    content: RemoteConfigContent,
}

impl RemoteConfig {
    pub fn is_supported(&self) -> bool {
        self.content.windows.cloud_storage.enabled
    }
}

pub async fn get_remote_config(
    client: &Client,
    client_id: &str,
) -> Result<RemoteConfig, ClientError> {
    let url = format!(
        "https://remote-config.gog.com/components/galaxy_client/clients/{}?component_version=2.0.43",
        client_id
    );
    let response = fetch_json::<RemoteConfig, String>(
        &url,
        None,
        client,
        crate::client::Method::Get,
        false,
        None,
    )
    .await?;

    Ok(response)
}

pub async fn get_auth_ids(
    client: &Client,
    game_id: i32,
    auth: &Auth,
) -> Result<(String, String), ClientError> {
    let game_builds = get_game_builds(auth, client, game_id).await?;
    let game_build_link = &game_builds.items[0].link;

    let auth_ids = fetch_json::<BuildMetadata, String>(
        game_build_link,
        Some(auth),
        client,
        crate::client::Method::Get,
        true,
        None,
    )
    .await?;
    Ok((auth_ids.client_id, auth_ids.client_secret))
}

pub async fn get_save_files_list(
    client: &Client,
    client_id: &str,
    auth: &SavesAuth,
) -> Result<String, ClientError> {
    let url = format!(
        "https://cloudstorage.gog.com/v1/{}/{}",
        auth.user_id, client_id
    );
    let response = fetch_plain::<String>(
        &url,
        Some(auth),
        client,
        crate::client::Method::Get,
        false,
        None,
    )
    .await?;

    Ok(response)
}
