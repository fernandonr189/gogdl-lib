use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::mpsc::UnboundedSender};

use crate::{
    auth::{Auth, SavesAuth},
    client::{ClientError, fetch_json, fetch_plain, fetch_save_file},
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
    fn known_folder_map(&self) -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("SAVED_GAMES", "Saved Games"),
            ("DOCUMENTS", "Documents"),
            ("DESKTOP", "Desktop"),
            ("APPDATA", "AppData/Roaming"),
            ("LOCAL_APPDATA", "AppData/Local"),
            ("PROGRAMDATA", "ProgramData"),
            ("PUBLIC", "Users/Public"),
        ])
    }
    pub fn is_supported(&self) -> bool {
        self.content.windows.cloud_storage.enabled
    }
    pub fn get_path(&self) -> Result<(String, String), ClientError> {
        let map = self.known_folder_map();
        let gog_path = self.content.windows.cloud_storage.locations[0]
            .location
            .clone();
        let (placeholder, remainder) = gog_path.split_once('>').ok_or(ClientError::NotFound)?;

        let folder_key = placeholder
            .strip_prefix("<?")
            .ok_or(ClientError::NotFound)?
            .strip_suffix("?")
            .ok_or(ClientError::NotFound)?;
        let mapped = map
            .get(folder_key)
            .ok_or(ClientError::NotFound)?
            .to_string();

        let rest = remainder.strip_prefix("/").ok_or(ClientError::NotFound)?;

        Ok((mapped, rest.to_owned()))
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

#[derive(Debug, Clone)]
pub struct SaveFile(String);

impl SaveFile {
    pub fn get_path(&self) -> String {
        self.0.clone()
    }
}

impl SaveFile {
    pub async fn download_file(
        &self,
        auth: &SavesAuth,
        client: &Client,
        tx: UnboundedSender<(i64, i64)>,
        path: &PathBuf,
    ) -> Result<(), ClientError> {
        let url = format!(
            "https://cloudstorage.gog.com/v1/{}/{}/{}",
            auth.user_id, auth.client_id, &self.0
        );
        let downloaded_bytes = Arc::new(AtomicI64::new(0));
        let bytes_clone = downloaded_bytes.clone();
        let file_data = fetch_save_file(&url, Some(auth), client, |bytes, total| {
            bytes_clone.fetch_add(bytes, Ordering::Relaxed);
            let _ = tx.send((bytes_clone.load(Ordering::Relaxed), total));
        })
        .await?;

        println!("Creating directories");
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        println!("Creating file");
        let mut file = match tokio::fs::File::create(path).await {
            Ok(f) => f,
            Err(err) => {
                println!("Path: {:?}", path);
                println!("Error: {}", err);
                return Err(ClientError::NotFound);
            }
        };

        println!("Writing file");
        match file.write_all(&file_data).await {
            Ok(_) => (),
            Err(err) => {
                println!("Path: {:?}", path);
                println!("Error: {}", err);
                return Err(ClientError::NotFound);
            }
        };
        match file.flush().await {
            Ok(_) => (),
            Err(err) => {
                println!("Path: {:?}", path);
                println!("Error: {}", err);
                return Err(ClientError::NotFound);
            }
        };

        println!("File written");
        Ok(())
    }
}

pub async fn get_save_files_list(
    client: &Client,
    client_id: &str,
    auth: &SavesAuth,
) -> Result<Vec<SaveFile>, ClientError> {
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

    let save_files: Vec<SaveFile> = response
        .lines()
        .map(|line| SaveFile(line.to_string()))
        .collect();

    Ok(save_files)
}
