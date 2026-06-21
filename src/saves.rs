use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use filetime::{FileTime, set_file_times};
use flate2::read::GzDecoder;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc::UnboundedSender},
};

use crate::{
    auth::{Auth, SavesAuth},
    client::{ClientError, fetch_json, fetch_plain, fetch_save_file, upload_save_file},
    games::{BuildMetadata, GameBuild, GameDetails, get_game_builds},
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
            ("INSTALL", "INSTALLATION_PATH"),
        ])
    }
    pub fn is_supported(&self) -> bool {
        self.content.windows.cloud_storage.enabled
            && self.content.windows.cloud_storage.locations.len() >= 1
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

        let mut path_buf = PathBuf::new();

        remainder
            .split(|c| c == '/' || c == '\\')
            .filter(|s| !s.is_empty())
            .for_each(|p| {
                path_buf.push(p);
            });

        let path_str = path_buf.to_str().unwrap();
        Ok((mapped, path_str.to_owned()))
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

fn first_build_link(items: &[GameBuild]) -> Result<&str, ClientError> {
    items
        .first()
        .map(|build| build.link.as_str())
        .ok_or(ClientError::NotFound)
}

pub async fn get_auth_ids(
    client: &Client,
    game_id: i32,
    auth: &Auth,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
) -> Result<(String, String), ClientError> {
    let game_builds = get_game_builds(auth, client, game_id, game_details_cache.clone()).await?;
    let game_build_link = first_build_link(&game_builds.items)?;

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
        self.0.strip_prefix("saves/").unwrap_or(&self.0).to_owned()
    }
}

fn verify_md5(data: &[u8], expected_hex: &str) -> Result<(), ClientError> {
    let digest = md5::compute(data);
    if format!("{:x}", digest) != expected_hex {
        Err(ClientError::HashMismatch)
    } else {
        Ok(())
    }
}

pub async fn download_file(
    save_file: &SaveFile,
    auth: &SavesAuth,
    client: &Client,
    tx: UnboundedSender<(i64, i64)>,
    path: &PathBuf,
) -> Result<(), ClientError> {
    let url = format!(
        "https://cloudstorage.gog.com/v1/{}/{}/{}",
        auth.user_id, auth.client_id, save_file.0
    );
    let downloaded_bytes = Arc::new(AtomicI64::new(0));
    let bytes_clone = downloaded_bytes.clone();
    let (file_data, md5, last_modified) =
        fetch_save_file(&url, Some(auth), client, |bytes, total| {
            bytes_clone.fetch_add(bytes, Ordering::Relaxed);
            let _ = tx.send((bytes_clone.load(Ordering::Relaxed), total));
        })
        .await?;

    if let Some(hash) = md5 {
        verify_md5(&file_data, &hash)?;
    }

    let mut decoded_buffer = Vec::new();
    let mut z = GzDecoder::new(&file_data[..]);
    z.read_to_end(&mut decoded_buffer)?;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = match tokio::fs::File::create(path).await {
        Ok(f) => f,
        Err(err) => {
            println!("\nPath: {:?}", path);
            println!("Error: {}", err);
            return Err(ClientError::NotFound);
        }
    };

    match file.write_all(&decoded_buffer).await {
        Ok(_) => (),
        Err(err) => {
            println!("\nPath: {:?}", path);
            println!("Error: {}", err);
            return Err(ClientError::NotFound);
        }
    };
    match file.flush().await {
        Ok(_) => (),
        Err(err) => {
            println!("\nPath: {:?}", path);
            println!("Error: {}", err);
            return Err(ClientError::NotFound);
        }
    };
    if let Some(timestamp) = last_modified {
        let dt: DateTime<FixedOffset> = timestamp.parse().map_err(|_err| ClientError::NotFound)?;
        let file_time = FileTime::from_unix_time(dt.timestamp(), dt.timestamp_subsec_nanos());
        set_file_times(path, file_time, file_time)?;
    }

    Ok(())
}

pub async fn upload_file(
    client: &Client,
    auth: &SavesAuth,
    path: &Path,
    url_path: &str,
    tx: UnboundedSender<(i64, i64)>,
) -> Result<(), ClientError> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let url = format!(
        "https://cloudstorage.gog.com/v1/{}/{}/saves/{}?_gog_request_id={}",
        auth.user_id, auth.client_id, url_path, request_id
    );

    let mut file = tokio::fs::File::open(path).await?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;

    let metadata = tokio::fs::metadata(path).await?;
    let modified = metadata.modified()?;
    let modified: DateTime<Utc> = modified.into();
    let timestamp = modified.to_rfc3339_opts(SecondsFormat::Secs, true);

    upload_save_file(
        &url,
        Some(auth),
        client,
        &timestamp,
        buffer,
        move |sent, total| {
            let _ = tx.send((sent, total));
        },
    )
    .await
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

    parse_save_files_list(&response)
}

fn parse_save_files_list(response: &str) -> Result<Vec<SaveFile>, ClientError> {
    response
        .lines()
        .map(|line| {
            if line.starts_with("saves/") {
                Ok(SaveFile(line.to_string()))
            } else {
                Err(ClientError::NotFound)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_save_files_list_accepts_valid_lines() {
        let response = "saves/foo/bar.sav\nsaves/baz.sav";
        let files = parse_save_files_list(response).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn parse_save_files_list_fails_on_malformed_line() {
        let response = "saves/foo/bar.sav\nnot-a-save-line";
        let result = parse_save_files_list(response);
        assert!(matches!(result, Err(ClientError::NotFound)));
    }

    #[test]
    fn first_build_link_returns_first_item() {
        let items = vec![GameBuild {
            build_id: "1".to_string(),
            version_name: "v1".to_string(),
            date_published: "2026-01-01".to_string(),
            link: "https://example.com/build".to_string(),
        }];
        assert_eq!(
            first_build_link(&items).unwrap(),
            "https://example.com/build"
        );
    }

    #[test]
    fn first_build_link_errors_on_empty_slice() {
        let items: Vec<GameBuild> = Vec::new();
        assert!(matches!(
            first_build_link(&items),
            Err(ClientError::NotFound)
        ));
    }

    #[test]
    fn verify_md5_ok_when_matching() {
        let data = b"hello world";
        let digest = md5::compute(data);
        let hex = format!("{:x}", digest);
        assert!(verify_md5(data, &hex).is_ok());
    }

    #[test]
    fn verify_md5_errors_when_mismatched() {
        let data = b"hello world";
        let result = verify_md5(data, "0000000000000000000000000000000");
        assert!(matches!(result, Err(ClientError::HashMismatch)));
    }

    #[test]
    fn get_path_strips_saves_prefix() {
        let save_file = SaveFile("saves/foo/bar.sav".to_string());
        assert_eq!(save_file.get_path(), "foo/bar.sav");
    }
}
