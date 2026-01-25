use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use url::Url;

use crate::{
    auth::Auth,
    client::{ClientError, Method, fetch_chunk, fetch_json},
};
use futures::{
    future::join_all,
    stream::{self, StreamExt},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{RwLock, Semaphore, mpsc::UnboundedSender},
    task::JoinHandle,
};

#[derive(Serialize, Deserialize)]
pub struct GameIds {
    pub owned: Vec<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct GameDetails {
    pub title: String,
    #[serde(skip)]
    pub id: i32,
}

#[derive(Serialize, Deserialize)]
pub struct GameBuild {
    pub build_id: String,
    pub version_name: String,
    pub date_published: String,
    pub link: String,
}

#[derive(Serialize, Deserialize)]
pub struct GameBuilds {
    #[serde(skip)]
    pub game_title: String,
    pub count: i32,
    pub items: Vec<GameBuild>,
}

#[derive(Serialize, Deserialize)]
pub struct Depot {
    pub manifest: String,
    pub size: u64,
    #[serde(alias = "compressedSize")]
    pub compressed_size: u64,
    #[serde(alias = "productId")]
    pub product_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct BuildMetadata {
    pub dependencies: Option<Vec<String>>,
    pub depots: Vec<Depot>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Chunk {
    pub md5: String,
    pub size: u64,
    #[serde(alias = "compressedMd5")]
    pub compressed_md5: String,
    #[serde(alias = "compressedSize")]
    pub compressed_size: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DepotFile {
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub path: String,
    pub chunks: Option<Vec<Chunk>>,
    #[serde(alias = "type")]
    pub file_type: String,
    /// The product_id this file belongs to (set during processing)
    #[serde(skip)]
    pub product_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DepotItems {
    pub items: Vec<DepotFile>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DepotInfo {
    pub depot: DepotItems,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CdnUrlParams {
    pub base_url: String,
    pub path: String,
    pub token: String,
    pub expires_at: Option<u64>,
    pub dirs: Option<u64>,
    pub ttl: Option<u64>,
    pub source: Option<String>,
    pub gog_token: Option<String>,
    pub l: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UrlFormat {
    pub endpoint_name: String,
    pub url_format: String,
    pub priority: u64,
    pub parameters: CdnUrlParams,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecureLinks {
    pub product_id: u64,
    pub urls: Vec<UrlFormat>,
}

/// Wrapper that manages secure links with automatic refresh when expired
pub struct SecureLinksManager {
    auth: Auth,
    client: Client,
    /// Cache of secure links per product_id
    links_cache: RwLock<std::collections::HashMap<String, SecureLinks>>,
    /// Buffer time in seconds before actual expiry to refresh (default 5 minutes)
    refresh_buffer: u64,
}

impl SecureLinksManager {
    pub fn new(auth: Auth, client: Client) -> Self {
        Self {
            auth,
            client,
            links_cache: RwLock::new(std::collections::HashMap::new()),
            refresh_buffer: 300, // 5 minutes buffer
        }
    }

    /// Get current timestamp in seconds since UNIX epoch
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Check if the current links are expired or about to expire
    fn is_expired(links: &SecureLinks, buffer: u64) -> bool {
        let now = Self::current_timestamp();

        // Check if any URL format has an expires_at that's past or within buffer
        for url_format in &links.urls {
            if let Some(expires_at) = url_format.parameters.expires_at {
                if now + buffer >= expires_at {
                    return true;
                }
            }
        }
        false
    }

    /// Get secure links for a specific product_id, refreshing if expired or not cached
    pub async fn get_links_for_product(
        &self,
        product_id: &str,
    ) -> Result<SecureLinks, ClientError> {
        // First, check with read lock if we have valid cached links
        {
            let cache = self.links_cache.read().await;
            if let Some(links) = cache.get(product_id) {
                if !Self::is_expired(links, self.refresh_buffer) {
                    return Ok(links.clone());
                }
            }
        }

        // Need to fetch or refresh - acquire write lock
        let mut cache = self.links_cache.write().await;

        // Double-check after acquiring write lock (another task might have fetched)
        if let Some(links) = cache.get(product_id) {
            if !Self::is_expired(links, self.refresh_buffer) {
                return Ok(links.clone());
            }
        }

        // Fetch new links for this product_id
        eprintln!("Fetching secure links for product {}...", product_id);
        let product_id_int: i32 = product_id.parse().map_err(|_| ClientError::NotFound)?;
        let new_links = get_secure_links(&self.auth, &self.client, product_id_int).await?;
        cache.insert(product_id.to_string(), new_links.clone());

        Ok(new_links)
    }
}

pub async fn get_owned_games(
    auth: &Auth,
    client: &reqwest::Client,
) -> Result<Vec<GameDetails>, ClientError> {
    let game_ids = fetch_json::<GameIds, String>(
        "https://embed.gog.com/user/data/games",
        Some(auth),
        client,
        Method::Get,
        false,
        None,
    )
    .await?;

    let games = stream::iter(game_ids.owned)
        .map(|game_id| async move { get_game_details(auth, client, game_id).await })
        .buffer_unordered(8)
        .filter_map(|res| async { res.ok() })
        .collect::<Vec<_>>()
        .await;

    Ok(games)
}

pub async fn get_game_details(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
) -> Result<GameDetails, ClientError> {
    let url = format!("https://embed.gog.com/account/gameDetails/{}.json", game_id);
    let mut game_details =
        fetch_json::<GameDetails, String>(&url, Some(auth), client, Method::Get, false, None)
            .await?;

    game_details.id = game_id;
    Ok(game_details)
}

pub async fn get_game_builds(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
) -> Result<GameBuilds, ClientError> {
    let url = format!(
        "https://content-system.gog.com/products/{}/os/windows/builds?generation=2",
        game_id
    );
    let mut game_builds =
        fetch_json::<GameBuilds, String>(&url, Some(auth), client, Method::Get, false, None)
            .await?;

    let game_details = get_game_details(auth, client, game_id).await?;

    game_builds.game_title = game_details.title;
    Ok(game_builds)
}

pub async fn get_build_metadata(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    version_name: &str,
) -> Result<BuildMetadata, ClientError> {
    let game_builds = get_game_builds(auth, client, game_id).await?;

    let game_link = game_builds
        .items
        .iter()
        .find(|build| build.version_name == version_name);

    if let Some(game_link) = game_link {
        let build_metadata = fetch_json::<BuildMetadata, String>(
            &game_link.link,
            Some(auth),
            client,
            Method::Get,
            true,
            None,
        )
        .await?;
        Ok(build_metadata)
    } else {
        Err(ClientError::NotFound)
    }
}

pub async fn get_depot_information(
    auth: &Auth,
    client: &reqwest::Client,
    depot: &Depot,
) -> Result<DepotInfo, ClientError> {
    let manifest = &depot.manifest;
    let url = format!(
        "https://cdn.gog.com/content-system/v2/meta/{}/{}/{}",
        &manifest[0..2],
        &manifest[2..4],
        &manifest
    );

    let depot_information =
        fetch_json::<DepotInfo, String>(&url, Some(auth), client, Method::Get, true, None).await?;

    Ok(depot_information)
}

pub async fn get_build_files(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    version_name: &str,
) -> Result<Vec<DepotFile>, ClientError> {
    let build_metadata = get_build_metadata(auth, client, game_id, version_name).await?;

    let depot_files: Result<Vec<_>, _> = join_all(
        build_metadata
            .depots
            .iter()
            .map(|depot| get_depot_information(auth, client, depot)),
    )
    .await
    .into_iter()
    .collect();

    let depot_files = depot_files?;

    let mut files: Vec<DepotFile> = Vec::new();

    for (info, depot) in depot_files.iter().zip(build_metadata.depots.iter()) {
        for mut file in info.depot.items.clone() {
            file.product_id = Some(depot.product_id.clone());
            files.push(file);
        }
    }

    Ok(files)
}

pub async fn get_build_chunks(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    version_name: &str,
) -> Result<Vec<Chunk>, ClientError> {
    let build_metadata = get_build_metadata(auth, client, game_id, version_name).await?;

    let depot_files: Result<Vec<_>, _> = join_all(
        build_metadata
            .depots
            .iter()
            .map(|depot| get_depot_information(auth, client, depot)),
    )
    .await
    .into_iter()
    .collect();

    let depot_files = depot_files?;

    let mut build_chunks: Vec<Chunk> = Vec::new();
    for info in depot_files {
        for file in info.depot.items {
            if let Some(chunks) = file.chunks {
                build_chunks.extend(chunks);
            }
        }
    }

    Ok(build_chunks)
}
pub async fn get_secure_links(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
) -> Result<SecureLinks, ClientError> {
    let url = format!(
        "https://content-system.gog.com/products/{}/secure_link?generation=2&_version=2&path=/",
        game_id
    );

    let secure_links =
        fetch_json::<SecureLinks, String>(&url, Some(auth), client, Method::Get, false, None)
            .await?;

    Ok(secure_links)
}

async fn handle_chunk_download(
    chunk: &Chunk,
    secure_links_manager: &Arc<SecureLinksManager>,
    product_id: &str,
    client: &reqwest::Client,
    tx: &UnboundedSender<i64>,
) -> Result<Vec<u8>, ClientError> {
    // Get fresh links for this product (will refresh if expired)
    let secure_links = secure_links_manager
        .get_links_for_product(product_id)
        .await?;

    let max_priority = secure_links
        .urls
        .iter()
        .map(|link| link.priority)
        .max()
        .unwrap_or(0);

    let url_format = secure_links
        .urls
        .iter()
        .find(|link| link.priority == max_priority)
        .expect("no secure link with max priority");

    let url = url_format.parse_url(&chunk.compressed_md5);
    let alternate_url = url_format.parse_url_redist(&chunk.compressed_md5);

    let downloaded_bytes = Arc::new(AtomicI64::new(0));
    let bytes_clone = downloaded_bytes.clone();
    let res = match fetch_chunk(&url, None, &client, |f| {
        bytes_clone.fetch_add(f, Ordering::Relaxed);
        let _ = tx.send(f);
    })
    .await
    {
        Ok(chunk) => Ok(chunk),
        Err(_primary_err) => {
            let downloaded = bytes_clone.swap(0, Ordering::Relaxed);
            let _ = tx.send(-downloaded);
            match fetch_chunk(&alternate_url, None, &client, |f| {
                bytes_clone.fetch_add(f, Ordering::Relaxed);
                let _ = tx.send(f);
            })
            .await
            {
                Ok(chunk) => Ok(chunk),
                Err(err) => {
                    let downloaded = bytes_clone.swap(0, Ordering::Relaxed);
                    let _ = tx.send(-downloaded);
                    Err(err)
                }
            }
        }
    };

    match res {
        Ok(downloaded_chunk) => {
            let digest = md5::compute(&downloaded_chunk);
            if format!("{:x}", digest) != chunk.md5 {
                println!("Hash mismatch: {:x} != {}", digest, chunk.md5);
                let downloaded = bytes_clone.swap(0, Ordering::Relaxed);
                let _ = tx.send(-downloaded);
                return Err(ClientError::HashMismatch);
            } else {
                Ok(downloaded_chunk)
            }
        }
        Err(err) => Err(err),
    }
}

async fn hash_file(file: &mut tokio::fs::File) -> Result<(md5::Digest, [u8; 32]), std::io::Error> {
    let mut md5_ctx = md5::Context::new();
    let mut sha256_ctx = Sha256::new();

    let mut buf = [0u8; 64 * 1024]; // 64 KiB buffer

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        md5_ctx.consume(&buf[..n]);
        sha256_ctx.update(&buf[..n]);
    }

    let md5 = md5_ctx.finalize();
    let sha256: [u8; 32] = sha256_ctx.finalize().into();

    Ok((md5, sha256))
}

fn handle_file_downloads(
    chunks: Vec<Chunk>,
    semaphore: Arc<Semaphore>,
    hashing_semaphore: Arc<Semaphore>,
    secure_links_manager: Arc<SecureLinksManager>,
    client: &Client,
    tx: &UnboundedSender<i64>,
    file: DepotFile,
    path: &str,
    game_name: &str,
) -> JoinHandle<Result<(), ClientError>> {
    let client = client.clone();
    let tx_clone = tx.clone();
    let path_copy = path.to_string();
    let game_name_clone = game_name.to_string();

    let handle: JoinHandle<Result<(), ClientError>> = tokio::spawn(async move {
        let file_path = format!(
            "{}/{}/{}",
            path_copy,
            game_name_clone,
            file.path
                .replace("\\\\", "//")
                .replace("\\ ", " ")
                .replace("\\", "/")
        );

        let path = Path::new(&file_path);

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let _permit = match hashing_semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => return Err(ClientError::SemaphoreError(err)),
        };
        if let Ok(mut existing_file) = tokio::fs::File::open(path).await {
            let mut file_valid = true;

            let (md5, sha256) = hash_file(&mut existing_file).await?;

            if let Some(file_md5) = &file.md5 {
                let md5_hex = format!("{:x}", md5);

                if md5_hex != *file_md5 {
                    file_valid = false;
                }
            }
            if let Some(file_sha256) = &file.sha256 {
                let sha256_hex = hex::encode(sha256);

                if sha256_hex != *file_sha256 {
                    file_valid = false;
                }
            }

            if !file_valid {
                println!("\nHash mismatch: Deleting invalid file...");
                drop(existing_file);
                tokio::fs::remove_file(path).await?;
            } else {
                if let Some(chunks) = &file.chunks {
                    let size: u64 = chunks.iter().map(|chunk| chunk.compressed_size).sum();
                    let _ = tx_clone.send(size as i64);
                } else {
                    println!("File is valid, but progress reporting may lie");
                }
                return Ok(());
            }
        }

        let mut md5_ctx = md5::Context::new();
        let mut sha256_ctx = Sha256::new();

        let _permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => return Err(ClientError::SemaphoreError(err)),
        };
        let mut tokio_file = tokio::fs::File::create(path).await?;
        for chunk in chunks {
            const MAX_RETRIES: usize = 3;
            let mut retries: usize = 0;
            loop {
                let product_id = file.product_id.as_deref().unwrap_or("unknown");
                match handle_chunk_download(
                    &chunk,
                    &secure_links_manager,
                    product_id,
                    &client,
                    &tx_clone,
                )
                .await
                {
                    Ok(data) => {
                        md5_ctx.consume(&data);
                        sha256_ctx.update(&data);
                        tokio_file.write_all(&data).await?;
                        break;
                    }
                    Err(err) => {
                        retries += 1;
                        tokio::time::sleep(Duration::from_millis(200 * retries as u64)).await;
                        if retries >= MAX_RETRIES {
                            eprintln!("Failed to download chunk: {}", err);
                            let _ = tokio::fs::remove_file(path).await;
                            return Err(err);
                        }
                    }
                }
            }
        }
        tokio_file.flush().await?;
        tokio_file.sync_all().await?;
        drop(tokio_file);
        // Verify hash
        if let Some(file_md5) = file.md5 {
            let digest = md5_ctx.finalize();
            if format!("{:x}", digest) != file_md5 {
                println!("Hash mismatch: {:x} != {}", digest, file_md5);
                return Err(ClientError::HashMismatch);
            }
        }
        if let Some(file_sha256) = file.sha256 {
            let sha_digest = sha256_ctx.finalize();
            let hash_bytes: [u8; 32] = sha_digest.into();
            let hash_hex = hex::encode(hash_bytes);
            if hash_hex != file_sha256 {
                println!("Hash mismatch: {} != {}", hash_hex, file_sha256);
                return Err(ClientError::HashMismatch);
            }
        }
        Ok(())
    });
    handle
}

pub async fn download_game(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    build_name: &str,
    tx: UnboundedSender<i64>,
    path: &str,
) -> Result<(), ClientError> {
    let game_files = get_build_files(auth, client, game_id, build_name).await?;

    let game_details = get_game_details(auth, client, game_id).await?;

    let semaphore = Arc::new(Semaphore::new(36));
    let hashing_semaphore = Arc::new(Semaphore::new(12));

    let mut handles: Vec<JoinHandle<Result<(), ClientError>>> = Vec::new();

    // Create a manager that will fetch and cache secure links per product_id
    let secure_links_manager = Arc::new(SecureLinksManager::new(auth.clone(), client.clone()));

    for file in game_files {
        let file_clone = file.clone();
        if let Some(chunks) = file.chunks {
            let handle = handle_file_downloads(
                chunks,
                semaphore.clone(),
                hashing_semaphore.clone(),
                secure_links_manager.clone(),
                client,
                &tx,
                file_clone,
                path,
                &game_details.title,
            );
            handles.push(handle);
        }
    }

    // Await all downloads

    for res in futures::future::join_all(handles).await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(join_err) => {
                return Err(ClientError::AsyncError(join_err));
            }
        }
    }

    Ok(())
}

impl UrlFormat {
    pub fn parse_url_redist(&self, chunk_hash: &str) -> String {
        let url = format!(
            "https://gog-cdn-fastly.gog.com/content-system/v2/dependencies/store/{}/{}/{}",
            &chunk_hash[0..2],
            &chunk_hash[2..4],
            chunk_hash
        );
        url
    }
    pub fn parse_url(&self, chunk_hash: &str) -> String {
        let mut url = self.url_format.clone();
        url = url.replace("{path}", &self.parameters.path);
        url = url.replace("{token}", &self.parameters.token);
        url = url.replace("{base_url}", &self.parameters.base_url);

        if let Some(expires_at) = self.parameters.expires_at {
            url = url.replace("{expires_at}", &expires_at.to_string());
        }
        if let Some(dirs) = self.parameters.dirs {
            url = url.replace("{dirs}", &dirs.to_string());
        }
        if let Some(ttl) = self.parameters.ttl {
            url = url.replace("{ttl}", &ttl.to_string());
        }
        if let Some(source) = &self.parameters.source {
            url = url.replace("{source}", source);
        }
        if let Some(gog_token) = &self.parameters.gog_token {
            url = url.replace("{gog_token}", gog_token);
        }
        if let Some(l) = &self.parameters.l {
            url = url.replace("{l}", l);
        }
        let galaxy_path = format!("{}/{}/{}", &chunk_hash[0..2], &chunk_hash[2..4], chunk_hash);

        // Properly insert chunk path into URL path component (before query string)
        if let Ok(mut parsed_url) = Url::parse(&url) {
            let current_path = parsed_url.path().trim_end_matches('/');
            let new_path = format!("{}/{}", current_path, galaxy_path);
            parsed_url.set_path(&new_path);
            parsed_url.to_string()
        } else {
            // Fallback to simple concatenation if URL parsing fails
            format!("{}/{}", url.trim_end_matches('/'), galaxy_path)
        }
    }
}
