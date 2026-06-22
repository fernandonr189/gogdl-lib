use std::{
    collections::HashMap,
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
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::{Mutex, RwLock, Semaphore, mpsc::UnboundedSender},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    Mac,
}

impl OperatingSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatingSystem::Windows => "windows",
            OperatingSystem::Linux => "linux",
            OperatingSystem::Mac => "osx",
        }
    }
}

impl std::fmt::Display for OperatingSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DownloadOptions {
    pub max_concurrent_files: usize,
    pub max_concurrent_hashing: usize,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        DownloadOptions {
            max_concurrent_files: 36,
            max_concurrent_hashing: 12,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GameIds {
    pub owned: Vec<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GameDetails {
    pub title: String,
    #[serde(skip)]
    pub id: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GameBuild {
    pub build_id: String,
    pub version_name: String,
    pub date_published: String,
    pub link: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GameBuilds {
    #[serde(skip)]
    pub game_title: String,
    pub count: i32,
    pub items: Vec<GameBuild>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Depot {
    pub manifest: String,
    pub size: u64,
    #[serde(alias = "compressedSize")]
    pub compressed_size: u64,
    #[serde(alias = "productId")]
    pub product_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BuildMetadata {
    pub dependencies: Option<Vec<String>>,
    pub depots: Vec<Depot>,
    #[serde(alias = "clientId")]
    pub client_id: String,
    #[serde(alias = "clientSecret")]
    pub client_secret: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Chunk {
    pub md5: String,
    pub size: u64,
    #[serde(alias = "compressedMd5")]
    pub compressed_md5: String,
    #[serde(alias = "compressedSize")]
    pub compressed_size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DepotItems {
    pub items: Vec<DepotFile>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DepotInfo {
    pub depot: DepotItems,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UrlFormat {
    pub endpoint_name: String,
    pub url_format: String,
    pub priority: u64,
    pub parameters: CdnUrlParams,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecureLinks {
    pub product_id: u64,
    pub urls: Vec<UrlFormat>,
}

/// Wrapper that manages secure links with automatic refresh when expired
#[derive(Debug)]
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
        let product_id_int: i32 = product_id
            .parse()
            .map_err(|_| ClientError::InvalidProductId(product_id.to_string()))?;
        let new_links = get_secure_links(&self.auth, &self.client, product_id_int).await?;
        cache.insert(product_id.to_string(), new_links.clone());

        Ok(new_links)
    }
}

pub async fn get_owned_games(
    auth: &Auth,
    client: &reqwest::Client,
    game_ids_cache: Arc<Mutex<Option<Vec<i32>>>>,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
) -> Result<Vec<GameDetails>, ClientError> {
    let game_ids;

    let cached_ids = {
        let cache_lock = game_ids_cache.lock().await;
        cache_lock.clone()
    };

    if let Some(ids_cache) = cached_ids {
        game_ids = GameIds { owned: ids_cache };
    } else {
        game_ids = fetch_json::<GameIds, String>(
            "https://embed.gog.com/user/data/games",
            Some(auth),
            client,
            Method::Get,
            false,
            None,
        )
        .await?;

        let mut cache_lock = game_ids_cache.lock().await;
        *cache_lock = Some(game_ids.owned.clone());
    }

    let games = stream::iter(game_ids.owned)
        .map(|id| {
            let cache_clone = game_details_cache.clone();
            (id, cache_clone)
        })
        .map(async move |(id, cache)| get_game_details(auth, client, id, cache).await)
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
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
) -> Result<GameDetails, ClientError> {
    let url = format!("https://embed.gog.com/account/gameDetails/{}.json", game_id);

    let mut game_details;
    let cached = {
        let cache_lock = game_details_cache.lock().await;
        cache_lock.get(&game_id).cloned()
    };

    if let Some(game) = cached {
        game_details = game;
    } else {
        game_details =
            fetch_json::<GameDetails, String>(&url, Some(auth), client, Method::Get, false, None)
                .await?;

        let mut cache_lock = game_details_cache.lock().await;
        cache_lock.insert(game_id, game_details.clone());
    }

    game_details.id = game_id;
    Ok(game_details)
}

pub async fn get_game_builds(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    os: OperatingSystem,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
) -> Result<GameBuilds, ClientError> {
    let url = format!(
        "https://content-system.gog.com/products/{}/os/{}/builds?generation=2",
        game_id,
        os.as_str()
    );
    let mut game_builds =
        fetch_json::<GameBuilds, String>(&url, Some(auth), client, Method::Get, false, None)
            .await?;

    let game_details = get_game_details(auth, client, game_id, game_details_cache.clone()).await?;

    game_builds.game_title = game_details.title;
    Ok(game_builds)
}

pub async fn get_build_metadata(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    os: OperatingSystem,
    version_name: &str,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
) -> Result<BuildMetadata, ClientError> {
    let game_builds =
        get_game_builds(auth, client, game_id, os, game_details_cache.clone()).await?;

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
        Err(ClientError::BuildNotFound(format!(
            "no version named {:?}",
            version_name
        )))
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

    let product_id = depot.product_id.clone();

    let mut depot_information =
        fetch_json::<DepotInfo, String>(&url, Some(auth), client, Method::Get, true, None).await?;

    depot_information.depot.items.iter_mut().for_each(|item| {
        item.product_id = Some(product_id.clone());
    });

    Ok(depot_information)
}

pub async fn get_build_files(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    os: OperatingSystem,
    version_name: &str,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
    game_ids_cache: Arc<Mutex<Option<Vec<i32>>>>,
) -> Result<Vec<DepotFile>, ClientError> {
    let mut cache = {
        let cache_lock = game_ids_cache.lock().await;
        cache_lock.clone()
    };

    if cache.is_none() {
        let _ = get_owned_games(
            auth,
            client,
            game_ids_cache.clone(),
            game_details_cache.clone(),
        )
        .await?;
        let cache_lock = game_ids_cache.lock().await;
        cache = cache_lock.clone();
    }

    let build_metadata = get_build_metadata(
        auth,
        client,
        game_id,
        os,
        version_name,
        game_details_cache.clone(),
    )
    .await?;

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

            if let (Some(owned_ids), Some(file_product_id)) =
                (cache.as_ref(), file.product_id.as_ref())
            {
                let file_id_int = parse_product_id(file_product_id)?;
                if owned_ids.contains(&file_id_int) {
                    files.push(file);
                }
            }
        }
    }

    Ok(files)
}

pub async fn get_build_chunks(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    os: OperatingSystem,
    version_name: &str,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
    game_ids_cache: Arc<Mutex<Option<Vec<i32>>>>,
) -> Result<Vec<Chunk>, ClientError> {
    let build_metadata = get_build_metadata(
        auth,
        client,
        game_id,
        os,
        version_name,
        game_details_cache.clone(),
    )
    .await?;

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

    let mut cache = {
        let cache_lock = game_ids_cache.lock().await;
        cache_lock.clone()
    };

    if cache.is_none() {
        let _ = get_owned_games(auth, client, game_ids_cache.clone(), game_details_cache).await?;
        let cache_lock = game_ids_cache.lock().await;
        cache = cache_lock.clone();
    }

    let mut build_chunks: Vec<Chunk> = Vec::new();
    for info in depot_files {
        for file in info.depot.items {
            if let (Some(ids), Some(file_id)) = (cache.as_ref(), file.product_id) {
                let file_id_int = parse_product_id(&file_id)?;
                if ids.contains(&file_id_int) {
                    if let Some(chunks) = file.chunks {
                        build_chunks.extend(chunks);
                    }
                }
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

fn parse_product_id(s: &str) -> Result<i32, ClientError> {
    s.parse::<i32>()
        .map_err(|_| ClientError::InvalidProductId(s.to_string()))
}

fn select_max_priority_url(urls: &[UrlFormat]) -> Result<&UrlFormat, ClientError> {
    urls.iter()
        .max_by_key(|link| link.priority)
        .ok_or(ClientError::NotFound)
}

async fn handle_chunk_download(
    chunk: &Chunk,
    secure_links_manager: &Arc<SecureLinksManager>,
    product_id: &str,
    client: &reqwest::Client,
    tx: &UnboundedSender<(i64, i64)>,
    downloaded_total: &Arc<AtomicI64>,
    total_size: i64,
) -> Result<Vec<u8>, ClientError> {
    // Get fresh links for this product (will refresh if expired)
    let secure_links = secure_links_manager
        .get_links_for_product(product_id)
        .await?;

    let url_format = select_max_priority_url(&secure_links.urls)?;

    let url = url_format.parse_url(&chunk.compressed_md5);
    let alternate_url = url_format.parse_url_redist(&chunk.compressed_md5);

    let downloaded_bytes = Arc::new(AtomicI64::new(0));
    let bytes_clone = downloaded_bytes.clone();
    let res = match fetch_chunk(&url, None, &client, |f| {
        bytes_clone.fetch_add(f, Ordering::Relaxed);
        let total_now = downloaded_total.fetch_add(f, Ordering::Relaxed) + f;
        let _ = tx.send((total_now, total_size));
    })
    .await
    {
        Ok(chunk) => Ok(chunk),
        Err(_primary_err) => {
            let downloaded = bytes_clone.swap(0, Ordering::Relaxed);
            let total_now = downloaded_total.fetch_sub(downloaded, Ordering::Relaxed) - downloaded;
            let _ = tx.send((total_now, total_size));
            match fetch_chunk(&alternate_url, None, &client, |f| {
                bytes_clone.fetch_add(f, Ordering::Relaxed);
                let total_now = downloaded_total.fetch_add(f, Ordering::Relaxed) + f;
                let _ = tx.send((total_now, total_size));
            })
            .await
            {
                Ok(chunk) => Ok(chunk),
                Err(err) => {
                    let downloaded = bytes_clone.swap(0, Ordering::Relaxed);
                    let total_now =
                        downloaded_total.fetch_sub(downloaded, Ordering::Relaxed) - downloaded;
                    let _ = tx.send((total_now, total_size));
                    Err(err)
                }
            }
        }
    };

    match res {
        Ok(downloaded_chunk) => {
            let digest = md5::compute(&downloaded_chunk);
            let actual = format!("{:x}", digest);
            if actual != chunk.md5 {
                let downloaded = bytes_clone.swap(0, Ordering::Relaxed);
                let total_now =
                    downloaded_total.fetch_sub(downloaded, Ordering::Relaxed) - downloaded;
                let _ = tx.send((total_now, total_size));
                return Err(ClientError::HashMismatch {
                    expected: chunk.md5.clone(),
                    actual,
                });
            } else {
                Ok(downloaded_chunk)
            }
        }
        Err(err) => Err(err),
    }
}

/// Checks how many leading chunks of `chunks` are already present and
/// hash-correct at `path`, stopping at the first chunk that doesn't fully
/// verify (file too short, or a hash mismatch). Stateless: re-derives the
/// answer from disk + the manifest's chunk hashes every call, no sidecar
/// state. Returns `(verified_chunk_count, verified_byte_length)`; a missing
/// file returns `(0, 0)`.
async fn verify_existing_chunks(
    path: &Path,
    chunks: &[Chunk],
) -> Result<(usize, u64), ClientError> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(_) => return Ok((0, 0)),
    };

    let mut offset: u64 = 0;
    let mut verified_chunks = 0usize;
    let mut buffer = Vec::new();

    for chunk in chunks {
        buffer.resize(chunk.size as usize, 0);
        if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
            break;
        }
        if file.read_exact(&mut buffer).await.is_err() {
            break;
        }
        let digest = md5::compute(&buffer);
        let actual = format!("{:x}", digest);
        if actual != chunk.md5 {
            break;
        }
        offset += chunk.size;
        verified_chunks += 1;
    }

    Ok((verified_chunks, offset))
}

/// Feeds the first `up_to` bytes of `file` into `md5_ctx`/`sha256_ctx`, so a
/// resumed download's whole-file hash check covers bytes that were already
/// on disk (and verified by `verify_existing_chunks`) rather than just the
/// bytes downloaded in this resumed session.
async fn prime_hash_contexts(
    file: &mut tokio::fs::File,
    up_to: u64,
    md5_ctx: &mut md5::Context,
    sha256_ctx: &mut Sha256,
) -> Result<(), ClientError> {
    file.seek(std::io::SeekFrom::Start(0)).await?;
    let mut remaining = up_to;
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..to_read]).await?;
        md5_ctx.consume(&buffer[..to_read]);
        sha256_ctx.update(&buffer[..to_read]);
        remaining -= to_read as u64;
    }
    Ok(())
}

fn handle_file_downloads(
    chunks: Vec<Chunk>,
    semaphore: Arc<Semaphore>,
    hashing_semaphore: Arc<Semaphore>,
    secure_links_manager: Arc<SecureLinksManager>,
    client: &Client,
    tx: &UnboundedSender<(i64, i64)>,
    file: DepotFile,
    path: &str,
    game_name: &str,
    cancellation_token: CancellationToken,
    downloaded_total: Arc<AtomicI64>,
    total_size: i64,
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

        if cancellation_token.is_cancelled() {
            return Err(ClientError::Cancelled);
        }

        let _permit = match hashing_semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => return Err(ClientError::SemaphoreError(err)),
        };
        let (verified_chunks, verified_len) = verify_existing_chunks(path, &chunks).await?;
        // Progress is tracked in compressed (network-transfer) bytes elsewhere in this
        // pipeline (see fetch_chunk's callback and download_game's total_size), while
        // verified_len above is decompressed (on-disk) bytes used for seeking/truncating.
        let verified_compressed_len: u64 = chunks[..verified_chunks]
            .iter()
            .map(|chunk| chunk.compressed_size)
            .sum();

        if !chunks.is_empty() && verified_chunks == chunks.len() {
            let total_now = downloaded_total
                .fetch_add(verified_compressed_len as i64, Ordering::Relaxed)
                + verified_compressed_len as i64;
            let _ = tx_clone.send((total_now, total_size));
            return Ok(());
        }

        if cancellation_token.is_cancelled() {
            return Err(ClientError::Cancelled);
        }

        let mut md5_ctx = md5::Context::new();
        let mut sha256_ctx = Sha256::new();

        let _permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => return Err(ClientError::SemaphoreError(err)),
        };
        let mut tokio_file = if verified_chunks > 0 {
            let mut existing_file = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .await?;
            prime_hash_contexts(
                &mut existing_file,
                verified_len,
                &mut md5_ctx,
                &mut sha256_ctx,
            )
            .await?;
            existing_file.set_len(verified_len).await?;
            existing_file
                .seek(std::io::SeekFrom::Start(verified_len))
                .await?;
            let total_now = downloaded_total
                .fetch_add(verified_compressed_len as i64, Ordering::Relaxed)
                + verified_compressed_len as i64;
            let _ = tx_clone.send((total_now, total_size));
            existing_file
        } else {
            tokio::fs::File::create(path).await?
        };
        for chunk in chunks.into_iter().skip(verified_chunks) {
            const MAX_RETRIES: usize = 3;
            let mut retries: usize = 0;
            loop {
                let product_id = file.product_id.as_deref().unwrap_or("unknown");
                let result = tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        let _ = tokio::fs::remove_file(path).await;
                        return Err(ClientError::Cancelled);
                    }
                    result = handle_chunk_download(
                        &chunk,
                        &secure_links_manager,
                        product_id,
                        &client,
                        &tx_clone,
                        &downloaded_total,
                        total_size,
                    ) => result,
                };
                match result {
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
            let actual = format!("{:x}", digest);
            if actual != file_md5 {
                return Err(ClientError::HashMismatch {
                    expected: file_md5,
                    actual,
                });
            }
        }
        if let Some(file_sha256) = file.sha256 {
            let sha_digest = sha256_ctx.finalize();
            let hash_bytes: [u8; 32] = sha_digest.into();
            let hash_hex = hex::encode(hash_bytes);
            if hash_hex != file_sha256 {
                return Err(ClientError::HashMismatch {
                    expected: file_sha256,
                    actual: hash_hex,
                });
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
    os: OperatingSystem,
    build_name: &str,
    tx: UnboundedSender<(i64, i64)>,
    path: &str,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
    game_ids_cache: Arc<Mutex<Option<Vec<i32>>>>,
    cancellation_token: CancellationToken,
    options: DownloadOptions,
) -> Result<(), ClientError> {
    let game_files = get_build_files(
        auth,
        client,
        game_id,
        os,
        build_name,
        game_details_cache.clone(),
        game_ids_cache.clone(),
    )
    .await?;

    if cancellation_token.is_cancelled() {
        return Err(ClientError::Cancelled);
    }

    let game_details = get_game_details(auth, client, game_id, game_details_cache.clone()).await?;

    let total_size: i64 = game_files
        .iter()
        .filter_map(|f| f.chunks.as_ref())
        .flat_map(|chunks| chunks.iter())
        .map(|chunk| chunk.compressed_size as i64)
        .sum();
    let downloaded_total = Arc::new(AtomicI64::new(0));

    let semaphore = Arc::new(Semaphore::new(options.max_concurrent_files));
    let hashing_semaphore = Arc::new(Semaphore::new(options.max_concurrent_hashing));

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
                cancellation_token.clone(),
                downloaded_total.clone(),
                total_size,
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

    if cancellation_token.is_cancelled() {
        return Err(ClientError::Cancelled);
    }

    Ok(())
}

/// Bytes already on disk vs. still needed for a build, in compressed
/// (network-transfer) bytes — matching the units `download_build`'s progress
/// channel already reports. `remaining` is what a consumer can use to derive
/// an ETA from its own measured throughput; this crate doesn't track
/// bandwidth itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct DownloadEstimate {
    pub total_size: i64,
    pub already_present: i64,
    pub remaining: i64,
}

/// Computes how much of a build is already present and valid on disk at
/// `path`, without downloading or writing anything. Stateless: re-derives
/// the answer from the manifest and on-disk chunk hashes every call, using
/// the same `verify_existing_chunks` check `download_build` itself uses to
/// decide what to resume — so the estimate always matches what an actual
/// (resumed) download would skip.
pub async fn estimate_download(
    auth: &Auth,
    client: &reqwest::Client,
    game_id: i32,
    os: OperatingSystem,
    version_name: &str,
    path: &str,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
    game_ids_cache: Arc<Mutex<Option<Vec<i32>>>>,
) -> Result<DownloadEstimate, ClientError> {
    let game_files = get_build_files(
        auth,
        client,
        game_id,
        os,
        version_name,
        game_details_cache.clone(),
        game_ids_cache.clone(),
    )
    .await?;

    let game_details = get_game_details(auth, client, game_id, game_details_cache.clone()).await?;

    let mut estimate = DownloadEstimate::default();

    for file in game_files {
        let Some(chunks) = file.chunks else {
            continue;
        };

        let file_total: i64 = chunks
            .iter()
            .map(|chunk| chunk.compressed_size as i64)
            .sum();
        estimate.total_size += file_total;

        let file_path = format!(
            "{}/{}/{}",
            path,
            game_details.title,
            file.path
                .replace("\\\\", "//")
                .replace("\\ ", " ")
                .replace("\\", "/")
        );
        let (verified_chunks, _) = verify_existing_chunks(Path::new(&file_path), &chunks).await?;
        let file_present: i64 = chunks[..verified_chunks]
            .iter()
            .map(|chunk| chunk.compressed_size as i64)
            .sum();
        estimate.already_present += file_present;
    }

    estimate.remaining = estimate.total_size - estimate.already_present;

    Ok(estimate)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_url_format(priority: u64) -> UrlFormat {
        UrlFormat {
            endpoint_name: "test".to_string(),
            url_format: "{base_url}".to_string(),
            priority,
            parameters: CdnUrlParams {
                base_url: "https://example.com".to_string(),
                path: String::new(),
                token: String::new(),
                expires_at: None,
                dirs: None,
                ttl: None,
                source: None,
                gog_token: None,
                l: None,
            },
        }
    }

    #[test]
    fn parse_product_id_accepts_numeric_string() {
        assert_eq!(parse_product_id("123").unwrap(), 123);
    }

    #[test]
    fn parse_product_id_rejects_non_numeric_string() {
        let result = parse_product_id("abc");
        match result {
            Err(ClientError::InvalidProductId(s)) => assert_eq!(s, "abc"),
            other => panic!("expected InvalidProductId, got {other:?}"),
        }
    }

    #[test]
    fn select_max_priority_url_errors_on_empty_slice() {
        let urls: Vec<UrlFormat> = Vec::new();
        assert!(matches!(
            select_max_priority_url(&urls),
            Err(ClientError::NotFound)
        ));
    }

    #[test]
    fn select_max_priority_url_picks_highest_priority() {
        let urls = vec![make_url_format(1), make_url_format(5), make_url_format(3)];
        let selected = select_max_priority_url(&urls).unwrap();
        assert_eq!(selected.priority, 5);
    }

    #[test]
    fn operating_system_as_str_maps_known_values() {
        assert_eq!(OperatingSystem::Windows.as_str(), "windows");
        assert_eq!(OperatingSystem::Linux.as_str(), "linux");
        assert_eq!(OperatingSystem::Mac.as_str(), "osx");
    }

    #[test]
    fn operating_system_display_matches_as_str() {
        assert_eq!(OperatingSystem::Windows.to_string(), "windows");
        assert_eq!(OperatingSystem::Linux.to_string(), "linux");
        assert_eq!(OperatingSystem::Mac.to_string(), "osx");
    }

    #[test]
    fn download_options_default_matches_prior_hardcoded_values() {
        let options = DownloadOptions::default();
        assert_eq!(options.max_concurrent_files, 36);
        assert_eq!(options.max_concurrent_hashing, 12);
    }

    #[tokio::test]
    async fn verify_existing_chunks_stops_at_first_mismatch() {
        let make_chunk = |data: &[u8]| Chunk {
            md5: format!("{:x}", md5::compute(data)),
            size: data.len() as u64,
            compressed_md5: String::new(),
            compressed_size: data.len() as u64,
        };
        let chunks = vec![
            make_chunk(b"AAAA"),
            make_chunk(b"BBBB"),
            make_chunk(b"CCCC"),
        ];

        let path = std::env::temp_dir().join("gogdl_lib_test_verify_existing_chunks.bin");
        // First two chunks match (AAAA, BBBB); the third's bytes (XXXX) don't match CCCC's hash.
        tokio::fs::write(&path, b"AAAABBBBXXXX").await.unwrap();

        let result = verify_existing_chunks(&path, &chunks).await;

        tokio::fs::remove_file(&path).await.unwrap();

        let (verified_chunks, verified_len) = result.unwrap();
        assert_eq!(verified_chunks, 2);
        assert_eq!(verified_len, 8);
    }

    #[tokio::test]
    async fn verify_existing_chunks_returns_zero_for_missing_file() {
        let chunks = vec![Chunk {
            md5: format!("{:x}", md5::compute(b"AAAA")),
            size: 4,
            compressed_md5: String::new(),
            compressed_size: 4,
        }];
        let path = std::env::temp_dir().join("gogdl_lib_test_verify_existing_chunks_missing.bin");

        let (verified_chunks, verified_len) = verify_existing_chunks(&path, &chunks).await.unwrap();

        assert_eq!(verified_chunks, 0);
        assert_eq!(verified_len, 0);
    }
}
