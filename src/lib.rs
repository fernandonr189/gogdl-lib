use std::{collections::HashMap, path::PathBuf, sync::Arc};

use thiserror::Error;
use tokio::sync::{Mutex, mpsc::UnboundedSender};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{Auth, get_login_tokens, refresh_token},
    client::ClientError,
    games::{
        BuildMetadata, Chunk, CleanupSummary, DepotFile, DownloadEstimate, DownloadOptions,
        GameBuilds, GameDetails, OperatingSystem, RepairProgress, RepairSummary, SecureLinks,
        VerifiedFileState,
    },
    saves::{RemoteConfig, SaveFile},
};

pub mod auth;
pub mod client;
pub mod games;
pub mod saves;

#[derive(Debug)]
pub struct GogDl {
    auth: Mutex<Option<Auth>>,
    client: reqwest::Client,
    game_ids_cache: Arc<Mutex<Option<Vec<i32>>>>,
    game_details_cache: Arc<Mutex<HashMap<i32, GameDetails>>>,
}

impl GogDl {
    pub async fn set_auth(&self, auth: Option<Auth>) {
        let mut auth_lock = self.auth.lock().await;
        *auth_lock = auth;
    }

    pub fn new(auth: Option<Auth>) -> Self {
        let game_ids_cache = Arc::new(Mutex::new(None));
        let game_details_cache = Arc::new(Mutex::new(HashMap::new()));
        GogDl {
            auth: Mutex::new(auth),
            client: reqwest::Client::new(),
            game_ids_cache,
            game_details_cache,
        }
    }

    pub fn get_login_url() -> &'static str {
        auth::LOGIN_URL
    }

    pub async fn refresh_token(&self) -> Result<Auth, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };

        if let Some(auth) = auth.as_ref() {
            let new_auth = refresh_token(&auth.refresh_token, &self.client).await?;
            Ok(new_auth)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }

    pub async fn get_login_tokens(&self, code: &str) -> Result<Auth, ClientError> {
        let auth = get_login_tokens(code, &self.client).await?;
        Ok(auth)
    }

    pub async fn validate_auth(&self) -> Result<(), ClientError> {
        let auth_lock = self.auth.lock().await;
        if let Some(auth) = auth_lock.as_ref() {
            auth.validate_token().await
        } else {
            Err(ClientError::NotLoggedIn)
        }
    }

    pub async fn get_game_details(&self, game_id: i32) -> Result<GameDetails, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let game_details = games::get_game_details(
                auth,
                &self.client,
                game_id,
                self.game_details_cache.clone(),
            )
            .await?;
            Ok(game_details)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_owned_games(&self) -> Result<Vec<GameDetails>, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let games = games::get_owned_games(
                &auth,
                &self.client,
                self.game_ids_cache.clone(),
                self.game_details_cache.clone(),
            )
            .await?;
            Ok(games)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }

    /// Clears the cached list of owned game IDs. The next call to
    /// `get_owned_games` or `get_build_files`/`get_build_chunks` (which lazily
    /// populate this cache) will re-fetch from the network.
    pub async fn invalidate_owned_games_cache(&self) {
        let mut cache_lock = self.game_ids_cache.lock().await;
        *cache_lock = None;
    }

    /// Clears cached game details. If `game_id` is `Some`, only that entry is
    /// removed; if `None`, the entire cache is cleared.
    pub async fn invalidate_game_details_cache(&self, game_id: Option<i32>) {
        let mut cache_lock = self.game_details_cache.lock().await;
        match game_id {
            Some(id) => {
                cache_lock.remove(&id);
            }
            None => cache_lock.clear(),
        }
    }

    /// Clears the owned-games cache and immediately re-fetches it.
    pub async fn refresh_owned_games(&self) -> Result<Vec<GameDetails>, GogdlError> {
        self.invalidate_owned_games_cache().await;
        self.get_owned_games().await
    }

    pub async fn get_game_builds(
        &self,
        game_id: i32,
        os: OperatingSystem,
    ) -> Result<GameBuilds, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let game_builds = games::get_game_builds(
                auth,
                &self.client,
                game_id,
                os,
                self.game_details_cache.clone(),
            )
            .await?;
            Ok(game_builds)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_build_metadata(
        &self,
        game_id: i32,
        os: OperatingSystem,
        version_name: &str,
    ) -> Result<BuildMetadata, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let build_metadata = games::get_build_metadata(
                auth,
                &self.client,
                game_id,
                os,
                version_name,
                self.game_details_cache.clone(),
            )
            .await?;
            Ok(build_metadata)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_build_files(
        &self,
        game_id: i32,
        os: OperatingSystem,
        version_name: &str,
    ) -> Result<Vec<DepotFile>, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let depot_files = games::get_build_files(
                auth,
                &self.client,
                game_id,
                os,
                &version_name,
                self.game_details_cache.clone(),
                self.game_ids_cache.clone(),
            )
            .await?;
            Ok(depot_files)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn download_build(
        &self,
        game_id: i32,
        version_name: &str,
        tx: UnboundedSender<(i64, i64)>,
        path: &str,
        os: OperatingSystem,
        cancellation_token: CancellationToken,
        options: DownloadOptions,
        verified_files: HashMap<String, VerifiedFileState>,
    ) -> Result<(), GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let res = games::download_game(
                auth,
                &self.client,
                game_id,
                os,
                &version_name,
                tx,
                path,
                self.game_details_cache.clone(),
                self.game_ids_cache.clone(),
                cancellation_token,
                options,
                verified_files,
            )
            .await?;
            Ok(res)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    /// Single-pass verify-and-repair: fetches the build manifest once,
    /// verifies on-disk state once (reporting `RepairProgress::Verifying`
    /// throughout), then downloads only what verification found
    /// missing/corrupt. See `games::verify_and_repair_build` for the full
    /// contract — in particular, `RepairProgress::Downloading` reports
    /// session-only bytes, not cumulative-including-already-valid.
    pub async fn verify_and_repair_build(
        &self,
        game_id: i32,
        version_name: &str,
        tx: UnboundedSender<RepairProgress>,
        path: &str,
        os: OperatingSystem,
        cancellation_token: CancellationToken,
        options: DownloadOptions,
    ) -> Result<RepairSummary, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let summary = games::verify_and_repair_build(
                auth,
                &self.client,
                game_id,
                os,
                version_name,
                tx,
                path,
                self.game_details_cache.clone(),
                self.game_ids_cache.clone(),
                cancellation_token,
                options,
            )
            .await?;
            Ok(summary)
        } else {
            Err(GogdlError::NotLoggedIn)
        }
    }
    /// Deletes on-disk files (and directories left empty as a result) under
    /// the resolved game directory for `build_name` that aren't referenced
    /// by that build's manifest. See `games::cleanup_build` for the full
    /// contract — in particular, it's a no-op if the game directory doesn't
    /// exist yet, rather than an error.
    pub async fn cleanup_build(
        &self,
        game_id: i32,
        build_name: &str,
        path: &str,
        os: OperatingSystem,
        cancellation_token: CancellationToken,
    ) -> Result<CleanupSummary, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let summary = games::cleanup_build(
                auth,
                &self.client,
                game_id,
                os,
                build_name,
                path,
                self.game_details_cache.clone(),
                self.game_ids_cache.clone(),
                cancellation_token,
            )
            .await?;
            Ok(summary)
        } else {
            Err(GogdlError::NotLoggedIn)
        }
    }
    pub async fn estimate_download(
        &self,
        game_id: i32,
        os: OperatingSystem,
        version_name: &str,
        path: &str,
        tx: UnboundedSender<(i64, i64)>,
    ) -> Result<DownloadEstimate, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let estimate = games::estimate_download(
                auth,
                &self.client,
                game_id,
                os,
                version_name,
                path,
                self.game_details_cache.clone(),
                self.game_ids_cache.clone(),
                tx,
            )
            .await?;
            Ok(estimate)
        } else {
            Err(GogdlError::NotLoggedIn)
        }
    }
    pub async fn get_build_chunks(
        &self,
        game_id: i32,
        os: OperatingSystem,
        version_name: &str,
    ) -> Result<Vec<Chunk>, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let build_chunks = games::get_build_chunks(
                auth,
                &self.client,
                game_id,
                os,
                &version_name,
                self.game_details_cache.clone(),
                self.game_ids_cache.clone(),
            )
            .await?;
            Ok(build_chunks)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_secure_links(&self, game_id: i32) -> Result<SecureLinks, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let secure_links = games::get_secure_links(auth, &self.client, game_id).await?;
            Ok(secure_links)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_remote_config(&self, client_id: &str) -> Result<RemoteConfig, ClientError> {
        let remote_config = saves::get_remote_config(&self.client, client_id).await?;
        Ok(remote_config)
    }
    pub async fn get_auth_ids(&self, game_id: i32) -> Result<(String, String), GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let auth_ids =
                saves::get_auth_ids(&self.client, game_id, auth, self.game_details_cache.clone())
                    .await?;
            Ok(auth_ids)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_save_file_list(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Vec<SaveFile>, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let saves_auth = auth
                .get_cloud_saves_tokens(&self.client, client_id, client_secret)
                .await?;
            let response = saves::get_save_files_list(&self.client, client_id, &saves_auth).await?;
            Ok(response)
        } else {
            Err(GogdlError::NotLoggedIn)
        }
    }
    pub async fn upload_save_file(
        &self,
        client_id: &str,
        client_secret: &str,
        tx: UnboundedSender<(i64, i64)>,
        path: &PathBuf,
        url_path: &str,
    ) -> Result<(), GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let saves_auth = auth
                .get_cloud_saves_tokens(&self.client, client_id, client_secret)
                .await?;
            saves::upload_file(&self.client, &saves_auth, path, &url_path, tx).await?;
            Ok(())
        } else {
            Err(GogdlError::NotLoggedIn)
        }
    }
    pub async fn download_save_file(
        &self,
        save_file: &SaveFile,
        client_id: &str,
        client_secret: &str,
        tx: UnboundedSender<(i64, i64)>,
        path: &PathBuf,
    ) -> Result<(), GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let saves_auth = auth
                .get_cloud_saves_tokens(&self.client, client_id, client_secret)
                .await?;
            saves::download_file(save_file, &saves_auth, &self.client, tx, path).await?;
            Ok(())
        } else {
            Err(GogdlError::NotLoggedIn)
        }
    }
    /// Deletes a cloud save file. See `saves::delete_save_file` — this
    /// endpoint's behavior is unverified against GOG's live API.
    pub async fn delete_save_file(
        &self,
        save_file: &SaveFile,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let saves_auth = auth
                .get_cloud_saves_tokens(&self.client, client_id, client_secret)
                .await?;
            saves::delete_save_file(save_file, &saves_auth, &self.client).await?;
            Ok(())
        } else {
            Err(GogdlError::NotLoggedIn)
        }
    }
}

#[derive(Error, Debug)]
pub enum GogdlError {
    #[error("Auth not available, please log in")]
    NotLoggedIn,
    #[error("Error: {0}")]
    ClientError(#[from] ClientError),
}
