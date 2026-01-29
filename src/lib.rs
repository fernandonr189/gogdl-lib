use std::{collections::HashMap, path::PathBuf, sync::Arc};

use thiserror::Error;
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::{
    auth::{Auth, get_login_tokens, refresh_token},
    client::ClientError,
    games::{BuildMetadata, Chunk, DepotFile, GameBuilds, GameDetails, SecureLinks},
    saves::{RemoteConfig, SaveFile},
};

pub mod auth;
pub mod client;
pub mod games;
pub mod saves;

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

    pub async fn get_game_builds(&self, game_id: i32) -> Result<GameBuilds, GogdlError> {
        let auth = {
            let auth_lock = self.auth.lock().await;
            auth_lock.clone()
        };
        if let Some(auth) = auth.as_ref() {
            let game_builds = games::get_game_builds(
                auth,
                &self.client,
                game_id,
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
                &version_name,
                self.game_details_cache.clone(),
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
        tx: UnboundedSender<i64>,
        path: &str,
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
                &version_name,
                tx,
                path,
                self.game_details_cache.clone(),
            )
            .await?;
            Ok(res)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_build_chunks(
        &self,
        game_id: i32,
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
                &version_name,
                self.game_details_cache.clone(),
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
    pub async fn get_auth_ids(&self, game_id: i32) -> Result<(String, String), ClientError> {
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
            return Err(ClientError::NotFound);
        }
    }
    pub async fn get_save_file_list(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Vec<SaveFile>, ClientError> {
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
            Err(ClientError::NotFound)
        }
    }
    pub async fn download_save_file(
        &self,
        save_file: &SaveFile,
        client_id: &str,
        client_secret: &str,
        tx: UnboundedSender<(i64, i64)>,
        path: &PathBuf,
    ) -> Result<(), ClientError> {
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
            Err(ClientError::NotFound)
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
