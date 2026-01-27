use std::path::PathBuf;

use thiserror::Error;
use tokio::sync::mpsc::UnboundedSender;

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
    auth: Option<Auth>,
    client: reqwest::Client,
}

impl GogDl {
    pub fn new(auth: Option<Auth>) -> Self {
        GogDl {
            auth: auth,
            client: reqwest::Client::new(),
        }
    }

    pub fn get_login_url() -> &'static str {
        auth::LOGIN_URL
    }

    pub async fn refresh_token(&self) -> Result<Auth, GogdlError> {
        if let Some(auth) = self.auth.as_ref() {
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
        if let Some(auth) = self.auth.as_ref() {
            let game_details = games::get_game_details(auth, &self.client, game_id).await?;
            Ok(game_details)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_owned_games(&self) -> Result<Vec<GameDetails>, GogdlError> {
        if let Some(auth) = self.auth.as_ref() {
            let games = games::get_owned_games(&auth, &self.client).await?;
            Ok(games)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }

    pub async fn get_game_builds(&self, game_id: i32) -> Result<GameBuilds, GogdlError> {
        if let Some(auth) = self.auth.as_ref() {
            let game_builds = games::get_game_builds(auth, &self.client, game_id).await?;
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
        if let Some(auth) = self.auth.as_ref() {
            let build_metadata =
                games::get_build_metadata(auth, &self.client, game_id, version_name).await?;
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
        if let Some(auth) = self.auth.as_ref() {
            let depot_files =
                games::get_build_files(auth, &self.client, game_id, &version_name).await?;
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
        if let Some(auth) = self.auth.as_ref() {
            let res =
                games::download_game(auth, &self.client, game_id, &version_name, tx, path).await?;
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
        if let Some(auth) = self.auth.as_ref() {
            let build_chunks =
                games::get_build_chunks(auth, &self.client, game_id, &version_name).await?;
            Ok(build_chunks)
        } else {
            return Err(GogdlError::NotLoggedIn);
        }
    }
    pub async fn get_secure_links(&self, game_id: i32) -> Result<SecureLinks, GogdlError> {
        if let Some(auth) = self.auth.as_ref() {
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
        if let Some(auth) = self.auth.as_ref() {
            let auth_ids = saves::get_auth_ids(&self.client, game_id, auth).await?;
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
        if let Some(auth) = self.auth.as_ref() {
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
        if let Some(auth) = self.auth.as_ref() {
            let saves_auth = auth
                .get_cloud_saves_tokens(&self.client, client_id, client_secret)
                .await?;
            save_file
                .download_file(&saves_auth, &self.client, tx, path)
                .await?;
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
