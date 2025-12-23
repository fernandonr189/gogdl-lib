use flate2::read::ZlibDecoder;
use futures::StreamExt;
use reqwest::{Body, Client, StatusCode, Url};
use serde::de::DeserializeOwned;
use std::io::prelude::*;
use thiserror::Error;
use tokio::{sync::AcquireError, task::JoinError};

use crate::auth::Auth;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Url parse error: {0}")]
    UrlParseErrr(#[from] url::ParseError),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("HTTP error {status}: {body}")]
    Http { status: StatusCode, body: String },

    #[error("Deserialization error: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("Could not find requested resource")]
    NotFound,

    #[error("Decode error: {0}")]
    DecodeError(#[from] std::io::Error),

    #[error("Async error: {0}")]
    AsyncError(#[from] JoinError),

    #[error("Semaphore error: {0}")]
    SemaphoreError(#[from] AcquireError),

    #[error("Hash mismatch")]
    HashMismatch,
}

pub enum Method {
    Post,
    Get,
}

pub async fn fetch_chunk<F>(
    url: &str,
    auth: Option<&Auth>,
    client: &Client,
    callback: F,
) -> Result<Vec<u8>, ClientError>
where
    F: Fn(i64),
{
    let url = Url::parse(url)?;
    let mut request = client.get(url);

    if let Some(auth) = auth {
        request = request.bearer_auth(&auth.access_token);
    }

    let response = request.send().await?;
    let status = response.status();

    if !status.is_success() {
        let response_text = response.text().await?;
        return Err(ClientError::Http {
            status,
            body: response_text,
        });
    }

    let mut stream = response.bytes_stream();

    let mut buffer: Vec<u8> = Vec::new();

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(downloaded_bytes) => {
                callback(downloaded_bytes.len() as i64);
                buffer.extend_from_slice(&downloaded_bytes);
            }
            Err(err) => return Err(ClientError::Network(err)),
        }
    }
    let mut decoded_buffer = Vec::new();
    let mut z = ZlibDecoder::new(&buffer[..]);
    z.read_to_end(&mut decoded_buffer)?;
    Ok(decoded_buffer)
}

pub async fn fetch_json<T, P>(
    url: &str,
    auth: Option<&Auth>,
    client: &Client,
    method: Method,
    decode: bool,
    body: Option<P>,
) -> Result<T, ClientError>
where
    T: DeserializeOwned,
    P: Into<Body>,
{
    let url = Url::parse(url)?;
    let mut request = match method {
        Method::Get => client.get(url),
        Method::Post => {
            let mut r = client.post(url);
            if let Some(body) = body {
                r = r.body(body);
            }
            r
        }
    };

    if let Some(auth) = auth {
        request = request.bearer_auth(&auth.access_token);
    }

    let response = request.send().await?;
    let status = response.status();

    if !status.is_success() {
        let response_text = response.text().await?;
        return Err(ClientError::Http {
            status,
            body: response_text,
        });
    }

    if decode {
        let response_bytes = response.bytes().await?;
        let mut z = ZlibDecoder::new(&response_bytes[..]);
        let mut s = String::new();
        z.read_to_string(&mut s)?;
        let data: T = serde_json::from_str(&s)?;
        Ok(data)
    } else {
        let response_text = response.text().await?;
        let data = serde_json::from_str(&response_text)?;
        Ok(data)
    }
}
