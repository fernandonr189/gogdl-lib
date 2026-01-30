use flate2::{Compression, read::ZlibDecoder, write::GzEncoder};
use futures::StreamExt;
use reqwest::{
    Body, Client, StatusCode, Url,
    header::{ACCEPT, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, EXPECT, USER_AGENT},
};
use serde::de::DeserializeOwned;
use std::io::prelude::*;
use thiserror::Error;
use tokio::{sync::AcquireError, task::JoinError};

use crate::auth::{Auth, SavesAuth};

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

    #[error("Token expired")]
    TokenExpired,

    #[error("Not logged in")]
    NotLoggedIn,
}

pub enum Method {
    Post,
    Get,
}

pub async fn upload_save_file<T>(
    url: &str,
    auth: Option<&SavesAuth>,
    client: &Client,
    timestamp: &str,
    uncompressed_body: Vec<u8>,
    callback: T,
) -> Result<(), ClientError>
where
    T: Fn(i64, i64) + Send + Sync + 'static,
{
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(&uncompressed_body)?;
    let mut gzipped = encoder.finish()?;
    let total_len = gzipped.len() as i64;
    let url = Url::parse(url)?;
    let digest = md5::compute(&gzipped);
    let etag = format!("{:x}", digest);
    let mut request = client
        .put(url)
        .header("X-Object-Meta-LocalLastModified", timestamp)
        .header(ETAG, etag)
        .header(CONTENT_ENCODING, "gzip")
        .header(CONTENT_LENGTH, total_len)
        .header(EXPECT, "100-continue")
        .header(ACCEPT, "*/*")
        .header(
            "X-Object-Meta-User-Agent",
            "GOGGalaxyCommunicationService/2.0.4.164 (Windows_32bit)",
        )
        .header(
            USER_AGENT,
            "GOGGalaxyCommunicationService/2.0.4.164 (Windows_32bit)",
        )
        .header(CONTENT_TYPE, "application/octet-stream");

    if let Some(auth) = auth {
        request = request.bearer_auth(&auth.access_token);
    }

    let mut sent = 0;

    let body_stream = futures_util::stream::iter(std::iter::from_fn(move || {
        if gzipped.is_empty() {
            return None;
        }
        let chunk = gzipped
            .drain(..gzipped.len().min(16 * 1024))
            .collect::<Vec<_>>();
        sent += chunk.len() as i64;
        callback(sent, total_len);

        Some(Ok::<_, std::io::Error>(chunk))
    }));

    let body = reqwest::Body::wrap_stream(body_stream);

    request = request.body(body);
    let response = request.send().await?;

    let status = response.status();

    if !status.is_success() {
        let text = response.text().await?;
        return Err(ClientError::Http { status, body: text });
    }

    Ok(())
}

pub async fn fetch_save_file<F>(
    url: &str,
    auth: Option<&SavesAuth>,
    client: &Client,
    callback: F,
) -> Result<(Vec<u8>, Option<String>, Option<String>), ClientError>
where
    F: Fn(i64, i64),
{
    let url = Url::parse(url)?;
    let mut request = client.get(url);

    if let Some(auth) = auth {
        request = request.bearer_auth(&auth.access_token);
    }

    let response = request.send().await?;
    let headers = response.headers().clone();
    let content_length = headers.get("content-length");
    let last_modified = headers.get("x-object-meta-locallastmodified");
    let etag = headers.get("etag");
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
                if let Some(lenght) = content_length {
                    callback(
                        downloaded_bytes.len() as i64,
                        lenght.to_str().unwrap().parse::<i64>().unwrap(),
                    );
                }
                buffer.extend_from_slice(&downloaded_bytes);
            }
            Err(err) => return Err(ClientError::Network(err)),
        }
    }
    if let Some(len) = content_length {
        let expected = len.to_str().unwrap().parse::<usize>().unwrap();
        if buffer.len() != expected {
            println!(
                "Truncated download: got {}, expected {}",
                buffer.len(),
                expected
            );
            panic!()
        }
    }

    let last_modified = last_modified.map(|h| h.to_str().unwrap().to_owned());
    if let Some(md5_header) = etag {
        let md5 = md5_header.to_str().unwrap();
        Ok((buffer, Some(md5.to_owned()), last_modified))
    } else {
        Ok((buffer, None, last_modified))
    }
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

pub async fn fetch_plain<T>(
    url: &str,
    auth: Option<&SavesAuth>,
    client: &Client,
    method: Method,
    decode: bool,
    body: Option<T>,
) -> Result<String, ClientError>
where
    T: Into<Body>,
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
        Ok(s)
    } else {
        let response_text = response.text().await?;
        Ok(response_text)
    }
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
        let data = match serde_json::from_str(&response_text) {
            Ok(data) => data,
            Err(err) => {
                return Err(ClientError::Deserialize(err));
            }
        };
        Ok(data)
    }
}
