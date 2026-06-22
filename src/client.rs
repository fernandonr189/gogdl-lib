use flate2::{Compression, read::ZlibDecoder, write::GzEncoder};
use futures::StreamExt;
use reqwest::{
    Body, Client, StatusCode, Url,
    header::{ACCEPT, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, EXPECT, USER_AGENT},
};
use serde::de::DeserializeOwned;
use std::io::prelude::*;
use std::time::Duration;
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

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Async error: {0}")]
    AsyncError(#[from] JoinError),

    #[error("Semaphore error: {0}")]
    SemaphoreError(#[from] AcquireError),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Token expired")]
    TokenExpired,

    #[error("Not logged in")]
    NotLoggedIn,

    #[error("Invalid header value: {0}")]
    InvalidHeader(String),

    #[error("Truncated download: expected {expected} bytes, got {actual}")]
    TruncatedDownload { expected: usize, actual: usize },

    #[error("Invalid product ID {0:?}: expected a numeric string")]
    InvalidProductId(String),

    #[error("No build found ({0})")]
    BuildNotFound(String),

    #[error("Malformed cloud-storage path placeholder: {0:?}")]
    MalformedRemotePath(String),

    #[error("Unknown known-folder key {0:?} in remote config")]
    UnknownFolderKey(String),

    #[error("Invalid timestamp {0:?}: not a valid RFC3339 date")]
    InvalidTimestamp(String),

    #[error("Malformed save-file listing line: {0:?}")]
    MalformedSaveLine(String),

    #[error("Download was cancelled")]
    Cancelled,
}

fn header_to_str(value: &reqwest::header::HeaderValue) -> Result<&str, ClientError> {
    value
        .to_str()
        .map_err(|e| ClientError::InvalidHeader(e.to_string()))
}

fn parse_content_length(value: &reqwest::header::HeaderValue) -> Result<usize, ClientError> {
    header_to_str(value)?
        .parse::<usize>()
        .map_err(|_| ClientError::InvalidHeader(format!("invalid content-length: {:?}", value)))
}

fn check_content_length(actual: usize, expected: usize) -> Result<(), ClientError> {
    if actual != expected {
        Err(ClientError::TruncatedDownload { expected, actual })
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum Method {
    Post,
    Get,
    Delete,
}

const FETCH_MAX_RETRIES: usize = 3;
const FETCH_RETRY_BASE_DELAY_MS: u64 = 200;

/// Decide whether a completed HTTP response status is worth retrying.
fn is_retryable_status(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}

/// Parse a `Retry-After` header value expressed in seconds. Returns `None`
/// if the value isn't a plain number (the HTTP-date form isn't needed for
/// GOG's API, so it's not supported here).
fn parse_retry_after(value: &reqwest::header::HeaderValue) -> Option<Duration> {
    header_to_str(value)
        .ok()?
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Sends a request built fresh on each attempt, retrying on transport errors,
/// 5xx, and 429 (honoring `Retry-After` if present). Only covers the
/// connect+send+headers phase — callers read/stream the body themselves, so
/// a stream error mid-flight is never retried here.
async fn send_with_retry<F>(build_request: F) -> Result<reqwest::Response, ClientError>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let mut attempt = 0;
    loop {
        match build_request().send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() || !is_retryable_status(status) {
                    return Ok(response);
                }
                attempt += 1;
                if attempt >= FETCH_MAX_RETRIES {
                    return Ok(response);
                }
                let delay = if status == StatusCode::TOO_MANY_REQUESTS {
                    response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(parse_retry_after)
                        .unwrap_or(Duration::from_millis(
                            FETCH_RETRY_BASE_DELAY_MS * attempt as u64,
                        ))
                } else {
                    Duration::from_millis(FETCH_RETRY_BASE_DELAY_MS * attempt as u64)
                };
                tokio::time::sleep(delay).await;
            }
            Err(err) => {
                attempt += 1;
                if attempt >= FETCH_MAX_RETRIES {
                    return Err(ClientError::Network(err));
                }
                tokio::time::sleep(Duration::from_millis(
                    FETCH_RETRY_BASE_DELAY_MS * attempt as u64,
                ))
                .await;
            }
        }
    }
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
    let response = send_with_retry(|| {
        let mut r = client.get(url.clone());
        if let Some(auth) = auth {
            r = r.bearer_auth(&auth.access_token);
        }
        r
    })
    .await?;
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
                if let Some(length) = content_length {
                    let expected = parse_content_length(length)?;
                    callback(downloaded_bytes.len() as i64, expected as i64);
                }
                buffer.extend_from_slice(&downloaded_bytes);
            }
            Err(err) => return Err(ClientError::Network(err)),
        }
    }
    if let Some(len) = content_length {
        let expected = parse_content_length(len)?;
        check_content_length(buffer.len(), expected)?;
    }

    let last_modified = last_modified
        .map(header_to_str)
        .transpose()?
        .map(|s| s.to_owned());
    if let Some(md5_header) = etag {
        let md5 = header_to_str(md5_header)?;
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
    let response = send_with_retry(|| {
        let mut r = client.get(url.clone());
        if let Some(auth) = auth {
            r = r.bearer_auth(&auth.access_token);
        }
        r
    })
    .await?;
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
    let response = match method {
        Method::Get => {
            send_with_retry(|| {
                let mut r = client.get(url.clone());
                if let Some(auth) = auth {
                    r = r.bearer_auth(&auth.access_token);
                }
                r
            })
            .await?
        }
        Method::Post => {
            let mut r = client.post(url);
            if let Some(body) = body {
                r = r.body(body);
            }
            if let Some(auth) = auth {
                r = r.bearer_auth(&auth.access_token);
            }
            r.send().await?
        }
        Method::Delete => {
            let mut r = client.delete(url);
            if let Some(auth) = auth {
                r = r.bearer_auth(&auth.access_token);
            }
            r.send().await?
        }
    };
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
    let response = match method {
        Method::Get => {
            send_with_retry(|| {
                let mut r = client.get(url.clone());
                if let Some(auth) = auth {
                    r = r.bearer_auth(&auth.access_token);
                }
                r
            })
            .await?
        }
        Method::Post => {
            let mut r = client.post(url);
            if let Some(body) = body {
                r = r.body(body);
            }
            if let Some(auth) = auth {
                r = r.bearer_auth(&auth.access_token);
            }
            r.send().await?
        }
        Method::Delete => {
            let mut r = client.delete(url);
            if let Some(auth) = auth {
                r = r.bearer_auth(&auth.access_token);
            }
            r.send().await?
        }
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn header_to_str_accepts_valid_ascii() {
        let value = HeaderValue::from_static("12345");
        assert_eq!(header_to_str(&value).unwrap(), "12345");
    }

    #[test]
    fn header_to_str_rejects_non_ascii_bytes() {
        let value = HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap();
        assert!(matches!(
            header_to_str(&value),
            Err(ClientError::InvalidHeader(_))
        ));
    }

    #[test]
    fn parse_content_length_accepts_valid_number() {
        let value = HeaderValue::from_static("12345");
        assert_eq!(parse_content_length(&value).unwrap(), 12345);
    }

    #[test]
    fn parse_content_length_rejects_non_numeric() {
        let value = HeaderValue::from_static("not-a-number");
        assert!(matches!(
            parse_content_length(&value),
            Err(ClientError::InvalidHeader(_))
        ));
    }

    #[test]
    fn check_content_length_ok_when_matching() {
        assert!(check_content_length(100, 100).is_ok());
    }

    #[test]
    fn check_content_length_errors_when_mismatched() {
        let err = check_content_length(50, 100).unwrap_err();
        assert!(matches!(
            err,
            ClientError::TruncatedDownload {
                expected: 100,
                actual: 50
            }
        ));
    }

    #[test]
    fn is_retryable_status_true_for_5xx() {
        assert!(is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
    }

    #[test]
    fn is_retryable_status_true_for_429() {
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
    }

    #[test]
    fn is_retryable_status_false_for_4xx_other_than_429() {
        assert!(!is_retryable_status(StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn is_retryable_status_false_for_2xx() {
        assert!(!is_retryable_status(StatusCode::OK));
    }

    #[test]
    fn parse_retry_after_accepts_seconds() {
        let value = HeaderValue::from_static("120");
        assert_eq!(parse_retry_after(&value), Some(Duration::from_secs(120)));
    }

    #[test]
    fn parse_retry_after_rejects_non_numeric() {
        let value = HeaderValue::from_static("not-a-number");
        assert_eq!(parse_retry_after(&value), None);
    }
}
