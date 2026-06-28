pub mod auth;
pub mod client;
pub mod games;
pub mod gogdl;
pub mod saves;

pub use gogdl::{GogDl, GogdlError};

// Re-export external types that appear directly in the public API surface.
// Clients can use gogdl_lib::CancellationToken etc. and are guaranteed
// to get the same version this crate compiled against, avoiding type mismatches.
pub use reqwest::Client;
pub use reqwest::StatusCode;
pub use tokio::sync::mpsc::UnboundedSender;
pub use tokio_util::sync::CancellationToken;
