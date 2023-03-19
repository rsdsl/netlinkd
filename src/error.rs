use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("link {0} not found")]
    LinkNotFound(String),
    #[error("io")]
    Io(#[from] io::Error),
    #[error("notify")]
    Notify(#[from] notify::Error),
    #[error("rtnetlink")]
    RtNetlink(#[from] rtnetlink::Error),
    #[error("serde_json")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
