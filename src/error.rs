use std::io;
use std::net;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("link {0} not found")]
    LinkNotFound(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("net: parse ip address: {0}")]
    NetAddrParseError(#[from] net::AddrParseError),
    #[error("notify: {0}")]
    Notify(#[from] notify::Error),
    #[error("rtnetlink: {0}")]
    RtNetlink(#[from] rtnetlink::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
