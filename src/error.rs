use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("link {0} not found")]
    LinkNotFound(String),
    #[error("io")]
    Io(#[from] io::Error),
    #[error("rtnetlink")]
    RtNetlink(#[from] rtnetlink::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
