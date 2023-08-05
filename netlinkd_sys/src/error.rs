use std::ffi;
use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("nul: {0}")]
    Nul(#[from] ffi::NulError),
}

pub type Result<T> = std::result::Result<T, Error>;
