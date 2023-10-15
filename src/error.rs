use std::{ffi, io, net};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("link {0} not found")]
    LinkNotFound(String),
    #[error("not enough ipv6 subnets")]
    NotEnoughIpv6Subnets,

    #[error("ffi nul: {0}")]
    Nul(#[from] ffi::NulError),
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("ipnet prefix len: {0}")]
    IpnetPrefixLen(#[from] ipnet::PrefixLenError),
    #[error("net: parse ip address: {0}")]
    NetAddrParseError(#[from] net::AddrParseError),
    #[error("rtnetlink: {0}")]
    RtNetlink(#[from] rtnetlink::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
