use crate::error::{Error, Result};

use std::net::Ipv4Addr;

use futures_util::TryStreamExt;
use tokio::runtime::Runtime;

async fn do_add4(dst: Ipv4Addr, prefix_len: u8, rtr: Ipv4Addr, link: String) -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let link = handle
        .link()
        .get()
        .match_name(link.clone())
        .execute()
        .try_next()
        .await?
        .ok_or(Error::LinkNotFound(link))?;

    let id = link.header.index;

    handle
        .route()
        .add()
        .v4()
        .destination_prefix(dst, prefix_len)
        .gateway(rtr)
        .output_interface(id)
        .execute()
        .await?;

    Ok(())
}

pub fn add4(dst: Ipv4Addr, prefix_len: u8, rtr: Ipv4Addr, link: String) -> Result<()> {
    Runtime::new()?.block_on(do_add4(dst, prefix_len, rtr, link))
}
