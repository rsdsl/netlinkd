use crate::error::{Error, Result};

use std::net::IpAddr;

use futures_util::TryStreamExt;
use netlink_packet_route::rtnl::AddressMessage;
use tokio::runtime::Runtime;

async fn do_flush(link: String) -> Result<()> {
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

    let addrs: Vec<AddressMessage> = handle
        .address()
        .get()
        .set_link_index_filter(id)
        .execute()
        .try_collect()
        .await?;

    for addr in addrs {
        handle.address().del(addr).execute().await?;
    }

    Ok(())
}

pub fn flush(link: String) -> Result<()> {
    Runtime::new()?.block_on(do_flush(link))
}

async fn do_add(link: String, addr: IpAddr, prefix_len: u8) -> Result<()> {
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

    handle.address().add(id, addr, prefix_len).execute().await?;

    Ok(())
}

pub fn add(link: String, addr: IpAddr, prefix_len: u8) -> Result<()> {
    Runtime::new()?.block_on(do_add(link, addr, prefix_len))
}
