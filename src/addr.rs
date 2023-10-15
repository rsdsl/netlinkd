use crate::{Error, Result};

use std::net::IpAddr;

use futures::future;
use futures_util::TryStreamExt;
use netlink_packet_route::{AddressMessage, AF_INET, AF_INET6, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE};
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

async fn do_flush4(link: String) -> Result<()> {
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
        .try_filter(|addr| future::ready(addr.header.family == AF_INET as u8))
        .try_collect()
        .await?;

    for addr in addrs {
        handle.address().del(addr).execute().await?;
    }

    Ok(())
}

pub fn flush4(link: String) -> Result<()> {
    Runtime::new()?.block_on(do_flush4(link))
}

async fn do_flush6(link: String) -> Result<()> {
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
        .try_filter(|addr| future::ready(addr.header.family == AF_INET6 as u8))
        .try_collect()
        .await?;

    for addr in addrs {
        handle.address().del(addr).execute().await?;
    }

    Ok(())
}

pub fn flush6(link: String) -> Result<()> {
    Runtime::new()?.block_on(do_flush6(link))
}

async fn do_flush6_global() -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let addrs: Vec<AddressMessage> = handle
        .address()
        .get()
        .execute()
        .try_filter(|addr| {
            future::ready(
                addr.header.family == AF_INET6 as u8 && addr.header.scope == RT_SCOPE_UNIVERSE,
            )
        })
        .try_collect()
        .await?;

    for addr in addrs {
        handle.address().del(addr).execute().await?;
    }

    Ok(())
}

pub fn flush6_global() -> Result<()> {
    Runtime::new()?.block_on(do_flush6_global())
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

async fn do_add_link_local(link: String, addr: IpAddr, prefix_len: u8) -> Result<()> {
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

    let mut req = handle.address().add(id, addr, prefix_len);
    req.message_mut().header.scope = RT_SCOPE_LINK;

    req.execute().await?;

    Ok(())
}

pub fn add_link_local(link: String, addr: IpAddr, prefix_len: u8) -> Result<()> {
    Runtime::new()?.block_on(do_add_link_local(link, addr, prefix_len))
}
