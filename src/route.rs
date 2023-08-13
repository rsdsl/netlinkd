use crate::error::{Error, Result};

use std::net::{Ipv4Addr, Ipv6Addr};

use futures::future;
use futures_util::TryStreamExt;
use netlink_packet_route::{RouteMessage, RT_SCOPE_LINK};
use rtnetlink::IpVersion;
use tokio::runtime::Runtime;

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

    let routes: Vec<RouteMessage> = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_filter(|route| {
            future::ready(if let Some(ifi) = route.output_interface() {
                ifi == id
            } else {
                false
            })
        })
        .try_collect()
        .await?;

    for route in routes {
        handle.route().del(route).execute().await?;
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

    let routes: Vec<RouteMessage> = handle
        .route()
        .get(IpVersion::V6)
        .execute()
        .try_filter(|route| {
            future::ready(if let Some(ifi) = route.output_interface() {
                ifi == id
            } else {
                false
            })
        })
        .try_collect()
        .await?;

    for route in routes {
        handle.route().del(route).execute().await?;
    }

    Ok(())
}

pub fn flush6(link: String) -> Result<()> {
    Runtime::new()?.block_on(do_flush6(link))
}

pub fn flush(link: String) -> Result<()> {
    flush4(link.clone())?;
    flush6(link)?;

    Ok(())
}

async fn do_add4(dst: Ipv4Addr, prefix_len: u8, rtr: Option<Ipv4Addr>, link: String) -> Result<()> {
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

    let mut add = handle
        .route()
        .add()
        .v4()
        .destination_prefix(dst, prefix_len)
        .output_interface(id);

    if let Some(rtr) = rtr {
        add = add.gateway(rtr);
    } else {
        add = add.scope(RT_SCOPE_LINK);
    }

    add.execute().await?;
    Ok(())
}

pub fn add4(dst: Ipv4Addr, prefix_len: u8, rtr: Option<Ipv4Addr>, link: String) -> Result<()> {
    Runtime::new()?.block_on(do_add4(dst, prefix_len, rtr, link))
}

async fn do_add6(dst: Ipv6Addr, prefix_len: u8, rtr: Option<Ipv6Addr>, link: String) -> Result<()> {
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

    let mut add = handle
        .route()
        .add()
        .v6()
        .destination_prefix(dst, prefix_len)
        .output_interface(id);

    if let Some(rtr) = rtr {
        add = add.gateway(rtr);
    } else {
        add = add.scope(RT_SCOPE_LINK);
    }

    add.execute().await?;
    Ok(())
}

pub fn add6(dst: Ipv6Addr, prefix_len: u8, rtr: Option<Ipv6Addr>, link: String) -> Result<()> {
    Runtime::new()?.block_on(do_add6(dst, prefix_len, rtr, link))
}
