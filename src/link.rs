use crate::error::{Error, Result};

use std::thread;
use std::time::Duration;

use futures_util::TryStreamExt;
use netlink_packet_route::rtnl::IFF_UP;
use rtnetlink::Error::NetlinkError;
use tokio::runtime::Runtime;

#[derive(Clone, Copy, Debug)]
enum State {
    Up,
    Down,
}

async fn set(link: String, state: State) -> Result<()> {
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

    match state {
        State::Up => handle.link().set(id).up(),
        State::Down => handle.link().set(id).down(),
    }
    .execute()
    .await?;

    Ok(())
}

pub fn up(link: String) -> Result<()> {
    Runtime::new()?.block_on(set(link, State::Up))
}

pub fn down(link: String) -> Result<()> {
    Runtime::new()?.block_on(set(link, State::Down))
}

async fn do_is_up(link: String) -> Result<bool> {
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

    let is_up = link.header.flags & IFF_UP == IFF_UP;
    Ok(is_up)
}

pub fn is_up(link: String) -> Result<bool> {
    Runtime::new()?.block_on(do_is_up(link))
}

async fn do_set_mtu(link: String, mtu: u32) -> Result<()> {
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

    handle.link().set(id).mtu(mtu).execute().await?;
    Ok(())
}

pub fn set_mtu(link: String, mtu: u32) -> Result<()> {
    Runtime::new()?.block_on(do_set_mtu(link, mtu))
}

async fn do_add_vlan(link: String, parent: String, vlan_id: u16) -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let parent = handle
        .link()
        .get()
        .match_name(parent.clone())
        .execute()
        .try_next()
        .await?
        .ok_or(Error::LinkNotFound(parent))?;

    let parent_id = parent.header.index;

    handle
        .link()
        .add()
        .vlan(link, parent_id, vlan_id)
        .execute()
        .await?;

    Ok(())
}

pub fn add_vlan(link: String, parent: String, vlan_id: u16) -> Result<()> {
    Runtime::new()?.block_on(do_add_vlan(link, parent, vlan_id))
}

pub fn wait_up(link: String) -> Result<()> {
    while !match is_up(link.clone()) {
        Ok(v) => v,
        Err(e) => {
            if let Error::LinkNotFound(_) = e {
                false
            } else if let Error::RtNetlink(NetlinkError(ref msg)) = e {
                // Error -19 is "No such device".
                if msg.code == -19 {
                    false
                } else {
                    return Err(e);
                }
            } else {
                return Err(e);
            }
        }
    } {
        thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}

async fn do_exists(link: String) -> Result<bool> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let exists = handle
        .link()
        .get()
        .match_name(link)
        .execute()
        .try_next()
        .await
        .is_ok();

    Ok(exists)
}

pub fn exists(link: String) -> Result<bool> {
    Runtime::new()?.block_on(do_exists(link))
}

pub fn wait_exists(link: String) -> Result<()> {
    while !exists(link.clone())? {
        thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}
