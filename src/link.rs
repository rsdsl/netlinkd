use crate::error::{Error, Result};

use futures_util::TryStreamExt;
use netlink_packet_route::rtnl::IFF_UP;
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
