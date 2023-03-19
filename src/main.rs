use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::{addr, link, route};

use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_ip_config::IpConfig;

fn main() -> Result<()> {
    link::up("eth0".into())?;
    link::up("eth1".into())?;

    let mut watcher = notify::recommended_watcher(|res: notify::Result<Event>| match res {
        Ok(event) => match event.kind {
            EventKind::Create(kind) if kind == CreateKind::File => {
                configure_wan();
            }
            EventKind::Modify(kind) if matches!(kind, ModifyKind::Data(_)) => {
                configure_wan();
            }
            _ => {}
        },
        Err(e) => println!("[netlinkd] watch error: {}", e),
    })?;

    watcher.watch(
        Path::new("/data/pppoe.ip_config"),
        RecursiveMode::NonRecursive,
    )?;

    Ok(())
}

fn configure_wan() {
    match configure_rsppp0() {
        Ok(_) => println!("[netlinkd] configure rsppp0 with PPPoE data"),
        Err(e) => println!("[netlinkd] can't configure rsppp0: {}", e),
    }
}

fn configure_rsppp0() -> Result<()> {
    link::up("rsppp0".into())?;

    let mut file = File::open("/data/pppoe.ip_config")?;
    let ip_config: IpConfig = serde_json::from_reader(&mut file)?;

    addr::flush("rsppp0".into())?;
    addr::add("rsppp0".into(), IpAddr::V4(ip_config.addr), 32)?;

    route::add4(Ipv4Addr::UNSPECIFIED, 0, ip_config.rtr, "rsppp0".into())?;

    Ok(())
}
