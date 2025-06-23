use rsdsl_netlinklib::blocking::Connection;
use rsdsl_netlinklib::route::{Route4, Route6};

use std::fs::{self, File};
use std::io;
use std::net::{self, IpAddr, Ipv4Addr, Ipv6Addr};
use std::process;

use tokio::runtime::Runtime;

use ipnet::Ipv6Net;
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    constants::{AF_UNSPEC, NFNETLINK_V0, NFNL_SUBSYS_CTNETLINK, NLM_F_ACK, NLM_F_REQUEST},
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner,
};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket};
use rsdsl_ip_config::DsConfig;
use rsdsl_pd_config::PdConfig;
use signal_hook::{consts::SIGUSR1, iterator::Signals};
use sysinfo::{ProcessExt, Signal, System, SystemExt};
use thiserror::Error;

const SIZEOFNLMSGHDR: u32 = 0x10;
const CONNTRACK_TABLE_CONNTRACK: u8 = 1;
const IPCTNL_MSG_CT_DELETE: u8 = 2;

const ADDR_AFTR: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 1);
const ADDR_B4: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 2);
const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const ULA_TEMPLATE: Ipv6Addr = Ipv6Addr::new(0xfd0b, 0x9272, 0x534e, 0, 0, 0, 0, 1);
const PI_TEMPLATE: Ipv6Addr = Ipv6Addr::new(0x2001, 0x678, 0xb24, 0x1000, 0, 0, 0, 1);

// Many DSL and GPON providers use this value, but some may require modifying
// this value. Since this is a custom system and potential ISPs are known in
// advance, robustness is more important than configurability here.
const VLAN_TAG: u16 = 7;

macro_rules! ula {
    ($subnet:expr) => {{
        let mut segments = ULA_TEMPLATE.segments();
        segments[3] += $subnet;
        Ipv6Addr::from(segments)
    }};
}

macro_rules! pi_net {
    ($subnet:expr) => {{
        let mut segments = PI_TEMPLATE.segments();
        segments[3] += $subnet;
        Ipv6Addr::from(segments)
    }};
}

#[derive(Debug, Error)]
enum Error {
    #[error("netlink did not return status information")]
    NoNlStatus,

    #[error("not enough ipv6 subnets")]
    NotEnoughIpv6Subnets,

    #[error("can't parse network address: {0}")]
    AddrParse(#[from] net::AddrParseError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid prefix length: {0}")]
    PrefixLen(#[from] ipnet::PrefixLenError),
    #[error("can't decode netlink packet: {0}")]
    NlDecode(#[from] netlink_packet_utils::DecodeError),
    #[error("netlinklib error: {0}")]
    Netlinklib(#[from] rsdsl_netlinklib::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let conn = Connection::new()?;

    println!("[info] wait for eth0");
    conn.link_wait_exists("eth0".into())?;
    println!("[info] detect eth0");

    conn.link_set("eth0".into(), true)?;

    configure_lan(&conn)?;
    println!("[info] config eth0 10.128.0.254/24 fe80::1/64 fd0b:9272:534e:1::/64");

    create_vlans(&conn)?;
    configure_vlans(&conn)?;
    println!("[info] config vlans 10.128.0.0/16 fe80::1/64 fd0b:9272:534e::/48");

    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    println!("[info] enable ipv4 routing");

    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    fs::write("/proc/sys/net/ipv6/conf/default/forwarding", "1")?;
    println!("[info] enable ipv6 routing");

    println!("[info] wait for eth1");
    conn.link_wait_exists("eth1".into())?;
    println!("[info] detect eth1");

    conn.link_set("eth1".into(), true)?;

    configure_modem(&conn)?;
    println!("[info] config eth1 192.168.1.2/24 192.168.100.2/24 (modem)");

    configure_carrier(&conn)?;
    println!("[info] config carrier0 eth1.{}", VLAN_TAG);

    let mut signals = Signals::new([SIGUSR1])?;
    for _ in signals.forever() {
        configure_wan_logged(&conn);
    }

    Ok(()) // unreachable
}

fn configure_lan(conn: &Connection) -> Result<()> {
    conn.address_flush("eth0".into())?;
    conn.address_add_link_local("eth0".into(), LINK_LOCAL.into(), 64)?;
    conn.address_add("eth0".into(), ula!(1).into(), 64)?;
    conn.address_add("eth0".into(), pi_net!(1).into(), 64)?;
    conn.address_add("eth0".into(), "10.128.0.254".parse()?, 24)?;

    Ok(())
}

fn create_vlans(conn: &Connection) -> Result<()> {
    let zones = ["trusted", "untrusted", "isolated", "exposed"];

    for (i, _) in zones.iter().enumerate() {
        let vlan_id = 10 * (i + 1);
        let vlan_name = format!("eth0.{}", vlan_id);

        if !conn.link_exists(vlan_name.clone())? {
            conn.link_add_vlan(vlan_name.clone(), "eth0".to_string(), vlan_id as u16)?;
        }
        conn.link_set(vlan_name.clone(), true)?;

        conn.address_flush(vlan_name.clone())?;
    }

    Ok(())
}

fn configure_vlans(conn: &Connection) -> Result<()> {
    let zones = ["trusted", "untrusted", "isolated", "exposed"];

    for (i, _) in zones.iter().enumerate() {
        let vlan_id = 10 * (i + 1);
        let vlan_name = format!("eth0.{}", vlan_id);
        let vlan_addr = IpAddr::V4(Ipv4Addr::new(10, 128, vlan_id as u8, 254));

        conn.address_add_link_local(vlan_name.clone(), LINK_LOCAL.into(), 64)?;
        conn.address_add(vlan_name.clone(), ula!(2 + i as u16).into(), 64)?;
        conn.address_add(vlan_name.clone(), pi_net!(2 + i as u16).into(), 64)?;
        conn.address_add(vlan_name.clone(), vlan_addr, 24)?;
    }

    Ok(())
}

fn configure_modem(conn: &Connection) -> Result<()> {
    conn.address_flush("eth1".into())?;
    conn.address_add("eth1".into(), "192.168.1.2".parse()?, 24)?;
    conn.address_add("eth1".into(), "192.168.100.2".parse()?, 24)?;

    Ok(())
}

fn configure_carrier(conn: &Connection) -> Result<()> {
    let vlan_name = String::from("carrier0");

    if !conn.link_exists(vlan_name.clone())? {
        conn.link_add_vlan(vlan_name.clone(), "eth1".to_string(), VLAN_TAG)?;
    }
    conn.link_set(vlan_name.clone(), true)?;

    Ok(())
}

fn configure_wan_logged(conn: &Connection) {
    match configure_wan(conn) {
        Ok(_) => {}
        Err(e) => println!("[warn] config wan: {}", e),
    }
}

fn configure_wan(conn: &Connection) -> Result<()> {
    if let Some(ds_config) = read_ds_config_optional() {
        // Only initialize the interface if an NCP is opened.
        // This not being the case is a good indicator
        // of the interface not being present due to not having a PPP session.
        if ds_config.v4.is_some() || ds_config.v6.is_some() {
            conn.link_set_mtu("ppp0".to_string(), 1492)?;
            conn.link_set("ppp0".to_string(), true)?;

            // Deconfigure everything, just to be safe.
            conn.address_flush("ppp0".to_string())?;
            conn.route_flush("ppp0".to_string())?;

            // Flush the conntrack state to prevent NAT hiccups.
            flush_conntrack()?;
        }

        if let Some(v4) = ds_config.v4 {
            conn.address_add("ppp0".to_string(), v4.addr.into(), 32)?;
            conn.route_add4(Route4 {
                dst: Ipv4Addr::UNSPECIFIED,
                prefix_len: 0,
                rtr: None,
                on_link: false,
                table: None,
                metric: Some(100),
                link: String::from("ppp0"),
            })?;

            println!("[info] config ppp0 {}/32", v4.addr);
        }

        if let Some(v6) = ds_config.v6 {
            conn.address_add_link_local("ppp0".to_string(), v6.laddr.into(), 64)?;
            conn.route_add6(Route6 {
                dst: Ipv6Addr::UNSPECIFIED,
                prefix_len: 0,
                rtr: None,
                on_link: false,
                table: None,
                metric: Some(100),
                link: String::from("ppp0"),
            })?;

            println!("[info] config ppp0 ll {}/64", v6.laddr);

            // Forward the event to dhcp6.
            // The IPv6 link has already been (re)configured at this point.
            inform_dhcp6();

            if let Some(pd_config) = read_pd_config_optional() {
                let prefix = Ipv6Net::new(pd_config.prefix, pd_config.len)?.trunc();
                let mut subnets = prefix.subnets(64)?;

                let addr_wan = next_ifid1(&mut subnets)?;

                conn.address_add("ppp0".to_string(), addr_wan.into(), 64)?;
                println!("[info] config ppp0 gua {}/64", addr_wan);

                let addr_lan = next_ifid1(&mut subnets)?;

                conn.address_flush6("eth0".to_string())?;
                conn.address_add_link_local("eth0".to_string(), LINK_LOCAL.into(), 64)?;
                conn.address_add("eth0".to_string(), ula!(0).into(), 64)?;
                conn.address_add("eth0".to_string(), pi_net!(0).into(), 64)?;
                conn.address_add("eth0".to_string(), addr_lan.into(), 64)?;

                println!("[info] config eth0 gua {}/64", addr_lan);

                let zones = ["trusted", "untrusted", "isolated", "exposed"];
                for (i, zone) in zones.iter().enumerate() {
                    let vlan_id = 10 * (i + 1);
                    let vlan_name = format!("eth0.{}", vlan_id);
                    let vlan_addr = next_ifid1(&mut subnets)?;

                    conn.address_flush6(vlan_name.clone())?;
                    conn.address_add_link_local(vlan_name.clone(), LINK_LOCAL.into(), 64)?;
                    conn.address_add(vlan_name.clone(), ula!(2 + i as u16).into(), 64)?;
                    conn.address_add(vlan_name.clone(), pi_net!(2 + i as u16).into(), 64)?;
                    conn.address_add(vlan_name.clone(), vlan_addr.into(), 64)?;

                    println!(
                        "[info] config {} gua {}/64 zone {}",
                        vlan_name, vlan_addr, zone
                    );
                }

                inform_radvd();

                if conn.link_exists("dslite0".to_string())? {
                    conn.link_set("dslite0".to_string(), true)?;

                    conn.address_flush("dslite0".to_string())?;
                    conn.address_add("dslite0".to_string(), ADDR_B4.into(), 29)?;

                    if ds_config.v4.is_none() {
                        conn.route_add4(Route4 {
                            dst: Ipv4Addr::UNSPECIFIED,
                            prefix_len: 0,
                            rtr: Some(ADDR_AFTR),
                            on_link: false,
                            table: None,
                            metric: Some(50),
                            link: String::from("dslite0"),
                        })?;
                    }

                    println!("[info] config dslite0 {}/29", ADDR_B4);
                }
            }
        } else {
            // Deconfiguration is critical too, forward event to dhcp6.
            inform_dhcp6();
        }
    }

    Ok(())
}

/// Flush the conntrack state to avoid breaking active NAT bindings.
/// This is required for VoIP to work if it uses a fast registration interval.
async fn flush_conntrack_async() -> Result<()> {
    let mut recv_buf = vec![0; 4096];

    let mut socket = Socket::new(NETLINK_NETFILTER)?;
    socket.bind_auto()?;

    let nfmsg = NetfilterMessage::new(
        NetfilterHeader::new(AF_UNSPEC, NFNETLINK_V0, 0),
        NetfilterMessageInner::Other {
            subsys: NFNL_SUBSYS_CTNETLINK,
            message_type: IPCTNL_MSG_CT_DELETE,
            nlas: Vec::default(),
        },
    );

    let mut header = NetlinkHeader::default();

    header.length = SIZEOFNLMSGHDR;
    header.message_type = ((CONNTRACK_TABLE_CONNTRACK as u16) << 8) | IPCTNL_MSG_CT_DELETE as u16;
    header.flags = NLM_F_REQUEST | NLM_F_ACK;
    header.sequence_number = 1;
    header.port_number = process::id();

    let mut packet = NetlinkMessage::new(header, NetlinkPayload::from(nfmsg));

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    socket.send(&buf[..], 0)?;

    let n = socket.recv(&mut &mut recv_buf[..], 0)?;
    let bytes = &recv_buf[..n];

    let rx_packet = <NetlinkMessage<NetfilterMessage>>::deserialize(bytes)?;

    if let NetlinkPayload::Error(e) = rx_packet.payload {
        if e.code.is_some() {
            Err(e.to_io().into())
        } else {
            Ok(())
        }
    } else {
        Err(Error::NoNlStatus)
    }
}

fn flush_conntrack() -> Result<()> {
    Runtime::new()?.block_on(flush_conntrack_async())
}

fn read_ds_config_optional() -> Option<DsConfig> {
    let mut file = File::open(rsdsl_ip_config::LOCATION).ok()?;
    serde_json::from_reader(&mut file).ok()
}

fn read_pd_config_optional() -> Option<PdConfig> {
    let mut file = File::open(rsdsl_pd_config::LOCATION).ok()?;
    serde_json::from_reader(&mut file).ok()
}

fn next_ifid1<T: Iterator<Item = Ipv6Net>>(subnets: &mut T) -> Result<Ipv6Addr> {
    Ok((u128::from(subnets.next().ok_or(Error::NotEnoughIpv6Subnets)?.addr()) + 1).into())
}

fn inform_radvd() {
    for radvd in System::new_all().processes_by_exact_name("rsdsl_radvd") {
        radvd.kill_with(Signal::User1);
    }
}

fn inform_dhcp6() {
    for dhcp6 in System::new_all().processes_by_exact_name("rsdsl_dhcp6") {
        dhcp6.kill_with(Signal::User1);
    }
}
