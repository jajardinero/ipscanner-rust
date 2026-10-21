//! MAC address discovery: the kernel's neighbour cache (`/proc/net/arp`) and an
//! optional raw ARP sweep for binaries that hold `CAP_NET_RAW`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use pnet_datalink::{Channel, MacAddr};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::{MutablePacket, Packet};

use crate::model::Mac;

use super::netinfo::LocalIface;

/// `ATF_COM`: the entry has a resolved hardware address.
const ATF_COM: u32 = 0x2;

/// Complete entries from the kernel ARP cache.
pub fn read_arp_table() -> HashMap<Ipv4Addr, Mac> {
    fs::read_to_string("/proc/net/arp")
        .map(|s| parse_arp_table(&s))
        .unwrap_or_default()
}

pub fn parse_arp_table(content: &str) -> HashMap<Ipv4Addr, Mac> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                return None;
            }
            let ip: Ipv4Addr = cols[0].parse().ok()?;
            let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).ok()?;
            let mac: Mac = cols[3].parse().ok()?;
            (flags & ATF_COM != 0 && !mac.is_zero()).then_some((ip, mac))
        })
        .collect()
}

#[derive(Debug)]
pub enum RawArpError {
    /// The process lacks `CAP_NET_RAW`.
    PermissionDenied,
    Other(String),
}

/// Broadcast ARP requests for `targets` on `iface` and report every reply through
/// `on_reply`. Blocks for roughly `rounds * send time + linger`; returns early once
/// `cancelled()` is true. Must run on a blocking thread.
pub fn raw_arp_sweep(
    iface: &LocalIface,
    targets: &[Ipv4Addr],
    rounds: u32,
    linger: Duration,
    cancelled: impl Fn() -> bool + Sync,
    mut on_reply: impl FnMut(Ipv4Addr, Mac),
) -> Result<(), RawArpError> {
    let dev = pnet_datalink::interfaces()
        .into_iter()
        .find(|d| d.name == iface.name)
        .ok_or_else(|| RawArpError::Other(format!("interface {} not found", iface.name)))?;
    let our_mac = dev
        .mac
        .filter(|m| !m.is_zero())
        .ok_or_else(|| RawArpError::Other(format!("{} has no MAC address", iface.name)))?;

    let config = pnet_datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        read_buffer_size: 1 << 20,
        ..Default::default()
    };
    let (mut tx, mut rx) = match pnet_datalink::channel(&dev, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(RawArpError::Other("unsupported channel type".into())),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Err(RawArpError::PermissionDenied);
        }
        Err(e) => return Err(RawArpError::Other(e.to_string())),
    };

    let wanted: HashSet<Ipv4Addr> = targets
        .iter()
        .copied()
        .filter(|ip| *ip != iface.ip)
        .collect();
    let mut seen = HashSet::new();

    thread::scope(|scope| {
        let sender = scope.spawn(|| {
            let mut frame = [0u8; 42];
            for _ in 0..rounds {
                for (i, target) in targets.iter().enumerate() {
                    if cancelled() {
                        return;
                    }
                    build_request(&mut frame, our_mac, iface.ip, *target);
                    if let Some(Err(e)) = tx.send_to(&frame, None) {
                        log::warn!("raw ARP send to {target} failed: {e}");
                    }
                    // Pace large sweeps so switches and the receive buffer keep up.
                    if i % 64 == 63 {
                        thread::sleep(Duration::from_millis(2));
                    }
                }
                thread::sleep(Duration::from_millis(250));
            }
        });

        let mut deadline: Option<Instant> = None;
        loop {
            if cancelled() {
                break;
            }
            if deadline.is_none() && sender.is_finished() {
                deadline = Some(Instant::now() + linger);
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
            match rx.next() {
                Ok(frame) => {
                    if let Some((ip, mac)) = parse_reply(frame)
                        && wanted.contains(&ip)
                        && seen.insert(ip)
                    {
                        on_reply(ip, mac);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                Err(e) => {
                    log::warn!("raw ARP receive failed: {e}");
                    break;
                }
            }
        }
    });
    Ok(())
}

fn build_request(frame: &mut [u8; 42], our_mac: MacAddr, our_ip: Ipv4Addr, target: Ipv4Addr) {
    let mut eth = MutableEthernetPacket::new(&mut frame[..]).expect("frame fits ethernet header");
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(our_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(eth.payload_mut()).expect("frame fits ARP packet");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(our_mac);
    arp.set_sender_proto_addr(our_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target);
}

fn parse_reply(frame: &[u8]) -> Option<(Ipv4Addr, Mac)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((
        arp.get_sender_proto_addr(),
        Mac(arp.get_sender_hw_addr().octets()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
10.1.1.190       0x1         0x2         00:50:56:94:c6:c9     *        enp1s0
10.1.1.1         0x1         0x2         00:09:0f:09:00:1c     *        enp1s0
10.1.1.77        0x1         0x0         00:00:00:00:00:00     *        enp1s0
10.1.1.80        0x1         0x6         d8:38:fc:04:82:e0     *        enp1s0
";

    #[test]
    fn parses_complete_entries_only() {
        let table = parse_arp_table(FIXTURE);
        assert_eq!(table.len(), 3);
        assert_eq!(
            table[&"10.1.1.1".parse().unwrap()],
            "00:09:0f:09:00:1c".parse().unwrap()
        );
        assert!(!table.contains_key(&"10.1.1.77".parse().unwrap()));
        assert!(table.contains_key(&"10.1.1.80".parse().unwrap()));
    }

    #[test]
    fn request_and_reply_roundtrip() {
        let mut frame = [0u8; 42];
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        build_request(
            &mut frame,
            mac,
            "10.0.0.2".parse().unwrap(),
            "10.0.0.9".parse().unwrap(),
        );
        // A request is not a reply.
        assert!(parse_reply(&frame).is_none());
        // Flip the opcode to "reply" (offset 14 + 6).
        frame[21] = 2;
        let (ip, sender) = parse_reply(&frame).unwrap();
        assert_eq!(ip, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(sender, Mac([2, 0, 0, 0, 0, 1]));
    }
}
