//! Host name resolution: reverse DNS and NetBIOS node status (NBSTAT) queries.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::model::Mac;

/// PTR lookup through the system resolver (honours /etc/hosts and nsswitch).
pub async fn reverse_dns(ip: Ipv4Addr, wait: Duration) -> Option<String> {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    let name = timeout(wait, lookup).await.ok()?.ok()??;
    let name = name.trim_end_matches('.').to_owned();
    // nss-myhostname synthesizes "_gateway" / "_outbound"; those say nothing about the host.
    (!name.is_empty() && !name.starts_with('_') && name != ip.to_string()).then_some(name)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetBiosInfo {
    pub name: Option<String>,
    pub workgroup: Option<String>,
    pub mac: Option<Mac>,
}

pub async fn netbios_query(ip: Ipv4Addr, wait: Duration) -> Option<NetBiosInfo> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let txid = (u32::from(ip) as u16) ^ 0x5a5a;
    let target = SocketAddr::from((ip, 137));
    socket.send_to(&nbstat_request(txid), target).await.ok()?;

    let mut buf = [0u8; 1024];
    timeout(wait, async {
        loop {
            let (len, from) = socket.recv_from(&mut buf).await.ok()?;
            if from.ip() == IpAddr::V4(ip)
                && let Some(info) = parse_nbstat_response(&buf[..len], txid)
            {
                return Some(info);
            }
        }
    })
    .await
    .ok()?
}

/// A node status request for the wildcard name `*`.
pub fn nbstat_request(txid: u16) -> [u8; 50] {
    let mut pkt = [0u8; 50];
    pkt[0..2].copy_from_slice(&txid.to_be_bytes());
    // Flags 0, one question, no other records.
    pkt[4..6].copy_from_slice(&1u16.to_be_bytes());
    pkt[12] = 32;
    // First-level encoding: each nibble of the 16-byte name becomes 'A' + nibble.
    let mut name = [0u8; 16];
    name[0] = b'*';
    for (i, byte) in name.iter().enumerate() {
        pkt[13 + i * 2] = b'A' + (byte >> 4);
        pkt[14 + i * 2] = b'A' + (byte & 0x0f);
    }
    pkt[45] = 0;
    pkt[46..48].copy_from_slice(&0x21u16.to_be_bytes()); // NBSTAT
    pkt[48..50].copy_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

pub fn parse_nbstat_response(buf: &[u8], txid: u16) -> Option<NetBiosInfo> {
    let u16_at = |i: usize| buf.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    if u16_at(0)? != txid || u16_at(6)? == 0 {
        return None;
    }

    // Skip the answer's owner name: either a compression pointer or labels.
    let mut pos = 12;
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            pos += 2;
            break;
        }
        pos += 1 + len as usize;
        if len == 0 {
            break;
        }
    }
    if u16_at(pos)? != 0x21 {
        return None;
    }
    pos += 10; // type, class, TTL, rdlength

    let count = *buf.get(pos)? as usize;
    pos += 1;
    let mut info = NetBiosInfo::default();
    for _ in 0..count {
        let entry = buf.get(pos..pos + 18)?;
        let name = String::from_utf8_lossy(&entry[..15]).trim_end().to_owned();
        let suffix = entry[15];
        let group = entry[16] & 0x80 != 0;
        if suffix == 0x00 {
            if group {
                info.workgroup.get_or_insert(name);
            } else {
                info.name.get_or_insert(name);
            }
        } else if suffix == 0x20 && !group && info.name.is_none() {
            info.name = Some(name);
        }
        pos += 18;
    }
    info.mac = buf
        .get(pos..pos + 6)
        .map(|b| Mac([b[0], b[1], b[2], b[3], b[4], b[5]]))
        .filter(|m| !m.is_zero());

    (info.name.is_some() || info.workgroup.is_some()).then_some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encodes_wildcard() {
        let pkt = nbstat_request(0x1234);
        assert_eq!(&pkt[0..2], &[0x12, 0x34]);
        assert_eq!(&pkt[13..15], b"CK");
        assert!(pkt[15..45].iter().all(|b| *b == b'A'));
        assert_eq!(&pkt[46..50], &[0x00, 0x21, 0x00, 0x01]);
    }

    fn entry(name: &str, suffix: u8, group: bool) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.push(suffix);
        e.extend_from_slice(&[if group { 0x84 } else { 0x04 }, 0x00]);
        e
    }

    #[test]
    fn parses_names_workgroup_and_mac() {
        let mut pkt = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        pkt.push(32);
        pkt.extend_from_slice(b"CK");
        pkt.extend_from_slice(&[b'A'; 30]);
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0]);
        let entries = [
            entry("FILESRV", 0x20, false),
            entry("WORKGROUP", 0x00, true),
            entry("FILESRV", 0x00, false),
        ];
        let rdata_len = 1 + entries.len() * 18 + 6;
        pkt.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        pkt.push(entries.len() as u8);
        for e in &entries {
            pkt.extend_from_slice(e);
        }
        pkt.extend_from_slice(&[0x00, 0x15, 0x5d, 0x01, 0x02, 0x03]);

        let info = parse_nbstat_response(&pkt, 0x1234).unwrap();
        assert_eq!(info.name.as_deref(), Some("FILESRV"));
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(info.mac, Some(Mac([0x00, 0x15, 0x5d, 0x01, 0x02, 0x03])));
        assert!(parse_nbstat_response(&pkt, 0x9999).is_none());
        assert!(parse_nbstat_response(&pkt[..40], 0x1234).is_none());
    }
}
