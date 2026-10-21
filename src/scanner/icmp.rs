//! ICMP echo through an unprivileged datagram socket (`net.ipv4.ping_group_range`).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use surge_ping::{Client, Config, PingIdentifier, PingSequence};

const PAYLOAD: [u8; 32] = [0; 32];

/// One shared ICMP socket per scan.
pub fn client() -> std::io::Result<Client> {
    Client::new(&Config::default())
}

/// Round-trip time of the first echo reply out of `tries` attempts.
pub async fn ping(
    client: &Client,
    ip: Ipv4Addr,
    timeout: Duration,
    tries: u32,
) -> Option<Duration> {
    // The kernel rewrites the identifier of datagram ICMP sockets; it only needs to be stable.
    let ident = PingIdentifier((u32::from(ip) & 0xffff) as u16);
    let mut pinger = client.pinger(IpAddr::V4(ip), ident).await;
    pinger.timeout(timeout);
    for seq in 0..tries.max(1) {
        match pinger.ping(PingSequence(seq as u16), &PAYLOAD).await {
            Ok((_, rtt)) => return Some(rtt),
            Err(e) => log::trace!("ping {ip} seq {seq}: {e}"),
        }
    }
    None
}
