//! Parsing of target ranges such as `10.1.1.1-254`, `10.1.1.1-10.1.2.20`, `10.1.1.0/24`
//! and comma-separated combinations of those.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// Upper bound on the number of addresses a single scan may target.
pub const MAX_TARGETS: usize = 65_536;

/// Expand a range expression into a sorted list of unique addresses.
pub fn parse_targets(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut spans = Vec::new();
    for item in input
        .split([',', ';', ' ', '\t', '\n'])
        .filter(|s| !s.is_empty())
    {
        spans.push(parse_item(item)?);
    }
    if spans.is_empty() {
        return Err("enter an IP address or range, e.g. 192.168.1.1-254".to_owned());
    }

    // Check the size before expanding so `0.0.0.0/0` can't exhaust memory.
    let total: u64 = spans.iter().map(|(a, b)| u64::from(b - a) + 1).sum();
    if total > MAX_TARGETS as u64 {
        return Err(format!(
            "range too large: {total} addresses (max {MAX_TARGETS})"
        ));
    }

    let set: BTreeSet<u32> = spans.into_iter().flat_map(|(a, b)| a..=b).collect();
    Ok(set.into_iter().map(Ipv4Addr::from).collect())
}

/// Parse one item into an inclusive `u32` span.
fn parse_item(item: &str) -> Result<(u32, u32), String> {
    let bad = || format!("invalid range: {item}");

    if let Some((addr, prefix)) = item.split_once('/') {
        let addr: Ipv4Addr = addr.parse().map_err(|_| bad())?;
        let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32).ok_or_else(bad)?;
        return Ok(cidr_hosts(addr, prefix));
    }

    if let Some((start, end)) = item.split_once('-') {
        let start: Ipv4Addr = start.trim().parse().map_err(|_| bad())?;
        let end = end.trim();
        let end: Ipv4Addr = if end.contains('.') {
            end.parse().map_err(|_| bad())?
        } else {
            // Short form: only the last octet is given.
            let last: u8 = end.parse().map_err(|_| bad())?;
            let [a, b, c, _] = start.octets();
            Ipv4Addr::new(a, b, c, last)
        };
        let (start, end) = (u32::from(start), u32::from(end));
        if start > end {
            return Err(format!("range start is after its end: {item}"));
        }
        return Ok((start, end));
    }

    let ip: Ipv4Addr = item.parse().map_err(|_| bad())?;
    Ok((u32::from(ip), u32::from(ip)))
}

/// The usable host span of a CIDR block. Network and broadcast addresses are
/// excluded for /30 and wider; /31 and /32 keep every address.
pub fn cidr_hosts(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network = u32::from(addr) & mask;
    let broadcast = network | !mask;
    if prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    }
}

/// A human-friendly range for an interface's subnet, e.g. `10.1.1.1-254`.
/// Subnets wider than /16 are narrowed to the /24 around `addr`.
pub fn subnet_range(addr: Ipv4Addr, prefix: u8) -> String {
    let prefix = if prefix < 16 { 24 } else { prefix };
    let (start, end) = cidr_hosts(addr, prefix);
    format_span(Ipv4Addr::from(start), Ipv4Addr::from(end))
}

fn format_span(start: Ipv4Addr, end: Ipv4Addr) -> String {
    if start == end {
        return start.to_string();
    }
    let (s, e) = (start.octets(), end.octets());
    if s[..3] == e[..3] {
        format!("{start}-{}", e[3])
    } else {
        format!("{start}-{end}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn single_and_short_range() {
        assert_eq!(parse_targets("10.0.0.7").unwrap(), vec![ip("10.0.0.7")]);
        let r = parse_targets("192.168.1.1-254").unwrap();
        assert_eq!(r.len(), 254);
        assert_eq!(r[0], ip("192.168.1.1"));
        assert_eq!(r[253], ip("192.168.1.254"));
    }

    #[test]
    fn full_range_crosses_octets() {
        let r = parse_targets("10.0.0.250-10.0.1.5").unwrap();
        assert_eq!(r.len(), 12);
        assert_eq!(r.last(), Some(&ip("10.0.1.5")));
    }

    #[test]
    fn cidr_excludes_network_and_broadcast() {
        let r = parse_targets("10.1.1.0/24").unwrap();
        assert_eq!(r.len(), 254);
        assert_eq!(r[0], ip("10.1.1.1"));
        assert_eq!(parse_targets("10.1.1.0/31").unwrap().len(), 2);
        assert_eq!(parse_targets("10.1.1.9/32").unwrap(), vec![ip("10.1.1.9")]);
        assert_eq!(
            parse_targets("10.1.1.0/30").unwrap(),
            vec![ip("10.1.1.1"), ip("10.1.1.2")]
        );
    }

    #[test]
    fn lists_are_merged_and_deduplicated() {
        let r = parse_targets("10.0.0.5, 10.0.0.1-6;10.0.0.3").unwrap();
        assert_eq!(r.len(), 6);
        assert!(r.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn errors() {
        assert!(parse_targets("").is_err());
        assert!(parse_targets("10.0.0.300").is_err());
        assert!(parse_targets("10.0.0.9-3").is_err());
        assert!(parse_targets("10.0.0.0/33").is_err());
        assert!(parse_targets("hello").is_err());
        assert!(parse_targets("10.0.0.0/8").is_err());
        assert!(parse_targets("10.0.0.0/16").is_ok());
    }

    #[test]
    fn subnet_range_formatting() {
        assert_eq!(subnet_range(ip("10.1.1.2"), 24), "10.1.1.1-254");
        assert_eq!(subnet_range(ip("10.1.2.2"), 22), "10.1.0.1-10.1.3.254");
        assert_eq!(subnet_range(ip("10.9.8.7"), 8), "10.9.8.1-254");
    }
}
