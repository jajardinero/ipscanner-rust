//! Information about the local machine's IPv4 interfaces and default route.

use std::fs;
use std::net::Ipv4Addr;

use crate::model::Mac;

use super::range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalIface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: Option<Mac>,
}

impl LocalIface {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        };
        u32::from(ip) & mask == u32::from(self.ip) & mask
    }

    /// The scan range covering this interface's subnet.
    pub fn default_range(&self) -> String {
        range::subnet_range(self.ip, self.prefix)
    }

    pub fn label(&self) -> String {
        format!("{} – {}/{}", self.name, self.ip, self.prefix)
    }
}

/// Network information gathered once at startup (and on "Detect").
#[derive(Clone, Debug, Default)]
pub struct NetInfo {
    pub ifaces: Vec<LocalIface>,
    pub gateway: Option<Ipv4Addr>,
    /// Index into `ifaces` of the interface carrying the default route.
    pub primary: Option<usize>,
    pub hostname: Option<String>,
}

impl NetInfo {
    pub fn detect() -> Self {
        let ifaces = local_interfaces();
        let route = default_route();
        let primary = route
            .as_ref()
            .and_then(|(name, _)| ifaces.iter().position(|i| &i.name == name))
            .or(if ifaces.is_empty() { None } else { Some(0) });
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        Self {
            ifaces,
            gateway: route.map(|(_, gw)| gw),
            primary,
            hostname,
        }
    }

    /// The interface whose subnet contains `ip`, i.e. hosts reachable without a router.
    pub fn local_iface_for(&self, ip: Ipv4Addr) -> Option<&LocalIface> {
        self.ifaces.iter().find(|i| i.contains(ip))
    }
}

/// Non-loopback IPv4 interfaces that are up.
pub fn local_interfaces() -> Vec<LocalIface> {
    let Ok(addrs) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut ifaces: Vec<LocalIface> = addrs
        .into_iter()
        // Tunnels such as WireGuard report an "unknown" operational state while working.
        .filter(|i| {
            !i.is_loopback()
                && matches!(
                    i.oper_status,
                    if_addrs::IfOperStatus::Up | if_addrs::IfOperStatus::Unknown
                )
        })
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(LocalIface {
                mac: read_iface_mac(&i.name),
                name: i.name,
                ip: v4.ip,
                prefix: v4.prefixlen,
            }),
            _ => None,
        })
        .collect();
    ifaces.sort_by(|a, b| a.name.cmp(&b.name).then(a.ip.cmp(&b.ip)));
    ifaces
}

fn read_iface_mac(name: &str) -> Option<Mac> {
    fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .ok()?
        .parse::<Mac>()
        .ok()
        .filter(|m| !m.is_zero())
}

/// The interface name and gateway of the lowest-metric default route.
fn default_route() -> Option<(String, Ipv4Addr)> {
    parse_default_route(&fs::read_to_string("/proc/net/route").ok()?)
}

fn parse_default_route(table: &str) -> Option<(String, Ipv4Addr)> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 || cols[1] != "00000000" {
                return None;
            }
            // Addresses are printed as the kernel's native-endian u32.
            let gw = u32::from_str_radix(cols[2], 16).ok()?;
            let metric: u32 = cols[6].parse().ok()?;
            Some((metric, cols[0].to_owned(), Ipv4Addr::from(gw.to_ne_bytes())))
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, name, gw)| (name, gw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_checks_subnet() {
        let iface = LocalIface {
            name: "eth0".into(),
            ip: "10.1.1.2".parse().unwrap(),
            prefix: 24,
            mac: None,
        };
        assert!(iface.contains("10.1.1.200".parse().unwrap()));
        assert!(!iface.contains("10.1.2.1".parse().unwrap()));
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_proc_net_route() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            wlo1\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            enp1s0\t00000000\t01010A0A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            enp1s0\t00010A0A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let (name, gw) = parse_default_route(table).unwrap();
        assert_eq!(name, "enp1s0");
        assert_eq!(gw, Ipv4Addr::new(10, 10, 1, 1));
    }
}
