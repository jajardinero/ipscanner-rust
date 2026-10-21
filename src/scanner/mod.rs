//! The scan pipeline. A scan runs on the tokio runtime and streams [`ScanEvent`]s
//! back to the UI thread over a std channel, waking egui on every event.

pub mod arp;
pub mod icmp;
pub mod names;
pub mod netinfo;
pub mod ports;
pub mod range;

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::model::{Host, HostStatus, Mac, Service, Settings};
use crate::oui;

use self::netinfo::NetInfo;
use self::ports::PortState;

/// Ports probed on every target to decide whether it is alive.
const DISCOVERY_PORTS: [u16; 8] = [22, 80, 135, 139, 443, 445, 3389, 8080];
/// How long an echo reply gets before the TCP discovery probes start.
const PING_HEAD_START: Duration = Duration::from_millis(150);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const NETBIOS_TIMEOUT: Duration = Duration::from_millis(800);
const ARP_ROUNDS: u32 = 2;
const ARP_LINGER: Duration = Duration::from_millis(1500);

pub enum ScanEvent {
    Host(Box<Host>),
    Progress { done: usize, total: usize },
    Notice(String),
    Finished { elapsed: Duration, cancelled: bool },
}

pub struct ScanRequest {
    pub targets: Vec<Ipv4Addr>,
    pub settings: Settings,
    pub net: NetInfo,
}

/// A running scan. Dropping the handle cancels the scan.
pub struct ScanHandle {
    cancel: watch::Sender<bool>,
    pub events: mpsc::Receiver<ScanEvent>,
}

impl ScanHandle {
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
}

#[derive(Clone)]
struct Events {
    tx: mpsc::Sender<ScanEvent>,
    ctx: egui::Context,
}

impl Events {
    fn send(&self, event: ScanEvent) {
        let _ = self.tx.send(event);
        self.ctx.request_repaint();
    }

    fn host(&self, host: Host) {
        self.send(ScanEvent::Host(Box::new(host)));
    }
}

pub fn start(rt: &Handle, request: ScanRequest, ctx: egui::Context) -> ScanHandle {
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (tx, rx) = mpsc::channel();
    let events = Events { tx, ctx };
    rt.spawn(async move {
        let started = Instant::now();
        run(request, &events, cancel_rx.clone()).await;
        events.send(ScanEvent::Finished {
            elapsed: started.elapsed(),
            cancelled: is_cancelled(&cancel_rx),
        });
    });
    ScanHandle {
        cancel: cancel_tx,
        events: rx,
    }
}

fn is_cancelled(rx: &watch::Receiver<bool>) -> bool {
    rx.has_changed().is_err() || *rx.borrow()
}

/// Resolves once the scan is cancelled or its handle is dropped.
async fn cancelled(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|c| *c).await;
}

/// State shared by every per-host task of one scan.
struct Shared {
    settings: Settings,
    ports: Vec<u16>,
    net: NetInfo,
    pinger: Option<surge_ping::Client>,
    /// Replies collected by the raw ARP sweep.
    arp_replies: HashMap<Ipv4Addr, Mac>,
    /// Interfaces whose targets were fully swept: silence there means the host is down.
    swept: HashSet<String>,
}

async fn run(request: ScanRequest, events: &Events, cancel: watch::Receiver<bool>) {
    let ScanRequest {
        targets,
        settings,
        net,
    } = request;
    let total = targets.len();
    events.send(ScanEvent::Progress { done: 0, total });

    let pinger = match icmp::client() {
        Ok(client) => Some(client),
        Err(e) => {
            events.send(ScanEvent::Notice(format!(
                "ICMP unavailable ({e}); using TCP and ARP only"
            )));
            None
        }
    };

    let (arp_replies, swept) = if settings.raw_arp {
        raw_arp_phase(&targets, &net, events, &cancel).await
    } else {
        Default::default()
    };
    if is_cancelled(&cancel) {
        return;
    }

    let shared = Arc::new(Shared {
        ports: settings.port_list().unwrap_or_default(),
        settings,
        net,
        pinger,
        arp_replies,
        swept,
    });
    let semaphore = Arc::new(Semaphore::new(shared.settings.max_parallel.clamp(1, 1024)));
    let done = Arc::new(AtomicUsize::new(0));
    let progress_step = (total / 200).max(1);
    let mut tasks = JoinSet::new();

    for ip in targets {
        let permit = tokio::select! {
            permit = semaphore.clone().acquire_owned() => permit.expect("semaphore is never closed"),
            _ = cancelled(cancel.clone()) => break,
        };
        let (shared, events, done, cancel) =
            (shared.clone(), events.clone(), done.clone(), cancel.clone());
        tasks.spawn(async move {
            tokio::select! {
                host = scan_host(ip, &shared, &events) => events.host(host),
                _ = cancelled(cancel) => return,
            }
            drop(permit);
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % progress_step == 0 || n == total {
                events.send(ScanEvent::Progress { done: n, total });
            }
        });
        while tasks.try_join_next().is_some() {}
    }

    tokio::select! {
        _ = async { while tasks.join_next().await.is_some() {} } => {}
        _ = cancelled(cancel) => tasks.abort_all(),
    }
}

/// Sweep each local subnet that has targets. Hosts are reported as soon as they reply.
async fn raw_arp_phase(
    targets: &[Ipv4Addr],
    net: &NetInfo,
    events: &Events,
    cancel: &watch::Receiver<bool>,
) -> (HashMap<Ipv4Addr, Mac>, HashSet<String>) {
    let mut replies = HashMap::new();
    let mut swept = HashSet::new();
    for iface in &net.ifaces {
        let local: Vec<Ipv4Addr> = targets
            .iter()
            .copied()
            .filter(|ip| iface.contains(*ip))
            .collect();
        if local.is_empty() {
            continue;
        }
        let (iface, sweep_events, cancel, net) =
            (iface.clone(), events.clone(), cancel.clone(), net.clone());
        let result = tokio::task::spawn_blocking(move || {
            let mut found = HashMap::new();
            let outcome = arp::raw_arp_sweep(
                &iface,
                &local,
                ARP_ROUNDS,
                ARP_LINGER,
                || is_cancelled(&cancel),
                |ip, mac| {
                    found.insert(ip, mac);
                    let mut host = base_host(ip, &net);
                    host.status = HostStatus::Alive;
                    host.mac = Some(mac);
                    host.vendor = oui::lookup(mac);
                    sweep_events.host(host);
                },
            );
            (iface.name, outcome, found)
        })
        .await;

        match result {
            Ok((name, Ok(()), found)) => {
                replies.extend(found);
                swept.insert(name);
            }
            Ok((_, Err(arp::RawArpError::PermissionDenied), _)) => {
                let exe = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "netscan".to_owned());
                events.send(ScanEvent::Notice(format!(
                    "Raw ARP unavailable – for faster scans run: sudo setcap cap_net_raw+ep {exe}"
                )));
                break;
            }
            Ok((name, Err(arp::RawArpError::Other(e)), _)) => {
                log::warn!("raw ARP sweep on {name} failed: {e}")
            }
            Err(e) => log::warn!("raw ARP task failed: {e}"),
        }
    }
    (replies, swept)
}

fn base_host(ip: Ipv4Addr, net: &NetInfo) -> Host {
    let mut host = Host::new(ip);
    host.is_gateway = net.gateway == Some(ip);
    host.is_self = net.ifaces.iter().any(|i| i.ip == ip);
    host
}

async fn scan_host(ip: Ipv4Addr, shared: &Shared, events: &Events) -> Host {
    let settings = &shared.settings;
    let net = &shared.net;
    let mut host = base_host(ip, net);
    let local_iface = net.local_iface_for(ip);

    if host.is_self {
        host.status = HostStatus::Alive;
        host.mac = net.ifaces.iter().find(|i| i.ip == ip).and_then(|i| i.mac);
        host.name = net.hostname.clone();
    } else if let Some(mac) = shared.arp_replies.get(&ip) {
        host.status = HostStatus::Alive;
        host.mac = Some(*mac);
    } else if local_iface.is_some_and(|i| shared.swept.contains(&i.name)) {
        // Every host on a local segment must answer ARP to be reachable at all.
        host.status = HostStatus::Dead;
        return host;
    }

    // Discovery: ICMP echo first; TCP connects only for hosts that stay quiet, so
    // the connect burst neither delays echo replies (skewing RTTs) nor hits pingable hosts.
    let tcp_timeout = Duration::from_millis(settings.tcp_timeout_ms);
    let ping = async {
        match &shared.pinger {
            Some(client) => {
                icmp::ping(
                    client,
                    ip,
                    Duration::from_millis(settings.ping_timeout_ms),
                    settings.ping_tries,
                )
                .await
            }
            None => None,
        }
    };
    let discovery = async {
        let mut set = JoinSet::new();
        for port in DISCOVERY_PORTS {
            set.spawn(async move { (port, ports::connect(ip, port, tcp_timeout).await.0) });
        }
        set.join_all().await
    };
    tokio::pin!(ping);
    let (rtt, tcp) = match tokio::time::timeout(PING_HEAD_START, &mut ping).await {
        Ok(Some(rtt)) => (Some(rtt), Vec::new()),
        Ok(None) => (None, discovery.await),
        Err(_) => tokio::join!(ping, discovery),
    };

    host.rtt = rtt;
    let mut alive = host.status == HostStatus::Alive
        || rtt.is_some()
        || tcp.iter().any(|(_, state)| *state != PortState::Silent);
    if local_iface.is_some() && host.mac.is_none() {
        // Our probes made the kernel resolve the address; firewalled hosts still answer ARP.
        if let Some(mac) = arp::read_arp_table().get(&ip) {
            host.mac = Some(*mac);
            alive = true;
        }
    }
    if !alive {
        host.status = HostStatus::Dead;
        return host;
    }
    host.status = HostStatus::Alive;
    host.vendor = host.mac.and_then(oui::lookup);
    host.services = tcp
        .iter()
        .filter(|(_, state)| *state == PortState::Open)
        .map(|(port, _)| Service::new(*port, None))
        .collect();
    host.services.sort_by_key(|s| s.port);
    events.host(host.clone());

    // Enrichment: names and the full service list.
    let dns = async {
        if settings.resolve_dns {
            names::reverse_dns(ip, DNS_TIMEOUT).await
        } else {
            None
        }
    };
    let netbios = async {
        if settings.resolve_netbios {
            names::netbios_query(ip, NETBIOS_TIMEOUT).await
        } else {
            None
        }
    };
    let services = async {
        let mut set = JoinSet::new();
        for &port in &shared.ports {
            let grab = settings.grab_banners;
            set.spawn(async move { (port, ports::probe(ip, port, tcp_timeout, grab).await) });
        }
        set.join_all().await
    };
    let (dns, netbios, services) = tokio::join!(dns, netbios, services);

    if let Some(nb) = netbios {
        host.netbios_name = nb.name;
        host.workgroup = nb.workgroup;
        if host.mac.is_none() {
            host.mac = nb.mac;
            host.vendor = host.mac.and_then(oui::lookup);
        }
    }
    host.dns_name = dns;
    if !host.is_self
        && let Some(name) = host.dns_name.clone().or_else(|| host.netbios_name.clone())
    {
        host.name = Some(name);
    }

    let mut update = Host::new(ip);
    update.services = services
        .into_iter()
        .filter(|(_, (state, _))| *state == PortState::Open)
        .map(|(port, (_, banner))| Service::new(port, banner))
        .collect();
    host.merge(update);
    host
}
