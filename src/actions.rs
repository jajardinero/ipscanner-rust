//! Launching external handlers: browsers, file managers, terminals and remote-desktop clients.

use std::env;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use crate::model::{Host, Service, ServiceKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launch {
    /// Hand a URL to xdg-open (browser, Nautilus for smb:// and ftp://).
    Url(String),
    /// Run a command inside the user's terminal emulator.
    Terminal(Vec<String>),
    /// Run a GUI program directly.
    Program(Vec<String>),
    /// No handler is installed; the message says what to install.
    Unavailable(String),
}

impl Launch {
    pub fn describe(&self) -> String {
        match self {
            Launch::Url(url) => url.clone(),
            Launch::Terminal(cmd) | Launch::Program(cmd) => cmd.join(" "),
            Launch::Unavailable(why) => why.clone(),
        }
    }

    pub fn run(&self) -> Result<(), String> {
        match self {
            Launch::Url(url) => {
                open::that_detached(url).map_err(|e| format!("could not open {url}: {e}"))
            }
            Launch::Terminal(cmd) => open_in_terminal(cmd),
            Launch::Program(cmd) => spawn_detached(Path::new(&cmd[0]), &cmd[1..]),
            Launch::Unavailable(why) => Err(why.clone()),
        }
    }
}

/// One entry per openable service of `host`, labelled for menus ("HTTP (8080)", "SMB shares", …).
pub fn service_launches(host: &Host, ssh_user: &str) -> Vec<(String, Launch)> {
    let mut out = Vec::new();
    let has_smb = host.service(ServiceKind::Smb).is_some();
    for service in &host.services {
        // 139 and 445 both mean "SMB shares"; list it once.
        if service.kind == ServiceKind::NetBios && has_smb {
            continue;
        }
        if let Some(launch) = service_launch(service, host.ip, ssh_user) {
            out.push((service_label(service), launch));
        }
    }
    out
}

fn service_label(service: &Service) -> String {
    match service.kind {
        ServiceKind::Smb | ServiceKind::NetBios => "SMB shares".to_owned(),
        _ => service.badge(),
    }
}

pub fn service_launch(service: &Service, ip: Ipv4Addr, ssh_user: &str) -> Option<Launch> {
    let port = service.port;
    let launch = match service.kind {
        ServiceKind::Http => Launch::Url(web_url("http", ip, port, 80)),
        ServiceKind::Https => Launch::Url(web_url("https", ip, port, 443)),
        ServiceKind::Smb | ServiceKind::NetBios => Launch::Url(format!("smb://{ip}/")),
        ServiceKind::Ftp => Launch::Url(web_url("ftp", ip, port, 21)),
        ServiceKind::Ssh => {
            let target = if ssh_user.trim().is_empty() {
                ip.to_string()
            } else {
                format!("{}@{ip}", ssh_user.trim())
            };
            let mut cmd = vec!["ssh".to_owned(), target];
            if port != 22 {
                cmd.extend(["-p".to_owned(), port.to_string()]);
            }
            Launch::Terminal(cmd)
        }
        ServiceKind::Telnet => match which("telnet") {
            Some(_) => Launch::Terminal(vec!["telnet".into(), ip.to_string(), port.to_string()]),
            None => Launch::Unavailable("No telnet client found (install inetutils)".into()),
        },
        ServiceKind::Rdp => rdp_launch(ip, port),
        ServiceKind::Vnc => vnc_launch(ip, port),
        ServiceKind::Other => return None,
    };
    Some(launch)
}

fn web_url(scheme: &str, ip: Ipv4Addr, port: u16, default_port: u16) -> String {
    if port == default_port {
        format!("{scheme}://{ip}/")
    } else {
        format!("{scheme}://{ip}:{port}/")
    }
}

fn rdp_launch(ip: Ipv4Addr, port: u16) -> Launch {
    for client in ["xfreerdp3", "xfreerdp", "wlfreerdp"] {
        if let Some(path) = which(client) {
            return Launch::Program(vec![
                path.display().to_string(),
                format!("/v:{ip}:{port}"),
                "/dynamic-resolution".into(),
            ]);
        }
    }
    if let Some(path) = which("remmina") {
        return Launch::Program(vec![
            path.display().to_string(),
            "-c".into(),
            format!("rdp://{ip}:{port}"),
        ]);
    }
    Launch::Unavailable("No RDP client found (install freerdp or remmina)".into())
}

fn vnc_launch(ip: Ipv4Addr, port: u16) -> Launch {
    if let Some(path) = which("vncviewer") {
        return Launch::Program(vec![path.display().to_string(), format!("{ip}::{port}")]);
    }
    if let Some(path) = which("remmina") {
        return Launch::Program(vec![
            path.display().to_string(),
            "-c".into(),
            format!("vnc://{ip}:{port}"),
        ]);
    }
    Launch::Unavailable("No VNC client found (install tigervnc or remmina)".into())
}

/// Locate an executable on `$PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let path = PathBuf::from(name);
        return path.is_file().then_some(path);
    }
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

fn open_in_terminal(cmd: &[String]) -> Result<(), String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(term) = env::var("TERMINAL")
        && !term.trim().is_empty()
    {
        candidates.push(term.trim().to_owned());
    }
    candidates.extend(
        [
            "xdg-terminal-exec",
            "alacritty",
            "kitty",
            "foot",
            "ghostty",
            "wezterm",
            "gnome-terminal",
            "konsole",
            "xterm",
        ]
        .map(String::from),
    );

    for term in candidates {
        let Some(path) = which(&term) else { continue };
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let mut args: Vec<String> = match name {
            "xdg-terminal-exec" | "kitty" | "foot" => Vec::new(),
            "wezterm" => vec!["start".into(), "--".into()],
            "gnome-terminal" | "kgx" | "ptyxis" => vec!["--".into()],
            _ => vec!["-e".into()],
        };
        args.extend_from_slice(cmd);
        return spawn_detached(&path, &args);
    }
    Err("No terminal emulator found (set $TERMINAL)".into())
}

fn spawn_detached(program: &Path, args: &[String]) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", program.display()))?;
    // Reap the child when it exits so it doesn't linger as a zombie.
    thread::spawn(move || child.wait());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_for_services() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        assert_eq!(
            service_launch(&Service::new(80, None), ip, ""),
            Some(Launch::Url("http://10.0.0.5/".into()))
        );
        assert_eq!(
            service_launch(&Service::new(8443, None), ip, ""),
            Some(Launch::Url("https://10.0.0.5:8443/".into()))
        );
        assert_eq!(
            service_launch(&Service::new(22, None), ip, "admin"),
            Some(Launch::Terminal(vec![
                "ssh".into(),
                "admin@10.0.0.5".into()
            ]))
        );
        assert_eq!(service_launch(&Service::new(9100, None), ip, ""), None);
    }

    #[test]
    fn smb_listed_once() {
        let mut host = Host::new(Ipv4Addr::new(10, 0, 0, 5));
        host.services = vec![
            Service::new(139, None),
            Service::new(445, None),
            Service::new(80, None),
        ];
        let labels: Vec<String> = service_launches(&host, "")
            .into_iter()
            .map(|(l, _)| l)
            .collect();
        assert_eq!(labels, vec!["SMB shares", "HTTP"]);
    }
}
