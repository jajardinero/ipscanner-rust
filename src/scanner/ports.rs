//! TCP connect probes with optional banner grabbing.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::ServiceKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    Open,
    /// The host answered with a reset, so it is up even though the port is closed.
    Refused,
    /// No answer before the timeout, or the host is unreachable.
    Silent,
}

pub async fn connect(ip: Ipv4Addr, port: u16, wait: Duration) -> (PortState, Option<TcpStream>) {
    match timeout(wait, TcpStream::connect(SocketAddr::from((ip, port)))).await {
        Ok(Ok(stream)) => (PortState::Open, Some(stream)),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => (PortState::Refused, None),
        _ => (PortState::Silent, None),
    }
}

/// Connect to `port` and, if `grab` is set, try to read something identifying.
pub async fn probe(
    ip: Ipv4Addr,
    port: u16,
    wait: Duration,
    grab: bool,
) -> (PortState, Option<String>) {
    let (state, stream) = connect(ip, port, wait).await;
    let banner = match stream {
        Some(stream) if grab => grab_banner(stream, ip, port).await,
        _ => None,
    };
    (state, banner)
}

const BANNER_WAIT: Duration = Duration::from_millis(300);
const HTTP_WAIT: Duration = Duration::from_millis(1200);

async fn grab_banner(mut stream: TcpStream, ip: Ipv4Addr, port: u16) -> Option<String> {
    match ServiceKind::from_port(port) {
        ServiceKind::Http => {
            let request = format!(
                "GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netscan\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await.ok()?;
            let body = read_some(&mut stream, 16 * 1024, HTTP_WAIT).await?;
            describe_http(&String::from_utf8_lossy(&body))
        }
        // These speak TLS or binary protocols; nothing readable without a handshake.
        ServiceKind::Https | ServiceKind::Smb | ServiceKind::NetBios | ServiceKind::Rdp => None,
        _ => {
            let data = read_some(&mut stream, 512, BANNER_WAIT).await?;
            first_line(&String::from_utf8_lossy(&data))
        }
    }
}

/// Read until EOF, `limit` bytes, or `wait` elapses, returning what arrived.
async fn read_some(stream: &mut TcpStream, limit: usize, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(limit.min(4096));
    let mut chunk = [0u8; 4096];
    let _ = timeout(wait, async {
        while buf.len() < limit {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    (!buf.is_empty()).then_some(buf)
}

fn first_line(text: &str) -> Option<String> {
    let line: String = text
        .lines()
        .map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == char::REPLACEMENT_CHARACTER))
        .find(|l| !l.is_empty())?
        .chars()
        // Telnet option negotiation and other binary noise decode to U+FFFD.
        .filter(|c| !c.is_control() && *c != char::REPLACEMENT_CHARACTER)
        .take(120)
        .collect();
    (!line.is_empty()).then_some(line)
}

/// "Title — Server" from an HTTP response, whichever parts are present.
pub fn describe_http(response: &str) -> Option<String> {
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
    let server = head.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("server")
            .then(|| value.trim().to_owned())
    });
    let title = html_title(body);
    let status = head
        .lines()
        .next()
        .filter(|l| l.starts_with("HTTP/"))
        .map(str::to_owned);
    let parts: Vec<String> = [title, server]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        status
    } else {
        first_line(&parts.join(" — "))
    }
}

fn html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let start = start + lower[start..].find('>')? + 1;
    let end = start + lower[start..].find("</title")?;
    let title = body
        .get(start..end)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!title.is_empty()).then(|| decode_entities(&title))
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_title_and_server() {
        let resp = "HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nContent-Type: text/html\r\n\r\n\
                    <html><head><TITLE>\n  Router &amp; Admin </TITLE></head></html>";
        assert_eq!(
            describe_http(resp).as_deref(),
            Some("Router & Admin — nginx/1.24")
        );
    }

    #[test]
    fn http_status_fallback() {
        let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            describe_http(resp).as_deref(),
            Some("HTTP/1.1 401 Unauthorized")
        );
    }

    #[test]
    fn greeting_first_line() {
        assert_eq!(
            first_line("\r\nSSH-2.0-OpenSSH_9.6\r\nmore").as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
        assert_eq!(first_line("\r\n \r\n"), None);
        assert_eq!(first_line("\u{FFFD}\u{FFFD}\u{FFFD}"), None);
    }
}
