//! Ping and Tracepath windows that stream the output of the system tools.

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::sync::mpsc;

use eframe::egui::{self, Context, RichText};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

const MAX_LINES: usize = 5000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolKind {
    Ping,
    Trace,
}

impl ToolKind {
    fn title(self) -> &'static str {
        match self {
            ToolKind::Ping => "Ping",
            ToolKind::Trace => "Tracepath",
        }
    }

    fn command(self, ip: Ipv4Addr) -> (&'static str, Vec<String>) {
        match self {
            // -O reports missing replies instead of staying silent.
            ToolKind::Ping => ("ping", vec!["-O".into(), ip.to_string()]),
            ToolKind::Trace => ("tracepath", vec!["-n".into(), ip.to_string()]),
        }
    }
}

enum ToolMsg {
    Line(String),
    Exit(String),
}

pub struct ToolWindow {
    id: u64,
    kind: ToolKind,
    ip: Ipv4Addr,
    lines: Vec<String>,
    rx: mpsc::Receiver<ToolMsg>,
    /// Dropping this sender stops the process.
    stop: Option<oneshot::Sender<()>>,
    open: bool,
}

impl ToolWindow {
    pub fn new(id: u64, kind: ToolKind, ip: Ipv4Addr, rt: &Handle, ctx: &Context) -> Self {
        let (rx, stop) = spawn(kind, ip, rt, ctx);
        Self {
            id,
            kind,
            ip,
            lines: Vec::new(),
            rx,
            stop: Some(stop),
            open: true,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    fn running(&self) -> bool {
        self.stop.is_some()
    }

    fn restart(&mut self, rt: &Handle, ctx: &Context) {
        self.stop = None;
        let (rx, stop) = spawn(self.kind, self.ip, rt, ctx);
        self.rx = rx;
        self.stop = Some(stop);
        self.lines.push(String::new());
    }

    pub fn show(&mut self, ctx: &Context, rt: &Handle) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                ToolMsg::Line(line) => self.lines.push(line),
                ToolMsg::Exit(status) => {
                    self.lines.push(format!("— {status}"));
                    self.stop = None;
                }
            }
        }
        if self.lines.len() > MAX_LINES {
            self.lines.drain(..self.lines.len() - MAX_LINES);
        }

        let mut open = self.open;
        egui::Window::new(format!("{} {}", self.kind.title(), self.ip))
            .id(egui::Id::unique(("tool", self.id)))
            .open(&mut open)
            .default_size([560.0, 340.0])
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.running() {
                        if ui.button("Stop").clicked() {
                            self.stop = None;
                        }
                        ui.spinner();
                    } else if ui.button("Run again").clicked() {
                        self.restart(rt, ctx);
                    }
                    if ui.button("Clear").clicked() {
                        self.lines.clear();
                    }
                    if ui.button("Copy").clicked() {
                        ctx.copy_text(self.lines.join("\n"));
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &self.lines {
                            ui.label(RichText::new(line).monospace());
                        }
                    });
            });
        self.open = open;
    }
}

fn spawn(
    kind: ToolKind,
    ip: Ipv4Addr,
    rt: &Handle,
    ctx: &Context,
) -> (mpsc::Receiver<ToolMsg>, oneshot::Sender<()>) {
    let (tx, rx) = mpsc::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let ctx = ctx.clone();
    rt.spawn(async move {
        let send = |msg| {
            let _ = tx.send(msg);
            ctx.request_repaint();
        };
        let (program, args) = kind.command(ip);
        let mut child = match Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                send(ToolMsg::Exit(format!("could not run {program}: {e}")));
                return;
            }
        };
        let out = child
            .stdout
            .take()
            .map(|s| rt_forward(s, tx.clone(), ctx.clone()));
        let err = child
            .stderr
            .take()
            .map(|s| rt_forward(s, tx.clone(), ctx.clone()));

        let status = tokio::select! {
            status = child.wait() => match status {
                Ok(s) if s.success() => "finished".to_owned(),
                Ok(s) => format!("exited ({s})"),
                Err(e) => format!("failed: {e}"),
            },
            // Fires on an explicit stop and when the window (and its sender) is dropped.
            _ = stop_rx => {
                let _ = child.kill().await;
                "stopped".to_owned()
            }
        };
        for task in [out, err].into_iter().flatten() {
            let _ = task.await;
        }
        send(ToolMsg::Exit(status));
    });
    (rx, stop_tx)
}

fn rt_forward(
    stream: impl AsyncRead + Unpin + Send + 'static,
    tx: mpsc::Sender<ToolMsg>,
    ctx: Context,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(ToolMsg::Line(line)).is_err() {
                break;
            }
            ctx.request_repaint();
        }
    })
}
