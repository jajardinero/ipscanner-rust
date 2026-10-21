mod actions;
mod app;
mod export;
mod model;
mod oui;
mod scanner;
mod ui;

use eframe::egui;

fn main() -> eframe::Result {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    raise_fd_limit();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("netscan")
            .with_title("NetScan")
            .with_inner_size([1180.0, 700.0])
            .with_min_inner_size([760.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "NetScan",
        options,
        Box::new(|cc| Ok(Box::new(app::NetScanApp::new(cc)))),
    )
}

/// Each probed port is a socket; lift the soft open-file limit (often 1024) to the hard limit.
fn raise_fd_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit only read and write the struct we pass.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < limit.rlim_max
        {
            limit.rlim_cur = limit.rlim_max.min(65_536);
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}
