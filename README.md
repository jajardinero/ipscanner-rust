# NetScan

A fast LAN scanner for Linux with a desktop GUI, written in Rust with
[egui](https://github.com/emilk/egui). Point it at a range of addresses and it lists every device
it finds, along with each device's name, manufacturer, MAC address and open services.

## Features

- **Flexible ranges:** `192.168.1.1-254`, `10.0.0.1-10.0.3.254`, `10.0.0.0/24`, or several of
  these separated by commas. The range starts out as your current subnet.
- **Reliable discovery:** ICMP echo, TCP connect probes and the kernel ARP cache. Firewalled
  machines on the local subnet still show up.
- **Rich results:** name (reverse DNS, falling back to NetBIOS), IP, manufacturer (IEEE OUI
  registry), MAC address, open services with banners and web page titles, round-trip time, and
  your own comments.
- **One-click actions:**
  - HTTP and HTTPS open in your browser.
  - SMB shares open in your file manager.
  - SSH and Telnet open in your terminal.
  - RDP and VNC open in FreeRDP, Remmina or vncviewer if one is installed.
- **Built-in tools:** Ping and Tracepath windows with live output.
- **Organisation:** a Favorites tab, per-host comments, sortable and searchable results, and CSV
  export.
- **No root required:** runs as a normal user.

## Running

```sh
cd ~/Projects/network-scanner
./target/release/netscan
```

Press **F5** or click **Scan**.

To rebuild after changing the code and launch in one step:

```sh
cargo run --release
```

If the shell reports `cargo: command not found`, open a new terminal or run `source ~/.cargo/env`.

To launch it from anywhere, copy the binary onto your `PATH`:

```sh
cp target/release/netscan ~/.local/bin/
```

## Faster scans (optional)

With the `CAP_NET_RAW` capability, NetScan first does a raw ARP sweep of local subnets. It then
marks silent addresses as down straight away, without waiting for ping timeouts:

```sh
sudo setcap cap_net_raw+ep target/release/netscan
```

Apply it to whichever copy of the binary you run. Rebuilding or copying the binary drops the
capability, so run the command again afterwards. Without the capability, NetScan uses the
unprivileged method and shows a hint in the status bar.

## Requirements

- Linux with unprivileged ICMP sockets, meaning `net.ipv4.ping_group_range` covers your group.
  Most distributions set this by default.
- `ping` and `tracepath` (iputils) for the tool windows.
- `xdg-open` handlers for `http`, `smb` and `ftp` URLs: a browser, plus a file manager with SMB
  support such as Nautilus with gvfs-smb.
- A terminal emulator for SSH and Telnet. NetScan uses `$TERMINAL`, then `xdg-terminal-exec`,
  then common emulators.

Settings, favorites and comments are saved in `~/.local/share/netscan/app.ron`.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Install Rust with [rustup](https://rustup.rs) if you don't already have it.

`assets/oui.tsv`, the MAC vendor table, is generated from the hwdata package's copy of the IEEE
registry:

```sh
grep -E '^[0-9A-F]{6}[[:space:]]+\(base 16\)' /usr/share/hwdata/oui.txt \
  | sed -E 's/^([0-9A-F]{6})[[:space:]]+\(base 16\)[[:space:]]*(.*)$/\1\t\2/' \
  | tr -d '\r' | sed -E 's/[[:space:]]+$//' | sort -u -k1,1 > assets/oui.tsv
```
