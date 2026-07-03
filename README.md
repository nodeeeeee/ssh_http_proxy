# SSH HTTP Proxy

A small browser-based desktop helper for opening a local SOCKS5 proxy through an SSH host from `~/.ssh/config`, then launching Chrome through that proxy.

## Run

```sh
./ssh-net-jumper
```

The launcher starts a local Web UI and opens it in your browser.

## Desktop Launcher

Install an application-menu entry:

```sh
./install-desktop-entry
```

After that, launch `SSH HTTP Proxy` from your desktop environment's application menu.

The app opens a local Web UI at:

```text
http://127.0.0.1:8765
```

## Usage

1. Choose a `Host` from `~/.ssh/config`.
2. Choose or keep the local SOCKS port.
3. Click `Start Tunnel`.
4. Click `Open Chrome`.

Only the Chrome instance opened by this app uses the proxy. System proxy settings and your normal browser windows are not changed.

The copied proxy URL has this format:

```text
socks5://127.0.0.1:<port>
```

## Notes

- The app reads SSH host aliases from your local `~/.ssh/config`.
- It does not upload or store SSH keys.
- If a host requires first-time host-key confirmation or password login, connect once in a terminal first with `ssh <host>`.
- Chrome or Chromium is required for the `Open Chrome` action.
