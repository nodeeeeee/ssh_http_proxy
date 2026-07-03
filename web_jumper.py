#!/usr/bin/env python3
import glob
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


APP_NAME = "SSH Net Jumper"
DEFAULT_URL = "about:blank"
HOST = "127.0.0.1"
PORT = int(os.environ.get("SSH_NET_JUMPER_UI_PORT", "8765"))

state_lock = threading.RLock()
tunnel_proc = None
tunnel_host = None
tunnel_port = None
logs = []


def add_log(message):
    with state_lock:
        logs.append({"time": time.strftime("%H:%M:%S"), "message": message})
        del logs[:-500]


def strip_inline_comment(line):
    in_single = False
    in_double = False
    escaped = False
    out = []
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out).strip()


def read_ssh_config_hosts(config_path=None):
    if config_path is None:
        config_path = Path.home() / ".ssh" / "config"
    config_path = Path(config_path).expanduser()
    visited = set()
    hosts = []

    def read_file(path):
        path = Path(path).expanduser()
        try:
            resolved = path.resolve()
        except FileNotFoundError:
            return
        if resolved in visited:
            return
        visited.add(resolved)
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            return
        for raw in lines:
            line = strip_inline_comment(raw)
            if not line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError:
                parts = line.split()
            if not parts:
                continue
            key = parts[0].lower()
            values = parts[1:]
            if key == "include":
                for value in values:
                    pattern = Path(os.path.expandvars(value)).expanduser()
                    if not pattern.is_absolute():
                        pattern = path.parent / pattern
                    for include_path in glob.glob(str(pattern)):
                        read_file(include_path)
            elif key == "host":
                for host in values:
                    if not host.startswith("!") and not any(ch in host for ch in "*?"):
                        hosts.append(host)

    read_file(config_path)
    return sorted(dict.fromkeys(hosts))


def describe_host(host):
    result = subprocess.run(
        ["ssh", "-G", host],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0 and not result.stdout:
        return {"host": host, "detail": result.stderr.strip() or "Unable to inspect host"}
    fields = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            fields[parts[0].lower()] = parts[1]
    user = fields.get("user", "")
    hostname = fields.get("hostname", host)
    port = fields.get("port", "22")
    proxyjump = fields.get("proxyjump")
    detail = f"{user + '@' if user else ''}{hostname}:{port}"
    if proxyjump and proxyjump.lower() != "none":
        detail += f" via {proxyjump}"
    return {"host": host, "detail": detail, "fields": fields}


def find_chrome():
    candidates = [
        "/opt/google/chrome/chrome",
        shutil.which("google-chrome"),
        shutil.which("chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def port_is_free(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((host, port)) != 0


def first_free_port(start=1080):
    port = start
    while port < 65535 and not port_is_free("127.0.0.1", port):
        port += 1
    return port if port < 65535 else None


def wait_for_port(host, port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def safe_profile_name(host, port):
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", host).strip("._")
    return f"{name or 'host'}-{port}"


def process_status():
    global tunnel_proc, tunnel_host, tunnel_port
    with state_lock:
        if tunnel_proc and tunnel_proc.poll() is not None:
            add_log(f"Tunnel process exited with code {tunnel_proc.returncode}.")
            tunnel_proc = None
            tunnel_host = None
            tunnel_port = None
        running = bool(tunnel_proc and tunnel_proc.poll() is None)
        return {
            "running": running,
            "host": tunnel_host,
            "port": tunnel_port,
            "status": f"Tunnel running on 127.0.0.1:{tunnel_port}" if running else "Idle",
            "proxy": f"socks5://127.0.0.1:{tunnel_port}" if running else None,
            "suggestedPort": first_free_port() or 1080,
        }


def read_stream(stream_name, stream):
    try:
        for line in stream:
            text = line.rstrip()
            if text:
                add_log(f"ssh {stream_name}: {text}")
    except Exception as exc:
        add_log(f"Could not read ssh {stream_name}: {exc}")


def start_tunnel(host, port):
    global tunnel_proc, tunnel_host, tunnel_port
    with state_lock:
        if tunnel_proc and tunnel_proc.poll() is None:
            raise RuntimeError("A tunnel is already running.")
        if not port_is_free("127.0.0.1", port):
            raise RuntimeError(f"127.0.0.1:{port} is already in use.")
        cmd = [
            "ssh",
            "-N",
            "-D",
            f"127.0.0.1:{port}",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
            host,
        ]
        add_log("Starting tunnel: " + " ".join(shlex.quote(part) for part in cmd))
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        tunnel_proc = proc
        tunnel_host = host
        tunnel_port = port
        threading.Thread(target=read_stream, args=("stdout", proc.stdout), daemon=True).start()
        threading.Thread(target=read_stream, args=("stderr", proc.stderr), daemon=True).start()

    if wait_for_port("127.0.0.1", port, timeout=5):
        add_log(f"SOCKS5 proxy is ready at 127.0.0.1:{port} via {host}.")
        return process_status()
    time.sleep(0.2)
    if proc.poll() is not None:
        code = proc.returncode
        with state_lock:
            tunnel_proc = None
            tunnel_host = None
            tunnel_port = None
        raise RuntimeError(f"Tunnel failed before the local port became ready. Exit code {code}.")
    add_log("Tunnel process is running, but the local port was not ready within 5 seconds.")
    return process_status()


def stop_tunnel():
    global tunnel_proc, tunnel_host, tunnel_port
    with state_lock:
        proc = tunnel_proc
    if not proc:
        return process_status()
    add_log("Stopping tunnel.")
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        add_log("Tunnel did not stop after SIGTERM; killing it.")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
    with state_lock:
        tunnel_proc = None
        tunnel_host = None
        tunnel_port = None
    add_log("Tunnel stopped.")
    return process_status()


def open_chrome(url, host, port):
    chrome = find_chrome()
    if not chrome:
        raise RuntimeError("Chrome/Chromium executable was not found.")
    if port_is_free("127.0.0.1", port):
        raise RuntimeError(f"No proxy is listening on 127.0.0.1:{port}.")
    profile = Path.home() / ".cache" / "ssh-net-jumper" / "chrome-profiles" / safe_profile_name(host, port)
    profile.mkdir(parents=True, exist_ok=True)
    log_file = Path.home() / ".cache" / "ssh-net-jumper" / "chrome.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        chrome,
        f"--user-data-dir={profile}",
        "--no-first-run",
        f"--proxy-server=socks5://127.0.0.1:{port}",
        "--new-window",
        url or DEFAULT_URL,
    ]
    add_log("Opening proxied Chrome: " + " ".join(shlex.quote(part) for part in cmd))
    with log_file.open("ab") as out:
        subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True)
    return {"profile": str(profile)}


def test_url(url, port):
    curl = shutil.which("curl")
    if not curl:
        raise RuntimeError("curl was not found.")
    cmd = [curl, "-I", "--socks5-hostname", f"127.0.0.1:{port}", "--max-time", "15", url or DEFAULT_URL]
    add_log("Testing URL: " + " ".join(shlex.quote(part) for part in cmd))
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=18)
    output = "\n".join(result.stdout.splitlines()[:16]).strip()
    add_log(output or f"curl exited with code {result.returncode}.")
    return {"returncode": result.returncode, "output": output}


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSH Net Jumper</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef3f8;
      --panel: #ffffff;
      --line: #d6e0ea;
      --text: #142033;
      --muted: #607086;
      --primary: #2563eb;
      --primary-dark: #1d4ed8;
      --danger: #dc2626;
      --success: #059669;
      --warning: #d97706;
      --log: #0f172a;
      --log-text: #dbeafe;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font: 20px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .app { width: min(1500px, calc(100vw - 48px)); margin: 24px auto; }
    header { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; margin-bottom: 20px; }
    h1 { margin: 0; font-size: 42px; line-height: 1.05; letter-spacing: 0; }
    .subtitle { margin-top: 8px; color: var(--muted); font-size: 20px; }
    .status { display: flex; align-items: center; gap: 10px; color: var(--muted); font-weight: 800; font-size: 20px; white-space: nowrap; }
    .dot { width: 16px; height: 16px; border-radius: 50%; background: var(--muted); }
    .dot.running { background: var(--success); }
    .dot.error { background: var(--danger); }
    .layout { display: grid; grid-template-columns: 370px minmax(0, 1fr); gap: 18px; min-height: calc(100vh - 150px); }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      box-shadow: 0 10px 26px rgba(15, 23, 42, 0.06);
    }
    .hosts { padding: 20px; display: flex; flex-direction: column; min-height: 0; }
    .panel-title { margin: 0; font-size: 24px; line-height: 1.2; }
    .count { color: var(--muted); margin: 4px 0 16px; font-size: 17px; }
    input, button {
      font: inherit;
    }
    input {
      width: 100%;
      height: 52px;
      padding: 0 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      color: var(--text);
      outline: none;
    }
    input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15); }
    .host-list {
      flex: 1;
      min-height: 360px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      margin-top: 14px;
      background: #fff;
    }
    .host-item {
      width: 100%;
      padding: 14px 16px;
      border: 0;
      border-bottom: 1px solid #edf2f7;
      background: #fff;
      color: var(--text);
      text-align: left;
      cursor: pointer;
      font-size: 19px;
    }
    .host-item:hover { background: #f8fafc; }
    .host-item.selected { background: var(--primary); color: #fff; font-weight: 800; }
    .right { display: grid; grid-template-rows: auto minmax(260px, 1fr); gap: 18px; min-width: 0; }
    .connection { padding: 24px; }
    .selected-host { margin: 8px 0 6px; font-size: 32px; font-weight: 850; overflow-wrap: anywhere; }
    .detail { color: var(--muted); font-size: 19px; overflow-wrap: anywhere; }
    .form-grid { display: grid; grid-template-columns: 240px minmax(0, 1fr); gap: 18px; margin-top: 24px; }
    label { display: block; margin-bottom: 8px; color: var(--muted); font-weight: 800; font-size: 16px; text-transform: uppercase; letter-spacing: .04em; }
    .proxy {
      margin-top: 20px;
      padding: 15px 16px;
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 8px;
      display: flex;
      gap: 14px;
      align-items: center;
    }
    .proxy strong { color: var(--muted); font-size: 16px; text-transform: uppercase; letter-spacing: .04em; }
    .proxy code { font-size: 20px; overflow-wrap: anywhere; }
    .actions { display: grid; grid-template-columns: 1.2fr 1fr 1fr 1fr .8fr; gap: 12px; margin-top: 22px; }
    button {
      height: 54px;
      border: 0;
      border-radius: 8px;
      padding: 0 18px;
      cursor: pointer;
      background: #e2e8f0;
      color: var(--text);
      font-weight: 750;
    }
    button:hover { filter: brightness(.97); }
    button.primary { background: var(--primary); color: #fff; }
    button.primary:hover { background: var(--primary-dark); filter: none; }
    button.danger { background: #fee2e2; color: var(--danger); }
    button:disabled { opacity: .5; cursor: not-allowed; }
    .log-panel { padding: 20px; min-height: 0; display: flex; flex-direction: column; }
    .log {
      flex: 1;
      min-height: 260px;
      margin-top: 12px;
      padding: 16px;
      border-radius: 8px;
      background: var(--log);
      color: var(--log-text);
      overflow: auto;
      font: 17px/1.5 "JetBrains Mono", ui-monospace, SFMono-Regular, Consolas, monospace;
      white-space: pre-wrap;
    }
    @media (max-width: 1050px) {
      .app { width: min(100vw - 28px, 900px); }
      .layout { grid-template-columns: 1fr; }
      .actions { grid-template-columns: 1fr 1fr; }
      .form-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="app">
    <header>
      <div>
        <h1>SSH Net Jumper</h1>
        <div class="subtitle">Choose an SSH host, create a SOCKS proxy, then open Chrome through that network.</div>
      </div>
      <div class="status"><span id="dot" class="dot"></span><span id="status">Idle</span></div>
    </header>
    <section class="layout">
      <aside class="panel hosts">
        <h2 class="panel-title">SSH Hosts</h2>
        <div id="count" class="count">Loading hosts...</div>
        <input id="search" placeholder="Search hosts">
        <div id="hosts" class="host-list"></div>
      </aside>
      <section class="right">
        <div class="panel connection">
          <h2 class="panel-title">Connection</h2>
          <div id="selectedHost" class="selected-host">No host selected</div>
          <div id="detail" class="detail">Select a host from ~/.ssh/config.</div>
          <div class="form-grid">
            <div>
              <label for="port">SOCKS port</label>
              <input id="port" inputmode="numeric">
            </div>
            <div>
              <label for="url">Target URL</label>
              <input id="url" placeholder="about:blank">
            </div>
          </div>
          <div class="proxy"><strong>Proxy</strong><code id="proxy">socks5://127.0.0.1:-</code></div>
          <div class="actions">
            <button id="start" class="primary">Start Tunnel</button>
            <button id="chrome">Open Chrome</button>
            <button id="test">Test URL</button>
            <button id="copy">Copy Proxy</button>
            <button id="stop" class="danger">Stop</button>
          </div>
        </div>
        <div class="panel log-panel">
          <h2 class="panel-title">Activity</h2>
          <div id="log" class="log"></div>
        </div>
      </section>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    let hosts = [];
    let selected = "";
    let logCount = 0;

    async function api(path, body) {
      const options = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
      const res = await fetch(path, options);
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || res.statusText);
      return data;
    }
    function renderHosts() {
      const q = $("search").value.toLowerCase().trim();
      const visible = hosts.filter(h => h.toLowerCase().includes(q));
      $("count").textContent = `${visible.length} of ${hosts.length} hosts`;
      $("hosts").innerHTML = "";
      for (const host of visible) {
        const btn = document.createElement("button");
        btn.className = "host-item" + (host === selected ? " selected" : "");
        btn.textContent = host;
        btn.onclick = () => selectHost(host);
        $("hosts").appendChild(btn);
      }
    }
    async function selectHost(host) {
      if (!host) {
        selected = "";
        $("selectedHost").textContent = "No host selected";
        $("detail").textContent = "Select a host from ~/.ssh/config.";
        renderHosts();
        return;
      }
      selected = host;
      localStorage.setItem("ssh-http-proxy:last-host", host);
      $("selectedHost").textContent = host;
      renderHosts();
      try {
        const info = await api(`/api/describe?host=${encodeURIComponent(host)}`);
        $("detail").textContent = info.detail || "";
      } catch (err) {
        $("detail").textContent = err.message;
      }
    }
    function setStatus(data) {
      const running = !!data.running;
      $("status").textContent = data.status || (running ? "Running" : "Idle");
      $("dot").className = "dot" + (running ? " running" : "");
      $("stop").disabled = !running;
      $("start").disabled = running;
      if (data.port && (!$("port").value || running)) $("port").value = data.port;
      if (data.suggestedPort && !$("port").value) $("port").value = data.suggestedPort;
      updateProxy();
    }
    function updateProxy() {
      $("proxy").textContent = `socks5://127.0.0.1:${$("port").value || "-"}`;
    }
    async function refresh() {
      const data = await api("/api/hosts");
      hosts = data.hosts;
      $("url").value = data.defaultUrl;
      $("port").value = data.suggestedPort;
      renderHosts();
      const lastHost = localStorage.getItem("ssh-http-proxy:last-host");
      await selectHost(lastHost && hosts.includes(lastHost) ? lastHost : "");
      setStatus(await api("/api/status"));
    }
    async function poll() {
      try {
        setStatus(await api("/api/status"));
        const data = await api(`/api/logs?since=${logCount}`);
        if (data.logs.length) {
          logCount = data.total;
          $("log").textContent = data.logs.map(x => `[${x.time}] ${x.message}`).join("\n");
          $("log").scrollTop = $("log").scrollHeight;
        }
      } catch (err) {}
      setTimeout(poll, 900);
    }
    $("search").addEventListener("input", renderHosts);
    $("port").addEventListener("input", updateProxy);
    $("start").onclick = async () => {
      try { setStatus(await api("/api/start", { host: selected, port: Number($("port").value) })); }
      catch (err) { alert(err.message); }
    };
    $("stop").onclick = async () => setStatus(await api("/api/stop", {}));
    $("chrome").onclick = async () => {
      try {
        const status = await api("/api/status");
        await api("/api/open_chrome", { url: $("url").value, host: selected || status.host || "host", port: Number($("port").value) });
      }
      catch (err) { alert(err.message); }
    };
    $("test").onclick = async () => {
      try { await api("/api/test", { url: $("url").value, port: Number($("port").value) }); }
      catch (err) { alert(err.message); }
    };
    $("copy").onclick = async () => navigator.clipboard.writeText($("proxy").textContent);
    refresh().then(poll).catch(err => alert(err.message));
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_HEAD(self):
        if urllib.parse.urlparse(self.path).path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path == "/":
                body = HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif parsed.path == "/api/hosts":
                self.send_json({"hosts": read_ssh_config_hosts(), "suggestedPort": first_free_port() or 1080, "defaultUrl": DEFAULT_URL})
            elif parsed.path == "/api/describe":
                self.send_json(describe_host(query.get("host", [""])[0]))
            elif parsed.path == "/api/status":
                self.send_json(process_status())
            elif parsed.path == "/api/logs":
                since = int(query.get("since", ["0"])[0])
                with state_lock:
                    self.send_json({"logs": logs[since:], "total": len(logs)})
            else:
                self.send_json({"error": "Not found"}, 404)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        try:
            data = self.read_json()
            if parsed.path == "/api/start":
                host = data.get("host", "")
                port = int(data.get("port", 0))
                if not host:
                    raise RuntimeError("Choose a jump host first.")
                if port < 1 or port > 65535:
                    raise RuntimeError("SOCKS port must be between 1 and 65535.")
                self.send_json(start_tunnel(host, port))
            elif parsed.path == "/api/stop":
                self.send_json(stop_tunnel())
            elif parsed.path == "/api/open_chrome":
                self.send_json(open_chrome(data.get("url") or DEFAULT_URL, data.get("host") or "host", int(data.get("port", 0))))
            elif parsed.path == "/api/test":
                self.send_json(test_url(data.get("url") or DEFAULT_URL, int(data.get("port", 0))))
            else:
                self.send_json({"error": "Not found"}, 404)
        except Exception as exc:
            add_log(f"Error: {exc}")
            self.send_json({"error": str(exc)}, 500)


def open_ui(url):
    chrome = find_chrome()
    if chrome:
        subprocess.Popen([chrome, "--new-window", url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    elif shutil.which("xdg-open"):
        subprocess.Popen(["xdg-open", url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def main():
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        if getattr(exc, "errno", None) in (48, 98):
            open_ui(f"http://{HOST}:{PORT}")
            return
        raise
    add_log(f"Web UI listening on http://{HOST}:{PORT}")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    open_ui(f"http://{HOST}:{PORT}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_tunnel()
        server.shutdown()


if __name__ == "__main__":
    main()
