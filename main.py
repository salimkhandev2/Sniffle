"""Sniffle MVP - local HTTP(S) inspector.
Run:  mitmdump -s main.py -p 8080
Then open the URL printed in the terminal (it contains a private token).

Environment variables:
  SNIFFLE_UI_PORT: UI server port (default: 8081)
"""
import base64, csv, json, os, secrets, shutil, subprocess, threading, time, urllib.request, urllib.error
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, parse_qsl
from io import StringIO

UI_PORT = int(os.environ.get("SNIFFLE_UI_PORT", "8081"))
TOKEN = secrets.token_urlsafe(16)
FLOWS, LOCK = [], threading.Lock()
FLOW_ID_COUNTER = 0


def body_text(msg):
    raw = msg.get_content(strict=False) or b""
    try:
        return raw.decode("utf-8"), len(raw), raw, False
    except UnicodeDecodeError:
        return f"<binary, {len(raw)} bytes>", len(raw), raw, True


def _find_browser():
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(pf, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(local, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"),
        os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
    ]
    return (next((p for p in candidates if os.path.exists(p)), None)
            or shutil.which("chrome") or shutil.which("msedge"))


def launch_browser_with_proxy(ui_url):
    """Open the Sniffle UI as an app window, plus a proxied browser for capturing."""
    browser = _find_browser()
    if not browser:
        return False
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    flags = 0
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    common = ["--no-first-run", "--no-default-browser-check"]

    # 1) Sniffle UI: app window (no tabs/address bar), NOT proxied
    mode = os.environ.get("SNIFFLE_WINDOW", "maximized")  # fullscreen | maximized | normal
    ui = [browser, f"--user-data-dir={os.path.join(base, 'sniffle-ui-profile')}",
          "--no-proxy-server", f"--app={ui_url}", *common]
    if mode == "fullscreen":
        ui.append("--start-fullscreen")
    elif mode == "maximized":
        ui.append("--start-maximized")

    # 2) Browser whose traffic gets captured
    sniffed = [browser, "--proxy-server=127.0.0.1:8080", "--proxy-bypass-list=<-loopback>",
               f"--user-data-dir={os.path.join(base, 'sniffle-profile')}",
               "--disable-quic", "--no-first-run", "https://example.com", *common]
    try:
        subprocess.Popen(ui, creationflags=flags, close_fds=True)
        time.sleep(1)
        subprocess.Popen(sniffed, creationflags=flags, close_fds=True)
        return True
    except Exception:
        return False


class Sniffle:
    started = False

    def running(self):
        if Sniffle.started:
            return
        Sniffle.started = True
        srv = ThreadingHTTPServer(("127.0.0.1", UI_PORT), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        ui_url = f"http://127.0.0.1:{UI_PORT}/?t={TOKEN}"
        print(f"\n  Sniffle UI: {ui_url}\n")
        print("  Launching Sniffle window + proxied browser...")
        if launch_browser_with_proxy(ui_url):
            print("  Launched\n")
        else:
            print("  Could not launch a browser automatically. Open the UI link above and set the proxy to 127.0.0.1:8080\n")

    def response(self, flow):
        self._add(flow)

    def error(self, flow):
        self._add(flow, str(flow.error))

    def _add(self, flow, error=None):
        global FLOW_ID_COUNTER
        req, res = flow.request, flow.response
        rb, req_size, req_raw, req_binary = body_text(req)
        
        rec = {
            "time": time.strftime("%H:%M:%S"), "method": req.method,
            "host": req.pretty_host, "path": req.path, "url": req.pretty_url,
            "req": {"headers": [list(h) for h in req.headers.items(multi=True)], "body": rb},
            "res": None, "status": 0, "size": 0, "ms": 0, "error": error,
        }
        
        # Add ISO timestamp
        rec["iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(req.timestamp_start))
        
        # Store request size and base64
        rec["req_size"] = req_size
        if req_binary:
            rec["req"]["body_base64"] = base64.b64encode(req_raw).decode("ascii")
        
        if res:
            sb, res_size, res_raw, res_binary = body_text(res)
            rec["status"], rec["size"] = res.status_code, res_size
            if res.timestamp_end:
                rec["ms"] = int((res.timestamp_end - req.timestamp_start) * 1000)
            rec["res"] = {"headers": [list(h) for h in res.headers.items(multi=True)], "body": sb}
            if res_binary:
                rec["res"]["body_base64"] = base64.b64encode(res_raw).decode("ascii")
        
        with LOCK:
            FLOW_ID_COUNTER += 1
            rec["id"] = FLOW_ID_COUNTER
            FLOWS.append(rec)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, data, ctype="application/json"):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _guard(self):
        # Blocks DNS-rebinding and other websites calling the local API
        if self.headers.get("Host", "") not in (f"127.0.0.1:{UI_PORT}", f"localhost:{UI_PORT}"):
            self._send(403, {"error": "bad host"})
            return False
        return True

    def _build_export_item(self, f):
        item = {
            "id": f["id"], "time": f["iso"], "method": f["method"],
            "url": f["url"], "host": f["host"], "path": f["path"],
            "status": f["status"], "duration_ms": f["ms"], "size": f["size"],
            "error": f["error"],
            "request": {
                "headers": dict(f["req"]["headers"]),
                "header_list": f["req"]["headers"],
                "body": f["req"]["body"],
                "body_json": None,
                "body_base64": f["req"].get("body_base64")
            },
            "response": None
        }
        try:
            item["request"]["body_json"] = json.loads(f["req"]["body"])
        except (ValueError, TypeError):
            pass
        if f["res"]:
            item["response"] = {
                "headers": dict(f["res"]["headers"]),
                "header_list": f["res"]["headers"],
                "body": f["res"]["body"],
                "body_json": None,
                "body_base64": f["res"].get("body_base64")
            }
            try:
                item["response"]["body_json"] = json.loads(f["res"]["body"])
            except (ValueError, TypeError):
                pass
        return item

    def _export_flows(self, flows, format_type):
        if format_type == "json":
            export_data = [self._build_export_item(f) for f in flows]
            return json.dumps(export_data, indent=2)
        elif format_type == "jsonl":
            return "\n".join(json.dumps(self._build_export_item(f)) for f in flows)
        elif format_type == "har":
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "Sniffle", "version": "1.0"},
                    "entries": []
                }
            }
            for f in flows:
                parsed_url = urlparse(f["url"])
                req_ct = next((v for k, v in f["req"]["headers"] if k.lower() == "content-type"), "")
                res_ct = next((v for k, v in f["res"]["headers"] if k.lower() == "content-type"), "") if f["res"] else "text/plain"
                
                entry = {
                    "startedDateTime": f.get("iso", f["time"]),
                    "time": f.get("ms", 0),
                    "request": {
                        "method": f["method"],
                        "url": f["url"],
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": h[0], "value": h[1]} for h in f["req"]["headers"]],
                        "queryString": [{"name": k, "value": v} for k, v in parse_qsl(parsed_url.query, keep_blank_values=True)],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": f.get("req_size", len(f["req"]["body"]))
                    },
                    "response": {
                        "status": f["status"],
                        "statusText": "",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": h[0], "value": h[1]} for h in f["res"]["headers"]] if f["res"] else [],
                        "cookies": [],
                        "content": {
                            "size": f["size"],
                            "mimeType": res_ct
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": f["size"]
                    },
                    "cache": {},
                    "timings": {
                        "send": 0,
                        "wait": f["ms"],
                        "receive": 0
                    }
                }
                
                # Set statusText using HTTPStatus
                try:
                    entry["response"]["statusText"] = HTTPStatus(f["status"]).phrase
                except ValueError:
                    pass
                
                if f["req"]["body"]:
                    entry["request"]["postData"] = {"text": f["req"]["body"], "mimeType": req_ct}
                if f["res"] and f["res"]["body"]:
                    if f["res"].get("body_base64"):
                        entry["response"]["content"]["text"] = f["res"]["body_base64"]
                        entry["response"]["content"]["encoding"] = "base64"
                    else:
                        entry["response"]["content"]["text"] = f["res"]["body"]
                har["log"]["entries"].append(entry)
            return json.dumps(har, indent=2)
        elif format_type == "csv":
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(["id", "time", "method", "url", "status", "duration_ms", "size", 
                           "req_content_type", "res_content_type", "req_headers", "req_body", 
                           "res_headers", "res_body"])
            for f in flows:
                req_ct = next((v for k, v in f["req"]["headers"] if k.lower() == "content-type"), "")
                res_ct = next((v for k, v in f["res"]["headers"] if k.lower() == "content-type"), "") if f["res"] else ""
                req_hdrs = "\n".join(f"{k}: {v}" for k, v in f["req"]["headers"])
                res_hdrs = "\n".join(f"{k}: {v}" for k, v in f["res"]["headers"]) if f["res"] else ""
                writer.writerow([f["id"], f["iso"], f["method"], f["url"], f["status"], 
                               f["ms"], f["size"], req_ct, res_ct, req_hdrs, f["req"]["body"],
                               res_hdrs, f["res"]["body"] if f["res"] else ""])
            return "\ufeff" + output.getvalue()  # BOM for Excel
        return ""

    def do_GET(self):
        if not self._guard():
            return
        u = urlparse(self.path)
        if u.path == "/":
            if parse_qs(u.query).get("t") != [TOKEN]:
                return self._send(403, b"Open the URL printed in the terminal.", "text/plain")
            return self._send(200, PAGE.replace("__TOKEN__", TOKEN).encode(), "text/html; charset=utf-8")
        if self.headers.get("X-Sniffle-Token") != TOKEN:
            return self._send(403, {"error": "bad token"})
        if u.path == "/api/flows":
            since_id = int(parse_qs(u.query).get("since", ["0"])[0])
            with LOCK:
                items = [f for f in FLOWS if f["id"] > since_id]
            return self._send(200, items)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._guard():
            return
        if self.headers.get("X-Sniffle-Token") != TOKEN:
            return self._send(403, {"error": "bad token"})
        u = urlparse(self.path)
        if u.path == "/api/clear":
            with LOCK:
                FLOWS.clear()
            return self._send(200, {"ok": True})
        if u.path == "/api/delete":
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            ids_to_delete = set(d.get("ids", []))
            with LOCK:
                FLOWS[:] = [f for f in FLOWS if f["id"] not in ids_to_delete]
            return self._send(200, {"ok": True})
        if u.path == "/api/send":
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if not d["url"].startswith(("http://", "https://")):
                return self._send(200, {"error": "URL must start with http:// or https://"})
            skip = {"host", "content-length", "connection", "accept-encoding",
                    "proxy-connection", "transfer-encoding"}
            hdrs = {k: v for k, v in d["headers"] if k.lower() not in skip}
            hdrs["Accept-Encoding"] = "identity"
            data = d["body"].encode() if d["body"] else None
            r = urllib.request.Request(d["url"], data=data, method=d["method"], headers=hdrs)
            t0 = time.time()
            try:
                resp = urllib.request.urlopen(r, timeout=30)
            except urllib.error.HTTPError as e:
                resp = e
            except Exception as e:
                return self._send(200, {"error": str(e)})
            raw = resp.read()
            return self._send(200, {
                "status": resp.getcode(), "ms": int((time.time() - t0) * 1000),
                "headers": [list(h) for h in resp.headers.items()],
                "body": raw.decode("utf-8", "replace"),
            })
        if u.path == "/api/export":
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            scope = d.get("scope", "all")
            format_type = d.get("format", "json")
            filter_text = d.get("filter", "")
            checked_ids = d.get("checked_ids", [])
            
            with LOCK:
                if scope == "checked":
                    flows = [f for f in FLOWS if f["id"] in checked_ids]
                elif scope == "filtered":
                    q = filter_text.lower()
                    flows = [f for f in FLOWS if not q or (f["method"] + " " + f["url"] + " " + str(f["status"]) + " " + f["req"]["body"] + " " + (f["res"]["body"] if f["res"] else "")).lower().find(q) != -1]
                else:
                    flows = list(FLOWS)
            
            if not flows:
                return self._send(400, {"error": "No flows to export"})
            
            content = self._export_flows(flows, format_type)
            data = content.encode("utf-8")
            ext = {"json": "json", "jsonl": "jsonl", "har": "har", "csv": "csv"}.get(format_type, "json")
            filename = f"sniffle-{time.strftime('%Y%m%d-%H%M%S')}.{ext}"
            ct = {"json": "application/json", "jsonl": "application/jsonl", "har": "application/json", "csv": "text/csv"}.get(format_type, "application/json")
            
            self.send_response(200)
            self.send_header(
                "Content-Type", ct)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        self._send(404, {"error": "not found"})


addons = [Sniffle()]

PAGE = r"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sniffle</title>
<style>
:root{--bg:#eef2f6;--panel:#fff;--ink:#1b2733;--mute:#66788a;--line:#cbd5df;--acc:#0969da;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e;--sel:#dcebf2;--danger-text:#cf222e;--json-key:#0451a5;--json-string:#a31515;--json-number:#098658;--json-bool:#0451a5;--json-null:#808080}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--ink:#e3eaf0;--mute:#8ea0b1;--line:#30363d;--acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--sel:#1f2428;--danger-text:#f85149;--json-key:#9cdcfe;--json-string:#ce9178;--json-number:#b5cea8;--json-bool:#569cd6;--json-null:#808080}}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--ink);font:14px/1.4 "Segoe UI",system-ui,sans-serif;display:flex;flex-direction:column}
header{display:flex;gap:12px;align-items:center;padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line);box-shadow:0 1px 3px rgba(0,0,0,0.05);flex-shrink:0}
header b{font-size:18px;letter-spacing:.3px;font-weight:700}
#st{color:var(--mute);font-size:13px;margin-right:auto;padding:4px 10px;background:var(--bg);border-radius:12px;white-space:nowrap}
input,textarea,button,select{font:inherit;color:inherit;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:6px 10px;transition:border-color 0.15s,background 0.15s}
input:focus,textarea:focus,button:focus-visible,select:focus{outline:2px solid var(--acc);outline-offset:0;border-color:var(--acc)}
textarea,.mono{font-family:"Cascadia Mono",Consolas,monospace;font-size:12.5px;line-height:1.5}
button{cursor:pointer;font-weight:500;font-size:13px;padding:6px 12px;transition:all 0.15s}button:hover{border-color:var(--acc);background:var(--bg)}
button.go{background:var(--acc);border-color:var(--acc);color:#fff}button.go:hover{opacity:0.88}
button.danger{background:transparent;border-color:var(--danger-text);color:var(--danger-text)}button.danger:hover{background:rgba(248,81,73,0.1)}
button.tab{background:transparent;border:none;border-bottom:2px solid transparent;padding:8px 12px;border-radius:0}button.tab:hover{background:var(--bg)}button.tab.on{border-color:var(--acc);color:var(--acc);font-weight:600}
main{flex:1;display:flex;min-height:0}
#left{display:flex;flex-direction:column;min-height:0;flex:0 0 40%;min-width:200px}
#toolbar{display:flex;gap:8px;align-items:center;padding:10px 12px;background:var(--panel);border-bottom:1px solid var(--line);flex-shrink:0;flex-wrap:wrap}
#list{flex:1;overflow:auto;border-right:1px solid var(--line);background:var(--panel)}
#divider{width:4px;background:var(--line);cursor:col-resize;flex-shrink:0;transition:background 0.15s;user-select:none}#divider:hover,#divider.dragging{background:var(--acc)}
table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
th{position:sticky;top:0;background:var(--panel);text-align:left;color:var(--mute);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);font-size:11px;letter-spacing:0.6px;text-transform:uppercase;z-index:10}
td{padding:6px 10px;border-bottom:1px solid var(--line);font-size:13px;font-family:"Cascadia Mono",Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr.r{cursor:pointer}tr.r:hover td{background:var(--bg)}tr.on td{background:var(--sel)!important}
tr:nth-child(even) td{background:rgba(0,0,0,0.02)}@media(prefers-color-scheme:dark){tr:nth-child(even) td{background:rgba(255,255,255,0.02)}}
.s2{color:var(--ok);font-weight:600}.s3{color:var(--acc);font-weight:600}.s4{color:var(--warn);font-weight:600}.s5,.s0{color:var(--bad);font-weight:600}
.method-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;text-align:center}
.method-get{background:#1a7f37;color:#fff}
.method-post{background:#0969da;color:#fff}
.method-put{background:#9a6700;color:#fff}
.method-patch{background:#bf8700;color:#fff}
.method-delete{background:#cf222e;color:#fff}
.method-head,.method-options{background:#57606a;color:#fff}
@media(prefers-color-scheme:dark){
  .method-get{background:#238636;color:#fff}
  .method-post{background:#1f6feb;color:#fff}
  .method-put,.method-patch{background:#bb8009;color:#fff}
  .method-delete{background:#da3633;color:#fff}
  .method-head,.method-options{background:#6e7681;color:#fff}
}
.slow{color:var(--warn);font-weight:600}
#right{display:flex;flex-direction:column;min-height:0;min-width:0;flex:1}
.pane{display:flex;flex-direction:column;gap:10px;padding:14px 18px}
.pane+.pane{border-top:1px solid var(--line)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.row input{min-width:0}
#m{width:90px;font-weight:600;font-family:"Cascadia Mono",Consolas,monospace}
#u{flex:1;font-family:"Cascadia Mono",Consolas,monospace}
.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.two textarea{resize:vertical;width:100%;min-height:60px}
#rb{width:100%;font-family:"Cascadia Mono",Consolas,monospace;line-height:1.5;min-height:80px}
#rh,#rraw{resize:vertical;width:100%;font-family:"Cascadia Mono",Consolas,monospace;line-height:1.5;min-height:80px}
.empty{margin:auto;color:var(--mute);text-align:center;padding:40px;line-height:1.8}
.empty-icon{font-size:48px;margin-bottom:16px}
.json-key{color:var(--json-key)}.json-string{color:var(--json-string)}.json-number{color:var(--json-number)}.json-bool{color:var(--json-bool)}.json-null{color:var(--json-null)}
.code-view{font-family:"Cascadia Mono",Consolas,monospace;font-size:12.5px;line-height:1.5;white-space:pre-wrap;word-break:break-all;overflow:auto;flex:1;padding:10px;background:var(--bg);border-radius:4px;border:1px solid var(--line)}
.toast{position:fixed;bottom:20px;right:20px;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 16px;box-shadow:0 4px 12px rgba(0,0,0,0.2);z-index:1000;animation:slideIn 0.25s ease;font-size:13px}
@keyframes slideIn{from{transform:translateY(12px);opacity:0}to{transform:translateY(0);opacity:1}}
.host-path{display:flex;gap:4px;overflow:hidden}.host{color:var(--mute);white-space:nowrap}.path{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.filter-bar{display:flex;gap:8px;align-items:center;padding:8px 12px;background:var(--panel);border-bottom:1px solid var(--line);flex-shrink:0}
.quick-filter{display:flex;gap:4px;margin-left:auto}.quick-filter button{padding:3px 8px;font-size:12px}
@keyframes newRowFlash{0%{background:rgba(88,166,255,0.5)}100%{background:transparent}}
.new-row td{animation:newRowFlash 1s ease forwards}
button.active{background:var(--acc)!important;color:#fff!important;border-color:var(--acc)!important}
#q{width:220px}
.slow-status{color:var(--warn)}
</style>
<header>
  <b>Sniffle</b>
  <span id="st">connecting&#8230;</span>
  <button id="pause" title="Pause/Resume capture">&#9208;</button>
  <button id="follow" title="Follow newest" class="active">&#128065;</button>
  <input id="q" placeholder="Filter&#8230; (host:example, status:2xx)" aria-label="Filter requests">
</header>
<div class="filter-bar">
  <button id="hide-noise" title="Hide common noise domains">Hide noise</button>
  <div class="quick-filter">
    <button data-filter="method:GET">GET</button>
    <button data-filter="method:POST">POST</button>
    <button data-filter="status:2xx">2xx</button>
    <button data-filter="status:4xx">4xx</button>
    <button data-filter="status:5xx">5xx</button>
  </div>
</div>
<main id="main">
  <div id="left">
    <div id="toolbar">
      <select id="export-scope" aria-label="Export scope">
        <option value="all">All captured</option>
        <option value="filtered">Matching filter</option>
        <option value="checked">Checked rows</option>
      </select>
      <select id="export-format" aria-label="Export format">
        <option value="json">JSON</option>
        <option value="jsonl">JSONL</option>
        <option value="har">HAR</option>
        <option value="csv">CSV</option>
      </select>
      <button id="export">Export</button>
      <span style="flex:1"></span>
      <button id="delete-checked" class="danger">Delete checked</button>
      <button id="delete-all" class="danger">Delete all</button>
    </div>
    <div id="list"><table><thead><tr>
      <th style="width:32px"><input type="checkbox" id="check-all" aria-label="Check all"></th>
      <th style="width:50px">ID</th>
      <th style="width:70px">Method</th>
      <th>URL</th>
      <th style="width:60px">Status</th>
      <th style="width:70px">Size</th>
      <th style="width:80px">Time</th>
    </tr></thead><tbody id="rows"></tbody></table></div>
  </div>
  <div id="divider"></div>
  <div id="right">
    <div class="empty" id="none">
      <div class="empty-icon">&#128225;</div>
      Send traffic through the proxy on port 8080, then pick a request to view details.
    </div>
    <div class="pane" id="ed" hidden>
      <div class="row">
        <input id="m" aria-label="Method" placeholder="GET">
        <input id="u" class="mono" aria-label="URL" placeholder="https://example.com">
      </div>
      <div class="two">
        <textarea id="h" spellcheck="false" aria-label="Request headers" placeholder="Header-Name: value"></textarea>
        <textarea id="b" spellcheck="false" aria-label="Request body" placeholder="Request body (JSON, form data, etc.)"></textarea>
      </div>
      <div class="row">
        <button class="go" id="send">Send edited request</button>
        <button id="reset">Reset</button>
        <span style="flex:1"></span>
        <button id="cj" title="Copy as JSON">JSON</button>
        <button id="cc" title="Copy as cURL">cURL</button>
        <button id="cf" title="Copy as fetch">fetch</button>
        <button id="cp" title="Copy as Python">Python</button>
      </div>
    </div>
    <div class="pane" id="rs" hidden>
      <div class="row">
        <button class="tab on" id="t1">Body</button>
        <button class="tab" id="t2">Headers</button>
        <button class="tab" id="t3">Raw</button>
        <span id="rst" class="mono" style="margin-left:12px;font-size:13px"></span>
        <span style="flex:1"></span>
        <button id="cb">Copy body</button>
        <button id="cr">Copy JSON</button>
      </div>
      <div id="rb" class="code-view" aria-label="Response body" style="min-height:80px"></div>
      <textarea id="rh" readonly spellcheck="false" aria-label="Response headers" placeholder="Response headers" style="display:none;min-height:80px"></textarea>
      <textarea id="rraw" readonly spellcheck="false" aria-label="Raw response" placeholder="Raw response" style="display:none;min-height:80px"></textarea>
    </div>
  </div>
</main>
<script>
const T="__TOKEN__";
let F=[],sel=null,edited=null,view="body",lastId=0,checked=new Set(),paused=false,followNew=true;
const NOISE=["google.com","doubleclick.net","analytics.google.com","googletagmanager.com","googleadservices.com","clients6.google.com","gstatic.com","update.googleapis.com","mtalk.google.com","facebook.com","facebook.net","fbcdn.net","twitter.com","t.co","linkedin.com","bing.com","yahoo.com","amazon-adsystem.com","hotjar.com","intercom.io","segment.io","mixpanel.com","amplitude.com","cloudflare.com","akamai.com"];
const $=i=>document.getElementById(i);

async function api(p,o={}){
  const r=await fetch(p,{...o,headers:{"X-Sniffle-Token":T,...(o.headers||{})}});
  return r.json();
}

const pretty=s=>{try{return JSON.stringify(JSON.parse(s),null,2)}catch(e){return s}};

function syntaxHighlight(json){
  if(typeof json!=="string")json=JSON.stringify(json,null,2);
  json=json.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  return json.replace(/(\"(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*\"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,m=>{
    let c="json-number";
    if(/^"/.test(m)){c=/:$/.test(m)?"json-key":"json-string";}
    else if(/true|false/.test(m))c="json-bool";
    else if(/null/.test(m))c="json-null";
    return`<span class="${c}">${m}</span>`;
  });
}

const hdrsText=a=>a.map(x=>x[0]+": "+x[1]).join("\n");
const parseHdrs=t=>t.split("\n").map(l=>{const i=l.indexOf(":");return i>0?[l.slice(0,i).trim(),l.slice(i+1).trim()]:null}).filter(Boolean);
const toObj=a=>Object.fromEntries(a);

function toast(msg){
  const t=document.createElement("div");t.className="toast";t.textContent=msg;
  document.body.appendChild(t);setTimeout(()=>t.remove(),2000);
}

function formatSize(s){
  if(!s)return"\u2013";
  if(s<1024)return s+" B";
  if(s<1048576)return(s/1024).toFixed(1)+" KB";
  return(s/1048576).toFixed(1)+" MB";
}

function methodBadge(m){
  return`<span class="method-badge method-${m.toLowerCase()}">${m}</span>`;
}

function isNoise(f){return NOISE.some(n=>f.host.includes(n))}

function matchesFilter(f,q){
  if(!q)return true;
  q=q.toLowerCase();
  if(q.startsWith("host:"))return f.host.toLowerCase().includes(q.slice(5));
  if(q.startsWith("status:")){
    const s=q.slice(7);
    if(s==="2xx")return f.status>=200&&f.status<300;
    if(s==="3xx")return f.status>=300&&f.status<400;
    if(s==="4xx")return f.status>=400&&f.status<500;
    if(s==="5xx")return f.status>=500;
    return f.status===parseInt(s);
  }
  if(q.startsWith("method:"))return f.method.toLowerCase()===q.slice(7);
  return(f.method+" "+f.url+" "+f.status+" "+f.req.body+" "+(f.res?f.res.body:"")).toLowerCase().includes(q);
}

function draw(){
  const q=$("q").value,tb=$("rows");
  tb.textContent="";
  const hideNoise=$("hide-noise").classList.contains("active");
  const visible=F.filter(f=>(!hideNoise||!isNoise(f))&&matchesFilter(f,q)).slice(-500);
  visible.forEach(f=>{
    const tr=document.createElement("tr");
    tr.className="r"+(f===sel?" on":"");
    if(f.id===lastId)tr.classList.add("new-row");

    const cbEl=document.createElement("input");
    cbEl.type="checkbox";cbEl.checked=checked.has(f.id);
    cbEl.setAttribute("aria-label","Select row "+f.id);
    cbEl.onclick=e=>{e.stopPropagation();checked[cbEl.checked?"add":"delete"](f.id)};
    const cbTd=document.createElement("td");cbTd.appendChild(cbEl);tr.appendChild(cbTd);

    const idTd=document.createElement("td");idTd.textContent=f.id;tr.appendChild(idTd);

    const mTd=document.createElement("td");mTd.innerHTML=methodBadge(f.method);tr.appendChild(mTd);

    const urlTd=document.createElement("td");urlTd.className="host-path";
    urlTd.innerHTML=`<span class="host">${f.host}</span><span class="path">${f.path}</span>`;
    tr.appendChild(urlTd);

    const sTd=document.createElement("td");
    sTd.textContent=f.status||"ERR";
    sTd.className="s"+String(f.status||0)[0];
    tr.appendChild(sTd);

    const szTd=document.createElement("td");szTd.textContent=formatSize(f.size);tr.appendChild(szTd);

    // Time: HH:MM:SS stored by Python in f.time; amber if response >1s
    const tTd=document.createElement("td");
    tTd.textContent=f.time||"\u2013";
    if(f.ms>1000)tTd.classList.add("slow");
    tr.appendChild(tTd);

    tr.onclick=()=>pick(f);
    tb.appendChild(tr);
  });
}

function pick(f){
  sel=f;edited=null;
  $("none").hidden=true;$("ed").hidden=false;$("rs").hidden=false;
  $("m").value=f.method;
  $("u").value=f.url;
  $("h").value=hdrsText(f.req.headers);
  $("b").value=f.req.body;
  showResponse("body");
  draw();
}

function showResponse(v){
  view=v;
  $("t1").classList.toggle("on",v==="body");
  $("t2").classList.toggle("on",v==="headers");
  $("t3").classList.toggle("on",v==="raw");

  // Prefer edited response (from "Send edited request"), else captured
  const src=edited||sel;
  const r=src&&src.res&&{status:src.status,headers:src.res.headers,body:src.res.body,ms:src.ms};

  if(!r){
    $("rst").textContent="";$("rst").className="mono";
    $("rh").value="";$("rb").innerHTML="";$("rraw").value="";
    return;
  }

  const slow=r.ms>1000;
  $("rst").textContent=r.status+" \u2022 "+r.ms+" ms"+(slow?" (slow)":"");
  $("rst").className="mono"+(slow?" slow-status":"");

  $("rh").value=hdrsText(r.headers);
  $("rraw").value=r.body;

  $("rb").style.display=v==="body"?"block":"none";
  $("rh").style.display=v==="headers"?"block":"none";
  $("rraw").style.display=v==="raw"?"block":"none";

  if(v==="body"){
    try{
      const parsed=JSON.parse(r.body);
      $("rb").innerHTML=syntaxHighlight(parsed);
    }catch(e){
      $("rb").textContent=r.body;
    }
  }
}

const reqObj=()=>({
  method:$("m").value.trim()||"GET",
  url:$("u").value.trim(),
  headers:parseHdrs($("h").value),
  body:$("b").value
});

const curId=s=>"'"+s.replace(/'/g,"'\\''")+"'";

$("send").onclick=async()=>{
  $("rst").textContent="Sending\u2026";$("rst").className="mono";
  const result=await api("/api/send",{method:"POST",body:JSON.stringify(reqObj())});
  if(result&&!result.error){
    // Overlay on selected flow so the response panel reflects the edited replay
    edited={...sel,status:result.status,ms:result.ms,res:{headers:result.headers,body:result.body}};
  }else if(result&&result.error){
    $("rst").textContent="Error: "+result.error;return;
  }
  showResponse("body");
};

$("reset").onclick=()=>{if(sel){edited=null;pick(sel)}};
$("t1").onclick=()=>showResponse("body");
$("t2").onclick=()=>showResponse("headers");
$("t3").onclick=()=>showResponse("raw");

$("cj").onclick=()=>{
  const r=reqObj();let body=r.body;try{body=JSON.parse(body)}catch(x){}
  navigator.clipboard.writeText(JSON.stringify({method:r.method,url:r.url,headers:toObj(r.headers),body},null,2));
  toast("JSON copied");
};
$("cc").onclick=()=>{
  const r=reqObj();let c="curl -X "+r.method+" "+curId(r.url);
  r.headers.forEach(h=>{if(!/^(host|content-length)$/i.test(h[0]))c+=" -H "+curId(h[0]+": "+h[1])});
  if(r.body)c+=" --data-raw "+curId(r.body);
  navigator.clipboard.writeText(c);toast("cURL copied");
};
$("cf").onclick=()=>{
  const r=reqObj();
  navigator.clipboard.writeText(`await fetch(${JSON.stringify(r.url)},{method:${JSON.stringify(r.method)},headers:${JSON.stringify(toObj(r.headers))},body:${JSON.stringify(r.body)}});`);
  toast("fetch copied");
};
$("cp").onclick=()=>{
  const r=reqObj();
  navigator.clipboard.writeText(`import requests\nrequests.${r.method.toLowerCase()}(\n    ${JSON.stringify(r.url)},\n    headers=${JSON.stringify(toObj(r.headers),null,4)},\n    json=${JSON.stringify(r.body)}\n)`);
  toast("Python copied");
};
$("cb").onclick=()=>{toast("Body copied");navigator.clipboard.writeText($("rb").textContent)};
$("cr").onclick=()=>{
  const src=edited||sel;const r=src&&src.res;if(!r)return;
  let b=r.body;try{b=JSON.parse(b)}catch(x){}
  navigator.clipboard.writeText(JSON.stringify({status:src.status,headers:toObj(r.headers),body:b},null,2));
  toast("JSON copied");
};

$("delete-all").onclick=async()=>{
  if(!confirm("Delete all flows?"))return;
  await api("/api/clear",{method:"POST"});
  F=[];sel=null;edited=null;checked.clear();
  $("ed").hidden=$("rs").hidden=true;$("none").hidden=false;draw();
};
$("delete-checked").onclick=async()=>{
  if(checked.size===0){alert("No rows checked");return}
  if(!confirm("Delete "+checked.size+" checked flow(s)?"))return;
  await api("/api/delete",{method:"POST",body:JSON.stringify({ids:[...checked]})});
  F=F.filter(f=>!checked.has(f.id));
  if(sel&&checked.has(sel.id)){sel=null;edited=null;$("ed").hidden=$("rs").hidden=true;$("none").hidden=false}
  checked.clear();draw();
};
$("check-all").onclick=e=>{
  const q=$("q").value,hideNoise=$("hide-noise").classList.contains("active");
  const shown=F.filter(f=>(!hideNoise||!isNoise(f))&&matchesFilter(f,q));
  shown.forEach(f=>checked[e.target.checked?"add":"delete"](f.id));
  draw();
};

$("pause").onclick=()=>{
  paused=!paused;$("pause").textContent=paused?"\u25B6":"\u23F8";toast(paused?"Paused":"Resumed");
};
$("follow").onclick=()=>{
  followNew=!followNew;$("follow").classList.toggle("active",followNew);
  toast(followNew?"Following newest":"Stopped following");
};
$("hide-noise").onclick=()=>{$("hide-noise").classList.toggle("active");draw()};

// Quick-filter toggle: click same again to clear
document.querySelectorAll(".quick-filter button").forEach(btn=>{
  btn.onclick=()=>{
    $("q").value=($("q").value===btn.dataset.filter)?"":btn.dataset.filter;draw();
  };
});

// Keyboard shortcuts: arrows, /, Delete
document.addEventListener("keydown",e=>{
  if(e.target.tagName==="INPUT"||e.target.tagName==="TEXTAREA")return;
  const q=$("q").value,hideNoise=$("hide-noise").classList.contains("active");
  const visible=F.filter(f=>(!hideNoise||!isNoise(f))&&matchesFilter(f,q));
  if(e.key==="ArrowDown"){
    const i=visible.findIndex(f=>f===sel);if(i<visible.length-1)pick(visible[i+1]);e.preventDefault();
  }else if(e.key==="ArrowUp"){
    const i=visible.findIndex(f=>f===sel);if(i>0)pick(visible[i-1]);e.preventDefault();
  }else if(e.key==="/"){
    $("q").focus();e.preventDefault();
  }else if(e.key==="Delete"&&sel){
    if(confirm("Delete this flow?")){
      api("/api/delete",{method:"POST",body:JSON.stringify({ids:[sel.id]})});
      F=F.filter(f=>f.id!==sel.id);sel=null;edited=null;
      $("ed").hidden=$("rs").hidden=true;$("none").hidden=false;draw();
    }
  }
});

// Draggable divider: 20%-80% constraint
const divider=$("divider"),leftPanel=$("left"),mainEl=$("main");
let isResizing=false;
divider.addEventListener("mousedown",e=>{
  isResizing=true;divider.classList.add("dragging");document.body.style.cursor="col-resize";e.preventDefault();
});
document.addEventListener("mousemove",e=>{
  if(!isResizing)return;
  const rect=mainEl.getBoundingClientRect();
  const pct=((e.clientX-rect.left)/rect.width)*100;
  if(pct>20&&pct<80)leftPanel.style.flex=`0 0 ${pct}%`;
});
document.addEventListener("mouseup",()=>{
  if(isResizing){isResizing=false;divider.classList.remove("dragging");document.body.style.cursor=""}
});

$("export").onclick=async()=>{
  const format=$("export-format").value;
  const res=await fetch("/api/export",{method:"POST",
    headers:{"X-Sniffle-Token":T,"Content-Type":"application/json"},
    body:JSON.stringify({scope:$("export-scope").value,format,filter:$("q").value,checked_ids:[...checked]})});
  if(!res.ok){let m="Export failed";try{m=(await res.json()).error||m}catch(x){}alert(m);return}
  const cd=res.headers.get("Content-Disposition")||"";
  const name=(cd.match(/filename="([^"]+)"/))?cd.match(/filename="([^"]+)"/)[1]:"sniffle."+format;
  const url=URL.createObjectURL(await res.blob());
  const a=document.createElement("a");a.href=url;a.download=name;
  document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
};

$("q").oninput=draw;

async function poll(){
  if(paused)return;
  try{
    const n=await api("/api/flows?since="+lastId);
    if(n.length){
      F.push(...n);n.forEach(f=>lastId=f.id);
      draw();
      if(followNew){const tb=$("rows");tb.scrollTop=tb.scrollHeight}
    }
    $("st").textContent="\u25CF capturing \u00B7 "+F.length+" requests";
  }catch(e){
    $("st").textContent="\u25CB disconnected";
  }
}
setInterval(poll,1000);poll();
</script></html>
"""

