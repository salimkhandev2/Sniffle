import argparse
import os
import shutil
import socket
import subprocess
import sys


def find_browser(prefer):
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local = os.environ.get("LOCALAPPDATA", "")
    chrome = [
        os.path.join(pf, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(local, r"Google\Chrome\Application\chrome.exe"),
    ]
    edge = [
        os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"),
        os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
    ]
    order = edge + chrome if prefer == "edge" else chrome + edge
    for p in order:
        if os.path.exists(p):
            return p
    return shutil.which("chrome") or shutil.which("msedge")


def proxy_up(proxy):
    host, port = proxy.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=0.5).close()
        return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description="Open a URL in an app window through the Sniffle proxy")
    ap.add_argument("url", nargs="?", default="https://example.com")
    ap.add_argument("--proxy", default="127.0.0.1:8080")
    ap.add_argument("--browser", choices=["chrome", "edge"], default="chrome")
    ap.add_argument("--window", choices=["fullscreen", "maximized", "normal"], default="fullscreen")
    ap.add_argument("--no-app", action="store_true", help="use a normal tabbed window instead of app mode")
    args = ap.parse_args()

    url = args.url
    if "://" not in url:
        url = "https://" + url

    browser = find_browser(args.browser)
    if not browser:
        sys.exit("No Chrome or Edge found")

    if not proxy_up(args.proxy):
        sys.exit(f"Sniffle proxy isn't listening on {args.proxy}. Start it first.")

    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    profile = os.path.join(base, "sniffle-profile")

    cmd = [
        browser,
        f"--proxy-server={args.proxy}",
        "--proxy-bypass-list=<-loopback>",
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-quic",
        "--disable-sync",
        "--disable-component-update",
        "--disable-background-networking",
    ]
    cmd.append(f"--app={url}" if not args.no_app else url)

    if args.window == "fullscreen":
        cmd.append("--start-fullscreen")   # press F11 to exit
    elif args.window == "maximized":
        cmd.append("--start-maximized")

    flags = 0
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(cmd, creationflags=flags, close_fds=True)


if __name__ == "__main__":
    main()
