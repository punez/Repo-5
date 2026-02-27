import asyncio
import aiohttp
import urllib.parse
import yaml
import subprocess
import tempfile
import os
import socket
import base64
import json
from datetime import datetime

SOURCE_URLS = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/final_sub.txt",
]

OUTPUT_FILE = "alive.txt"
MAX_ALIVE = 3000
TCP_TIMEOUT = 3
CONCURRENCY = 200

alive = []

def log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}")

# ---------------- FETCH ---------------- #

async def fetch_links(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            text = await resp.text()
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            return set(lines)
    except:
        return set()

# ---------------- TCP CHECK ---------------- #

async def tcp_check(host, port, semaphore):
    async with semaphore:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=TCP_TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

# ---------------- PARSERS ---------------- #

def parse_vless(link):
    try:
        u = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(u.query)
        return {
            "type": "vless",
            "server": u.hostname,
            "port": u.port or 443,
            "uuid": u.username,
            "security": params.get("security", [""])[0],
        }
    except:
        return None

def parse_trojan(link):
    try:
        u = urllib.parse.urlparse(link)
        return {
            "type": "trojan",
            "server": u.hostname,
            "port": u.port or 443,
            "password": u.username,
        }
    except:
        return None

def parse_vmess(link):
    try:
        raw = link.replace("vmess://", "")
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode()
        data = json.loads(decoded)
        return {
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port")),
            "uuid": data.get("id"),
        }
    except:
        return None

# ---------------- BUILD CONFIG ---------------- #

def build_config(outbound):
    return yaml.safe_dump({
        "log": {"level": "silent"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": 10809
        }],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rules": [{"outbound": outbound["tag"]}]
        }
    }, sort_keys=False)

def build_outbound(parsed):
    if parsed["type"] == "vless":
        return {
            "type": "vless",
            "tag": "proxy",
            "server": parsed["server"],
            "server_port": parsed["port"],
            "uuid": parsed["uuid"]
        }
    elif parsed["type"] == "trojan":
        return {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed["server"],
            "server_port": parsed["port"],
            "password": parsed["password"]
        }
    elif parsed["type"] == "vmess":
        return {
            "type": "vmess",
            "tag": "proxy",
            "server": parsed["server"],
            "server_port": parsed["port"],
            "uuid": parsed["uuid"]
        }

# ---------------- SING-BOX CHECK ---------------- #

def singbox_check(config_str):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        tmp.write(config_str)
        path = tmp.name
    try:
        subprocess.run(["./sing-box", "check", "-c", path],
                       capture_output=True,
                       timeout=5,
                       check=True)
        return True
    except:
        return False
    finally:
        os.remove(path)

# ---------------- MAIN ---------------- #

async def main():
    log("Stage 1: Fetch")
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_links(session, url) for url in SOURCE_URLS]
        results = await asyncio.gather(*tasks)
        all_links = set().union(*results)

    log(f"Total raw links: {len(all_links):,}")

    log("Stage 2: TCP filtering")
    semaphore = asyncio.Semaphore(CONCURRENCY)
    tcp_pass = []

    async def process(link):
        parsed = None
        if link.startswith("vless://"):
            parsed = parse_vless(link)
        elif link.startswith("trojan://"):
            parsed = parse_trojan(link)
        elif link.startswith("vmess://"):
            parsed = parse_vmess(link)

        if not parsed or not parsed.get("server"):
            return None

        ok = await tcp_check(parsed["server"], parsed["port"], semaphore)
        if ok:
            return (link, parsed)
        return None

    results = await asyncio.gather(*[process(l) for l in all_links])
    tcp_pass = [r for r in results if r]

    log(f"After TCP filter: {len(tcp_pass):,}")

    log("Stage 3: sing-box config validation")

    for link, parsed in tcp_pass:
        outbound = build_outbound(parsed)
        config = build_config(outbound)
        if singbox_check(config):
            alive.append(link)
        if len(alive) >= MAX_ALIVE:
            break

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for l in alive:
            f.write(l + "\n")

    log(f"Done: {len(alive):,} validated nodes")

if __name__ == "__main__":
    asyncio.run(main())
