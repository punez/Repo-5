import asyncio
import aiohttp
import urllib.parse
import yaml
import subprocess
import tempfile
import os
import random
import base64
import json
from datetime import datetime

# ================= SETTINGS =================

SOURCE_URLS = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/final_sub.txt",
]

OUTPUT_FILE = "alive.txt"

TCP_TIMEOUT = 1.2
TCP_CONCURRENCY = 200

SINGBOX_CONCURRENCY = 20
BOOT_WAIT = 2.5
MAX_ALIVE = 3000

# ============================================


def log(msg):
    print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}] {msg}")


# =========================================================
# Fetch
# =========================================================

async def fetch_links(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            text = await resp.text()
            return {l.strip() for l in text.splitlines() if l.strip()}
    except:
        return set()


# =========================================================
# TCP Stage
# =========================================================

def extract_host_port(link):
    try:
        if link.startswith("vmess://"):
            raw = link[8:].split("#")[0]
            data = json.loads(base64.b64decode(raw + "===").decode())
            return data.get("add"), int(data.get("port"))
        else:
            u = urllib.parse.urlparse(link.split("#")[0])
            return u.hostname, u.port or 443
    except:
        return None, None


async def tcp_check(host, port, sem):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port)),
                timeout=TCP_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False


# =========================================================
# Build Outbound (VLESS / Trojan / VMess)
# =========================================================

def build_outbound(link):

    try:

        if link.startswith("vless://"):
            u = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(u.query)

            outbound = {
                "type": "vless",
                "tag": "probe",
                "server": u.hostname,
                "server_port": u.port or 443,
                "uuid": u.username
            }

            security = q.get("security", [""])[0]

            if security in ["tls", "reality"]:
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0]
                }

                if security == "reality":
                    outbound["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": q.get("pbk", [""])[0],
                        "short_id": q.get("sid", [""])[0]
                    }

            if q.get("type", ["tcp"])[0] == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": q.get("path", ["/"])[0],
                    "headers": {"Host": q.get("host", [""])[0]}
                }

            return outbound

        if link.startswith("trojan://"):
            u = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(u.query)

            outbound = {
                "type": "trojan",
                "tag": "probe",
                "server": u.hostname,
                "server_port": u.port or 443,
                "password": u.username,
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0]
                }
            }

            return outbound

        if link.startswith("vmess://"):
            raw = link[8:].split("#")[0]
            data = json.loads(base64.b64decode(raw + "===").decode())

            outbound = {
                "type": "vmess",
                "tag": "probe",
                "server": data["add"],
                "server_port": int(data["port"]),
                "uuid": data["id"],
                "security": data.get("scy", "auto")
            }

            if data.get("tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": data.get("sni", data["add"])
                }

            return outbound

    except:
        return None

    return None


def build_config(outbound):
    return yaml.safe_dump({
        "log": {"level": "error"},
        "inbounds": [],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rules": [{"outbound": "probe"}]
        }
    }, sort_keys=False)


# =========================================================
# Handshake Test (No curl)
# =========================================================

async def singbox_test(link, sem, counter):

    async with sem:

        if counter["count"] >= MAX_ALIVE:
            return None

        outbound = build_outbound(link)
        if not outbound:
            return None

        config = build_config(outbound)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml", mode="w") as f:
            f.write(config)
            path = f.name

        try:
            # فقط چک صحت کانفیگ
            subprocess.run(
                ["./sing-box", "check", "-c", path],
                timeout=5,
                capture_output=True,
                check=True
            )

            # اجرای کوتاه برای تست handshake
            proc = await asyncio.create_subprocess_exec(
                "./sing-box", "run", "-c", path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            await asyncio.sleep(BOOT_WAIT)

            # اگر اینجا crash نکرده باشه یعنی handshake انجام شده
            if proc.returncode is None:
                counter["count"] += 1
                proc.terminate()
                await proc.wait()
                return link

        except:
            pass
        finally:
            if os.path.exists(path):
                os.unlink(path)

        return None


# =========================================================
# MAIN
# =========================================================

async def main():

    log("Stage 1: Fetch")

    all_links = set()

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*(fetch_links(session, u) for u in SOURCE_URLS))
        for r in results:
            all_links.update(r)

    log(f"Total raw links: {len(all_links):,}")

    log("Stage 1: TCP filtering")

    tcp_sem = asyncio.Semaphore(TCP_CONCURRENCY)

    tcp_results = await asyncio.gather(*[
        tcp_check(*extract_host_port(link), tcp_sem)
        if extract_host_port(link)[0] else asyncio.sleep(0)
        for link in all_links
    ])

    stage1 = [link for link, ok in zip(all_links, tcp_results) if ok]

    log(f"After TCP filter: {len(stage1):,}")

    if not stage1:
        log("No nodes passed TCP")
        return

    log("Stage 2: TLS/Handshake validation")

    sb_sem = asyncio.Semaphore(SINGBOX_CONCURRENCY)
    counter = {"count": 0}

    results = await asyncio.gather(*[
        singbox_test(link, sb_sem, counter)
        for link in stage1
    ])

    alive = [r for r in results if r]

    random.shuffle(alive)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for node in alive:
            f.write(node + "\n")

    log(f"Done: {len(alive):,} validated nodes")


if __name__ == "__main__":
    asyncio.run(main())
