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

# ========= تنظیمات =========
SOURCE_URLS = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/final_sub.txt",
]

OUTPUT_FILE = "alive.txt"

TCP_TIMEOUT = 1.2
TCP_CONCURRENCY = 200

SINGBOX_CONCURRENCY = 20
TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 6

MAX_ALIVE = 2000
# ===========================


def log(msg):
    print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}] {msg}")


# ---------------------------
# Stage 1 – Fetch + TCP
# ---------------------------

async def fetch_links(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            text = await resp.text()
            return {l.strip() for l in text.splitlines() if l.strip().startswith("vless://")}
    except:
        return set()


def extract_host_port(link):
    try:
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


# ---------------------------
# Stage 2 – sing-box real test
# ---------------------------

def parse_vless_reality(link):
    try:
        u = urllib.parse.urlparse(link)
        uuid = u.username
        host = u.hostname
        port = u.port or 443
        q = urllib.parse.parse_qs(u.query)

        flow = q.get("flow", [""])[0]
        security = q.get("security", [""])[0]
        sni = q.get("sni", [""])[0] or host
        fp = q.get("fp", ["chrome"])[0]
        pbk = q.get("pbk", [""])[0]
        sid = q.get("sid", [""])[0]

        if security != "reality" or not flow:
            return None

        return {
            "type": "vless",
            "tag": "probe",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "flow": flow,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {"enabled": True, "public_key": pbk, "short_id": sid}
            }
        }
    except:
        return None


def build_config(outbound):
    return yaml.safe_dump({
        "log": {"level": "silent"},
        "inbounds": [{
            "type": "socks",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": 10809
        }],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"}
        ],
        "route": {"rules": [{"outbound": "probe"}]}
    }, sort_keys=False)


async def singbox_test(link, sem, counter):
    async with sem:
        if counter["count"] >= MAX_ALIVE:
            return None

        outbound = parse_vless_reality(link)
        if not outbound:
            return None

        config = build_config(outbound)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml", mode="w") as f:
            f.write(config)
            path = f.name

        try:
            subprocess.run(["./sing-box", "check", "-c", path],
                           timeout=5, capture_output=True, check=True)

            proc = await asyncio.create_subprocess_exec(
                "./sing-box", "run", "-c", path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            await asyncio.sleep(1.8)

            curl = await asyncio.create_subprocess_exec(
                "curl",
                "-x", "socks5h://127.0.0.1:10809",
                "--max-time", str(TEST_TIMEOUT),
                "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                TEST_URL,
                stdout=asyncio.subprocess.PIPE
            )

            stdout, _ = await curl.communicate()
            code = stdout.decode().strip()

            proc.terminate()
            await proc.wait()

            if code == "204":
                counter["count"] += 1
                return link

        except:
            pass
        finally:
            os.unlink(path)

        return None


# ---------------------------
# Main
# ---------------------------

async def main():
    log("Stage 1: Fetch + TCP filtering")

    all_links = set()
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            *(fetch_links(session, u) for u in SOURCE_URLS)
        )
        for r in results:
            all_links.update(r)

    log(f"Total raw vless: {len(all_links):,}")

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

    log("Stage 2: sing-box reality test")

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

    log(f"Done: {len(alive):,} high-quality nodes")


if __name__ == "__main__":
    asyncio.run(main())
