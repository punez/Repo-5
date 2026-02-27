import asyncio
import aiohttp
import urllib.parse
import base64
import json
import time
from datetime import datetime

SOURCE_URLS = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/final_sub.txt",
]

OUTPUT_FILE = "alive.txt"
MAX_ALIVE = 5000
TCP_TIMEOUT = 3
CONCURRENCY = 300
LATENCY_LIMIT_MS = 300  # فقط زیر 300ms

def log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}")

# ---------------- FETCH ---------------- #

async def fetch_links(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            text = await resp.text()
            return {l.strip() for l in text.splitlines() if l.strip()}
    except:
        return set()

# ---------------- PARSE ---------------- #

def parse_link(link):
    try:
        if link.startswith("vless://") or link.startswith("trojan://"):
            u = urllib.parse.urlparse(link)
            return u.hostname, u.port or 443

        if link.startswith("vmess://"):
            raw = link.replace("vmess://", "")
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode()
            data = json.loads(decoded)
            return data.get("add"), int(data.get("port"))
    except:
        return None
    return None

# ---------------- TCP + LATENCY ---------------- #

async def tcp_latency(host, port, semaphore):
    async with semaphore:
        try:
            start = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=TCP_TIMEOUT
            )
            latency = (time.perf_counter() - start) * 1000  # ms
            writer.close()
            await writer.wait_closed()
            return latency
        except:
            return None

# ---------------- MAIN ---------------- #

async def main():
    log("Stage 1: Fetch")

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_links(session, url) for url in SOURCE_URLS]
        results = await asyncio.gather(*tasks)
        all_links = set().union(*results)

    log(f"Total raw links: {len(all_links):,}")
    log("Stage 2: TCP latency filtering (<300ms)")

    semaphore = asyncio.Semaphore(CONCURRENCY)
    results = []

    async def process(link):
        parsed = parse_link(link)
        if not parsed:
            return None

        host, port = parsed
        if not host or not port:
            return None

        latency = await tcp_latency(host, port, semaphore)
        if latency is not None and latency < LATENCY_LIMIT_MS:
            return (link, latency)
        return None

    tasks = [process(l) for l in all_links]
    checked = await asyncio.gather(*tasks)

    valid = [r for r in checked if r]

    # مرتب‌سازی بر اساس سریع‌ترین
    valid.sort(key=lambda x: x[1])

    final_nodes = [v[0] for v in valid][:MAX_ALIVE]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for node in final_nodes:
            f.write(node + "\n")

    log(f"Done: {len(final_nodes):,} fast TCP nodes (<{LATENCY_LIMIT_MS}ms)")

if __name__ == "__main__":
    asyncio.run(main())
