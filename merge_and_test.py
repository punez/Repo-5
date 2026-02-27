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
TCP_TIMEOUT = 3
CONCURRENCY = 300
LATENCY_LIMIT_MS = 300
TOP_PERCENT = 0.30
MAX_JITTER = 80
SUPER_FAST_THRESHOLD = 30
SUPER_FAST_CONFIRM = 50

def log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}")

async def fetch_links(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            text = await resp.text()
            return {l.strip() for l in text.splitlines() if l.strip()}
    except:
        return set()

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

async def tcp_latency(host, port, semaphore):
    async with semaphore:
        try:
            start = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=TCP_TIMEOUT
            )
            latency = (time.perf_counter() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return latency
        except:
            return None

async def main():
    log("Stage 1: Fetch")

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_links(session, url) for url in SOURCE_URLS]
        results = await asyncio.gather(*tasks)
        all_links = set().union(*results)

    log(f"Total raw links: {len(all_links):,}")
    log("Stage 2: TCP latency filtering (stability + super-fast guard)")

    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def process(link):
        parsed = parse_link(link)
        if not parsed:
            return None

        host, port = parsed
        if not host or not port:
            return None

        # تست اول
        latency1 = await tcp_latency(host, port, semaphore)
        if latency1 is None or latency1 >= LATENCY_LIMIT_MS:
            return None

        # تست دوم
        latency2 = await tcp_latency(host, port, semaphore)
        if latency2 is None or latency2 >= LATENCY_LIMIT_MS:
            return None

        # Stability check (Jitter)
        if abs(latency1 - latency2) > MAX_JITTER:
            return None

        avg_latency = (latency1 + latency2) / 2

        # Super-fast guard
        if avg_latency < SUPER_FAST_THRESHOLD:
            latency3 = await tcp_latency(host, port, semaphore)
            if latency3 is None or latency3 > SUPER_FAST_CONFIRM:
                return None

        return (link, avg_latency)

    tasks = [process(l) for l in all_links]
    checked = await asyncio.gather(*tasks)

    valid = [r for r in checked if r]

    log(f"Passed stability filter: {len(valid):,}")

    valid.sort(key=lambda x: x[1])

    cut_count = int(len(valid) * TOP_PERCENT)
    final_nodes = [v[0] for v in valid[:cut_count]]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for node in final_nodes:
            f.write(node + "\n")

    log(f"Done: {len(final_nodes):,} elite stable nodes")

if __name__ == "__main__":
    asyncio.run(main())
