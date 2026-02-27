import asyncio
import aiohttp
import urllib.parse
import base64
import json
import time
from datetime import datetime

# ======================================
# 🔧 تنظیمات (همه قابل تغییر)
# ======================================

SOURCE_URLS = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/output/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-0/refs/heads/main/output/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-3/refs/heads/main/output/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-2/refs/heads/main/output/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-1/refs/heads/main/output/final.txt"
]

OUTPUT_FILE = "alive.txt"

TCP_TIMEOUT = 2              # چند ثانیه صبر کند برای اتصال
CONCURRENCY = 200            # تعداد تست همزمان
MAX_LATENCY_MS = 1500        # حداکثر پینگ قابل قبول
MAX_OUTPUT = 0               # 0 = بدون محدودیت

# ======================================

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

def fingerprint(link):
    try:
        if link.startswith("vmess://"):
            raw = link.replace("vmess://", "")
            raw += "=" * (-len(raw) % 4)
            decoded = base64.b64decode(raw).decode()
            data = json.loads(decoded)
            return f"vmess-{data.get('add')}-{data.get('port')}-{data.get('id')}"

        parsed = urllib.parse.urlparse(link)
        return f"{parsed.scheme}-{parsed.hostname}-{parsed.port}-{parsed.username}"

    except:
        return None

def parse_host_port(link):
    try:
        if link.startswith(("vless://", "trojan://")):
            u = urllib.parse.urlparse(link)
            return u.hostname, u.port or 443

        if link.startswith("vmess://"):
            raw = link.replace("vmess://", "")
            raw += "=" * (-len(raw) % 4)
            decoded = base64.b64decode(raw).decode()
            data = json.loads(decoded)
            return data.get("add"), int(data.get("port"))

    except:
        return None

    return None

async def tcp_check(host, port, semaphore):
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

            if latency <= MAX_LATENCY_MS:
                return latency

        except:
            return None

    return None

async def main():

    log("Stage 1: Fetching sources")

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_links(session, url) for url in SOURCE_URLS]
        results = await asyncio.gather(*tasks)
        all_links = set().union(*results)

    log(f"Fetched links: {len(all_links):,}")

    # Dedup
    log("Stage 2: Dedup")
    seen = set()
    deduped = []

    for link in all_links:
        fp = fingerprint(link)
        if fp and fp not in seen:
            seen.add(fp)
            deduped.append(link)

    log(f"After dedup: {len(deduped):,}")

    # TCP Check
    log("Stage 3: TCP Check")

    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def process(link):
        parsed = parse_host_port(link)
        if not parsed:
            return None

        host, port = parsed
        if not host or not port:
            return None

        latency = await tcp_check(host, port, semaphore)
        if latency is not None:
            return (link, latency)

        return None

    tasks = [process(l) for l in deduped]
    checked = await asyncio.gather(*tasks)

    alive = [r for r in checked if r]
    alive.sort(key=lambda x: x[1])

    final_links = [a[0] for a in alive]

    if MAX_OUTPUT > 0:
        final_links = final_links[:MAX_OUTPUT]

    log(f"Alive nodes: {len(final_links):,}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for link in final_links:
            f.write(link + "\n")

    log("Done ✔")

if __name__ == "__main__":
    asyncio.run(main())
