import asyncio
import aiohttp
import time
from urllib.parse import urlparse, parse_qs

TIMEOUT = 3
CONCURRENCY = 150
MAX_OUTPUT = 10000

def extract_params(link):
    try:
        parsed = urlparse(link)
        scheme = parsed.scheme
        host = parsed.hostname
        port = parsed.port
        query = parse_qs(parsed.query)

        return {
            "scheme": scheme,
            "host": host,
            "port": port,
            "id": parsed.username,
            "network": query.get("type", [""])[0],
            "path": query.get("path", [""])[0],
            "security": query.get("security", [""])[0],
            "sni": query.get("sni", [""])[0],
            "alpn": query.get("alpn", [""])[0],
        }
    except:
        return None

def fingerprint(p):
    if not p:
        return None
    return "|".join([
        str(p.get("scheme")),
        str(p.get("host")),
        str(p.get("port")),
        str(p.get("id")),
        str(p.get("network")),
        str(p.get("path")),
        str(p.get("security")),
        str(p.get("sni")),
        str(p.get("alpn")),
    ])

async def tcp_latency(host, port):
    try:
        start = time.time()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT
        )
        latency = (time.time() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return latency
    except:
        return None

async def main():
    sources = open("inputs.txt").read().splitlines()
    links = set()

    async with aiohttp.ClientSession() as session:
        for url in sources:
            try:
                async with session.get(url, timeout=20) as resp:
                    text = await resp.text()
                    for line in text.splitlines():
                        if "://" in line:
                            links.add(line.strip())
            except:
                pass

    seen = set()
    unique = []

    for link in links:
        p = extract_params(link)
        fp = fingerprint(p)
        if fp and fp not in seen:
            seen.add(fp)
            unique.append((link, p))

    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    async def check(item):
        async with sem:
            link, p = item
            if p and p["host"] and p["port"]:
                latency = await tcp_latency(p["host"], p["port"])
                if latency is not None:
                    results.append((latency, link))

    await asyncio.gather(*(check(i) for i in unique))

    results.sort(key=lambda x: x[0])

    final_links = [r[1] for r in results[:MAX_OUTPUT]]

    with open("final.txt", "w") as f:
        f.write("\n".join(final_links))

asyncio.run(main())
