import asyncio
import aiohttp
import random
from datetime import datetime

# تنظیمات
SOURCE_URLS = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/final_sub.txt",
    "https://raw.githubusercontent.com/punez/Repo-2/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-3/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-1/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-0/refs/heads/main/final.txt",
    # ↑↑↑ اینجا یوزرنیم و اسم ریپوها رو درست وارد کن
]

OUTPUT_FILE = "alive.txt"
TIMEOUT = 1.5
CONCURRENCY = 200
MAX_ALIVE = 5000           # وقتی به این عدد رسید، تست بقیه رو متوقف می‌کنه

def log(msg):
    print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}] {msg}")

def extract_host_port(link):
    link = link.strip()
    if not link: return None, None

    try:
        if link.startswith("vmess://"):
            import base64, json
            raw = link[8:].split("#", 1)[0]
            decoded = base64.b64decode(raw + "===").decode(errors="ignore")
            data = json.loads(decoded)
            return data.get("add"), data.get("port")

        elif link.startswith(("vless://", "trojan://")):
            from urllib.parse import urlparse
            u = urlparse(link.split("#", 1)[0])
            return u.hostname, u.port or 443

        else:
            after = link.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
            if "@" in after:
                after = after.split("@")[-1]
            if ":" in after:
                host, port = after.rsplit(":", 1)
                return host.strip(), port.strip()
        return None, None
    except:
        return None, None

async def tcp_check(host, port, semaphore, counter):
    async with semaphore:
        if counter["count"] >= MAX_ALIVE:
            return False

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port)),
                timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()

            if counter["count"] < MAX_ALIVE:
                counter["count"] += 1
                return True
            return False
        except:
            return False

async def fetch_links(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status != 200:
                log(f"خطا در دانلود {url} → وضعیت {resp.status}")
                return set()
            text = await resp.text()
            links = {line.strip() for line in text.splitlines() if line.strip()}
            log(f"از {url} → {len(links)} لینک خوانده شد")
            return links
    except Exception as e:
        log(f"خطا در دانلود {url}: {e}")
        return set()

async def main():
    log("Repo-5 شروع: دانلود + ترکیب + تست TCP سریع")

    all_links = set()
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_links(session, url) for url in SOURCE_URLS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                all_links.update(res)

    total = len(all_links)
    log(f"مجموع لینک‌های یکتا قبل از تست: {total:,}")

    if total == 0:
        log("هیچ لینکی نبود")
        return

    semaphore = asyncio.Semaphore(CONCURRENCY)
    counter = {"count": 0}
    alive = []

    async def check(link):
        host, port = extract_host_port(link)
        if host and port:
            if await tcp_check(host, port, semaphore, counter):
                alive.append(link)

    await asyncio.gather(*(check(link) for link in all_links), return_exceptions=True)

    random.shuffle(alive)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for link in alive:
            f.write(link + "\n")          # هر لینک در یک خط

    log(f"پایان: {len(alive):,} نود زنده (حداکثر {MAX_ALIVE:,}) → {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
