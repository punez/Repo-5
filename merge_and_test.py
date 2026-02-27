import asyncio
import aiohttp
import urllib.parse
import yaml
import subprocess
import tempfile
import os
import random
from datetime import datetime

# تنظیمات (اینجا منبع‌ها رو عوض کن)
SOURCE_URLS = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/final_sub.txt",

    # بقیه URLهای قبلی‌ات رو اینجا نگه دار یا اضافه کن
    # برای تست اول فقط یکی بذار مثلاً:
    # "https://your-sub-link-here/subscription"
]

OUTPUT_FILE = "alive.txt"
MAX_ALIVE = 3000          # سقف منطقی - می‌تونی تغییر بدی
CONCURRENCY = 30          # کم نگه دار تا runner هنگ نکنه
TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 8          # ثانیه

alive = []  # لیست نهایی زنده‌ها

def log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}")

async def fetch_links(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status != 200:
                log(f"خطا در دانلود {url} → وضعیت {resp.status}")
                return set()
            text = await resp.text()
            links = {line.strip() for line in text.splitlines() if line.strip() and line.startswith("vless://")}
            log(f"از {url} → {len(links)} vless لینک")
            return links
    except Exception as e:
        log(f"خطا در دانلود {url}: {e}")
        return set()

def parse_vless_to_outbound(link):
    try:
        u = urllib.parse.urlparse(link)
        uuid = u.username
        host = u.hostname
        port = u.port or 443
        params = urllib.parse.parse_qs(u.query)

        flow = params.get("flow", [""])[0]
        security = params.get("security", [""])[0]
        sni = params.get("sni", [""])[0] or params.get("serverName", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0] or params.get("shortId", [""])[0]

        if security != "reality" or not flow:
            return None  # فقط reality + flowدار (مثل xtls-rprx-vision)

        outbound = {
            "type": "vless",
            "tag": "probe-out",
            "server": host,
            "server_port": int(port),
            "uuid": uuid,
            "flow": flow,
            "tls": {
                "enabled": True,
                "server_name": sni or host,
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {"enabled": True, "public_key": pbk, "short_id": sid}
            }
        }
        return outbound
    except Exception:
        return None

def build_singbox_config(outbound):
    config = {
        "log": {"level": "silent"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10809}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
        "route": {"rules": [{"outbound": "probe-out"}]}
    }
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)

async def test_single_link(link, semaphore):
    async with semaphore:
        if len(alive) >= MAX_ALIVE:
            return None

        outbound = parse_vless_to_outbound(link)
        if not outbound:
            return None

        config_str = build_singbox_config(outbound)

        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.yaml') as tmp:
            tmp.write(config_str)
            cfg_path = tmp.name

        try:
            # چک کانفیگ
            subprocess.run(["./sing-box", "check", "-c", cfg_path], timeout=6, capture_output=True, check=True)

            # اجرا sing-box
            proc = await asyncio.create_subprocess_exec(
                "./sing-box", "run", "-c", cfg_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.sleep(2.0)

            # تست با curl
            curl = ["curl", "-x", "socks5h://127.0.0.1:10809", "--max-time", "5", "-s", "-o", "/dev/null", "-w", "%{http_code}", TEST_URL]
            curl_proc = await asyncio.create_subprocess_exec(*curl, stdout=asyncio.subprocess.PIPE)
            stdout, _ = await curl_proc.communicate()
            code = stdout.decode().strip()

            await proc.terminate()
            await proc.wait()

            if code == "204":
                log(f"زنده → {link[:70]}...")
                return link

        except Exception as e:
            # log(f"تست شکست: {link[:50]}... → {str(e)}")  # اگر لاگ زیاد می‌خوای فعال کن
            pass
        finally:
            if os.path.exists(cfg_path):
                os.unlink(cfg_path)

        return None

async def main():
    log("شروع تست vless-reality با sing-box (فقط reality)")

    all_links = set()
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_links(session, url) for url in SOURCE_URLS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                all_links.update(res)

    total = len(all_links)
    log(f"مجموع vless لینک‌های یکتا: {total:,}")

    if total == 0:
        log("هیچ vlessی نبود")
        return

    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [test_single_link(link, semaphore) for link in all_links]
    checked = await asyncio.gather(*tasks, return_exceptions=True)

    global alive
    alive = [item for item in checked if item]

    random.shuffle(alive)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for node in alive:
            f.write(node + "\n")

    log(f"پایان: {len(alive):,} نود زنده (حداکثر {MAX_ALIVE}) → {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
