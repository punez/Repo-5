import asyncio
import aiohttp
import json
import yaml
import subprocess
import tempfile
import os
import random
from datetime import datetime

# تنظیمات مهم
SOURCE_URLS = [ ... ]  # همون لیست قبلی‌ات
OUTPUT_FILE = "alive.txt"
MAX_ALIVE = 5000          # سقف منطقی
CONCURRENCY = 50          # کمتر از قبل، چون sing-box سنگین‌تره
TEST_URL = "http://www.gstatic.com/generate_204"   # یا cloudflare.com/cdn-cgi/trace
TIMEOUT = 8               # ثانیه برای کل تست

def log(msg):
    print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}] {msg}")

async def fetch_links(session, url):
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/final_sub.txt",
    "https://raw.githubusercontent.com/punez/Repo-2/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-3/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-1/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/punez/Repo-0/refs/heads/main/final.txt"

def generate_singbox_config(link):
    """کانفیگ ساده sing-box فقط برای تست این outbound"""
    config = {
        "log": {"level": "silent"},
        "inbounds": [
            {
                "type": "direct",
                "tag": "direct-in",
                "listen": "127.0.0.1",
                "listen_port": 0  # random port بعداً
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {"outbound": "direct"}
            ]
        }
    }

    # تبدیل لینک به outbound sing-box
    # این قسمت نیاز به parser داره (می‌تونی از کتابخانه یا دستی بنویسی)
    # مثال ساده برای vless / vmess / trojan
    if link.startswith("vless://"):
        # parse کن و outbound بساز (اینجا ساده نوشتم - کاملش کن)
        outbound = {
            "type": "vless",
            "tag": "test-out",
            "server": "parsed_host",
            "server_port": 443,
            "uuid": "parsed_uuid",
            "flow": "xtls-rprx-vision",  # اگر reality باشه
            "tls": {
                "enabled": True,
                "server_name": "parsed_sni",
                "reality": {
                    "enabled": True,
                    "public_key": "parsed_pubkey",
                    "short_id": "parsed_shortid"
                }
            }
        }
        config["outbounds"].append(outbound)
        config["route"]["rules"][0]["outbound"] = "test-out"

    # برای vmess/trojan هم مشابه
    # ...

    return yaml.dump(config, allow_unicode=True, sort_keys=False)

async def test_with_singbox(link, semaphore):
    async with semaphore:
        if len(alive) >= MAX_ALIVE:
            return None

        config_str = generate_singbox_config(link)
        if not config_str:
            return None

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
            tmp.write(config_str)
            config_path = tmp.name

        try:
            # sing-box check config اول
            check = subprocess.run(["./sing-box", "check", "-c", config_path], capture_output=True, timeout=10)
            if check.returncode != 0:
                os.unlink(config_path)
                return None

            # run sing-box و تست delay
            proc = await asyncio.create_subprocess_exec(
                "./sing-box", "run", "-c", config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # منتظر startup (چند ثانیه)
            await asyncio.sleep(2)

            # تست واقعی با curl داخل sing-box یا urltest
            test_cmd = [
                "curl", "--proxy", "socks5h://127.0.0.1:10808",  # فرض socks inbound اضافه کن
                "-o", "/dev/null", "-s", "-w", "%{time_connect}",
                TEST_URL
            ]
            test_proc = await asyncio.create_subprocess_exec(*test_cmd, stdout=asyncio.subprocess.PIPE)
            stdout, _ = await test_proc.communicate()
            delay_str = stdout.decode().strip()

            await proc.terminate()
            try:
                await proc.wait()
            except:
                pass

            delay = float(delay_str) if delay_str else 9999
            if delay < 8 and test_proc.returncode == 0:  # موفق
                os.unlink(config_path)
                return link, delay

        except Exception as e:
            log(f"Error testing {link[:60]}...: {e}")
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)

        return None

async def main():
    log("شروع تست با sing-box")

    all_links = set()
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_links(session, url) for url in SOURCE_URLS]
        results = await asyncio.gather(*tasks)
        for res in results:
            all_links.update(res)

    log(f"تعداد لینک قبل تست: {len(all_links):,}")

    semaphore = asyncio.Semaphore(CONCURRENCY)
    global alive
    alive = []

    tasks = [test_with_singbox(link, semaphore) for link in all_links]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid = [r[0] for r in results if isinstance(r, tuple) and r]
    valid.sort(key=lambda x: x[1])  # sort بر اساس delay اگر خواستی

    random.shuffle(valid)  # یا نگه دار sorted

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for link in valid:
            f.write(link + "\n")

    log(f"زنده ماند: {len(valid):,} نود")

if __name__ == "__main__":
    asyncio.run(main())
