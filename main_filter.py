import requests
import base64
import json
from urllib.parse import urlparse, parse_qs, urlunparse

MAX_TOTAL = 10000

SOURCES = [
    "https://raw.githubusercontent.com/punez/Repo-4/refs/heads/main/healthy.txt",
    "https://raw.githubusercontent.com/punez/Repo-2/refs/heads/main/healthy.txt",
    "https://raw.githubusercontent.com/punez/Repo-3/refs/heads/main/healthy.txt",
    "https://raw.githubusercontent.com/punez/Repo-1/refs/heads/main/healthy.txt",
]

def safe_b64_decode(data):
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode("utf-8")
    except:
        return None

def fetch(url):
    try:
        r = requests.get(url, timeout=20)
        return r.text.splitlines()
    except:
        return []

def fingerprint(link):
    try:
        if link.startswith("vmess://"):
            raw = link.replace("vmess://", "")
            decoded = safe_b64_decode(raw)
            if not decoded:
                return None
            data = json.loads(decoded)
            return f"vmess-{data.get('add')}-{data.get('port')}-{data.get('id')}-{data.get('sni')}-{data.get('path')}"

        parsed = urlparse(link)
        qs = parse_qs(parsed.query)

        protocol = parsed.scheme
        host = parsed.hostname
        port = parsed.port
        user = parsed.username

        sni = qs.get("sni", [""])[0] or qs.get("serverName", [""])[0]
        path = qs.get("path", [""])[0]

        return f"{protocol}-{host}-{port}-{user}-{sni}-{path}"
    except:
        return None

def rename_config(link, new_name):
    try:
        if link.startswith("vmess://"):
            raw = link.replace("vmess://", "")
            decoded = safe_b64_decode(raw)
            if not decoded:
                return link
            data = json.loads(decoded)
            data["ps"] = new_name
            new_encoded = base64.b64encode(
                json.dumps(data, separators=(',', ':')).encode()
            ).decode()
            return "vmess://" + new_encoded

        parsed = urlparse(link)
        return urlunparse(parsed._replace(fragment=new_name))
    except:
        return link

def main():
    all_links = []
    for url in SOURCES:
        all_links.extend(fetch(url))

    seen = set()
    final = []
    counter = 1

    for link in all_links:
        link = link.strip()
        if not link:
            continue

        fp = fingerprint(link)
        if not fp:
            continue

        if fp not in seen:
            seen.add(fp)
            renamed = rename_config(link, f"Final-{counter}")
            final.append(renamed)
            counter += 1

        if len(final) >= MAX_TOTAL:
            break

    with open("final.txt", "w") as f:
        f.write("\n".join(final))

if __name__ == "__main__":
    main()
