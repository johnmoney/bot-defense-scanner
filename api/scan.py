"""Bot Defense Scanner: server-side probe for the bot-defense-check Claude skill.

POST /api/scan  with header  X-Scan-Key: <SCAN_KEY>  and JSON body {"url": "example.com"}
Returns raw JSON evidence. It renders nothing; the Claude skill interprets the payload.

Polite by design: homepage + robots.txt only, three homepage fetches (browser-like,
plain client, labeled bot), no crawling, no forms, no retries.
"""

import hmac
import ipaddress
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from urllib.parse import urljoin, urlparse

import requests

SCAN_KEY = os.environ.get("SCAN_KEY", "")
# Optional target allowlist. Empty or unset = any public domain may be scanned.
# Populated = comma-separated domains; each also covers its subdomains, e.g. "acquia.com,yale.edu".
ALLOWED_DOMAINS = [
    d.strip().lower().lstrip(".") for d in os.environ.get("ALLOWED_DOMAINS", "").split(",") if d.strip()
]
TIMEOUT = 8
MAX_HOPS = 5
MAX_BODY = 200_000
DOH = "https://cloudflare-dns.com/dns-query"

BOT_UA = "AcquiaBotDefenseCheck/0.1 (+https://www.acquia.com)"
PROFILES = {
    "browser": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    },
    "plain": {},  # library default user agent, no browser headers
    "bot": {"User-Agent": BOT_UA, "Accept": "*/*"},
}

KEEP = re.compile(
    r"^(server|via|cf-|x-cache|x-served-by|x-timer|x-akamai|akamai|x-amz|x-vercel|x-ah-|"
    r"x-pantheon|x-styx|x-iinfo|x-sucuri|x-azure|fastly|server-timing|x-age|age|"
    r"x-generator|x-drupal|x-datadome|x-kpsdk|alt-svc|strict-transport-security)",
    re.I,
)

CHALLENGE_MARKERS = {
    "cloudflare_challenge": r"Just a moment\.\.\.|cf-chl|/cdn-cgi/challenge-platform",
    "cloudflare_turnstile": r"challenges\.cloudflare\.com/turnstile",
    "akamai_block": r"Access Denied.{0,400}Reference #|errors\.edgesuite\.net",
    "akamai_bot_manager": r"/akam/\d+/",
    "imperva": r"_Incapsula_Resource|Incapsula incident",
    "datadome": r"captcha-delivery\.com|datadome",
    "human_perimeterx": r"px-captcha|perimeterx|/px/client",
    "kasada": r"kpsdk",
    "aws_waf": r"awswaf|aws-waf-token",
    "generic_captcha": r"g-recaptcha|hcaptcha\.com",
}

BOT_COOKIES = {
    "cloudflare": r"^(__cf_bm|cf_clearance)$",
    "akamai": r"^(_abck|bm_sz|bm_sv|bm_so|ak_bmsc)$",
    "human_perimeterx": r"^_px",
    "datadome": r"^datadome$",
    "imperva": r"^(incap_ses|visid_incap|nlbi_|reese84)",
    "aws_waf": r"^aws-waf-token$",
}

AI_BOTS = [
    "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-User", "PerplexityBot",
    "Google-Extended", "CCBot", "Bytespider", "Meta-ExternalAgent", "Amazonbot",
]


class ScanError(Exception):
    """Carries a stable code the skill maps to a plain-language message."""

    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail


# ---------- DNS over HTTPS ----------

def doh(name, rtype):
    r = requests.get(
        DOH, params={"name": name, "type": rtype},
        headers={"accept": "application/dns-json"}, timeout=5,
    )
    r.raise_for_status()
    return r.json()


def resolve(host):
    data = doh(host, "A")
    if data.get("Status") == 3:  # NXDOMAIN
        raise ScanError("domain_not_found", host)
    chain, ips = [], []
    for ans in data.get("Answer", []):
        if ans.get("type") == 5:
            chain.append(ans["data"].rstrip("."))
        elif ans.get("type") == 1:
            ips.append(ans["data"])
    if not ips:
        raise ScanError("domain_not_found", host)
    return chain, ips


def asn_lookup(ip):
    try:
        rev = ".".join(reversed(ip.split(".")))
        txt = doh(f"{rev}.origin.asn.cymru.com", "TXT").get("Answer", [])
        asn = txt[0]["data"].strip('"').split("|")[0].strip() if txt else None
        if not asn:
            return None
        name = doh(f"AS{asn.split()[0]}.asn.cymru.com", "TXT").get("Answer", [])
        org = name[0]["data"].strip('"').split("|")[-1].strip() if name else None
        return {"asn": asn, "org": org}
    except Exception:
        return None


_checked = {}


def domain_allowed(host):
    """True when no allowlist is set, or when host is a listed domain or one of its subdomains."""
    if not ALLOWED_DOMAINS:
        return True
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)


def assert_public(host):
    """Allowlist check (if populated), then SSRF guard: refuse private, loopback, or reserved addresses.
    The SSRF guard always applies, allowlist or not."""
    if not domain_allowed(host):
        raise ScanError("domain_not_allowed", host)
    if host in _checked:
        return _checked[host]
    chain, ips = resolve(host)
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            raise ScanError("blocked_target", host)
    _checked[host] = (chain, ips)
    return chain, ips


# ---------- HTTP probes ----------

def read_capped(resp):
    out = b""
    for chunk in resp.iter_content(16_384):
        out += chunk
        if len(out) >= MAX_BODY:
            break
    return out.decode(resp.encoding or "utf-8", errors="replace")


def cookie_names(resp):
    try:
        raw = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw = [resp.headers.get("Set-Cookie", "")]
    return sorted({c.split("=", 1)[0].strip() for c in raw if "=" in c})


def fetch(url, headers):
    hops, cur = [], url
    t0 = time.time()
    for _ in range(MAX_HOPS + 1):
        host = urlparse(cur).hostname or ""
        assert_public(host)
        try:
            r = requests.get(cur, headers=headers, timeout=TIMEOUT, allow_redirects=False, stream=True)
        except requests.exceptions.Timeout:
            raise ScanError("no_response", host)
        except requests.exceptions.ConnectionError as e:
            raise ScanError("no_response", f"{host}: {type(e).__name__}")
        hops.append({"url": cur, "status": r.status_code})
        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            r.close()
            if not loc:
                break
            cur = urljoin(cur, loc)
            continue
        body = read_capped(r)
        r.close()
        return {
            "final_url": cur,
            "status": r.status_code,
            "hops": hops,
            "ms": int((time.time() - t0) * 1000),
            "headers": {k.lower(): v[:200] for k, v in r.headers.items() if KEEP.match(k)},
            "set_cookie_names": cookie_names(r),
            "body_bytes": len(body),
            "title": (re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S) or [None, None])[1],
            "markers": [k for k, rx in CHALLENGE_MARKERS.items() if re.search(rx, body, re.I | re.S)],
            "_body": body,
        }
    raise ScanError("redirect_loop", url)


def safe_fetch(url, headers):
    try:
        return fetch(url, headers)
    except ScanError as e:
        return {"error": e.code, "detail": e.detail}


def robots_rules(base):
    res = safe_fetch(urljoin(base, "/robots.txt"), PROFILES["bot"])
    body = res.pop("_body", "") if "error" not in res else ""
    rules = {}
    for bot in AI_BOTS:
        m = re.search(rf"user-agent:\s*{re.escape(bot)}[\s\S]*?(?=user-agent:|$)", body, re.I)
        if m:
            rules[bot] = "blocked" if re.search(r"disallow:\s*/\s*$", m.group(0), re.I | re.M) else "rules"
    return {"status": res.get("status"), "ai_bots": rules, "wildcard_only": not rules}


def platform(page):
    h, body = page.get("headers", {}), page.get("_body", "")
    gen = h.get("x-generator", "") + " " + " ".join(
        re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    )
    major = (re.search(r"Drupal\s+(\d+)", gen, re.I) or [None, None])[1]
    is_drupal = bool(major) or any(k.startswith("x-drupal") for k in h) or "drupalSettings" in body \
        or "Drupal.settings" in body
    legacy7 = "Drupal.settings" in body and "drupalSettings" not in body
    other = None
    if not is_drupal:
        if re.search(r"wordpress", gen, re.I) or "/wp-content/" in body:
            other = "WordPress"
        elif gen.strip():
            other = gen.strip()[:40]
    return {"is_drupal": is_drupal, "drupal_major": major or ("7" if legacy7 else None), "other_cms": other}


def compare(probes):
    ok = {k: v for k, v in probes.items() if "error" not in v}
    base = ok.get("browser")
    out = {}
    for name in ("plain", "bot"):
        p = ok.get(name)
        if not (base and p):
            out[name] = "not_comparable"
            continue
        ratio = p["body_bytes"] / max(base["body_bytes"], 1)
        if p["status"] != base["status"] or p["markers"] != base["markers"]:
            out[name] = "treated_differently"
        elif ratio < 0.5:
            out[name] = "smaller_response"
        else:
            out[name] = "same_as_browser"
    return out


def scan(raw_url):
    raw_url = raw_url.strip()
    if not re.match(r"^https?://", raw_url, re.I):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        raise ScanError("invalid_url", raw_url)
    base = f"https://{host}/"

    chain, ips = assert_public(host)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {name: pool.submit(safe_fetch, base, hdrs) for name, hdrs in PROFILES.items()}
        f_robots = pool.submit(robots_rules, base)
        f_asn = pool.submit(asn_lookup, ips[0])
        probes = {k: f.result() for k, f in futures.items()}
        robots, asn = f_robots.result(), f_asn.result()

    if all("error" in p for p in probes.values()):
        raise ScanError(probes["browser"]["error"], probes["browser"].get("detail", ""))

    ref = next(p for p in (probes["browser"], probes["plain"], probes["bot"]) if "error" not in p)
    plat = platform(ref)
    cookies = sorted({c for p in probes.values() for c in p.get("set_cookie_names", [])})
    bot_cookies = {k: [c for c in cookies if re.match(rx, c)] for k, rx in BOT_COOKIES.items()}
    for p in probes.values():
        p.pop("_body", None)

    final_host = urlparse(ref["final_url"]).hostname
    return {
        "ok": True,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_host": host,
        "final_host": final_host,
        "redirected_offsite": bool(final_host and final_host.removeprefix("www.") != host.removeprefix("www.")),
        "dns": {"cname_chain": chain, "ips": ips[:4], "network": asn},
        "probes": probes,
        "differential": compare(probes),
        "bot_cookies": {k: v for k, v in bot_cookies.items() if v},
        "robots": robots,
        "platform": plat,
        "scanner": {"version": "0.2", "requests_sent": 4, "bot_user_agent": BOT_UA,
                    "allowlist": "on" if ALLOWED_DOMAINS else "off"},
    }


# ---------- Vercel handler ----------

class handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(405, {"ok": False, "error": "method_not_allowed"})

    def do_POST(self):
        if not SCAN_KEY:
            return self._send(500, {"ok": False, "error": "not_configured"})
        if not hmac.compare_digest(self.headers.get("X-Scan-Key", ""), SCAN_KEY):
            return self._send(401, {"ok": False, "error": "unauthorized"})
        try:
            length = min(int(self.headers.get("Content-Length", 0)), 4096)
            url = json.loads(self.rfile.read(length) or b"{}").get("url", "")
            _checked.clear()
            self._send(200, scan(url))
        except ScanError as e:
            self._send(200, {"ok": False, "error": e.code, "detail": e.detail})
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"ok": False, "error": "bad_request"})
        except Exception as e:  # never leak a stack trace
            self._send(200, {"ok": False, "error": "scan_failed", "detail": type(e).__name__})
