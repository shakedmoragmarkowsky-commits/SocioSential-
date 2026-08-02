from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from typing import Any, Callable
from urllib.parse import quote_plus, urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sociosential")

VERSION = "3.0.0-strict"
MAX_ITEMS = 15
REQUEST_TIMEOUT = 7
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()-]{6,24}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "SocioSential/3.0 public-source verification (+https://sociosential.onrender.com)",
    "Accept-Language": "en-US,en;q=0.8,th;q=0.6",
})

# Small in-memory protections. Nothing is persisted.
_rate_lock = threading.Lock()
_rate: dict[str, list[float]] = {}
RATE_WINDOW = 60
RATE_LIMIT = 12


@dataclass
class Result:
    source: str
    level: str  # verified | possible | manual
    title: str
    url: str = ""
    evidence: str = ""
    score: int | None = None
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {k: v for k, v in data.items() if v not in (None, "", {})}


def client_key() -> str:
    # Render may set X-Forwarded-For. Hash it so raw IPs are not stored in memory.
    raw = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def rate_limited() -> bool:
    now = time.time()
    key = client_key()
    with _rate_lock:
        entries = [t for t in _rate.get(key, []) if now - t < RATE_WINDOW]
        if len(entries) >= RATE_LIMIT:
            _rate[key] = entries
            return True
        entries.append(now)
        _rate[key] = entries
    return False


def split_items(raw: str) -> list[str]:
    # Supports lines, commas, semicolons, and * separators, but preserves spaces inside names.
    parts = re.split(r"[\n,;*]+", raw)
    cleaned: list[str] = []
    seen: set[str] = set()
    for part in parts:
        value = re.sub(r"\s+", " ", part).strip()
        if not value:
            continue
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            cleaned.append(value)
    if not cleaned:
        raise ValueError("Enter at least one value.")
    if len(cleaned) > MAX_ITEMS:
        raise ValueError(f"Use up to {MAX_ITEMS} values per search.")
    return cleaned


def infer_type(value: str) -> str:
    v = value.strip()
    if EMAIL_RE.fullmatch(v):
        return "email"
    if v.startswith(("http://", "https://")):
        return "url"
    if PHONE_RE.fullmatch(v):
        return "phone"
    if DOMAIN_RE.fullmatch(v.lower()):
        return "domain"
    if " " in v or re.search(r"[\u0E00-\u0E7F]", v):
        return "name"
    return "username"


def exact_search_url(text: str, domain: str | None = None) -> str:
    query = f'site:{domain} "{text}"' if domain else f'"{text}"'
    return "https://www.google.com/search?q=" + quote_plus(query)


def manual_pivots(value: str, kind: str) -> list[Result]:
    pivots = [
        Result("Google", "manual", "Exact web search", exact_search_url(value), "Search link only; not counted as a match."),
        Result("Bing", "manual", "Exact web search", "https://www.bing.com/search?q=" + quote_plus(f'"{value}"'), "Search link only; not counted as a match."),
    ]
    if kind in {"username", "name", "phone", "email"}:
        sources = [
            ("Facebook", "facebook.com"), ("Instagram", "instagram.com"),
            ("TikTok", "tiktok.com"), ("X", "x.com"),
            ("Threads", "threads.net"), ("YouTube", "youtube.com"),
            ("Pantip", "pantip.com"), ("ASEAN NOW", "aseannow.com"),
            ("TeakDoor", "teakdoor.com"), ("Thailand-247", "thailand-247.com"),
            ("Thaiger Talk", "thethaiger.com/talk"),
        ]
        for label, domain in sources:
            pivots.append(Result(label, "manual", f"Search {label}", exact_search_url(value, domain), "Public indexed pages only; not counted as a match."))
        pivots.extend([
            Result("LINE OpenChat", "manual", "Search public OpenChat", "https://openchat.line.me/th/search?q=" + quote_plus(value), "Public OpenChat only; private LINE accounts are not searchable."),
            Result("WeChat", "manual", "Search public WeChat content", exact_search_url(value, "mp.weixin.qq.com"), "Public indexed articles only; private WeChat accounts are not searchable."),
        ])
    return pivots


def safe_json_get(url: str, **kwargs: Any) -> requests.Response:
    return SESSION.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, **kwargs)


def verify_github(username: str) -> Result | None:
    try:
        r = safe_json_get(f"https://api.github.com/users/{quote_plus(username)}", headers={"Accept": "application/vnd.github+json"})
        if r.status_code == 200:
            data = r.json()
            if str(data.get("login", "")).casefold() == username.casefold():
                return Result(
                    "GitHub", "verified", "Exact public account confirmed",
                    data.get("html_url", ""),
                    "GitHub API returned an exact username match.", 98,
                    {"name": data.get("name"), "bio": data.get("bio"), "location": data.get("location"), "created_at": data.get("created_at")},
                )
    except (requests.RequestException, ValueError):
        pass
    return None


def verify_reddit(username: str) -> Result | None:
    try:
        r = safe_json_get(f"https://www.reddit.com/user/{quote_plus(username)}/about.json", headers={"Accept": "application/json"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            if str(data.get("name", "")).casefold() == username.casefold():
                return Result(
                    "Reddit", "verified", "Exact public account confirmed",
                    f"https://www.reddit.com/user/{quote_plus(username)}/",
                    "Reddit public JSON endpoint returned an exact username match.", 98,
                    {"created_utc": data.get("created_utc"), "total_karma": data.get("total_karma"), "is_suspended": data.get("is_suspended", False)},
                )
    except (requests.RequestException, ValueError):
        pass
    return None


def verify_keybase(username: str) -> Result | None:
    try:
        r = safe_json_get("https://keybase.io/_/api/1.0/user/lookup.json", params={"usernames": username})
        if r.status_code == 200:
            data = r.json()
            them = data.get("them") or []
            for person in them:
                name = ((person.get("basics") or {}).get("username") or "")
                if name.casefold() == username.casefold():
                    return Result(
                        "Keybase", "verified", "Exact public account confirmed",
                        f"https://keybase.io/{quote_plus(username)}",
                        "Keybase public API returned an exact username match.", 98,
                    )
    except (requests.RequestException, ValueError):
        pass
    return None


def verify_telegram_possible(username: str) -> Result | None:
    # Telegram public pages are ambiguous, so never call this verified.
    try:
        url = f"https://t.me/{quote_plus(username)}"
        r = safe_json_get(url)
        if r.status_code == 200 and "tgme_page" in r.text and username.casefold() in r.text.casefold():
            return Result("Telegram", "possible", "Public page appears to exist", url, "The public page contains the exact handle, but ownership/identity is not verified.", 65)
    except requests.RequestException:
        pass
    return None


def run_sherlock(username: str) -> list[Result]:
    """Run official Sherlock as a discovery layer. Its hits are POSSIBLE only."""
    if os.getenv("ENABLE_SHERLOCK", "1") != "1":
        return []
    commands = [
        ["sherlock", username, "--print-found", "--no-color", "--timeout", "5"],
        ["python", "-m", "sherlock_project", username, "--print-found", "--no-color", "--timeout", "5"],
    ]
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=55, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        results: list[Result] = []
        seen: set[str] = set()
        for line in output.splitlines():
            # Typical Sherlock output: [+] SiteName: https://example/user
            m = re.search(r"(?:\[\+\]|\+)?\s*([^:]{1,80}):\s*(https?://\S+)", line)
            if not m:
                continue
            source = re.sub(r"^[^A-Za-z0-9]+", "", m.group(1)).strip() or "Sherlock"
            url = m.group(2).rstrip(".,);]")
            if url in seen:
                continue
            seen.add(url)
            results.append(Result(source, "possible", "Sherlock reported a public username hit", url, "Discovery signal only. Open and independently verify the profile before attribution.", 55))
        if results or proc.returncode == 0:
            return results[:60]
    return []


def search_username(username: str) -> list[Result]:
    username = username.strip().lstrip("@")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError(f"Invalid username: {username}")
    results: list[Result] = []
    for fn in (verify_github, verify_reddit, verify_keybase, verify_telegram_possible):
        item = fn(username)
        if item:
            results.append(item)
    # Sherlock is secondary and never upgrades anything to verified.
    known_urls = {r.url for r in results if r.url}
    for item in run_sherlock(username):
        if item.url and item.url not in known_urls:
            known_urls.add(item.url)
            results.append(item)
    return results


def domain_lookup(domain: str) -> dict[str, list[str]]:
    import dns.resolver
    domain = domain.lower().strip().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"Invalid domain: {domain}")
    out: dict[str, list[str]] = {}
    for record in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=5)
            out[record] = [str(x).strip('"') for x in answers][:20]
        except Exception:
            out[record] = []
    return out


def search_email(email: str) -> list[Result]:
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError(f"Invalid email: {email}")
    results: list[Result] = []
    digest = hashlib.md5(email.encode()).hexdigest()
    try:
        avatar = f"https://www.gravatar.com/avatar/{digest}?d=404"
        r = safe_json_get(avatar)
        if r.status_code == 200:
            results.append(Result("Gravatar", "verified", "Public avatar exists for this exact email hash", f"https://gravatar.com/{digest}", "Gravatar returned an avatar for the exact normalized email hash.", 92))
    except requests.RequestException:
        pass
    domain = email.rsplit("@", 1)[1]
    try:
        dns = domain_lookup(domain)
        results.append(Result("Email domain", "verified", "Domain infrastructure resolved", "", "DNS records exist for the email domain; this does not verify the mailbox.", 80, dns))
    except ValueError:
        pass
    return results


def normalize_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    if digits.startswith("66") and len(digits) >= 10:
        return "+" + digits
    if digits.startswith("0") and len(digits) >= 9:
        return "+66" + digits[1:]
    return "+" + digits if phone.strip().startswith("+") else digits


def is_public_host(host: str) -> bool:
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False


def search_url(value: str) -> list[Result]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
        raise ValueError("Enter a public http/https URL.")
    try:
        r = SESSION.get(value, timeout=REQUEST_TIMEOUT, allow_redirects=True, stream=True)
        ctype = r.headers.get("content-type", "")
        details = {"http_status": r.status_code, "content_type": ctype, "final_url": r.url}
        return [Result("Web page", "verified" if r.status_code < 400 else "possible", "Direct URL checked", r.url, "Direct HTTP response received.", 90 if r.status_code < 400 else 40, details)]
    except requests.RequestException as exc:
        return [Result("Web page", "possible", "URL could not be reached", value, f"Network error: {type(exc).__name__}", 20)]


def search_domain(domain: str) -> list[Result]:
    info = domain_lookup(domain)
    found = any(info.values())
    return [Result("DNS", "verified" if found else "possible", "Public DNS lookup", "", "At least one DNS record resolved." if found else "No DNS records resolved.", 95 if found else 25, info)]


def perform_item(value: str, requested_type: str) -> dict[str, Any]:
    kind = infer_type(value) if requested_type == "auto" else requested_type
    query_value = value
    if kind == "username":
        query_value = value.lstrip("@").strip()
        findings = search_username(query_value)
    elif kind == "email":
        findings = search_email(value)
    elif kind == "domain":
        findings = search_domain(value)
    elif kind == "url":
        findings = search_url(value)
    elif kind == "phone":
        query_value = normalize_phone(value)
        findings = []
    elif kind in {"name", "thailand"}:
        findings = []
    else:
        raise ValueError(f"Unsupported search type: {kind}")

    verified = [r.to_dict() for r in findings if r.level == "verified"]
    possible = [r.to_dict() for r in findings if r.level == "possible"]
    manual = [r.to_dict() for r in manual_pivots(query_value, kind)]
    return {
        "query": query_value,
        "type": kind,
        "counts": {"verified": len(verified), "possible": len(possible), "manual": len(manual)},
        "verified": verified,
        "possible": possible,
        "manual": manual,
    }


HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SocioSential Strict OSINT</title><style>
:root{--bg:#06110e;--panel:#091713;--line:#21d8a6;--text:#ddfff6;--muted:#7fa99d;--red:#ff6969;--yellow:#f7c967;--blue:#83b8ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}main{max-width:980px;margin:auto;padding:22px}.brand{letter-spacing:.28em;color:var(--line);font-size:22px}.sub{color:var(--muted);line-height:1.5;margin:10px 0 22px}.panel{border:1px solid #17614f;background:var(--panel);padding:17px;margin:15px 0}select,textarea,button{width:100%;padding:14px;border:1px solid #2a715e;background:#06110e;color:var(--text);font:inherit}textarea{min-height:120px;resize:vertical}button{border-color:#b74242;color:#ff9999;margin-top:10px}.status{border-left:4px solid var(--line);padding:12px;margin-top:12px}.error{border-color:var(--red);color:#ffc0c0}.item{border:1px solid #1d604f;padding:14px;margin:15px 0}.summary{color:var(--muted);margin-bottom:12px}.card{border:1px solid #285f52;padding:12px;margin:9px 0;overflow-wrap:anywhere}.verified{border-color:var(--line)}.possible{border-color:var(--yellow)}.manual{border-color:var(--blue)}.badge{display:inline-block;padding:3px 7px;margin-right:8px;border:1px solid currentColor}.verified .badge{color:var(--line)}.possible .badge{color:var(--yellow)}.manual .badge{color:var(--blue)}a{color:#5ce6bf}.small{color:var(--muted);font-size:12px;line-height:1.45}.score{float:right}.privacy{font-size:12px;color:var(--muted);margin-top:8px}@media(max-width:650px){.brand{font-size:18px}}
</style></head><body><main>
<div class="brand">SOCIOSENTIAL STRICT OSINT</div>
<div class="sub">Precision first. Verified means a direct public endpoint returned an exact match. Sherlock hits remain “Possible” until independently confirmed.</div>
<div class="panel"><select id="type"><option value="auto">Auto detect</option><option value="username">Username</option><option value="email">Email</option><option value="name">Full name</option><option value="phone">Phone</option><option value="domain">Domain</option><option value="url">URL</option><option value="thailand">Thailand public sources</option></select>
<textarea id="query" placeholder="Up to 15 values. Separate with a new line, comma, semicolon, or *"></textarea><button id="go">SEARCH</button>
<div class="privacy">No search history is stored by the application. Public sources only. Manual search links are never counted as findings.</div><div id="status"></div></div><div id="results"></div>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function card(r,level){return `<div class="card ${level}"><span class="badge">${level.toUpperCase()}</span><b>${esc(r.source)} — ${esc(r.title)}</b>${r.score!=null?`<span class="score">${esc(r.score)}%</span>`:''}${r.url?`<div><a target="_blank" rel="noopener noreferrer" href="${esc(r.url)}">Open</a></div>`:''}${r.evidence?`<div class="small">${esc(r.evidence)}</div>`:''}${r.details?`<pre class="small">${esc(JSON.stringify(r.details,null,2))}</pre>`:''}</div>`}
function render(data){let h=`<div class="panel"><b>Version:</b> ${esc(data.version)} · <b>Items:</b> ${data.items.length}</div>`;for(const x of data.items){h+=`<div class="item"><h3>${esc(x.query)} <span class="small">(${esc(x.type)})</span></h3><div class="summary">Verified: ${x.counts.verified} · Possible: ${x.counts.possible} · Manual: ${x.counts.manual}</div>`;if(x.verified.length){h+='<h4>Verified findings</h4>'+x.verified.map(r=>card(r,'verified')).join('')}if(x.possible.length){h+='<h4>Possible leads</h4>'+x.possible.map(r=>card(r,'possible')).join('')}h+='<details><summary>Manual public-source pivots</summary>'+x.manual.map(r=>card(r,'manual')).join('')+'</details></div>'}$('#results').innerHTML=h}
$('#go').onclick=async()=>{const query=$('#query').value.trim();if(!query)return;$('#go').disabled=true;$('#status').innerHTML='<div class="status">Searching and verifying…</div>';$('#results').innerHTML='';try{const c=new AbortController();const t=setTimeout(()=>c.abort(),110000);const r=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query,type:$('#type').value}),signal:c.signal});clearTimeout(t);const d=await r.json();if(!r.ok)throw new Error(d.error||'Search failed');render(d);$('#status').innerHTML='<div class="status">Complete.</div>'}catch(e){$('#status').innerHTML=`<div class="status error">${esc(e.name==='AbortError'?'Timed out. Try fewer usernames.':e.message)}</div>`}finally{$('#go').disabled=false}};
</script></main></body></html>'''


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
    return response


@app.get("/")
def index():
    return HTML


@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": VERSION})


@app.post("/api/search")
def api_search():
    if rate_limited():
        return jsonify({"error": "Too many searches. Wait one minute and try again."}), 429
    payload = request.get_json(silent=True) or {}
    raw = str(payload.get("query", ""))[:5000]
    requested_type = str(payload.get("type", "auto")).lower()
    if requested_type not in {"auto", "username", "email", "name", "phone", "domain", "url", "thailand"}:
        return jsonify({"error": "Unsupported search type."}), 400
    try:
        values = split_items(raw)
        items = [perform_item(v, requested_type) for v in values]
        return jsonify({"version": VERSION, "items": items})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        # Do not leak query values or internal stack traces to the client.
        logger.exception("search failed: %s", type(exc).__name__)
        return jsonify({"error": "Search failed internally. Check Render logs."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
