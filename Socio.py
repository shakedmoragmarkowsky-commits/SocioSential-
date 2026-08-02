from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import quote, quote_plus, urlparse

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 48 * 1024
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sociosential")

VERSION = "6.0.0-evidence-graph"
MAX_ITEMS = 15
HTTP_TIMEOUT = 7
SHERLOCK_TIMEOUT = 55
MAX_SHERLOCK_VERIFY = 30
MAX_WMN_CHECKS = 80
MAX_PIVOTS = 10
RATE_WINDOW = 60
RATE_LIMIT = 10
JOB_TTL = 30 * 60

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()-]{6,24}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; SocioSential/6.0; public-source research)",
    "Accept-Language": "en-US,en;q=0.8,th;q=0.7",
})

_rate_lock = threading.Lock()
_rate: dict[str, list[float]] = {}
_jobs_lock = threading.Lock()
_jobs: dict[str, dict[str, Any]] = {}
_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, Any]] = {}
CACHE_TTL = 15 * 60
_WMN_CACHE: tuple[float, list[dict[str, Any]]] | None = None
WMN_URLS = [
    "https://raw.githubusercontent.com/Arcade-Project/WhatsMyName/main/wmn-data.json",
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
]
SOCIAL_HOSTS = {
    "github.com", "gitlab.com", "reddit.com", "www.reddit.com", "keybase.io",
    "dev.to", "chess.com", "www.chess.com", "t.me", "codeberg.org",
    "hub.docker.com", "scratch.mit.edu", "medium.com", "www.pinterest.com",
    "pinterest.com", "www.tiktok.com", "tiktok.com", "www.instagram.com",
    "instagram.com", "x.com", "www.facebook.com", "facebook.com",
}


@dataclass
class Finding:
    source: str
    level: str  # verified | strong_possible | possible | manual | info
    title: str
    url: str = ""
    evidence: str = ""
    score: int | None = None
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {k: v for k, v in data.items() if v not in (None, "", {})}


def _cache_get(key: str) -> Any | None:
    now = time.time()
    with _cache_lock:
        item = _cache.get(key)
        if not item:
            return None
        ts, value = item
        if now - ts > CACHE_TTL:
            _cache.pop(key, None)
            return None
        return value


def _cache_set(key: str, value: Any) -> None:
    with _cache_lock:
        _cache[key] = (time.time(), value)


def client_key() -> str:
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


def manual_pivots(value: str, kind: str) -> list[Finding]:
    pivots = [
        Finding("Google", "manual", "Exact web search", exact_search_url(value), "Search pivot only; never counted as a finding."),
        Finding("Bing", "manual", "Exact web search", "https://www.bing.com/search?q=" + quote_plus(f'"{value}"'), "Search pivot only; never counted as a finding."),
    ]
    if kind in {"username", "name", "phone", "email", "thailand"}:
        sources = [
            ("Facebook", "facebook.com"), ("Instagram", "instagram.com"),
            ("TikTok", "tiktok.com"), ("X", "x.com"),
            ("Threads", "threads.net"), ("YouTube", "youtube.com"),
            ("Pantip", "pantip.com"), ("ASEAN NOW", "aseannow.com"),
            ("TeakDoor", "teakdoor.com"), ("Thailand-247", "thailand-247.com"),
            ("Thaiger Talk", "thethaiger.com/talk"), ("Sanook", "sanook.com"),
            ("Kapook", "kapook.com"), ("MThai", "mthai.com"),
        ]
        for label, domain in sources:
            pivots.append(Finding(label, "manual", f"Search {label}", exact_search_url(value, domain), "Public indexed pages only; not counted as a match."))
        pivots.extend([
            Finding("LINE OpenChat", "manual", "Search public OpenChat", "https://openchat.line.me/th/search?q=" + quote_plus(value), "Public OpenChat only; private LINE accounts are not searchable."),
            Finding("WeChat public content", "manual", "Search indexed WeChat articles", exact_search_url(value, "mp.weixin.qq.com"), "Public indexed articles only; private WeChat accounts are not searchable."),
            Finding("Telegram", "manual", "Search public Telegram pages", exact_search_url(value, "t.me"), "Public pages only; attribution requires independent evidence."),
        ])
    return pivots


def get(url: str, **kwargs: Any) -> requests.Response:
    return SESSION.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    return SESSION.post(url, timeout=HTTP_TIMEOUT, allow_redirects=True, **kwargs)


def verified_result(source: str, username: str, url: str, evidence: str, details: dict[str, Any] | None = None, score: int = 98) -> Finding:
    return Finding(source, "verified", f"Exact public account exists for @{username}", url, evidence + " This confirms account existence, not the real-world owner's identity.", score, details)


def verify_github(username: str) -> Finding | None:
    r = get(f"https://api.github.com/users/{quote(username)}", headers={"Accept": "application/vnd.github+json"})
    if r.status_code == 200:
        d = r.json()
        if str(d.get("login", "")).casefold() == username.casefold():
            return verified_result("GitHub", username, d.get("html_url", ""), "GitHub's public API returned an exact username match.", {"name": d.get("name"), "bio": d.get("bio"), "location": d.get("location"), "created_at": d.get("created_at")})
    return None


def verify_reddit(username: str) -> Finding | None:
    r = get(f"https://www.reddit.com/user/{quote(username)}/about.json", headers={"Accept": "application/json"})
    if r.status_code == 200:
        d = r.json().get("data", {})
        if str(d.get("name", "")).casefold() == username.casefold():
            return verified_result("Reddit", username, f"https://www.reddit.com/user/{quote(username)}/", "Reddit's public JSON endpoint returned an exact username match.", {"created_utc": d.get("created_utc"), "total_karma": d.get("total_karma"), "is_suspended": d.get("is_suspended", False)})
    return None


def verify_gitlab(username: str) -> Finding | None:
    r = get("https://gitlab.com/api/v4/users", params={"username": username})
    if r.status_code == 200:
        for d in r.json():
            if str(d.get("username", "")).casefold() == username.casefold():
                return verified_result("GitLab", username, d.get("web_url", ""), "GitLab's public API returned an exact username match.", {"name": d.get("name"), "state": d.get("state")})
    return None


def verify_codeberg(username: str) -> Finding | None:
    r = get(f"https://codeberg.org/api/v1/users/{quote(username)}")
    if r.status_code == 200:
        d = r.json()
        if str(d.get("login", "")).casefold() == username.casefold():
            return verified_result("Codeberg", username, d.get("html_url", f"https://codeberg.org/{quote(username)}"), "Codeberg's public API returned an exact username match.", {"full_name": d.get("full_name"), "location": d.get("location")})
    return None


def verify_keybase(username: str) -> Finding | None:
    r = get("https://keybase.io/_/api/1.0/user/lookup.json", params={"usernames": username})
    if r.status_code == 200:
        for person in r.json().get("them") or []:
            name = ((person.get("basics") or {}).get("username") or "")
            if name.casefold() == username.casefold():
                return verified_result("Keybase", username, f"https://keybase.io/{quote(username)}", "Keybase's public API returned an exact username match.")
    return None


def verify_hackernews(username: str) -> Finding | None:
    r = get(f"https://hacker-news.firebaseio.com/v0/user/{quote(username)}.json")
    if r.status_code == 200 and r.text.strip() not in {"null", ""}:
        d = r.json()
        if str(d.get("id", "")).casefold() == username.casefold():
            return verified_result("Hacker News", username, f"https://news.ycombinator.com/user?id={quote_plus(username)}", "Hacker News' public Firebase API returned an exact username match.", {"created": d.get("created"), "karma": d.get("karma"), "about": d.get("about")})
    return None


def verify_devto(username: str) -> Finding | None:
    r = get("https://dev.to/api/users/by_username", params={"url": username})
    if r.status_code == 200:
        d = r.json()
        if str(d.get("username", "")).casefold() == username.casefold():
            return verified_result("DEV Community", username, f"https://dev.to/{quote(username)}", "DEV's public API returned an exact username match.", {"name": d.get("name"), "summary": d.get("summary"), "location": d.get("location")})
    return None


def verify_chesscom(username: str) -> Finding | None:
    r = get(f"https://api.chess.com/pub/player/{quote(username)}")
    if r.status_code == 200:
        d = r.json()
        if str(d.get("username", "")).casefold() == username.casefold():
            return verified_result("Chess.com", username, d.get("url", f"https://www.chess.com/member/{quote(username)}"), "Chess.com's public API returned an exact username match.", {"name": d.get("name"), "location": d.get("location"), "joined": d.get("joined"), "status": d.get("status")})
    return None


def verify_dockerhub(username: str) -> Finding | None:
    r = get(f"https://hub.docker.com/v2/users/{quote(username)}/")
    if r.status_code == 200:
        d = r.json()
        if str(d.get("username", "")).casefold() == username.casefold():
            return verified_result("Docker Hub", username, f"https://hub.docker.com/u/{quote(username)}", "Docker Hub's public API returned an exact username match.", {"full_name": d.get("full_name"), "location": d.get("location"), "date_joined": d.get("date_joined")})
    return None


def verify_scratch(username: str) -> Finding | None:
    r = get(f"https://api.scratch.mit.edu/users/{quote(username)}")
    if r.status_code == 200:
        d = r.json()
        if str(d.get("username", "")).casefold() == username.casefold():
            return verified_result("Scratch", username, f"https://scratch.mit.edu/users/{quote(username)}/", "Scratch's public API returned an exact username match.", {"joined": d.get("history", {}).get("joined"), "country": d.get("profile", {}).get("country"), "bio": d.get("profile", {}).get("bio")})
    return None


DIRECT_ADAPTERS: list[Callable[[str], Finding | None]] = [
    verify_github, verify_reddit, verify_gitlab, verify_codeberg, verify_keybase,
    verify_hackernews, verify_devto, verify_chesscom, verify_dockerhub, verify_scratch,
]


def run_direct_adapters(username: str) -> list[Finding]:
    results: list[Finding] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(fn, username): fn.__name__ for fn in DIRECT_ADAPTERS}
        for future in as_completed(futures):
            try:
                item = future.result()
                if item:
                    results.append(item)
            except (requests.RequestException, ValueError, json.JSONDecodeError):
                continue
            except Exception as exc:
                logger.info("adapter %s unavailable: %s", futures[future], type(exc).__name__)
    return sorted(results, key=lambda x: x.source.casefold())


def telegram_possible(username: str) -> Finding | None:
    try:
        url = f"https://t.me/{quote(username)}"
        r = get(url)
        text = r.text[:250000]
        if r.status_code == 200 and "tgme_page" in text and username.casefold() in text.casefold():
            return Finding("Telegram", "possible", "Public Telegram page appears to exist", url, "The page contains the exact handle, but Telegram pages can be ambiguous and do not prove identity.", 62)
    except requests.RequestException:
        pass
    return None


def run_sherlock(username: str) -> list[tuple[str, str]]:
    if os.getenv("ENABLE_SHERLOCK", "1") != "1":
        return []
    commands = [
        ["sherlock", username, "--print-found", "--no-color", "--timeout", "5"],
        ["python", "-m", "sherlock_project", username, "--print-found", "--no-color", "--timeout", "5"],
    ]
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SHERLOCK_TIMEOUT, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            m = re.search(r"(?:\[\+\]|\+)?\s*([^:]{1,80}):\s*(https?://\S+)", line)
            if not m:
                continue
            source = re.sub(r"^[^A-Za-z0-9]+", "", m.group(1)).strip() or "Sherlock"
            url = m.group(2).rstrip(".,);]")
            if url not in seen:
                seen.add(url)
                found.append((source, url))
        if found or proc.returncode == 0:
            return found[:MAX_SHERLOCK_VERIFY]
    return []


def _wmn_sites() -> list[dict[str, Any]]:
    """Load WhatsMyName's public site definition database with a short in-memory cache."""
    global _WMN_CACHE
    now = time.time()
    if _WMN_CACHE and now - _WMN_CACHE[0] < 6 * 60 * 60:
        return _WMN_CACHE[1]
    for url in WMN_URLS:
        try:
            r = get(url)
            if r.status_code != 200:
                continue
            data = r.json()
            sites = data.get("sites") if isinstance(data, dict) else data
            if isinstance(sites, list) and sites:
                _WMN_CACHE = (now, sites)
                return sites
        except Exception as exc:
            logger.info("WhatsMyName database unavailable: %s", type(exc).__name__)
    return []


def _wmn_site_url(site: dict[str, Any], username: str) -> str:
    template = str(site.get("uri_check") or site.get("uri") or site.get("url") or "")
    for token in ("{account}", "{username}", "{}"):
        template = template.replace(token, quote(username))
    return template


def _wmn_match(site: dict[str, Any], response: requests.Response) -> bool:
    text = response.text[:250000]
    status = response.status_code
    expected_code = site.get("e_code")
    missing_code = site.get("m_code")
    expected = str(site.get("e_string") or "")
    missing = str(site.get("m_string") or "")
    if missing_code not in (None, "") and status == int(missing_code):
        return False
    if missing and missing in text:
        return False
    if expected_code not in (None, "") and status != int(expected_code):
        return False
    if expected and expected not in text:
        return False
    return status < 400 and bool(expected or expected_code not in (None, ""))


def run_whatsmyname(username: str) -> list[tuple[str, str]]:
    sites = _wmn_sites()[:MAX_WMN_CHECKS]
    if not sites:
        return []
    def check(site: dict[str, Any]) -> tuple[str, str] | None:
        url = _wmn_site_url(site, username)
        if not url.startswith(("http://", "https://")):
            return None
        try:
            r = get(url)
            if _wmn_match(site, r):
                return str(site.get("name") or site.get("site") or "WhatsMyName"), r.url
        except Exception:
            return None
        return None
    found=[]
    seen=set()
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures=[pool.submit(check, site) for site in sites]
        for future in as_completed(futures):
            item=future.result()
            if item and item[1] not in seen:
                seen.add(item[1]); found.append(item)
    return found


def extract_public_pivots(findings: list[Finding], original_username: str) -> list[tuple[str, str, str]]:
    """Extract a small number of public cross-profile links from confirmed pages."""
    pivots=[]
    seen=set()
    href_re=re.compile(r'href=["\'](https?://[^"\']+)', re.I)
    for finding in findings:
        if not finding.url or finding.level not in {"verified", "strong_possible"}:
            continue
        try:
            r=get(finding.url)
            if r.status_code != 200 or "text/html" not in r.headers.get("content-type", "").lower():
                continue
            for href in href_re.findall(r.text[:350000]):
                parsed=urlparse(href)
                host=(parsed.hostname or "").lower()
                if host not in SOCIAL_HOSTS or href in seen:
                    continue
                parts=[x for x in parsed.path.split("/") if x]
                candidate=(parts[-1] if parts else "").lstrip("@").strip()
                if candidate and USERNAME_RE.fullmatch(candidate) and candidate.casefold()!=original_username.casefold():
                    seen.add(href); pivots.append((finding.source, href, candidate))
                    if len(pivots)>=MAX_PIVOTS:
                        return pivots
        except requests.RequestException:
            continue
    return pivots


BLOCK_MARKERS = [
    "cloudflare", "captcha", "access denied", "403 forbidden", "bot protection",
    "sign in to continue", "login required", "page not found", "not found",
]


def verify_discovery_page(source: str, url: str, username: str) -> Finding | None:
    try:
        r = get(url)
        if r.status_code != 200:
            return None
        ctype = r.headers.get("content-type", "").lower()
        if "text/html" not in ctype:
            return None
        text = r.text[:300000]
        low = text.casefold()
        if any(marker in low for marker in BLOCK_MARKERS):
            return None
        parsed = urlparse(r.url)
        path_signal = username.casefold() in parsed.path.casefold()
        content_signal = re.search(rf"(?<![A-Za-z0-9._-]){re.escape(username)}(?![A-Za-z0-9._-])", text, re.I) is not None
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:180] if title_match else ""
        if path_signal and content_signal:
            return Finding(source, "strong_possible", "Public profile page passed two checks", r.url, "The final URL path and page content both contain the exact handle. This is strong evidence of account existence, but not identity ownership.", 76, {"page_title": title})
        if path_signal or content_signal:
            return Finding(source, "possible", "Public page contains one exact-handle signal", r.url, "One exact-handle signal was observed. Manual review is required.", 52, {"page_title": title})
    except requests.RequestException:
        return None
    return None


def verify_candidate_hits(username: str, direct_urls: set[str]) -> list[Finding]:
    engine_hits: list[tuple[str, str, str]] = []
    for source, url in run_sherlock(username):
        engine_hits.append(("Sherlock", source, url))
    for source, url in run_whatsmyname(username):
        engine_hits.append(("WhatsMyName", source, url))
    unique: dict[str, tuple[str, str]] = {}
    for engine, source, url in engine_hits:
        if url not in direct_urls and url not in unique:
            unique[url] = (engine, source)
    candidates=list(unique.items())[:MAX_SHERLOCK_VERIFY + MAX_WMN_CHECKS]
    results: list[Finding] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures={pool.submit(verify_discovery_page, source, url, username):(engine,source,url) for url,(engine,source) in candidates}
        for future in as_completed(futures):
            engine, source, url=futures[future]
            try:
                item=future.result()
                if item:
                    item.details = {**(item.details or {}), "discovery_engine": engine}
                    results.append(item)
                else:
                    results.append(Finding(source, "possible", f"{engine} candidate requires manual review", url, f"{engine} reported this public account URL, but independent page verification was blocked or inconclusive.", 28, {"discovery_engine": engine}))
            except Exception:
                continue
    dedup={}
    for item in results:
        dedup[item.url or (item.source+item.title)] = item
    return sorted(dedup.values(), key=lambda x:(0 if x.level=="strong_possible" else 1, -(x.score or 0), x.source.casefold()))

def cross_source_summary(username: str, verified: list[Finding], strong: list[Finding]) -> Finding | None:
    if len(verified) >= 2:
        return Finding("Cross-source", "info", "Exact handle confirmed on multiple independent public services", "", f"The exact handle @{username} exists on {len(verified)} direct-API sources. This supports handle reuse, not common ownership.", min(95, 72 + len(verified) * 5), {"verified_sources": [x.source for x in verified]})
    if len(verified) == 1 and strong:
        return Finding("Cross-source", "info", "One direct confirmation plus additional page evidence", "", "One source confirmed the exact account through a public API and at least one additional page passed two handle checks. Ownership still requires contextual evidence.", 78, {"verified_source": verified[0].source, "supporting_sources": [x.source for x in strong[:5]]})
    return None


def search_username(username: str, progress: Callable[[str], None] | None = None) -> list[Finding]:
    username = username.strip().lstrip("@")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError(f"Invalid username: {username}")
    key = "username-v6:" + username.casefold()
    cached = _cache_get(key)
    if cached is not None:
        return [Finding(**x) for x in cached]
    if progress:
        progress(f"Direct API checks for @{username}")
    verified = run_direct_adapters(username)
    direct_urls = {x.url for x in verified if x.url}
    if progress:
        progress(f"Sherlock + WhatsMyName discovery for @{username}")
    candidates = verify_candidate_hits(username, direct_urls)
    telegram = telegram_possible(username)
    if telegram and telegram.url not in direct_urls:
        candidates.append(telegram)
    strong = [x for x in candidates if x.level == "strong_possible"]
    summary = cross_source_summary(username, verified, strong)
    findings = verified + ([summary] if summary else []) + candidates
    if progress:
        progress(f"Second-hop public pivot analysis for @{username}")
    for parent, url, discovered in extract_public_pivots(verified + strong, username):
        findings.append(Finding("Evidence graph", "info", f"Public linked handle discovered: @{discovered}", url, f"A public link from {parent} points to another social profile. This is a pivot lead, not proof of common ownership.", 55, {"parent_source": parent, "discovered_username": discovered}))
    dedup={}
    for item in findings:
        dedup[(item.url or item.source+item.title, item.level)] = item
    findings=list(dedup.values())
    _cache_set(key, [x.to_dict() for x in findings])
    return findings

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


def search_email(email: str) -> list[Finding]:
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError(f"Invalid email: {email}")
    results: list[Finding] = []
    digest = hashlib.md5(email.encode()).hexdigest()
    try:
        avatar = f"https://www.gravatar.com/avatar/{digest}?d=404"
        r = get(avatar)
        if r.status_code == 200:
            results.append(Finding("Gravatar", "verified", "Public avatar exists for this exact email hash", f"https://gravatar.com/{digest}", "Gravatar returned an avatar for the exact normalized email hash. This confirms a public Gravatar association, not identity ownership.", 92))
    except requests.RequestException:
        pass
    domain = email.rsplit("@", 1)[1]
    dns = domain_lookup(domain)
    if any(dns.values()):
        results.append(Finding("Email domain", "info", "Email domain has public DNS infrastructure", "", "DNS infrastructure exists for the domain. This does not verify the mailbox.", 60, dns))
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


def search_url(value: str) -> list[Finding]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
        raise ValueError("Enter a public http/https URL.")
    try:
        r = SESSION.get(value, timeout=HTTP_TIMEOUT, allow_redirects=True, stream=True)
        ctype = r.headers.get("content-type", "")
        details = {"http_status": r.status_code, "content_type": ctype, "final_url": r.url}
        level = "verified" if r.status_code < 400 else "possible"
        return [Finding("Web page", level, "Direct URL checked", r.url, "A direct HTTP response was received. This verifies URL reachability only.", 90 if r.status_code < 400 else 35, details)]
    except requests.RequestException as exc:
        return [Finding("Web page", "possible", "URL could not be reached", value, f"Network error: {type(exc).__name__}", 15)]


def search_domain(domain: str) -> list[Finding]:
    info = domain_lookup(domain)
    found = any(info.values())
    return [Finding("DNS", "verified" if found else "possible", "Public DNS lookup", "", "At least one DNS record resolved." if found else "No DNS records resolved.", 95 if found else 20, info)]


def perform_item(value: str, requested_type: str, progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    kind = infer_type(value) if requested_type == "auto" else requested_type
    query_value = value
    if kind == "username":
        query_value = value.lstrip("@").strip()
        findings = search_username(query_value, progress)
    elif kind == "email":
        findings = search_email(value)
    elif kind == "domain":
        findings = search_domain(value)
    elif kind == "url":
        findings = search_url(value)
    elif kind == "phone":
        query_value = normalize_phone(value)
        findings = [Finding("Phone search", "info", "No reliable free direct lookup is enabled", "", "Phone-number identity lookup cannot be verified reliably from free public endpoints. No search-engine links are shown as results.", 0)]
    elif kind in {"name", "thailand"}:
        findings = [Finding("Name search", "info", "No reliable free direct lookup is enabled", "", "A name alone is too ambiguous for automatic verification. No search-engine links are shown as results. Use known usernames for real account checks.", 0)]
    else:
        raise ValueError(f"Unsupported search type: {kind}")

    levels = {"verified": [], "strong_possible": [], "possible": [], "manual": [], "info": []}
    for item in findings:
        levels.setdefault(item.level, []).append(item.to_dict())
    levels["manual"] = [r.to_dict() for r in manual_pivots(query_value, kind)] if os.getenv("SHOW_MANUAL_LINKS", "0") == "1" else []
    counts = {k: len(v) for k, v in levels.items()}
    return {"query": query_value, "type": kind, "counts": counts, **levels}


def update_job(job_id: str, **changes: Any) -> None:
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(changes)
            _jobs[job_id]["updated_at"] = time.time()


def cleanup_jobs() -> None:
    cutoff = time.time() - JOB_TTL
    with _jobs_lock:
        for job_id in list(_jobs):
            if _jobs[job_id].get("updated_at", 0) < cutoff:
                _jobs.pop(job_id, None)


def run_job(job_id: str, values: list[str], requested_type: str) -> None:
    try:
        items: list[dict[str, Any]] = []
        total = len(values)
        for idx, value in enumerate(values, 1):
            update_job(job_id, status="running", progress=round((idx - 1) / total * 100), message=f"Processing {idx}/{total}: {value}")
            def progress(message: str) -> None:
                update_job(job_id, message=message)
            items.append(perform_item(value, requested_type, progress))
        result = {"version": VERSION, "items": items, "disclaimer": "Public-source evidence only. Account existence and real-world identity are separate questions."}
        update_job(job_id, status="complete", progress=100, message="Complete", result=result)
    except ValueError as exc:
        update_job(job_id, status="error", error=str(exc), progress=100)
    except Exception as exc:
        logger.exception("job failed: %s", type(exc).__name__)
        update_job(job_id, status="error", error="Search failed internally. Check Render logs.", progress=100)


HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SocioSential Evidence OSINT</title><style>
:root{--bg:#06110e;--panel:#091713;--line:#21d8a6;--text:#ddfff6;--muted:#7fa99d;--red:#ff6969;--yellow:#f7c967;--blue:#83b8ff;--violet:#c19cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}main{max-width:1050px;margin:auto;padding:22px}.brand{letter-spacing:.22em;color:var(--line);font-size:22px}.sub{color:var(--muted);line-height:1.5;margin:10px 0 22px}.panel{border:1px solid #17614f;background:var(--panel);padding:17px;margin:15px 0}select,textarea,button{width:100%;padding:14px;border:1px solid #2a715e;background:#06110e;color:var(--text);font:inherit}textarea{min-height:125px;resize:vertical}button{border-color:#b74242;color:#ff9999;margin-top:10px}.status{border-left:4px solid var(--line);padding:12px;margin-top:12px}.error{border-color:var(--red);color:#ffc0c0}.bar{height:8px;background:#15352d;margin-top:8px}.bar>div{height:100%;background:var(--line);width:0}.item{border:1px solid #1d604f;padding:14px;margin:15px 0}.summary{color:var(--muted);margin-bottom:12px}.card{border:1px solid #285f52;padding:12px;margin:9px 0;overflow-wrap:anywhere}.verified{border-color:var(--line)}.strong_possible{border-color:var(--violet)}.possible{border-color:var(--yellow)}.manual{border-color:var(--blue)}.info{border-color:#7ea89c}.badge{display:inline-block;padding:3px 7px;margin-right:8px;border:1px solid currentColor}.verified .badge{color:var(--line)}.strong_possible .badge{color:var(--violet)}.possible .badge{color:var(--yellow)}.manual .badge{color:var(--blue)}.info .badge{color:#aacbc1}a{color:#5ce6bf}.small{color:var(--muted);font-size:12px;line-height:1.45}.score{float:right}.privacy{font-size:12px;color:var(--muted);margin-top:8px}.actions{display:flex;gap:10px}.actions button{width:auto;flex:1}@media(max-width:650px){.brand{font-size:18px}.actions{display:block}}
</style></head><body><main>
<div class="brand">SOCIOSENTIAL EVIDENCE GRAPH</div>
<div class="sub">Multi-engine public-source discovery: direct APIs, Sherlock, WhatsMyName, strict page verification, and limited second-hop pivots. Search links never count as findings.</div>
<div class="panel"><select id="type"><option value="auto">Auto detect</option><option value="username">Username</option><option value="email">Email</option><option value="name">Full name</option><option value="phone">Phone</option><option value="domain">Domain</option><option value="url">URL</option><option value="thailand">Thailand public sources</option></select>
<textarea id="query" placeholder="Up to 15 values. Separate with a new line, comma, semicolon, or *"></textarea><button id="go">SEARCH</button>
<div class="privacy">No search history is intentionally persisted by the application. Public sources only. Verified means an exact account exists on that service—not proof that multiple accounts belong to the same person.</div><div id="status"></div></div><div id="results"></div>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let lastData=null;
function card(r,level){return `<div class="card ${level}"><span class="badge">${level.replace('_',' ').toUpperCase()}</span><b>${esc(r.source)} — ${esc(r.title)}</b>${r.score!=null?`<span class="score">${esc(r.score)}%</span>`:''}${r.url?`<div><a target="_blank" rel="noopener noreferrer" href="${esc(r.url)}">Open</a></div>`:''}${r.evidence?`<div class="small">${esc(r.evidence)}</div>`:''}${r.details?`<pre class="small">${esc(JSON.stringify(r.details,null,2))}</pre>`:''}</div>`}
function section(title,arr,level){return arr?.length?`<h4>${title}</h4>${arr.map(r=>card(r,level)).join('')}`:''}
function render(data){lastData=data;let h=`<div class="panel"><b>Version:</b> ${esc(data.version)} · <b>Items:</b> ${data.items.length}<div class="small">${esc(data.disclaimer||'')}</div><div class="actions"><button onclick="downloadJSON()">EXPORT JSON</button><button onclick="downloadCSV()">EXPORT CSV</button></div></div>`;for(const x of data.items){h+=`<div class="item"><h3>${esc(x.query)} <span class="small">(${esc(x.type)})</span></h3><div class="summary">Verified: ${x.counts.verified||0} · Strong possible: ${x.counts.strong_possible||0} · Possible: ${x.counts.possible||0} · Manual: ${x.counts.manual||0}</div>`;h+=section('Verified account existence',x.verified,'verified');h+=section('Cross-source information',x.info,'info');h+=section('Strong possible leads',x.strong_possible,'strong_possible');h+=section('Possible leads',x.possible,'possible');h+=`<details><summary>Manual public-source pivots (${x.manual.length})</summary>${x.manual.map(r=>card(r,'manual')).join('')}</details></div>`}$('#results').innerHTML=h}
function download(name,text,type){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function downloadJSON(){if(lastData)download('sociosential-results.json',JSON.stringify(lastData,null,2),'application/json')}
function downloadCSV(){if(!lastData)return;const rows=[['query','type','level','source','title','url','score','evidence']];for(const x of lastData.items){for(const level of ['verified','info','strong_possible','possible','manual'])for(const r of x[level]||[])rows.push([x.query,x.type,level,r.source||'',r.title||'',r.url||'',r.score??'',r.evidence||''])}const csv=rows.map(row=>row.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(',')).join('\n');download('sociosential-results.csv',csv,'text/csv')}
async function poll(id){for(let i=0;i<240;i++){const r=await fetch('/api/jobs/'+id);const d=await r.json();if(!r.ok)throw new Error(d.error||'Job failed');$('#status').innerHTML=`<div class="status">${esc(d.message||d.status)}<div class="bar"><div style="width:${d.progress||0}%"></div></div></div>`;if(d.status==='complete'){render(d.result);$('#status').innerHTML='<div class="status">Complete.</div>';return}if(d.status==='error')throw new Error(d.error||'Search failed');await new Promise(x=>setTimeout(x,1000))}throw new Error('Search took too long. Try fewer values.')}
$('#go').onclick=async()=>{const query=$('#query').value.trim();if(!query)return;$('#go').disabled=true;$('#status').innerHTML='<div class="status">Starting…</div>';$('#results').innerHTML='';try{const r=await fetch('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query,type:$('#type').value})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not start search');await poll(d.job_id)}catch(e){$('#status').innerHTML=`<div class="status error">${esc(e.message)}</div>`}finally{$('#go').disabled=false}};
</script></main></body></html>'''


@app.after_request
def security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
    return response


@app.get("/")
def index() -> str:
    return HTML


@app.get("/health")
def health() -> Response:
    return jsonify({"status": "ok", "version": VERSION, "sherlock_enabled": os.getenv("ENABLE_SHERLOCK", "1") == "1", "whatsmyname_enabled": True, "mode": "evidence-graph"})


@app.post("/api/jobs")
def create_job() -> Response:
    cleanup_jobs()
    if rate_limited():
        return jsonify({"error": "Too many searches. Wait one minute and try again."}), 429
    payload = request.get_json(silent=True) or {}
    raw = str(payload.get("query", ""))[:5000]
    requested_type = str(payload.get("type", "auto")).lower()
    if requested_type not in {"auto", "username", "email", "name", "phone", "domain", "url", "thailand"}:
        return jsonify({"error": "Unsupported search type."}), 400
    try:
        values = split_items(raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {"status": "queued", "progress": 0, "message": "Queued", "created_at": time.time(), "updated_at": time.time()}
    threading.Thread(target=run_job, args=(job_id, values, requested_type), daemon=True).start()
    return jsonify({"job_id": job_id, "status": "queued"}), 202


@app.get("/api/jobs/<job_id>")
def get_job(job_id: str) -> Response:
    cleanup_jobs()
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found or expired."}), 404
        return jsonify({k: v for k, v in job.items() if k not in {"created_at", "updated_at"}})


@app.post("/api/search")
def api_search_compat() -> Response:
    """Compatibility endpoint for older frontends. Runs synchronously for small non-username searches."""
    if rate_limited():
        return jsonify({"error": "Too many searches. Wait one minute and try again."}), 429
    payload = request.get_json(silent=True) or {}
    raw = str(payload.get("query", ""))[:5000]
    requested_type = str(payload.get("type", "auto")).lower()
    try:
        values = split_items(raw)
        items = [perform_item(v, requested_type) for v in values]
        return jsonify({"version": VERSION, "items": items, "disclaimer": "Public-source evidence only."})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.exception("search failed: %s", type(exc).__name__)
        return jsonify({"error": "Search failed internally. Check Render logs."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
