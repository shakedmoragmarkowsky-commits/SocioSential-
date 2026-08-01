import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
from html import escape
from urllib.parse import quote_plus, urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sociosential")

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SocioSential OSINT</title>
<style>
:root{--bg:#07110f;--panel:#0b1815;--line:#16d7a2;--text:#d9fff4;--muted:#76a99b;--warn:#ffbd59}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
main{max-width:980px;margin:auto;padding:24px}.brand{letter-spacing:.35em;color:var(--line);font-size:22px}.sub{color:var(--muted);margin:10px 0 24px}
.panel{border:1px solid #17624f;background:var(--panel);padding:18px;margin:16px 0}.row{display:grid;grid-template-columns:150px 1fr 130px;gap:10px}
select,input,button{width:100%;padding:14px;border:1px solid #26755f;background:#06100e;color:var(--text);font:inherit}button{border-color:#bb3d3d;color:#ff8e8e;cursor:pointer}button:disabled{opacity:.5}
.small{font-size:12px;color:var(--muted)}.status{padding:12px;border-left:3px solid var(--line);margin-top:12px}.error{border-color:#ff6363;color:#ffb2b2}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.card{border:1px solid #1b5a4b;padding:14px;overflow-wrap:anywhere}
a{color:#51e8bd}.badge{display:inline-block;padding:3px 7px;border:1px solid #2a765f;margin:2px;font-size:12px}.warn{color:var(--warn)}
@media(max-width:700px){.row{grid-template-columns:1fr}.brand{font-size:18px}}
</style></head><body><main>
<div class="brand">SOCIOSENTIAL OSINT</div><div class="sub">Public-source discovery. No X login, cookies, or API keys required.</div>
<div class="panel"><div class="row">
<select id="type"><option value="auto">Auto detect</option><option value="username">Username</option><option value="email">Email</option><option value="name">Full name</option><option value="domain">Domain</option><option value="url">URL</option></select>
<input id="query" placeholder="username, email, name, domain or URL" autocomplete="off">
<button id="go">SEARCH</button></div>
<div class="small" style="margin-top:10px">Only public data and availability signals are checked. Results are leads, not identity proof.</div><div id="status"></div></div>
<div id="results"></div>
<script>
const q=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function link(url,label){return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label||url)}</a>`}
function render(data){let h=`<div class="panel"><b>TYPE:</b> ${esc(data.type)} &nbsp; <b>QUERY:</b> ${esc(data.query)}</div>`;
if(data.summary)h+=`<div class="panel">${esc(data.summary)}</div>`;
if(data.results?.length){h+=`<div class="grid">`;for(const r of data.results){h+=`<div class="card"><b>${esc(r.platform||r.kind||r.name||'Result')}</b><br>`+(r.url?link(r.url,r.url):'')+(r.status?`<div class="small">${esc(r.status)}</div>`:'')+(r.details?`<pre class="small">${esc(JSON.stringify(r.details,null,2))}</pre>`:'')+`</div>`}h+=`</div>`}
if(data.search_links?.length){h+=`<div class="panel"><b>SEARCH LINKS</b><div class="grid">`;for(const r of data.search_links)h+=`<div class="card">${link(r.url,r.name)}</div>`;h+=`</div></div>`}
if(data.warnings?.length)h+=`<div class="panel warn">${data.warnings.map(esc).join('<br>')}</div>`;q('#results').innerHTML=h}
q('#go').onclick=async()=>{const query=q('#query').value.trim();if(!query)return;q('#go').disabled=true;q('#status').innerHTML='<div class="status">Searching public sources…</div>';q('#results').innerHTML='';try{const c=new AbortController();const t=setTimeout(()=>c.abort(),55000);const r=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query,type:q('#type').value}),signal:c.signal});clearTimeout(t);const d=await r.json();if(!r.ok)throw new Error(d.error||'Search failed');render(d);q('#status').innerHTML='<div class="status">Search complete.</div>'}catch(e){q('#status').innerHTML=`<div class="status error">${esc(e.name==='AbortError'?'Search timed out. Try again or use a narrower query.':e.message)}</div>`}finally{q('#go').disabled=false}};
q('#query').addEventListener('keydown',e=>{if(e.key==='Enter')q('#go').click()});
</script></main></body></html>'''


def infer_type(value: str) -> str:
    if EMAIL_RE.fullmatch(value):
        return "email"
    if value.startswith(("http://", "https://")):
        return "url"
    if " " in value.strip():
        return "name"
    if "." in value and not value.startswith("@") and value.count(".") >= 1:
        try:
            socket.getaddrinfo(value, None)
            return "domain"
        except Exception:
            pass
    return "username"


def common_search_links(query: str, kind: str):
    encoded = quote_plus(query)
    links = [
        {"name": "Google exact search", "url": f"https://www.google.com/search?q=%22{encoded}%22"},
        {"name": "Bing exact search", "url": f"https://www.bing.com/search?q=%22{encoded}%22"},
        {"name": "GitHub search", "url": f"https://github.com/search?q={encoded}&type=users"},
    ]
    if kind == "name":
        links += [
            {"name": "LinkedIn public search", "url": f"https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22{encoded}%22"},
            {"name": "Social profiles search", "url": f"https://www.google.com/search?q=%22{encoded}%22+(site%3Ax.com+OR+site%3Ainstagram.com+OR+site%3Afacebook.com+OR+site%3Atiktok.com)"},
        ]
    return links


def search_username(username: str):
    username = username.lstrip("@").strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Use a username only: letters, numbers, dot, dash, or underscore.")
    from maigret import search as maigret_search
    from maigret.sites import MaigretDatabase
    import maigret as maigret_package

    db_path = os.path.join(os.path.dirname(maigret_package.__file__), "resources", "data.json")
    db = MaigretDatabase().load_from_path(db_path)
    top = max(10, min(int(os.getenv("MAIGRET_TOP_SITES", "40")), 100))
    sites = db.ranked_sites_dict(top=top, excluded_tags=["nsfw", "dating"])

    raw = asyncio.run(maigret_search(
        username=username,
        site_dict=sites,
        logger=logging.getLogger("maigret"),
        timeout=5,
        is_parsing_enabled=False,
        max_connections=20,
        no_progressbar=True,
        retries=0,
    ))
    found = []
    for site, item in raw.items():
        if not item:
            continue
        status = item.get("status")
        try:
            is_found = bool(status and status.is_found())
        except Exception:
            is_found = False
        if is_found:
            found.append({
                "platform": site,
                "url": item.get("url_user") or "",
                "status": "Public profile match",
                "details": {"http_status": item.get("http_status")},
            })
    found.sort(key=lambda x: x["platform"].lower())
    return {
        "type": "username", "query": username,
        "summary": f"Found {len(found)} public profile matches across {len(sites)} major sites.",
        "results": found,
        "search_links": common_search_links(username, "username"),
        "warnings": ["Some sites may block cloud-hosted scanners. Missing results do not prove an account does not exist."],
    }


def search_email(email: str):
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Enter a valid email address.")
    local, domain = email.rsplit("@", 1)
    results = []

    # Gravatar is deterministic public metadata; a 200 response means an avatar exists.
    digest = hashlib.md5(email.encode("utf-8")).hexdigest()
    gravatar = f"https://www.gravatar.com/avatar/{digest}?d=404"
    try:
        r = requests.get(gravatar, timeout=6, allow_redirects=True)
        if r.status_code == 200:
            results.append({"platform": "Gravatar", "url": f"https://gravatar.com/{digest}", "status": "Public avatar found"})
    except requests.RequestException:
        pass

    # Socialscan provides public availability signals; failures are isolated.
    try:
        from socialscan.util import sync_execute_queries
        scan = sync_execute_queries([email])
        for item in scan:
            if getattr(item, "success", False):
                available = getattr(item, "available", None)
                status = "Appears registered/taken" if available is False else "Appears available" if available is True else getattr(item, "message", "Checked")
                results.append({"platform": str(getattr(item, "platform", "Platform")), "status": status})
    except Exception as exc:
        logger.warning("socialscan unavailable: %s", exc)

    dns_info = domain_lookup(domain)
    results.append({"platform": "Email domain", "status": domain, "details": dns_info})
    return {
        "type": "email", "query": email,
        "summary": f"Checked public avatar, registration-availability signals, and domain infrastructure for {email}.",
        "results": results,
        "search_links": common_search_links(email, "email") + [
            {"name": "Search username portion", "url": f"/?type=username&query={quote_plus(local)}"}
        ],
        "warnings": ["Registration signals can be wrong or rate-limited and do not prove who controls an account.", "Use only for lawful, authorized investigations."],
    }


def domain_lookup(domain: str):
    domain = domain.strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", domain):
        raise ValueError("Enter a valid domain.")
    import dns.resolver
    out = {}
    for record in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=5)
            out[record] = [str(x).strip('"') for x in answers][:20]
        except Exception:
            out[record] = []
    return out


def search_domain(domain: str):
    info = domain_lookup(domain)
    return {
        "type": "domain", "query": domain,
        "summary": "Public DNS records retrieved.",
        "results": [{"platform": "DNS", "status": "Resolved", "details": info}],
        "search_links": common_search_links(domain, "domain") + [
            {"name": "crt.sh certificates", "url": f"https://crt.sh/?q=%25.{quote_plus(domain)}"},
            {"name": "VirusTotal domain page", "url": f"https://www.virustotal.com/gui/domain/{quote_plus(domain)}"},
        ],
        "warnings": [],
    }


def is_public_host(host: str) -> bool:
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False


def search_url(value: str):
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
        raise ValueError("Enter a public http/https URL.")
    r = requests.get(value, timeout=8, allow_redirects=True, headers={"User-Agent": "SocioSential-Public-OSINT/1.0"}, stream=True)
    ctype = r.headers.get("content-type", "")
    title = ""
    description = ""
    if "text/html" in ctype:
        text = r.raw.read(250000, decode_content=True).decode(r.encoding or "utf-8", errors="replace")
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:300]
        m = re.search(r'<meta[^>]+(?:name|property)=["\'](?:description|og:description)["\'][^>]+content=["\'](.*?)["\']', text, re.I | re.S)
        if m:
            description = re.sub(r"\s+", " ", m.group(1)).strip()[:500]
    return {
        "type": "url", "query": value,
        "summary": "Public URL metadata retrieved.",
        "results": [{"platform": "Web page", "url": r.url, "status": f"HTTP {r.status_code}", "details": {"title": title, "description": description, "content_type": ctype}}],
        "search_links": common_search_links(value, "url"), "warnings": [],
    }


@app.get("/")
def index():
    return HTML


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/search")
def api_search():
    payload = request.get_json(silent=True) or {}
    query = str(payload.get("query", "")).strip()
    kind = str(payload.get("type", "auto")).lower()
    if not query:
        return jsonify({"error": "Query is required."}), 400
    if kind == "auto":
        kind = infer_type(query)
    try:
        if kind == "username":
            data = search_username(query)
        elif kind == "email":
            data = search_email(query)
        elif kind == "name":
            data = {"type": "name", "query": query, "summary": "Generated public-source search pivots for this name.", "results": [], "search_links": common_search_links(query, "name"), "warnings": ["Name matches are ambiguous; verify with independent identifiers."]}
        elif kind == "domain":
            data = search_domain(query)
        elif kind == "url":
            data = search_url(query)
        else:
            return jsonify({"error": "Unsupported search type."}), 400
        return jsonify(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.exception("search failed")
        return jsonify({"error": f"Search failed: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
