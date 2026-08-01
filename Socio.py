import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from threading import Lock
from urllib.parse import quote, quote_plus, urlparse

import dns.resolver
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

USER_AGENT = "Mozilla/5.0 (compatible; SocioSentialVerified/2.0; +public-source-research)"
HTTP_TIMEOUT = 7
MAX_ITEMS = 15
CACHE_TTL = 900
CACHE = {}
CACHE_LOCK = Lock()
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().-]{6,20}$")

HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SocioSential Verified OSINT</title><style>
:root{--bg:#07110f;--panel:#0b1815;--line:#18d8a4;--text:#dffef6;--muted:#81aa9f;--ok:#5ee6a8;--maybe:#ffd166;--manual:#8cb4ff;--bad:#ff7b7b}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}main{max-width:1040px;margin:auto;padding:22px}.brand{letter-spacing:.25em;color:var(--line);font-size:21px}.sub{color:var(--muted);margin:8px 0 18px}.panel{border:1px solid #17624f;background:var(--panel);padding:16px;margin:14px 0}.row{display:grid;grid-template-columns:170px 1fr 130px;gap:10px}select,textarea,button{width:100%;padding:13px;border:1px solid #26755f;background:#06100e;color:var(--text);font:inherit}textarea{min-height:110px;resize:vertical}button{border-color:#b73d3d;color:#ff9797;cursor:pointer}button:disabled{opacity:.55}.small{font-size:12px;color:var(--muted)}.status{padding:10px;border-left:3px solid var(--line);margin-top:10px}.error{border-color:var(--bad);color:#ffc1c1}.query-block{border:1px solid #1b5a4b;margin:14px 0;padding:14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:10px}.card{border:1px solid #245c50;padding:13px;overflow-wrap:anywhere}.verified{border-color:var(--ok)}.possible{border-color:var(--maybe)}.manual{border-color:var(--manual)}.badge{display:inline-block;padding:3px 7px;margin:0 4px 6px 0;border:1px solid currentColor;font-size:11px}.verified .badge{color:var(--ok)}.possible .badge{color:var(--maybe)}.manual .badge{color:var(--manual)}a{color:#63e8c1}.why{font-size:12px;color:var(--muted);margin-top:7px}.note{color:#ffd166}@media(max-width:700px){.row{grid-template-columns:1fr}.brand{font-size:17px}}
</style></head><body><main><div class="brand">SOCIOSENTIAL VERIFIED OSINT</div><div class="sub">Precision first: fewer results, clearer evidence. Public sources only.</div><div class="panel"><div class="row"><select id="type"><option value="auto">Auto detect</option><option value="username">Username</option><option value="email">Email</option><option value="name">Full name</option><option value="phone">Phone</option><option value="domain">Domain</option><option value="url">URL</option></select><textarea id="query" placeholder="One item per line, or separate with commas / semicolons / *"></textarea><button id="go">SEARCH</button></div><div class="small" style="margin-top:9px">Up to 15 items. Search links are never counted as matches. LINE/WeChat and Thailand forums appear only as manual public-source pivots unless a direct public page can be verified.</div><div id="status"></div></div><div id="results"></div><script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function card(r){const cls=r.level==='verified'?'verified':r.level==='possible'?'possible':'manual';return `<div class="card ${cls}"><span class="badge">${esc(r.level.toUpperCase())}</span><b>${esc(r.platform||r.label)}</b>${r.url?`<div><a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">Open</a></div>`:''}<div class="why">${esc(r.reason||'')}</div>${r.details?`<pre class="small">${esc(JSON.stringify(r.details,null,2))}</pre>`:''}</div>`}
function render(data){let h='';for(const g of data.items){h+=`<div class="query-block"><b>${esc(g.query)}</b> <span class="small">(${esc(g.type)})</span><div class="small">Verified: ${g.counts.verified} · Possible: ${g.counts.possible} · Manual: ${g.counts.manual}</div>`;if(g.results.length){h+='<div class="grid">'+g.results.map(card).join('')+'</div>'}else h+='<div class="small">No verified public match found.</div>';if(g.warnings?.length)h+=`<div class="small note">${g.warnings.map(esc).join('<br>')}</div>`;h+='</div>'}$('#results').innerHTML=h}
$('#go').onclick=async()=>{const query=$('#query').value.trim();if(!query)return;$('#go').disabled=true;$('#status').innerHTML='<div class="status">Checking and verifying public sources…</div>';$('#results').innerHTML='';try{const c=new AbortController(),t=setTimeout(()=>c.abort(),70000);const r=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query,type:$('#type').value}),signal:c.signal});clearTimeout(t);const d=await r.json();if(!r.ok)throw new Error(d.error||'Search failed');render(d);$('#status').innerHTML='<div class="status">Complete.</div>'}catch(e){$('#status').innerHTML=`<div class="status error">${esc(e.name==='AbortError'?'Search timed out. Try fewer items.':e.message)}</div>`}finally{$('#go').disabled=false}};
</script></main></body></html>'''


def cached(fn):
    @wraps(fn)
    def wrapper(*args):
        key = (fn.__name__,) + args
        now = time.time()
        with CACHE_LOCK:
            row = CACHE.get(key)
            if row and now - row[0] < CACHE_TTL:
                return row[1]
        value = fn(*args)
        with CACHE_LOCK:
            CACHE[key] = (now, value)
        return value
    return wrapper


def split_items(raw: str):
    parts = [x.strip() for x in re.split(r"[\n,;*]+", raw) if x.strip()]
    out = []
    seen = set()
    for p in parts:
        k = p.casefold()
        if k not in seen:
            seen.add(k); out.append(p)
    if not out:
        raise ValueError("Enter at least one search value.")
    if len(out) > MAX_ITEMS:
        raise ValueError(f"Use up to {MAX_ITEMS} items per search.")
    return out


def infer_type(v: str):
    v = v.strip()
    if EMAIL_RE.fullmatch(v): return "email"
    if v.startswith(("http://", "https://")): return "url"
    if PHONE_RE.fullmatch(v): return "phone"
    if " " in v: return "name"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", v): return "domain"
    return "username"


def result(level, platform, url="", reason="", details=None):
    return {"level": level, "platform": platform, "url": url, "reason": reason, "details": details}


def http_get(url, **kwargs):
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    headers.update(kwargs.pop("headers", {}))
    return requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, headers=headers, **kwargs)


@cached
def verify_github(username):
    r = http_get(f"https://api.github.com/users/{quote(username)}", headers={"Accept":"application/vnd.github+json"})
    if r.status_code == 200:
        d = r.json()
        if str(d.get("login","")).casefold() == username.casefold():
            return result("verified","GitHub",d.get("html_url",f"https://github.com/{username}"),"GitHub API returned the exact username.",{"name":d.get("name"),"bio":d.get("bio"),"public_repos":d.get("public_repos")})
    return None


@cached
def verify_reddit(username):
    r = http_get(f"https://www.reddit.com/user/{quote(username)}/about.json")
    if r.status_code == 200:
        d = r.json().get("data",{})
        if str(d.get("name","")).casefold() == username.casefold():
            return result("verified","Reddit",f"https://www.reddit.com/user/{quote(username)}/","Reddit public API returned the exact username.",{"created_utc":d.get("created_utc"),"total_karma":d.get("total_karma")})
    return None


@cached
def verify_gitlab(username):
    r = http_get("https://gitlab.com/api/v4/users", params={"username": username})
    if r.status_code == 200:
        for d in r.json():
            if str(d.get("username","")).casefold() == username.casefold():
                return result("verified","GitLab",d.get("web_url",f"https://gitlab.com/{username}"),"GitLab API returned the exact username.",{"name":d.get("name"),"state":d.get("state")})
    return None


@cached
def verify_hackernews(username):
    r = http_get(f"https://hacker-news.firebaseio.com/v0/user/{quote(username)}.json")
    if r.status_code == 200 and r.text not in ("null", ""):
        d = r.json()
        if str(d.get("id","")).casefold() == username.casefold():
            return result("verified","Hacker News",f"https://news.ycombinator.com/user?id={quote_plus(username)}","Official Firebase API returned the exact username.",{"karma":d.get("karma"),"created":d.get("created")})
    return None


@cached
def verify_telegram(username):
    r = http_get(f"https://t.me/{quote(username)}")
    if r.status_code == 200:
        text = r.text[:250000]
        marker = f"@{username}".casefold()
        bad = any(x in text.casefold() for x in ["if you have telegram, you can contact", "tgme_page_error"])
        if marker in text.casefold() and not bad:
            return result("possible","Telegram",f"https://t.me/{quote(username)}","Public page contains the exact handle, but Telegram pages can be ambiguous.")
    return None


def username_manual_links(username):
    e = quote_plus(username)
    return [
        result("manual","Google exact social search",f'https://www.google.com/search?q=%22{e}%22+(site%3Ainstagram.com+OR+site%3Atiktok.com+OR+site%3Ax.com+OR+site%3Athreads.net+OR+site%3Afacebook.com)',"Search pivot only; not counted as a match."),
        result("manual","LINE OpenChat public search",f"https://openchat.line.me/th/search?q={e}","Public OpenChat search only; private LINE users cannot be searched."),
        result("manual","WeChat public-content search",f"https://www.google.com/search?q=%22{e}%22+(site%3Amp.weixin.qq.com+OR+site%3Achannels.weixin.qq.com)","Public WeChat articles/channels only; private users cannot be searched."),
        result("manual","Pantip",f"https://www.google.com/search?q=site%3Apantip.com+%22{e}%22","Public indexed discussions only."),
        result("manual","ASEAN NOW",f"https://www.google.com/search?q=site%3Aaseannow.com+%22{e}%22","Public indexed discussions only."),
        result("manual","Thailand-247",f"https://www.google.com/search?q=site%3Athailand-247.com+%22{e}%22","Public indexed discussions only."),
        result("manual","TeakDoor",f"https://www.google.com/search?q=site%3Ateakdoor.com+%22{e}%22","Public indexed discussions only."),
    ]


def search_username(value):
    u = value.strip().lstrip("@")
    if not USERNAME_RE.fullmatch(u): raise ValueError("Invalid username format.")
    checks = [verify_github, verify_reddit, verify_gitlab, verify_hackernews, verify_telegram]
    rows = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(f,u) for f in checks]
        for f in as_completed(futs):
            try:
                v=f.result()
                if v: rows.append(v)
            except Exception:
                pass
    rows.extend(username_manual_links(u))
    return rows, ["No result is treated as proof that an account does not exist."]


def dns_records(domain):
    out={}
    for typ in ("A","AAAA","MX","NS","TXT"):
        try: out[typ]=[str(x).strip('"') for x in dns.resolver.resolve(domain,typ,lifetime=4)][:15]
        except Exception: out[typ]=[]
    return out


def search_email(value):
    email=value.strip().lower()
    if not EMAIL_RE.fullmatch(email): raise ValueError("Invalid email address.")
    local,domain=email.rsplit("@",1); rows=[]
    digest=hashlib.md5(email.encode()).hexdigest()
    try:
        r=http_get(f"https://www.gravatar.com/avatar/{digest}?d=404")
        if r.status_code==200: rows.append(result("verified","Gravatar",f"https://gravatar.com/{digest}","A public Gravatar image exists for the exact email hash."))
    except Exception: pass
    records=dns_records(domain)
    rows.append(result("verified","Email domain DNS",reason="Public DNS records for the email domain.",details=records))
    rows += [
        result("manual","Exact public web search",f'https://www.google.com/search?q=%22{quote_plus(email)}%22',"Search pivot only; not proof of account ownership."),
        result("manual","Username-part search",f"/?type=username&query={quote_plus(local)}","Search the part before @ as a possible username."),
    ]
    return rows,["Email searches are limited to public evidence. Registration probing is intentionally not used because it creates false positives and privacy risk."]


def search_name(value):
    e=quote_plus(value.strip())
    rows=[
        result("manual","Google exact name",f'https://www.google.com/search?q=%22{e}%22',"Exact-name search; names are not unique."),
        result("manual","Thai social networks",f'https://www.google.com/search?q=%22{e}%22+(site%3Afacebook.com+OR+site%3Ainstagram.com+OR+site%3Atiktok.com+OR+site%3Apantip.com)',"Public indexed pages only."),
        result("manual","LINE OpenChat",f"https://openchat.line.me/th/search?q={e}","Public OpenChat only."),
        result("manual","WeChat public content",f'https://www.google.com/search?q=%22{e}%22+(site%3Amp.weixin.qq.com+OR+site%3Achannels.weixin.qq.com)',"Public articles/channels only."),
    ]
    return rows,["A name match is never marked verified without another exact identifier."]


def normalize_phone(v): return re.sub(r"\D","",v)

def search_phone(value):
    if not PHONE_RE.fullmatch(value.strip()): raise ValueError("Invalid phone number.")
    digits=normalize_phone(value); variants={digits}
    if digits.startswith("66"): variants.add("0"+digits[2:])
    if digits.startswith("0"): variants.add("66"+digits[1:])
    query=" OR ".join(f'\"{x}\"' for x in sorted(variants))
    rows=[
        result("manual","Exact public web search",f"https://www.google.com/search?q={quote_plus(query)}","Public indexed mentions only."),
        result("manual","Thailand public pages",f"https://www.google.com/search?q={quote_plus(query+' (site:facebook.com OR site:pantip.com OR site:kaidee.com)')}","Public indexed pages only."),
    ]
    return rows,["Phone ownership cannot be verified from a search result alone."]


def public_host(host):
    try:
        for info in socket.getaddrinfo(host,None):
            ip=ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast: return False
        return True
    except Exception:return False


def search_domain(value):
    d=value.strip().lower().rstrip('.')
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}",d): raise ValueError("Invalid domain.")
    return [result("verified","DNS records",reason="Public DNS lookup succeeded.",details=dns_records(d)),result("manual","Certificate transparency",f"https://crt.sh/?q=%25.{quote_plus(d)}","Public certificate search.")],[]


def search_url(value):
    p=urlparse(value)
    if p.scheme not in {"http","https"} or not p.hostname or not public_host(p.hostname): raise ValueError("Enter a public http/https URL.")
    r=http_get(value,stream=True); ctype=r.headers.get("content-type","")
    return [result("verified","Public URL",r.url,f"HTTP {r.status_code}",{"content_type":ctype})],[]


def count_levels(rows):
    return {k:sum(1 for r in rows if r["level"]==k) for k in ("verified","possible","manual")}

@app.get("/")
def index(): return HTML
@app.get("/health")
def health(): return jsonify({"status":"ok","version":"verified-2.0"})
@app.post("/api/search")
def api_search():
    payload=request.get_json(silent=True) or {}; raw=str(payload.get("query","")).strip(); forced=str(payload.get("type","auto")).lower()
    try:
        items=[]
        for value in split_items(raw):
            kind=infer_type(value) if forced=="auto" else forced
            if kind=="username": rows,w=search_username(value)
            elif kind=="email": rows,w=search_email(value)
            elif kind=="name": rows,w=search_name(value)
            elif kind=="phone": rows,w=search_phone(value)
            elif kind=="domain": rows,w=search_domain(value)
            elif kind=="url": rows,w=search_url(value)
            else: raise ValueError("Unsupported search type.")
            items.append({"query":value,"type":kind,"results":rows,"counts":count_levels(rows),"warnings":w})
        return jsonify({"items":items,"version":"verified-2.0"})
    except ValueError as e:return jsonify({"error":str(e)}),400
    except Exception:return jsonify({"error":"Search failed safely. Try fewer items."}),500

if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.getenv("PORT","10000")))
