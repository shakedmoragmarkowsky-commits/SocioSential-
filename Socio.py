"""SocioSential original bootstrap + online email search.

Loads the upstream/original SocioSential application at startup, preserves its
Twitter/Reddit UI and routes, and adds a privacy-first public email search page.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from html import escape
from pathlib import Path
from urllib.parse import quote, quote_plus
from urllib.request import Request, urlopen

UPSTREAM_URL = os.environ.get(
    "SOCIO_UPSTREAM_URL",
    "https://raw.githubusercontent.com/h9zdev/SocioSential/main/Socio.py",
)
CACHE_FILE = Path("/tmp/sociosential_upstream.py")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def fetch_original() -> str:
    req = Request(UPSTREAM_URL, headers={"User-Agent": "SocioSential-Original-Email/1.0"})
    try:
        with urlopen(req, timeout=25) as response:
            source = response.read().decode("utf-8")
        if "Flask" not in source or "@app.route" not in source:
            raise RuntimeError("The upstream file did not look like SocioSential.")
        CACHE_FILE.write_text(source, encoding="utf-8")
        return source
    except Exception:
        if CACHE_FILE.exists():
            return CACHE_FILE.read_text(encoding="utf-8")
        raise


def prepare_original(source: str) -> str:
    # Do not let the upstream file start its own server before our routes are added.
    source = source.replace('if __name__ == "__main__":', 'if False:  # started by wrapper')
    source = source.replace("if __name__ == '__main__':", "if False:  # started by wrapper")

    # Make optional AI configuration genuinely optional instead of failing startup.
    source = re.sub(
        r'HF_TOKEN\s*=\s*["\'][^"\']*["\']\s*#.*',
        'HF_TOKEN = os.environ.get("HF_TOKEN", "")',
        source,
        count=1,
    )
    source = source.replace(
        'if not HF_TOKEN:\n    raise RuntimeError("Set HF_TOKEN in .env")',
        'if not HF_TOKEN:\n    logging.getLogger(__name__).info("HF_TOKEN not configured; AI route remains optional.")',
    )
    return source


_original = prepare_original(fetch_original())
exec(compile(_original, "upstream_Socio.py", "exec"), globals(), globals())

# The original app writes Reddit captures to this directory.
Path(app.root_path, "data").mkdir(parents=True, exist_ok=True)


def public_email_checks(email: str) -> list[dict]:
    import requests

    results: list[dict] = []
    md5 = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()

    # Gravatar: a concrete public profile/avatar check.
    try:
        profile_url = f"https://www.gravatar.com/{md5}.json"
        r = requests.get(profile_url, timeout=8, headers={"User-Agent": "SocioSential/EmailSearch"})
        if r.status_code == 200:
            entry = (r.json().get("entry") or [{}])[0]
            results.append({
                "source": "Gravatar",
                "status": "found",
                "title": entry.get("displayName") or "Public Gravatar profile",
                "url": f"https://gravatar.com/{md5}",
                "evidence": "Gravatar returned a public profile for the exact normalized email hash.",
            })
    except Exception:
        pass

    # GitHub public commit metadata. Optional token increases rate limits but is not required.
    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "SocioSential/EmailSearch",
        }
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = requests.get(
            "https://api.github.com/search/commits",
            params={"q": f'author-email:"{email}"', "per_page": 10},
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            for item in r.json().get("items", [])[:10]:
                commit = item.get("commit", {})
                author = commit.get("author", {}) or {}
                if str(author.get("email", "")).casefold() != email.casefold():
                    continue
                results.append({
                    "source": "GitHub commits",
                    "status": "found",
                    "title": (commit.get("message") or "Public commit").splitlines()[0][:120],
                    "url": item.get("html_url", ""),
                    "evidence": "The exact email appears in public Git commit author metadata.",
                })
    except Exception:
        pass

    return results


def search_links(email: str) -> list[tuple[str, str]]:
    exact = f'"{email}"'
    return [
        ("Google exact", "https://www.google.com/search?nfpr=1&q=" + quote_plus(exact)),
        ("Bing exact", "https://www.bing.com/search?q=" + quote_plus(exact)),
        ("DuckDuckGo exact", "https://duckduckgo.com/?q=" + quote_plus(exact)),
        ("GitHub", "https://github.com/search?q=" + quote_plus(exact) + "&type=commits"),
        ("Reddit", "https://www.reddit.com/search/?q=" + quote(exact)),
        ("X / Twitter", "https://x.com/search?q=" + quote(exact) + "&src=typed_query"),
        ("Facebook indexed pages", "https://www.google.com/search?nfpr=1&q=" + quote_plus(f'site:facebook.com {exact}')),
        ("LinkedIn indexed pages", "https://www.google.com/search?nfpr=1&q=" + quote_plus(f'site:linkedin.com {exact}')),
        ("Thai websites", "https://www.google.com/search?nfpr=1&q=" + quote_plus(f'{exact} site:.th')),
        ("Have I Been Pwned", "https://haveibeenpwned.com/account/" + quote(email)),
    ]


@app.route("/email-search", methods=["GET", "POST"])
def email_search():
    email = ""
    results: list[dict] = []
    error = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        if not EMAIL_RE.fullmatch(email):
            error = "Enter a valid email address."
        else:
            results = public_email_checks(email)

    result_html = ""
    if email and not error:
        cards = "".join(
            f'''<article class="card"><strong>{escape(x["source"])}</strong><h3>{escape(x["title"])}</h3>
            <p>{escape(x["evidence"])}</p><a target="_blank" rel="noopener" href="{escape(x["url"])}">Open source ↗</a></article>'''
            for x in results
        )
        if not cards:
            cards = '<article class="card"><strong>No direct public matches</strong><p>No Gravatar or exact GitHub commit match was returned. Use the exact online searches below.</p></article>'
        links = "".join(
            f'<a class="search-link" target="_blank" rel="noopener" href="{escape(url)}">{escape(label)} ↗</a>'
            for label, url in search_links(email)
        )
        result_html = f'<section><h2>Direct checks</h2>{cards}<h2>Exact online searches</h2><div class="links">{links}</div></section>'

    error_html = f'<p class="error">{escape(error)}</p>' if error else ""
    safe_email = escape(email, quote=True)
    return f'''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Email Search — SocioSential</title><style>
    :root{{--bg:#081713;--panel:#10251f;--line:#2e8b70;--text:#e5f3ed;--muted:#9bb9ae;--accent:#55e6b1}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif}}
    main{{max-width:900px;margin:auto;padding:28px 18px 70px}}a{{color:var(--accent)}}h1{{letter-spacing:.08em}}.sub{{color:var(--muted)}}
    form,.card{{background:var(--panel);border:1px solid var(--line);padding:20px;border-radius:14px;margin:16px 0}}
    input{{width:100%;padding:16px;border-radius:10px;border:1px solid var(--line);background:#07110e;color:white;font-size:17px}}
    button{{width:100%;margin-top:12px;padding:15px;border:0;border-radius:10px;background:var(--accent);font-weight:800;font-size:16px}}
    .links{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}}.search-link{{border:1px solid var(--line);padding:14px;border-radius:10px;text-decoration:none}}
    .error{{color:#ff9b9b}}nav{{display:flex;gap:16px;margin-bottom:20px}}
    </style></head><body><main><nav><a href="/">← Original dashboard</a><a href="/health">Health</a></nav>
    <h1>EMAIL SEARCH</h1><p class="sub">Online public-source search. Nothing is stored. Exact email only; no automatic spelling correction.</p>
    <form method="post"><input name="email" type="email" autocomplete="off" placeholder="name@example.com" value="{safe_email}" required>
    <button type="submit">SEARCH ONLINE</button></form>{error_html}{result_html}</main></body></html>'''


@app.route("/health")
def original_plus_health():
    return jsonify({
        "status": "ok",
        "version": "original-plus-email-1.0",
        "original_ui": True,
        "email_search": True,
        "github_token_configured": bool(os.environ.get("GITHUB_TOKEN")),
    })


@app.after_request
def add_email_search_link(response):
    # Add a visible shortcut to original HTML pages without changing their templates.
    ctype = response.headers.get("Content-Type", "")
    if response.status_code == 200 and "text/html" in ctype and request.path != "/email-search":
        try:
            text = response.get_data(as_text=True)
            shortcut = '<a href="/email-search" style="position:fixed;right:18px;bottom:18px;z-index:99999;background:#19c58b;color:#06130f;padding:12px 16px;border-radius:999px;font:700 14px system-ui;text-decoration:none;box-shadow:0 6px 24px #0008">Email Search</a>'
            text = text.replace("</body>", shortcut + "</body>")
            response.set_data(text)
            response.headers["Content-Length"] = str(len(response.get_data()))
        except Exception:
            pass
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
