"""
server.py - Web Clipper Backend v4.0
══════════════════════════════════════════════════════════════
ROOT CAUSE FIX for "Token exchange: 400":

The .env file has REDIRECT_URI=http://localhost:5001/auth/callback
but the server is reachable via ngrok at https://xxxx.ngrok-free.app
So Notion gets redirect_uri=http://localhost... during /login,
but the registered URI in the Notion integration is the ngrok URL.
They don't match → 400.

FIX: get_redirect_uri() auto-detects the correct URI from the
incoming HTTP Host header. Works for localhost AND ngrok
without any .env changes.

AUTH FLOW:
1. Extension opens popup → GET /login
2. Server builds OAuth URL using auto-detected redirect_uri
3. Notion calls back → GET /auth/callback?code=xxx
4. Server exchanges code, creates/finds DB, stores in _pending_auth
5. background.js polls GET /auth/latest every second
6. /auth/latest returns {ready, token, db_id} — no cookie needed
7. background.js writes to chrome.storage → context menu updates
"""

import os, base64, io, time, traceback, json, secrets, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from PIL import Image
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

CORS(app,
    origins="*",
    methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Session-Id"],
    supports_credentials=True)

NOTION_CLIENT_ID     = os.getenv("NOTION_CLIENT_ID", "")
NOTION_CLIENT_SECRET = os.getenv("NOTION_CLIENT_SECRET", "")
NOTION_VERSION       = "2022-06-28"
USERS_FILE           = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")

# ── Admin dashboard access key ─────────────────────────────────────────────
# Change this (or set ADMIN_KEY in .env) before sharing the extension!
ADMIN_KEY            = os.getenv("ADMIN_KEY", "admin123")

# ── Shared HTTP session ─────────────────────────────────────────────────────
# Reuses TCP/TLS connections to api.notion.com instead of renegotiating a
# new handshake on every single request. Speeds up clips that make many
# sequential Notion API calls (page create, multiple image uploads, etc).
_http = requests.Session()

# In-memory stores
_sessions:     dict = {}  # sid  → {token, db_id, name, user_id}
_pending_auth: dict = {}  # code → {token, db_id, name}  (one-time, consumed by /auth/latest)


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def get_redirect_uri() -> str:
    """
    Build the redirect_uri from the ACTUAL request Host header.

    When running under ngrok the Host header is  xxxx.ngrok-free.app
    so this returns  https://xxxx.ngrok-free.app/auth/callback

    When running locally the Host is  localhost:5001
    so this returns  http://localhost:5001/auth/callback

    Both /login and /auth/callback call this, so they always agree.
    No .env value needed (but REDIRECT_URI in .env still overrides if set).
    """
    # Explicit override wins (useful for production deployments)
    env = os.getenv("REDIRECT_URI", "")
    if env and not env.startswith("YOUR") and "localhost" not in env:
        return env

    # Auto-detect from Host header
    host   = request.headers.get("Host", "localhost:5001")
    scheme = "https" if request.headers.get("X-Forwarded-Proto") == "https" \
            else ("https" if not host.startswith("localhost") else "http")
    return f"{scheme}://{host}/auth/callback"


def h(token: str) -> dict:
    return {
        "Authorization":  f"Bearer {token}",
        "Content-Type":   "application/json",
        "Notion-Version": NOTION_VERSION
    }


def h_file(token: str) -> dict:
    return {
        "Authorization":  f"Bearer {token}",
        "Notion-Version": NOTION_VERSION
    }


def load_users() -> dict:
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def find_user_by_db(users: dict, db_id: str):
    """Return (user_id, user_dict) for a given db_id, or (None, None)."""
    for uid, u in users.items():
        if u.get("db_id") == db_id:
            return uid, u
    return None, None


def find_user_by_token(users: dict, token: str):
    """Return (user_id, user_dict) for a given Notion token, or (None, None)."""
    for uid, u in users.items():
        if u.get("token") == token:
            return uid, u
    return None, None


def get_user_status(token: str = None, db_id: str = None) -> str:
    """Look up approval status for a user by token and/or db_id.
    Returns 'approved' | 'pending' | 'rejected' | 'unknown'."""
    users = load_users()
    uid, u = (None, None)
    if db_id:
        uid, u = find_user_by_db(users, db_id)
    if not u and token:
        uid, u = find_user_by_token(users, token)
    if not u:
        return "unknown"
    return u.get("status", "pending")


def is_admin(req) -> bool:
    key = (req.headers.get("X-Admin-Key")
        or req.args.get("key")
        or (req.get_json(silent=True) or {}).get("key"))
    return key == ADMIN_KEY


def get_session(req) -> tuple:
    sid = (req.headers.get("X-Session-Id")
        or req.cookies.get("sc_session")
        or (req.get_json(silent=True) or {}).get("session_id"))
    if sid and sid in _sessions:
        return sid, _sessions[sid]
    return None, None


def make_session(user_id: str, token: str, db_id: str, name: str) -> str:
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {"token": token, "db_id": db_id, "name": name, "user_id": user_id}
    return sid


# ══════════════════════════════════════════════════════════════
# LOGIN PAGE  (pretty landing page)
# ══════════════════════════════════════════════════════════════

@app.route("/login-page")
def login_page():
    base = request.host_url.rstrip("/")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web Clipper — Login</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0c0c14;--card:#13131f;--border:rgba(255,255,255,.07);--accent:#6c63ff;--text:#e8e6f0;--muted:#7a7890}}
body{{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;min-height:100vh;
    display:flex;align-items:center;justify-content:center}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:24px;padding:52px 48px;
    max-width:440px;width:92%;text-align:center;box-shadow:0 40px 80px rgba(0,0,0,.5)}}
.icon{{display:inline-flex;align-items:center;justify-content:center;width:72px;height:72px;
    background:linear-gradient(135deg,var(--accent),#9b59b6);border-radius:20px;
    font-size:32px;margin-bottom:28px}}
h1{{font-family:'DM Serif Display',serif;font-size:2rem;margin-bottom:10px;
    background:linear-gradient(135deg,#fff,#b0a8ff);-webkit-background-clip:text;
    -webkit-text-fill-color:transparent;background-clip:text}}
.tag{{color:var(--muted);font-size:.9rem;margin-bottom:40px;line-height:1.6}}
.btn{{display:flex;align-items:center;justify-content:center;gap:14px;width:100%;
    padding:16px 24px;background:#fff;color:#1a1a2e;border:none;border-radius:14px;
    font-family:'DM Sans',sans-serif;font-size:.95rem;font-weight:500;cursor:pointer;
    text-decoration:none;transition:all .2s}}
.btn:hover{{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.4)}}
.feats{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:32px}}
.feat{{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:12px;
    padding:14px 10px;font-size:.75rem;color:var(--muted)}}
.feat span{{display:block;font-size:1.2rem;margin-bottom:6px}}
.uid{{font-family:monospace;font-size:.72rem;color:#7a7890;cursor:pointer;transition:color .15s}}
.uid:hover{{color:#a0b4ff}}
.uid.copied{{color:#2ecc71}}
</style></head><body>
<div class="card">
<div class="icon"></div>
<h1>Web Clipper</h1>
<p class="tag">Clip anything from the web<br>directly into your Notion workspace.</p>
<a class="btn" href="{base}/login">
    <svg width="22" height="22" viewBox="0 0 100 100"><rect width="100" height="100" rx="14" fill="#000"/>
    <path d="M28 28h44v44H28z" fill="#fff"/>
    <path d="M35 35h14v14H35zM51 35h14v14H51zM35 51h14v14H35z" fill="#000"/></svg>
    Continue with Notion
</a>
<div class="feats">
    <div class="feat"><span>🔐</span>Secure OAuth</div>
    <div class="feat"><span>🗄️</span>Auto DB setup</div>
    <div class="feat"><span>👥</span>Multi-user</div>
</div>
</div></body></html>"""


# ══════════════════════════════════════════════════════════════
# OAUTH — START
# ══════════════════════════════════════════════════════════════

@app.route("/login")
def login():
    if not NOTION_CLIENT_ID:
        return "<h2>❌ NOTION_CLIENT_ID not set in .env</h2>", 500

    redirect_uri = get_redirect_uri()
    print(f"\n🔗 /login — redirect_uri: {redirect_uri}")

    auth_url = (
        "https://api.notion.com/v1/oauth/authorize"
        f"?client_id={NOTION_CLIENT_ID}"
        "&response_type=code"
        "&owner=user"
        f"&redirect_uri={redirect_uri}"
    )
    return redirect(auth_url)


# ══════════════════════════════════════════════════════════════
# OAUTH — CALLBACK
# ══════════════════════════════════════════════════════════════

@app.route("/auth/callback")
def auth_callback():
    code  = request.args.get("code")
    error = request.args.get("error")

    if error:
        return f"<h1>❌ Notion denied: {error}</h1>", 400
    if not code:
        return "<h1>❌ Missing authorization code</h1>", 400

    # MUST use the same redirect_uri that was sent in /login
    redirect_uri = get_redirect_uri()

    try:
        print("\n" + "="*60)
        print("🔐 AUTH CALLBACK")
        print(f"   redirect_uri: {redirect_uri}")
        print("="*60)

        # ── Exchange code for access token ────────────────────
        r = _http.post(
            "https://api.notion.com/v1/oauth/token",
            auth=(NOTION_CLIENT_ID, NOTION_CLIENT_SECRET),
            json={
                "grant_type":   "authorization_code",
                "code":         code,
                "redirect_uri": redirect_uri
            }
        )
        d = r.json()
        print(f"Token exchange: {r.status_code}")

        if not r.ok:
            err_msg = d.get("error_description") or d.get("error") or str(d)
            print(f"❌ {err_msg}")
            return f"""<!DOCTYPE html>
<html><body style="background:#0c0c14;color:#e8e6f0;font-family:sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<div style="text-align:center;padding:40px;background:#13131f;border-radius:16px;
            max-width:440px;width:90%">
<div style="font-size:3rem">❌</div>
<h2 style="color:#ff6b6b;margin:16px 0">Connection Failed</h2>
<p style="color:#7a7890;margin-bottom:12px">{err_msg}</p>
<p style="color:#556;font-size:.82rem;margin-bottom:20px">
    In your Notion integration, set the redirect URI to exactly:<br><br>
    <code style="color:#a0b4ff;background:#1a1a2e;padding:6px 12px;
                border-radius:6px;display:inline-block">{redirect_uri}</code>
</p>
<a href="/login" style="display:inline-block;padding:10px 28px;background:#6c63ff;
    color:#fff;border-radius:8px;text-decoration:none">Try Again</a>
</div></body></html>""", 500

        access_token = d.get("access_token")
        if not access_token:
            return "<h1>❌ No access token returned</h1>", 500
        print("✅ Token obtained")
        
        # ── Get user info ──────────────────────────────────────
        user_r    = _http.get("https://api.notion.com/v1/users/me", headers=h(access_token))
        user_data = user_r.json() if user_r.ok else {}
        user_id   = user_data.get("id", secrets.token_hex(8))
        user_name = user_data.get("name", "User")
        workspace_name = user_data.get("bot", {}).get("workspace_name") or user_name
        print(f"✅ User: {user_name} ({user_id}) — workspace: {workspace_name}")

        # ── Find or create database ────────────────────────────
        users        = load_users()
        stored_db_id = users.get(user_id, {}).get("db_id")
        db_id        = None

        if stored_db_id:
            check = _http.get(f"https://api.notion.com/v1/databases/{stored_db_id}",
                                headers=h(access_token))
            if check.status_code == 200:
                db_id = stored_db_id
                users[user_id]["token"] = access_token
                users[user_id]["name"]  = user_name
                users[user_id]["workspace_name"] = workspace_name
                # keep existing approval status; pre-existing records get "approved"
                if "status" not in users[user_id]:
                    users[user_id]["status"] = "approved"
                print(f"♻️  Returning user — db: {db_id} (status: {users[user_id]['status']})")
            else:
                print(f"⚠️  Stored db invalid ({check.status_code}), will recreate")

        if not db_id:
            db_id = find_or_create_database(access_token)
            if not db_id:
                return ("<h1>❌ Database setup failed</h1>"
                        "<p>Open Notion → page ··· → Connections → "
                        "connect your integration → try again.</p>"), 500
            users[user_id] = {"token": access_token, "db_id": db_id, "name": user_name, "workspace_name": workspace_name, "status": "pending"}
            print(f"✨ New database: {db_id}  (status: pending admin approval)")

        save_users(users)
        user_status = users[user_id].get("status", "pending")

        sid = make_session(user_id, access_token, db_id, user_name)
        print(f"✅ Session: {sid[:16]}…")

        # ── Store for /auth/latest polling ─────────────────────
        code_key = secrets.token_urlsafe(16)
        _pending_auth[code_key] = {"token": access_token, "db_id": db_id, "name": user_name, "status": user_status}
        print("✅ Pending auth stored — background.js will pick it up")

        # ── Success page ───────────────────────────────────────
        resp = make_response(f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
body{{background:#0c0c14;color:#e8e6f0;font-family:'DM Sans',sans-serif;
    display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{text-align:center;padding:48px;background:#13131f;border-radius:24px;
    border:1px solid rgba(255,255,255,.07);max-width:380px;width:92%}}
h1{{font-family:'DM Serif Display',serif;font-size:1.8rem;margin:16px 0 10px;
    background:linear-gradient(135deg,#fff,#b0a8ff);-webkit-background-clip:text;
    -webkit-text-fill-color:transparent;background-clip:text}}
p{{color:#7a7890;font-size:.9rem;line-height:1.6}}
.name{{color:#a0b4ff;font-weight:500;margin-top:10px}}
.big{{font-size:3rem;margin-bottom:4px}}
.badge{{display:inline-block;margin-top:16px;padding:6px 16px;
        background:rgba(108,99,255,.15);border:1px solid rgba(108,99,255,.3);
        border-radius:100px;font-size:.78rem;color:#8b83ff}}
.badge.pending{{background:rgba(255,180,60,.15);border-color:rgba(255,180,60,.35);color:#ffb43c}}
.timer{{margin-top:20px;font-size:.75rem;color:#4a4860}}
</style></head>
<body><div class="card">
<div class="big">{"✅" if user_status == "approved" else "⏳"}</div>
<h1>{"You're connected!" if user_status == "approved" else "Almost there!"}</h1>
<p>Web Clipper is now linked to your Notion workspace.</p>
<p class="name">👤 {user_name}</p>
<div class="badge{' pending' if user_status != 'approved' else ''}">{"Database ready ✓" if user_status == "approved" else "Awaiting admin approval ⏳"}</div>
{f'<p style="margin-top:16px;font-size:.8rem">An admin needs to approve your account before the clipper works. Check back soon!</p>' if user_status != "approved" else ""}
<p class="timer" id="t">Closing in 3s…</p>
</div>
<script>
// Try direct chrome.storage write — works only if this page
// somehow runs inside extension context (rare). background.js
// /auth/latest polling handles the normal case.
try {{
if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {{
    chrome.storage.sync.set({{
    notionToken: "{access_token}",
    databaseId:  "{db_id}"
    }}, function() {{
    console.log('WebClipper: credentials written directly');
    }});
}}
}} catch(e) {{}}

var i = 3;
var t = document.getElementById('t');
var iv = setInterval(function() {{
i--;
if (i > 0) {{ t.textContent = 'Closing in ' + i + 's\u2026'; }}
else {{
    clearInterval(iv);
    t.textContent = 'You can close this window.';
    try {{ window.close(); }} catch(e) {{}}
}}
}}, 5000);
</script></body></html>""")

        resp.set_cookie("sc_session", sid, max_age=30*24*3600, httponly=True, samesite="Lax")
        return resp

    except Exception as e:
        traceback.print_exc()
        return f"<h1>❌ Server Error</h1><p>{e}</p>", 500


# ══════════════════════════════════════════════════════════════
# AUTH STATUS  (cookie-based, for browser tab checks)
# ══════════════════════════════════════════════════════════════

@app.route("/auth/status")
def auth_status():
    sid, sess = get_session(request)
    if sess:
        return jsonify({"logged_in": True, "name": sess["name"],
                        "session_id": sid, "token": sess["token"], "db_id": sess["db_id"]})
    return jsonify({"logged_in": False, "token": None, "db_id": None})


# ══════════════════════════════════════════════════════════════
# AUTH LATEST  ← background.js polls this every second
#
# No session cookie needed — plain GET.
# Returns credentials once and removes them (one-time use).
# ══════════════════════════════════════════════════════════════

@app.route("/auth/latest")
def auth_latest():
    if _pending_auth:
        code = next(iter(_pending_auth))
        data = _pending_auth.pop(code)
        print(f"✅ /auth/latest consumed — user: {data['name']} (status: {data.get('status','pending')})")
        return jsonify({"ready": True, "token": data["token"],
                        "db_id": data["db_id"], "name": data["name"],
                        "status": data.get("status", "pending")})
    return jsonify({"ready": False})


@app.route("/auth/logout", methods=["POST", "OPTIONS"])
def auth_logout():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    sid, _ = get_session(request)
    if sid and sid in _sessions:
        del _sessions[sid]
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie("sc_session")
    return resp


@app.route("/auth/clear", methods=["POST", "OPTIONS"])
def auth_clear():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    return jsonify({"ok": True})


@app.route("/auth/check-user", methods=["POST", "OPTIONS"])
def auth_check_user():
    """
    Called by background.js on startup/periodically.
    If users.json was deleted, previously stored tokens in chrome.storage
    are now invalid (no DB mapping). This endpoint verifies the token+db_id
    are still valid. If not, the extension should clear storage and show login.
    """
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    try:
        data  = request.get_json() or {}
        token = data.get("token")
        db_id = data.get("db_id")
        if not token or not db_id:
            return jsonify({"valid": False, "reason": "missing_params"})
        # Check if db still accessible
        check = _http.get(f"https://api.notion.com/v1/databases/{db_id}",
                            headers=h(token))
        if check.status_code == 200:
            # Also re-register in users.json if it was deleted
            users = load_users()
            # Try to find user id
            user_r = _http.get("https://api.notion.com/v1/users/me", headers=h(token))
            if user_r.ok:
                user_data = user_r.json()
                user_id   = user_data.get("id", "unknown")
                user_name = user_data.get("name", "User")
                workspace_name = user_data.get("bot", {}).get("workspace_name") or user_name
                if user_id not in users:
                    users[user_id] = {"token": token, "db_id": db_id, "name": user_name, "workspace_name": workspace_name, "status": "pending"}
                    save_users(users)
                    print(f"♻️  Re-registered user {user_name} after users.json restore (status: pending)")
                elif not users[user_id].get("workspace_name"):
                    users[user_id]["workspace_name"] = workspace_name
                    save_users(users)
                    print(f"📝 Backfilled workspace name for {user_name}: {workspace_name}")
            status = get_user_status(token=token, db_id=db_id)
            return jsonify({"valid": True, "status": status})
        else:
            return jsonify({"valid": False, "reason": "db_not_found", "status": check.status_code})
    except Exception as e:
        return jsonify({"valid": False, "reason": str(e)})


# ══════════════════════════════════════════════════════════════
# APPROVAL STATUS  ← extension polls this to check admin approval
# ══════════════════════════════════════════════════════════════

@app.route("/auth/check-status", methods=["POST", "OPTIONS"])
def auth_check_status():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    data  = request.get_json() or {}
    token = data.get("token")
    db_id = data.get("db_id")
    if not token and not db_id:
        return jsonify({"status": "unknown"})
    status = get_user_status(token=token, db_id=db_id)
    return jsonify({"status": status})


# ══════════════════════════════════════════════════════════════
# DATABASE SETUP
# ══════════════════════════════════════════════════════════════

def find_or_create_database(token: str) -> str | None:
    hdr = {"Authorization": f"Bearer {token}",
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json"}

    # 1. Search for existing Web Clipper DB (also check old SmartClipper name)
    print("    🔍 Searching for existing Web Clipper database…")
    try:
        for search_name in ["Web Clipper", "Web Clipper"]:
            sr = _http.post("https://api.notion.com/v1/search", headers=hdr,
                            json={"query": search_name,
                                    "filter": {"value": "database", "property": "object"}})
            if sr.ok:
                for db in sr.json().get("results", []):
                    titles = db.get("title", [])
                    name   = titles[0].get("plain_text", "") if titles else ""
                    if search_name in name:
                        found = db["id"].replace("-", "")
                        print(f"    ♻️  Found existing DB: {found}")
                        return found
    except Exception as e:
        print(f"    ⚠️  Search warning: {e}")

    # 2. Find any existing page for parent
    parent_id = None
    try:
        pr = _http.post("https://api.notion.com/v1/search", headers=hdr,
                        json={"filter": {"value": "page", "property": "object"}, "page_size": 1})
        if pr.ok and pr.json().get("results"):
            parent_id = pr.json()["results"][0]["id"]
            print(f"    🔗 Using parent page: {parent_id}")
    except Exception as e:
        print(f"    ⚠️  Page scan warning: {e}")

    # 3. Create hub page at workspace root if no pages exist
    if not parent_id:
        print("    🚀 Creating Web Clipper Hub at workspace root…")
        try:
            cr = _http.post("https://api.notion.com/v1/pages", headers=hdr,
                            json={"parent": {"type": "workspace", "workspace": True},
                                    "properties": {"title": [{"text": {"content": "Web Clipper Hub"}}]}})
            if cr.ok:
                parent_id = cr.json()["id"]
                print(f"    ✅ Hub page: {parent_id}")
            else:
                print(f"    ❌ Hub page failed: {cr.text}")
                return None
        except Exception as e:
            print(f"    ❌ Hub page error: {e}")
            return None

    # 4. Create database
    print("    ✨ Creating Web Clipper database…")
    schema = {
        "parent": {"type": "page_id", "page_id": parent_id},
        "title":  [{"type": "text", "text": {"content": "Web Clipper"}}],
        "properties": {
            "Name":         {"title": {}},
            "URL":          {"url": {}},
            "Screenshot":   {"files": {}},
            "Type": {"select": {"options": [
                {"name": "Fullpage",  "color": "orange"},
                {"name": "Article",   "color": "yellow"},
                {"name": "Bookmark",  "color": "blue"},
                {"name": "Image",     "color": "green"},
                {"name": "Text",      "color": "purple"},
                {"name": "Link",      "color": "gray"},
            ]}},
            "Tags":         {"multi_select": {}},
            "Clipped Date": {"date": {}}
        }
    }
    try:
        dr = _http.post("https://api.notion.com/v1/databases", headers=hdr, json=schema)
        print(f"    DB create: {dr.status_code}")
        if dr.status_code in (200, 201):
            db_id = dr.json()["id"].replace("-", "")
            print(f"    ✅ Database: {db_id}")
            return db_id
        print(f"    ❌ DB failed: {dr.text}")
    except Exception as e:
        print(f"    ❌ DB error: {e}")
    return None


# ══════════════════════════════════════════════════════════════
# IMAGE HELPERS
# ══════════════════════════════════════════════════════════════

def compress_image(img_bytes: bytes, max_bytes: int = 4*1024*1024):
    """
    SPEED FIX: previously this could loop re-encoding the SAME full-resolution
    image up to 4 times (quality 85→70→55→40→...), each pass costly for large
    images. Now: downsize once, encode once at quality=80 with optimize=False
    (the optimize pass is the slow part and saves little), and only fall back
    to a single lower-quality re-encode if still too big. This cuts image
    processing time substantially for large screenshots/photos.
    """
    if len(img_bytes) <= max_bytes:
        mime = "image/jpeg" if img_bytes[:2] == b'\xff\xd8' else "image/png"
        return img_bytes, mime, "jpg" if mime == "image/jpeg" else "png"
    pil = Image.open(io.BytesIO(img_bytes))
    if pil.mode in ("RGBA", "P", "LA"):
        pil = pil.convert("RGB")
    if max(pil.size) > 1600:
        pil.thumbnail((1600, 1600), Image.LANCZOS)
    out = io.BytesIO()
    pil.save(out, format="JPEG", quality=80, optimize=False)
    if len(out.getvalue()) <= max_bytes:
        return out.getvalue(), "image/jpeg", "jpg"
    out = io.BytesIO()
    pil.save(out, format="JPEG", quality=55, optimize=False)
    return out.getvalue(), "image/jpeg", "jpg"


def upload_image(token: str, b64_data: str):
    try:
        if isinstance(b64_data, str) and "," in b64_data:
            b64_data = b64_data.split(",")[1]
        raw = base64.b64decode(b64_data)
        img_bytes, mime, ext = compress_image(raw)
        fname  = f"clip_{int(time.time())}.{ext}"
        init_r = _http.post("https://api.notion.com/v1/file_uploads",
                            headers=h(token), json={"name": fname, "content_type": mime})
        if not init_r.ok:
            return None, None
        d         = init_r.json()
        upload_id = d.get("id")
        upload_url= d.get("upload_url") or f"https://api.notion.com/v1/file_uploads/{upload_id}/send"
        send_r    = _http.post(upload_url, headers=h_file(token),
                                files={"file": (fname, img_bytes, mime)})
        return (upload_id, fname) if send_r.ok else (None, None)
    except Exception as e:
        print(f"      ❌ upload_image: {e}")
        return None, None


def fetch_url_as_b64(url: str):
    """Download a remote image (e.g. an inline <img src> found while clipping
    an article/full page) and return it as base64 so upload_image() can use it."""
    try:
        r = _http.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.ok and r.content:
            return base64.b64encode(r.content).decode()
    except Exception as e:
        print(f"      ⚠️  fetch_url_as_b64 failed for {url}: {e}")
    return None


def collect_extra_image_b64s(data: dict) -> list:
    """
    Pulls images from optional extra fields the extension may send, on top of
    the existing image_list / screenshot_b64 handling in /clip (untouched).

    Supported, all optional:
      - "images":      list of base64 strings, URL strings, or {"b64": ...} / {"url": ...} dicts
      - "image_urls":  list of plain remote image URLs (e.g. inline <img> srcs from an article)
    """
    out = []

    extra = data.get("images")
    if extra and isinstance(extra, list):
        for entry in extra:
            if isinstance(entry, str):
                if entry.startswith("http://") or entry.startswith("https://"):
                    b64 = fetch_url_as_b64(entry)
                    if b64:
                        out.append(b64)
                else:
                    out.append(entry)
            elif isinstance(entry, dict):
                if entry.get("b64"):
                    out.append(entry["b64"])
                elif entry.get("url"):
                    b64 = fetch_url_as_b64(entry["url"])
                    if b64:
                        out.append(b64)

    url_list = data.get("image_urls")
    if url_list and isinstance(url_list, list):
        for u in url_list:
            if isinstance(u, str) and u:
                b64 = fetch_url_as_b64(u)
                if b64:
                    out.append(b64)

    return out


def append_image_block(token: str, page_id: str, upload_id: str):
    try:
        _http.patch(
            f"https://api.notion.com/v1/blocks/{page_id}/children",
            headers=h(token),
            json={"children": [{"type": "image",
                                "image": {"type": "file_upload",
                                        "file_upload": {"id": upload_id}}}]}
        )
    except Exception:
        pass


def set_screenshot_prop(token: str, page_id: str, uploads: list):
    if not uploads:
        return
    files = [{"name": f, "type": "file_upload", "file_upload": {"id": u}} for u, f in uploads]
    _http.patch(f"https://api.notion.com/v1/pages/{page_id}",
                headers=h(token), json={"properties": {"Screenshot": {"files": files}}})


# ══════════════════════════════════════════════════════════════
# TEXT BODY HELPERS
# ──────────────────────────────────────────────────────────────
# Clipped text / article text / full-page text / notes now live in
# the PAGE BODY as blocks, not in database properties. Notion caps a
# single rich_text "content" string at 2000 characters, so long text
# gets chunked into multiple paragraph blocks on paragraph boundaries.
# ══════════════════════════════════════════════════════════════

NOTION_RICH_TEXT_LIMIT = 1800      # chunk size for body text blocks


def chunk_text(text: str, max_len: int = NOTION_RICH_TEXT_LIMIT) -> list:
    """Split text into <=max_len pieces, preferring line/paragraph boundaries."""
    text = (text or "").strip()
    if not text:
        return []
    chunks, current = [], ""
    for para in text.split("\n"):
        candidate = f"{current}\n{para}" if current else para
        if len(candidate) <= max_len:
            current = candidate
            continue
        if current:
            chunks.append(current)
        if len(para) <= max_len:
            current = para
        else:
            # single paragraph longer than the limit — hard-slice it
            for i in range(0, len(para), max_len):
                chunks.append(para[i:i + max_len])
            current = ""
    if current:
        chunks.append(current)
    return chunks


def paragraph_block(text: str) -> dict:
    return {"type": "paragraph",
            "paragraph": {"rich_text": [{"type": "text", "text": {"content": text}}]}}


def heading_block(text: str, level: int = 3) -> dict:
    key = f"heading_{level}"
    return {"type": key, key: {"rich_text": [{"type": "text", "text": {"content": text}}]}}


def divider_block() -> dict:
    return {"type": "divider", "divider": {}}


def text_section_blocks(text: str, heading: str) -> list:
    """Build a heading block + N paragraph blocks for one labelled text section.
    No length cap — the full clipped/article/full-page text is preserved,
    just split across as many paragraph blocks as it takes."""
    chunks = chunk_text(text or "")
    if not chunks:
        return []
    blocks = [heading_block(heading)]
    blocks.extend(paragraph_block(c) for c in chunks)
    return blocks


def append_blocks_in_batches(token: str, page_id: str, blocks: list, batch_size: int = 90):
    """Notion's children-append endpoint caps out around 100 blocks per call."""
    for i in range(0, len(blocks), batch_size):
        batch = blocks[i:i + batch_size]
        try:
            r = _http.patch(
                f"https://api.notion.com/v1/blocks/{page_id}/children",
                headers=h(token), json={"children": batch}
            )
            if not r.ok:
                print(f"      ⚠️  append_blocks batch failed: {r.status_code} {r.text[:200]}")
        except Exception as e:
            print(f"      ❌ append_blocks_in_batches: {e}")


def bulleted_block(text: str) -> dict:
    return {"type": "bulleted_list_item",
            "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": text}}]}}


def build_ordered_body_blocks(token: str, items: list) -> list:
    """
    OPTIONAL path: if the extension sends "content_blocks" — an ordered list
    describing the page exactly as it appears (heading, paragraph, image,
    bullet, image, paragraph, ...) — this builds the Notion body in that exact
    sequence instead of grouping all text first and all images after.

    Each entry in `items` is a dict, e.g.:
        {"type": "heading",   "text": "Random Picker", "level": 2}
        {"type": "paragraph", "text": "Pick random items or images..."}
        {"type": "bullet",    "text": "Image URL Support: Paste image URLs..."}
        {"type": "image",     "b64": "..."}            # or {"type": "image", "url": "..."}
        {"type": "link",      "text": "Embed Random Picker Widget", "url": "https://..."}

    Returns blocks only. These images go into the page BODY ONLY — they are
    NOT collected for the Screenshot property. (Articles have no screenshot;
    fullpage clips get their dedicated screenshot added to the property
    separately, by the caller, from data["screenshot_b64"].)

    SPEED FIX: all image uploads in this list are done CONCURRENTLY via a
    thread pool (these are network-bound calls — fetch + Notion upload — so
    threads give a real speedup despite the GIL). Previously every image was
    fetched/uploaded one-by-one in a simple for-loop, so a page with 10
    images took ~10x as long as one image. Final block order is still
    preserved exactly as the page laid it out.
    """
    # First pass: build the block order, leaving a placeholder slot for images
    plan = []  # list of ("text", block) or ("image", item)
    for item in items:
        if not isinstance(item, dict):
            continue
        itype = (item.get("type") or "paragraph").lower()

        if itype in ("image", "img", "screenshot"):
            plan.append(("image", item))
            continue

        text = (item.get("text") or "").strip()
        if not text:
            continue

        if itype in ("heading", "h1", "h2", "h3", "title"):
            level = item.get("level") or (1 if itype == "h1" else 3 if itype == "h3" else 2)
            level = max(1, min(3, int(level)))
            for c in chunk_text(text):
                plan.append(("text", heading_block(c, level=level)))
        elif itype in ("bullet", "list_item", "li", "bulleted_list_item"):
            for c in chunk_text(text):
                plan.append(("text", bulleted_block(c)))
        elif itype == "link":
            # Standalone link found on the page — rendered as a real clickable
            # hyperlink in the body (not just plain text with a URL pasted in).
            url = (item.get("url") or "").strip()
            chunks = chunk_text(text) or [text[:NOTION_RICH_TEXT_LIMIT]]
            for i, c in enumerate(chunks):
                rich = {"type": "text", "text": {"content": c}}
                if url and i == 0:
                    rich["text"]["link"] = {"url": url}
                plan.append(("text", {"type": "paragraph", "paragraph": {"rich_text": [rich]}}))
        else:  # paragraph / text / default
            for c in chunk_text(text):
                plan.append(("text", paragraph_block(c)))

    # Second pass: upload all images concurrently, keyed by their slot index
    image_slots = [(idx, item) for idx, (kind, item) in enumerate(plan) if kind == "image"]
    uploaded_at = {}

    def _upload_one(idx, item):
        b64 = item.get("b64")
        if not b64 and item.get("url"):
            b64 = fetch_url_as_b64(item["url"])
        if not b64:
            return idx, None
        uid, fname = upload_image(token, b64)
        if not uid:
            return idx, None
        return idx, {"type": "image",
                    "image": {"type": "file_upload", "file_upload": {"id": uid}}}

    if image_slots:
        with ThreadPoolExecutor(max_workers=min(8, len(image_slots))) as ex:
            futures = [ex.submit(_upload_one, idx, item) for idx, item in image_slots]
            for fut in as_completed(futures):
                idx, block = fut.result()
                uploaded_at[idx] = block

    # Third pass: assemble final ordered blocks (drop any image that failed)
    blocks = []
    for idx, (kind, item) in enumerate(plan):
        if kind == "text":
            blocks.append(item)
        else:
            block = uploaded_at.get(idx)
            if block:
                blocks.append(block)

    return blocks


# ══════════════════════════════════════════════════════════════
# /clip
# ══════════════════════════════════════════════════════════════

@app.route("/clip", methods=["POST", "OPTIONS"])
def clip():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    try:
        data = request.get_json()
        if not data:
            return jsonify({"ok": False, "error": "No JSON body"}), 400

        print(f"\n{'='*55}")
        print(f"📌 /clip  type={data.get('type')}  "
            f"title={str(data.get('page_title',''))[:50]}")

        sid, sess = get_session(request)
        token = data.get("token") or (sess["token"] if sess else None)
        db_id = data.get("db_id") or (sess["db_id"] if sess else None)

        if not token or not db_id:
            return jsonify({"ok": False,
                            "error": "Not authenticated. Please login again."}), 401

        # ── Approval gate ───────────────────────────────────────
        status = get_user_status(token=token, db_id=db_id)
        if status != "approved":
            print(f"   ⛔ Clip blocked — user status: {status}")
            return jsonify({
                "ok": False,
                "approval_pending": True,
                "status": status,
                "error": "Your account is pending approval from the admin. "
                        "You'll be able to clip once approved."
            }), 403

        type_map = {
            "text": "Text", "image": "Image", "both": "Both",
            "fullpage": "Fullpage", "article": "Article",
            "link": "Link", "bookmark": "Bookmark",
            "collection": "Image", "simplified": "Article"
        }
        ntype        = type_map.get((data.get("type") or "text").lower(), "Text")
        # Full text content (clipped text / article / full-page text) and notes
        # now go into the PAGE BODY, not properties — no more 2000-char truncation here.
        clipped_text = data.get("clipped_text") or ""
        note         = data.get("note") or ""
        tags         = [t for t in (data.get("tags") or []) if t]

        # Properties stay lightweight — just metadata for sorting/filtering.
        props = {
            "Name":         {"title": [{"text": {"content": (data.get("page_title") or "Untitled")[:100]}}]},
            "URL":          {"url": data.get("page_url") or ""},
            "Clipped Date": {"date": {"start": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")}},
            "Type":         {"select": {"name": ntype}},
            "Tags":         {"multi_select": [{"name": t} for t in tags]},
        }

        pr = _http.post("https://api.notion.com/v1/pages",
                        headers=h(token),
                        json={"parent": {"database_id": db_id}, "properties": props})

        if pr.status_code not in (200, 201):
            print(f"❌ Page create: {pr.text[:300]}")
            if pr.status_code in (401, 403):
                return jsonify({"ok": False, "reauth_required": True,
                                "error": "Authorization expired. Please login again."}), 401
            if pr.status_code == 404:
                return jsonify({"ok": False, "reauth_required": True,
                                "error": "Database not found. Please reconnect."}), 404
            return jsonify({"ok": False, "error": pr.text}), 500

        page    = pr.json()
        page_id = page["id"]
        page_url= page.get("url", "")
        print(f"   ✅ Page created: {page_id}")

        # ── Body content ─────────────────────────────────────────
        # Two paths:
        #  1) Extension sends "content_blocks" (ordered list matching the
        #     website's actual layout) → build body in that EXACT sequence:
        #     text, image, text, image... as it appears on the page.
        #     These images go to the BODY ONLY (uploaded concurrently — see
        #     build_ordered_body_blocks). If the request also includes a
        #     dedicated "screenshot_b64" (fullpage clips), that single image
        #     is uploaded separately, IN PARALLEL with the body build, and is
        #     the ONLY thing that goes into the Screenshot property. Articles
        #     send no screenshot_b64, so their images never touch the property.
        #  2) Otherwise → previous behavior is preserved as-is, just with the
        #     order flipped to image-first for fullpage/both/screenshot clips
        #     (so a full-page screenshot clip shows the image, then the text).
        all_uploads = []
        content_blocks_input = data.get("content_blocks")

        if content_blocks_input and isinstance(content_blocks_input, list):
            with ThreadPoolExecutor(max_workers=2) as ex:
                blocks_future = ex.submit(build_ordered_body_blocks, token, content_blocks_input)
                screenshot_future = None
                if data.get("screenshot_b64"):
                    screenshot_future = ex.submit(upload_image, token, data["screenshot_b64"])

                ordered_blocks = blocks_future.result()
                if ordered_blocks:
                    append_blocks_in_batches(token, page_id, ordered_blocks)
                    print(f"   ✅ Ordered body appended ({len(ordered_blocks)} blocks, "
                        f"website sequence preserved)")

                if screenshot_future:
                    uid, fname = screenshot_future.result()
                    if uid:
                        all_uploads.append((uid, fname))
                        print("   ✅ Screenshot uploaded to Screenshot property")

        else:
            def _append_text_body():
                body_blocks = []
                if clipped_text.strip():
                    body_blocks += text_section_blocks(clipped_text, "📝 Clipped Content")
                if note.strip():
                    if body_blocks:
                        body_blocks.append(divider_block())
                    body_blocks += text_section_blocks(note, "🗒️ Note")
                if body_blocks:
                    append_blocks_in_batches(token, page_id, body_blocks)
                    print(f"   ✅ Body text appended ({len(body_blocks)} blocks)")

            def _append_images():
                img_list = data.get("image_list")
                uploaded = []  # (uid, fname) collected from concurrent uploads, in order

                if img_list and isinstance(img_list, list):
                    targets = img_list[:5]
                    with ThreadPoolExecutor(max_workers=min(8, len(targets) or 1)) as ex:
                        results = list(ex.map(lambda b64: upload_image(token, b64), targets))
                    uploaded.extend(results)
                elif data.get("screenshot_b64"):
                    uploaded.append(upload_image(token, data["screenshot_b64"]))

                # Extra images — covers any other image/screenshot the extension sends
                # (e.g. inline article images, image URLs) via "images" / "image_urls".
                extra_b64s = collect_extra_image_b64s(data)[:15]
                if extra_b64s:
                    with ThreadPoolExecutor(max_workers=min(8, len(extra_b64s))) as ex:
                        extra_results = list(ex.map(lambda b64: upload_image(token, b64), extra_b64s))
                    uploaded.extend(extra_results)

                for uid, fname in uploaded:
                    if uid:
                        all_uploads.append((uid, fname))
                        append_image_block(token, page_id, uid)       # → body

            raw_type = (data.get("type") or "").lower()
            if raw_type in ("fullpage", "both", "screenshot"):
                _append_images()   # image first…
                _append_text_body()  # …then text
            else:
                _append_text_body()
                _append_images()

        if all_uploads:
            set_screenshot_prop(token, page_id, all_uploads)  # → property

        return jsonify({"ok": True, "page_id": page_id, "page_url": page_url,
                        "title": data.get("page_title", "Untitled"), "type": ntype})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# DELETE PAGE
# ══════════════════════════════════════════════════════════════

@app.route("/delete-page", methods=["POST", "OPTIONS"])
def delete_page():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    try:
        data  = request.get_json()
        sid, sess = get_session(request)
        token = data.get("token") or (sess["token"] if sess else None)
        pid   = data.get("page_id")
        if not token or not pid:
            return jsonify({"ok": False, "error": "Missing params"}), 400
        r = _http.patch(f"https://api.notion.com/v1/pages/{pid}",
                        headers=h(token), json={"archived": True})
        return jsonify({"ok": r.status_code == 200})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════

@app.route("/fetch-image", methods=["POST", "OPTIONS"])
def fetch_image():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    try:
        url = (request.get_json() or {}).get("url", "")
        if not url:
            return jsonify({"error": "Missing url"}), 400
        r = _http.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        return jsonify({"b64": base64.b64encode(r.content).decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stitch-screenshots", methods=["POST", "OPTIONS"])
def stitch_screenshots():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    try:
        data   = request.get_json() or {}
        shots  = data.get("screenshots", [])
        images = [Image.open(io.BytesIO(base64.b64decode(
            s["b64"].split(",")[1] if "data:" in s["b64"] else s["b64"]
        ))) for s in shots]
        if not images:
            return jsonify({"error": "No images"}), 400
        total_h = data.get("total_height", 0) or sum(i.height for i in images)
        canvas  = Image.new("RGB", (images[0].width, total_h), "white")
        y = 0
        for img in images:
            canvas.paste(img, (0, y)); y += img.height
        out = io.BytesIO()
        canvas.save(out, format="PNG")
        return jsonify({"b64": base64.b64encode(out.getvalue()).decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def index():
    return jsonify({"status": "Web Clipper running", "version": "4.0.0"})


# ══════════════════════════════════════════════════════════════
# ADMIN API  — approve / reject / list users
# ══════════════════════════════════════════════════════════════

@app.route("/admin/users")
def admin_users():
    if not is_admin(request):
        return jsonify({"error": "unauthorized"}), 401
    users = load_users()
    out = []
    for uid, u in users.items():
        out.append({
            "user_id": uid,
            "name":    u.get("name", "Unknown"),
            "workspace_name": u.get("workspace_name") or u.get("name", "Unknown"),
            "db_id":   u.get("db_id", ""),
            "status":  u.get("status", "pending")
        })
    out.sort(key=lambda x: x["name"].lower())
    return jsonify({"users": out})


@app.route("/admin/approve", methods=["POST", "OPTIONS"])
def admin_approve():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    if not is_admin(request):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json() or {}
    uid  = data.get("user_id")
    users = load_users()
    if uid not in users:
        return jsonify({"ok": False, "error": "User not found"}), 404
    users[uid]["status"] = "approved"
    save_users(users)
    print(f"✅ Admin approved user: {users[uid].get('name')} ({uid})")
    return jsonify({"ok": True})


@app.route("/admin/reject", methods=["POST", "OPTIONS"])
def admin_reject():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    if not is_admin(request):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json() or {}
    uid  = data.get("user_id")
    users = load_users()
    if uid not in users:
        return jsonify({"ok": False, "error": "User not found"}), 404
    users[uid]["status"] = "rejected"
    save_users(users)
    print(f"⛔ Admin rejected user: {users[uid].get('name')} ({uid})")
    return jsonify({"ok": True})


@app.route("/admin/revoke", methods=["POST", "OPTIONS"])
def admin_revoke():
    """Move an approved user back to pending (revoke access)."""
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    if not is_admin(request):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json() or {}
    uid  = data.get("user_id")
    users = load_users()
    if uid not in users:
        return jsonify({"ok": False, "error": "User not found"}), 404
    users[uid]["status"] = "pending"
    save_users(users)
    print(f"↩️  Admin revoked user: {users[uid].get('name')} ({uid})")
    return jsonify({"ok": True})


# @app.route("/admin/delete", methods=["POST", "OPTIONS"])
# def admin_delete():
#     if request.method == "OPTIONS":
#         return jsonify({"ok": True})
#     if not is_admin(request):
#         return jsonify({"error": "unauthorized"}), 401
#     data = request.get_json() or {}
#     uid  = data.get("user_id")
#     users = load_users()
#     if uid in users:
#         del users[uid]
#         save_users(users)
#     return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════
# ADMIN DASHBOARD  — served at /admin
# ══════════════════════════════════════════════════════════════

@app.route("/admin")
def admin_dashboard():
    return ADMIN_DASHBOARD_HTML


ADMIN_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Dashboard</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22 font-size=%2280%22><text y=%2275%22>%F0%9F%9A%80</text></svg>">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0f1a;color:#e8e6f0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:18px 28px;background:#11131f;border-bottom:1px solid #20232f}
.topbar h1{font-size:1.15rem;font-weight:700;display:flex;align-items:center;gap:10px}
.live{display:flex;align-items:center;gap:14px;color:#7a7890;font-size:.8rem}
.dot{width:8px;height:8px;border-radius:50%;background:#2ecc71;display:inline-block;margin-right:6px;box-shadow:0 0 8px #2ecc71}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}
.card{background:#151827;border:1px solid #20232f;border-radius:12px;padding:18px}
.card .label{font-size:.7rem;color:#7a7890;text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px}
.card .num{font-size:2rem;font-weight:800;margin-bottom:4px}
.card .sub{font-size:.78rem;color:#7a7890}
.num.blue{color:#6c63ff}.num.green{color:#2ecc71}.num.orange{color:#f5a623}.num.red{color:#e74c3c}.num.gray{color:#9aa0c0}
.tabs{display:flex;gap:6px;border-bottom:1px solid #20232f;margin-bottom:16px}
.tab{padding:10px 18px;background:transparent;border:none;color:#7a7890;font-size:.85rem;font-weight:600;cursor:pointer;border-radius:8px 8px 0 0;display:flex;align-items:center;gap:8px}
.tab.active{color:#fff;background:#151827}
.badge{background:#e74c3c;color:#fff;font-size:.7rem;padding:1px 7px;border-radius:10px;font-weight:700}
.badge.zero{background:#2a2d3d;color:#7a7890}
.search{width:100%;padding:12px 14px;background:#151827;border:1px solid #20232f;border-radius:8px;color:#fff;font-size:.85rem;margin-bottom:16px;outline:none}
.search:focus{border-color:#6c63ff}
table{width:100%;border-collapse:collapse;background:#151827;border:1px solid #20232f;border-radius:12px;overflow:hidden}
th{text-align:left;padding:12px 16px;font-size:.7rem;color:#7a7890;text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid #20232f}
td{padding:14px 16px;font-size:.85rem;border-bottom:1px solid #1c1f2d}
tr:last-child td{border-bottom:none}
.uid{font-family:monospace;font-size:.72rem;color:#7a7890}
.status-pill{padding:3px 10px;border-radius:100px;font-size:.72rem;font-weight:600;display:inline-block}
.status-pill.pending{background:rgba(245,166,35,.15);color:#f5a623;border:1px solid rgba(245,166,35,.3)}
.status-pill.approved{background:rgba(46,204,113,.15);color:#2ecc71;border:1px solid rgba(46,204,113,.3)}
.status-pill.rejected{background:rgba(231,76,60,.15);color:#e74c3c;border:1px solid rgba(231,76,60,.3)}
.actions{display:flex;gap:8px}
.btn{padding:7px 14px;border:none;border-radius:6px;font-size:.78rem;font-weight:600;cursor:pointer;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn.approve{background:#2ecc71;color:#0d1f14}
.btn.reject{background:#e74c3c;color:#fff}
.btn.revoke{background:#2a2d3d;color:#f5a623}
.empty{text-align:center;padding:60px 20px;color:#7a7890}
.empty .emoji{font-size:2.6rem;margin-bottom:12px}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-card{background:#151827;border:1px solid #20232f;border-radius:16px;padding:40px;width:340px;text-align:center}
.login-card h2{margin-bottom:18px}
.login-card input{width:100%;padding:12px;background:#0d0f1a;border:1px solid #20232f;border-radius:8px;color:#fff;margin-bottom:14px;outline:none;font-size:.9rem}
.login-card input:focus{border-color:#6c63ff}
.login-card button{width:100%;padding:12px;background:#6c63ff;color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-size:.9rem}
.err{color:#e74c3c;font-size:.78rem;margin-top:10px;min-height:16px}
</style></head>
<body>

<div id="login-screen" class="login-wrap">
  <div class="login-card">
    <h2>🔐 Admin Login</h2>
    <input type="password" id="admin-key-input" placeholder="Enter admin key" onkeydown="if(event.key === 'Enter') adminLogin()" />
    <button onclick="adminLogin()">Enter Dashboard</button>
    <div class="err" id="login-err"></div>
  </div>
</div>

<div id="dashboard" style="display:none">
  <div class="topbar">
    <h1>🧷 Web Clipper Dashboard</h1>
    <div class="live"><span><span class="dot"></span>Live</span><span id="updated-at"></span></div>
  </div>

  <div class="wrap">
    <div class="cards">
      <div class="card"><div class="label">Total Users</div><div class="num blue" id="c-total">0</div><div class="sub">All time</div></div>
      <div class="card"><div class="label">Approved</div><div class="num green" id="c-approved">0</div><div class="sub">Active access</div></div>
      <div class="card"><div class="label">Pending</div><div class="num orange" id="c-pending">0</div><div class="sub">Awaiting approval</div></div>
      <div class="card"><div class="label">Rejected</div><div class="num red" id="c-rejected">0</div><div class="sub">Declined</div></div>
    </div>

    <div class="tabs">
      <button class="tab active" data-tab="all" onclick="setTab('all')">All Users <span class="badge zero" id="tab-badge-all">0</span></button>
      <button class="tab" data-tab="pending" onclick="setTab('pending')">Pending <span class="badge" id="tab-badge-pending">0</span></button>
      <button class="tab" data-tab="approved" onclick="setTab('approved')">Approved <span class="badge zero" id="tab-badge-approved">0</span></button>
      <button class="tab" data-tab="rejected" onclick="setTab('rejected')">Rejected <span class="badge zero" id="tab-badge-rejected">0</span></button>
    </div>

    <input class="search" id="search-box" placeholder="Search name, user ID, or database ID…" oninput="renderTable()" />

    <table>
      <thead><tr><th>User</th><th>User ID</th><th>Database ID</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody id="table-body"></tbody>
    </table>
  </div>
</div>

<script>
let ADMIN_KEY = sessionStorage.getItem("wc_admin_key") || "";
let currentTab = "all";
let allUsers = [];

if (ADMIN_KEY) showDashboard();

function adminLogin() {
  const key = document.getElementById("admin-key-input").value.trim();
  if (!key) return;
  ADMIN_KEY = key;
  fetchUsers().then(ok => {
    if (ok) {
      sessionStorage.setItem("wc_admin_key", key);
      showDashboard();
    } else {
      document.getElementById("login-err").textContent = "Invalid admin key.";
    }
  });
}

function showDashboard() {
  document.getElementById("login-screen").style.display = "none";
  document.getElementById("dashboard").style.display = "block";
  refresh();
  setInterval(refresh, 8000);
}

async function fetchUsers() {
  try {
    const res = await fetch(`/admin/users?key=${encodeURIComponent(ADMIN_KEY)}`);
    if (!res.ok) return false;
    const data = await res.json();
    allUsers = data.users || [];
    return true;
  } catch (e) { return false; }
}

async function refresh() {
  const ok = await fetchUsers();
  if (!ok) return;
  renderCards();
  renderTable();
  document.getElementById("updated-at").textContent =
    "Updated " + new Date().toLocaleTimeString();
}

function renderCards() {
  const total    = allUsers.length;
  const approved = allUsers.filter(u => u.status === "approved").length;
  const pending  = allUsers.filter(u => u.status === "pending").length;
  const rejected = allUsers.filter(u => u.status === "rejected").length;

  document.getElementById("c-total").textContent = total;
  document.getElementById("c-approved").textContent = approved;
  document.getElementById("c-pending").textContent = pending;
  document.getElementById("c-rejected").textContent = rejected;

  setBadge("tab-badge-pending", pending);
  setBadge("tab-badge-approved", approved);
  setBadge("tab-badge-rejected", rejected);
  setBadge("tab-badge-all", total);
}

function setBadge(id, val) {
  const el = document.getElementById(id);
  el.textContent = val;
  el.classList.toggle("zero", val === 0);
}

function setTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
  renderTable();
}

function maskId(id) {
  if (!id || id.length <= 10) return id || "";
  return id.slice(0, 6) + "••••••••" + id.slice(-4);
}

function renderTable() {
  const q = (document.getElementById("search-box").value || "").toLowerCase();
  let rows = allUsers;
  if (currentTab !== "all") rows = rows.filter(u => u.status === currentTab);
  if (q) rows = rows.filter(u =>
    u.name.toLowerCase().includes(q) ||
    (u.workspace_name || "").toLowerCase().includes(q) ||
    u.user_id.toLowerCase().includes(q) ||
    (u.db_id || "").toLowerCase().includes(q));

  const tbody = document.getElementById("table-body");
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty"><div class="emoji">👀</div>
      No ${currentTab === 'all' ? '' : currentTab} users found</div></td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(u => `
    <tr>
      <td>${escapeHtml(u.workspace_name || u.name)}</td>
      <td class="uid masked" data-full="${escapeHtml(u.user_id)}" onclick="toggleId(this)" title="Click to reveal / copy">${maskId(u.user_id)}</td>
      <td class="uid masked" data-full="${escapeHtml(u.db_id)}" onclick="toggleId(this)" title="Click to reveal / copy">${maskId(u.db_id)}</td>
      <td><span class="status-pill ${u.status}">${u.status}</span></td>
      <td><div class="actions">${actionButtons(u)}</div></td>
    </tr>
  `).join("");
}

function toggleId(el) {
  if (el.classList.contains("masked")) {
    el.textContent = el.dataset.full;
    el.classList.remove("masked");
    navigator.clipboard && navigator.clipboard.writeText(el.dataset.full);
    el.classList.add("copied");
    setTimeout(() => el.classList.remove("copied"), 600);
  } else {
    el.textContent = maskId(el.dataset.full);
    el.classList.add("masked");
  }
}
function actionButtons(u) {
  let btns = "";
  if (u.status !== "approved") btns += `<button class="btn approve" onclick="act('approve','${u.user_id}')">Approve</button>`;
  if (u.status !== "rejected") btns += `<button class="btn reject" onclick="act('reject','${u.user_id}')">Reject</button>`;
  if (u.status === "approved") btns += `<button class="btn revoke" onclick="act('revoke','${u.user_id}')">Revoke</button>`;
  return btns;
}

async function act(action, userId) {
  await fetch(`/admin/${action}`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ key: ADMIN_KEY, user_id: userId })
  });
  refresh();
}

function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
</script>
</body></html>"""


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 Web Clipper v4.0")
    print("="*60)
    print("  Login page:  http://127.0.0.1:5001/login-page")
    print("  Auth poll:   http://127.0.0.1:5001/auth/latest")
    print()
    print("  ⚠️  In your Notion integration settings,")
    print("  the redirect URI MUST be your ngrok URL + /auth/callback")
    print("  e.g.  https://xxxx.ngrok-free.app/auth/callback")
    print()
    print("  The server auto-detects this from the Host header —")
    print("  REDIRECT_URI in .env is only needed for production.")
    print("="*60 + "\n")
    # app.run(host="0.0.0.0", port=5001, debug=True)
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)