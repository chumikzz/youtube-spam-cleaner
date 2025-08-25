# -*- coding: utf-8 -*-
"""
Judiclean (Discord Logging + Debug v2)
- Adds proper headers (User-Agent, Accept) to bypass Cloudflare 1010.
- Falls back to discordapp.com domain if 403/1010 happens.
- Includes /debug endpoints to test quickly.
"""
import os
import re
import json
import unicodedata
from datetime import datetime
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from flask import Flask, redirect, request, session, url_for, render_template, jsonify
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base
# === imports tambahan untuk SaaS MVP ===
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from cryptography.fernet import Fernet
import base64, hashlib
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from werkzeug.middleware.proxy_fix import ProxyFix

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")
CRON_KEY = os.getenv("CRON_KEY", "change-this")
BAN_AUTHOR = os.getenv("BAN_AUTHOR", "0") in ("1","true","True","yes","on")
LOG_WEBHOOK_URL = os.getenv("LOG_WEBHOOK_URL", "").strip()
LOG_WEBHOOK_DEBUG = os.getenv("LOG_WEBHOOK_DEBUG", "0") in ("1","true","True","yes","on")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/youtube.force-ssl",
]

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///local.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(PREFERRED_URL_SCHEME="https", SESSION_COOKIE_SECURE=True)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String(255))
    channel_id = Column(String(64))
    channel_title = Column(String(255))
    refresh_token = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scan_at = Column(DateTime, nullable=True)
    last_scan_summary = Column(Text, nullable=True)
# ======== MULTI-USER MODELS (SaaS MVP) ========

def _fernet():
    # turunkan SECRET_KEY jadi 32 bytes agar valid untuk Fernet
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True)
    name = Column(String(255))
    avatar = Column(String(512))
    created_at = Column(DateTime, default=datetime.utcnow)

    connections = relationship("Connection", back_populates="user", cascade="all,delete")
    settings = relationship("Setting", back_populates="user", uselist=False, cascade="all,delete")

class Connection(Base):
    __tablename__ = "connections"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    provider = Column(String(32), default="google")
    channel_id = Column(String(64), index=True)
    channel_title = Column(String(255))
    refresh_token_enc = Column(Text)   # disimpan terenkripsi
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scan_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="connections")

    # helper simpan/ambil token terenkripsi
    def set_refresh_token(self, token: str):
        self.refresh_token_enc = _fernet().encrypt(token.encode()).decode()

    def get_refresh_token(self) -> str:
        return _fernet().decrypt(self.refresh_token_enc.encode()).decode()

class Setting(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    keywords = Column(Text)                          # JSON string list
    discord_webhook = Column(String(512), nullable=True)
    ban_author = Column(Integer, default=0)          # 0/1
    schedule = Column(String(32), default="manual")  # manual/hourly/3h/daily
    plan = Column(String(32), default="free")        # free/pro/creator/agency

    user = relationship("User", back_populates="settings")

# ======== END MULTI-USER MODELS ========

Base.metadata.create_all(engine)
# imports tambahan
from functools import wraps

def db():
    """Dapatkan sesi DB baru dari SessionLocal."""
    return SessionLocal()

def login_required(fn):
    """Proteksi route: wajib sudah login (punya session['uid'])."""
    @wraps(fn)
    def _wrap(*a, **kw):
        if "uid" not in session:
            return redirect(url_for("index"))  # ganti 'index' kalau nama view-mu beda
        return fn(*a, **kw)
    return _wrap

KEYWORDS = [
    'pulau', 'pulauwin', 'pluto', 'plut088', 'pluto88', 'probet855',
    'mona', 'mona4d', 'alexis17', 'istanabet17', 'mudahwin',
    'akunpro', 'voli4d', 'maxwin', 'pulau777', 'weton88',
    'plutowin', 'plutowinn', 'pluto8', 'pulowin', 'pulauw', 'plu88',
    'pulautoto', 'tempatnyaparapemenangsejatiberkumpul',
    'bahkandilaguremix', 'bergabunglahdenganpulau777',
    '퓟퓤퓛퓐퓤퓦퓘퓝', '홿횄홻홰횄횆홸홽'
]
KEYWORD_REGEX = re.compile("(" + "|".join(re.escape(k) for k in KEYWORDS) + ")", re.IGNORECASE)

def normalize_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s or "")

def is_spam(text: str) -> bool:
    return bool(KEYWORD_REGEX.search(normalize_text(text)))

def get_flow():
    if not (CLIENT_ID and CLIENT_SECRET):
        raise RuntimeError("Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET")
    redirect_uri = OAUTH_REDIRECT_URI or urljoin(request.host_url, "oauth/callback")
    config = {"web": {
        "client_id": CLIENT_ID,
        "project_id": "youtube-public-bot",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_secret": CLIENT_SECRET,
        "redirect_uris": [redirect_uri],
        "javascript_origins": [request.host_url.rstrip("/")],
    }}
    return Flow.from_client_config(config, scopes=SCOPES, redirect_uri=redirect_uri)

def yt_from_refresh(refresh_token: str):
    creds = Credentials(
        None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=SCOPES,
    )
    return build("youtube", "v3", credentials=creds)

def list_channel_threads(yt, channel_id: str, max_threads=300):
    page_token = None
    scanned = 0
    while True:
        req = yt.commentThreads().list(
            part="snippet,replies",
            allThreadsRelatedToChannelId=channel_id,
            maxResults=100,
            textFormat="plainText",
            order="time",
            pageToken=page_token
        )
        resp = req.execute()
        for item in resp.get("items", []):
            scanned += 1
            yield item
            if scanned >= max_threads:
                return
        page_token = resp.get("nextPageToken")
        if not page_token: break

def iter_comments(thread):
    top = thread["snippet"]["topLevelComment"]
    yield (top["id"], top["snippet"].get("textDisplay", ""), top["snippet"].get("authorDisplayName", ""), False)
    for r in thread.get("replies", {}).get("comments", []):
        yield (r["id"], r["snippet"].get("textDisplay", ""), r["snippet"].get("authorDisplayName", ""), True)

def remove_comment(yt, cid: str):
    try:
        yt.comments().setModerationStatus(id=cid, moderationStatus="rejected", banAuthor=bool(BAN_AUTHOR)).execute()
        return "rejected"
    except HttpError:
        try:
            yt.comments().markAsSpam(id=cid).execute()
            return "marked_spam"
        except HttpError:
            yt.comments().delete(id=cid).execute()
            return "deleted"

def _truncate(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"

def _discord_embed(summary: dict) -> dict:
    ch_title = summary.get("channel_title", "Unknown")
    ch_id = summary.get("channel_id", "")
    url = f"https://www.youtube.com/channel/{ch_id}" if ch_id else None
    fields = [
        {"name":"Scanned","value":str(summary.get("scanned",0)),"inline":True},
        {"name":"Flagged","value":str(summary.get("flagged",0)),"inline":True},
        {"name":"Rejected","value":str(summary.get("rejected",0)),"inline":True},
        {"name":"Spam","value":str(summary.get("marked_spam",0)),"inline":True},
        {"name":"Deleted","value":str(summary.get("deleted",0)),"inline":True},
        {"name":"Errors","value":str(summary.get("errors",0)),"inline":True},
    ]
    examples = summary.get("examples", [])[:3]
    if examples:
        ex_lines = []
        for ex in examples:
            who = ex.get("author","anon")
            text = _truncate(ex.get("text",""), 180)
            action = ex.get("action","?")
            ex_lines.append(f"**{who}** — _{action}_\n{text}")
        fields.append({"name":"Examples","value":_truncate("\n\n".join(ex_lines),1000),"inline":False})
    kw = summary.get("keywords_used")
    if kw:
        fields.append({"name":"Keywords","value":_truncate(", ".join(kw),1000),"inline":False})
    return {
        "title": "Judiclean — Scan Result",
        "description": f"Channel: **{ch_title}**",
        "url": url,
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "color": 0x2ecc71 if summary.get("errors",0)==0 else 0xe74c3c,
        "fields": fields,
        "footer": {"text":"Judiclean"},
    }

def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Browser-like UA to avoid Cloudflare 1010
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36 Judiclean/1.0"
    }
    req = Request(url, data=data, headers=headers)
    try:
        with urlopen(req, timeout=10) as r:
            status = r.getcode()
            body = r.read()[:500].decode("utf-8","ignore")
    except HTTPError as e:
        status = e.code
        body = e.read()[:500].decode("utf-8","ignore")
    except URLError as e:
        status = 0
        body = str(e)
    if LOG_WEBHOOK_DEBUG:
        print(f"[WEBHOOK] status={status} body-error code: {body[:50]}")
    return {"status": status, "body": body}

def _send_webhook(summary: dict):
    if not LOG_WEBHOOK_URL:
        if LOG_WEBHOOK_DEBUG: print("[WEBHOOK] LOG_WEBHOOK_URL not set")
        return
    # prefer wait=true for JSON response
    url = LOG_WEBHOOK_URL
    if "wait=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}wait=true"
    # try main domain first
    resp = _post_json(url, {"content":"", "embeds":[_discord_embed(summary)], "allowed_mentions":{"parse":[]}})
    # on Cloudflare 403 1010, try alternate discordapp.com domain and plain text fallback
    if resp["status"] == 403 and "1010" in resp["body"]:
        alt = url.replace("https://discord.com", "https://discordapp.com")
        resp2 = _post_json(alt, {"content":"", "embeds":[_discord_embed(summary)], "allowed_mentions":{"parse":[]}})
        if not (200 <= resp2["status"] < 300 or resp2["status"] == 204):
            txt = f"Judiclean — {summary.get('channel_title')} | scanned={summary.get('scanned')} flagged={summary.get('flagged')} rejected={summary.get('rejected')} spam={summary.get('marked_spam')} deleted={summary.get('deleted')}"
            _post_json(alt, {"content": txt, "allowed_mentions": {"parse":[]}})
    elif not (200 <= resp["status"] < 300 or resp["status"] == 204):
        # generic fallback if not 403/1010
        txt = f"Judiclean — {summary.get('channel_title')} | scanned={summary.get('scanned')} flagged={summary.get('flagged')} rejected={summary.get('rejected')} spam={summary.get('marked_spam')} deleted={summary.get('deleted')}"
        _post_json(url, {"content": txt, "allowed_mentions": {"parse":[]}})

@app.get("/")
def index():
    acc_id = session.get("acc_id")
    if not acc_id:
        return render_template("index.html")
    with SessionLocal() as db:
        acc = db.get(Account, acc_id)
        last = {}
        try:
            last = json.loads(acc.last_scan_summary) if acc.last_scan_summary else {}
        except Exception:
            last = {}
        return render_template("dashboard.html", acc=acc, last=last)

@app.get("/auth/login")
def auth_login():
    flow = get_flow()
    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    session["state"] = state
    return redirect(auth_url)

@app.get("/oauth/callback")
def oauth_callback():
    try:
        flow = get_flow()
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
    except Exception as e:
        return f"OAuth error while fetching token: {e}", 400
    try:
        refresh_token = creds.refresh_token
        if not refresh_token:
            return "No refresh_token received; remove previous consent and login again.", 400
        yt = build("youtube", "v3", credentials=creds)
        ch = yt.channels().list(part="id,snippet", mine=True).execute()
    except Exception as e:
        return f"YouTube API error: {e}", 400
    items = ch.get("items", [])
    if not items: return "Tidak dapat mengambil channel dari akun ini.", 400
    channel_id = items[0]["id"]
    channel_title = items[0]["snippet"]["title"]
    from sqlalchemy import select
    with SessionLocal() as db:
        row = db.execute(select(Account).where(Account.channel_id==channel_id)).scalar_one_or_none()
        if row:
            row.channel_title = channel_title
            row.refresh_token = refresh_token
            db.commit()
            acc = row
        else:
            acc = Account(email="user", channel_id=channel_id, channel_title=channel_title, refresh_token=refresh_token)
            db.add(acc); db.commit()
        session["acc_id"] = acc.id
    return redirect(url_for("index"))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.post("/scan")
@login_required
def scan_my_channel():
    acc_id = session["acc_id"]  # sudah dijamin ada oleh @login_required

    with SessionLocal() as db:
        acc = db.get(Account, acc_id)
        if not acc:
            return jsonify({"error": "Account not found"}), 404

        yt = yt_from_refresh(acc.refresh_token)

        flagged = []
        removed = {"rejected": 0, "marked_spam": 0, "deleted": 0, "errors": 0}
        scanned = 0

        for thread in list_channel_threads(yt, acc.channel_id):
            for cid, text, author, is_reply in iter_comments(thread):
                scanned += 1
                if is_spam(text):
                    item = {
                        "comment_id": cid,
                        "author": author,
                        "text": text[:200],
                        "is_reply": is_reply,
                    }
                    try:
                        how = remove_comment(yt, cid)
                        item["action"] = how
                        removed[how] = removed.get(how, 0) + 1
                    except Exception as e:
                        removed["errors"] += 1
                        item["delete_error"] = str(e)
                    flagged.append(item)

        summary = {
            "channel_id": acc.channel_id,
            "channel_title": acc.channel_title,
            "scanned": scanned,
            "flagged": len(flagged),
            **removed,
            "examples": flagged[:10],
            "ts": datetime.utcnow().isoformat() + "Z",
            "keywords_used": KEYWORDS,
        }

        # simpan hasil scan ke DB
        acc.last_scan_at = datetime.utcnow()
        acc.last_scan_summary = json.dumps(summary)
        db.commit()

    # (opsional) kirim notifikasi ke Discord
    _send_webhook(summary)

    return jsonify(summary)

@app.get("/debug/ping_webhook")
def debug_ping():
    demo = {
        "channel_id": "demo",
        "channel_title": "DEMO",
        "scanned": 10,
        "flagged": 2,
        "rejected": 2,
        "marked_spam": 0,
        "deleted": 0,
        "errors": 0,
        "examples": [{"author":"spammer","text":"pluto88 maxwin","action":"rejected"}],
        "ts": datetime.utcnow().isoformat()+"Z",
        "keywords_used": KEYWORDS[:5],
    }
    _send_webhook(demo)
    return jsonify({"ok": True, "sent": True, "webhook_set": bool(LOG_WEBHOOK_URL)})

@app.get("/debug/show_env")
def debug_env():
    return jsonify({
        "LOG_WEBHOOK_URL_set": bool(LOG_WEBHOOK_URL),
        "LOG_WEBHOOK_DEBUG": LOG_WEBHOOK_DEBUG,
        "BAN_AUTHOR": BAN_AUTHOR,
    })
# --- debug: lihat tabel di DB ---
from sqlalchemy import inspect

@app.route("/debug/db_tables", methods=["GET"])
def debug_db_tables():
    try:
        insp = inspect(engine)
        return jsonify({"tables": insp.get_table_names()}), 200
    except Exception as e:
        return jsonify({"error": type(e).__name__, "message": str(e)}), 500

@app.get("/health")
def health():
    return jsonify({"ok": True})

if __name__ == "__main__":
    if os.getenv("ENV", "dev") == "dev":
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
