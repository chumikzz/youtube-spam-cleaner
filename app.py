# -*- coding: utf-8 -*-
import os
import re
import json
import unicodedata
from datetime import datetime
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from flask import Flask, redirect, request, session, url_for, render_template, jsonify
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base
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

# Trust Railway proxy & prefer HTTPS
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

Base.metadata.create_all(engine)

# === KEYWORDS-ONLY MATCHING ===
KEYWORDS = [
    'pulau', 'pulauwin', 'pluto', 'plut088', 'pluto88', 'probet855',
    'mona', 'mona4d', 'alexis17', 'soundeffect', 'mudahwin',
    'akunpro', '혗혜혓혈혜혞혐형', 'maxwin', 'pulau777', 'weton88',
    'plutowin', 'plutowinn', 'pluto8', 'pulowin', 'pulauw', 'plu88',
    'pulautoto', 'tempatnyaparapemenangsejatiberkumpul',
    'doyokjp', 'bergabunglahdenganpulau777',
    '퓟퓤퓛퓐퓤퓦퓘퓝', '홿횄홻홰횄횆홸홽'
]
KEYWORDS = [k.strip() for k in KEYWORDS if k.strip()]
KEYWORD_REGEX = re.compile("(" + "|".join(re.escape(k) for k in KEYWORDS) + ")", re.IGNORECASE)

def normalize_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s or "")

def is_spam(text: str) -> bool:
    return bool(KEYWORD_REGEX.search(normalize_text(text)))

def get_flow():
    if not (CLIENT_ID and CLIENT_SECRET):
        raise RuntimeError("Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET")
    redirect_uri = OAUTH_REDIRECT_URI or urljoin(request.host_url, "oauth/callback")
    config = {
        "web": {
            "client_id": CLIENT_ID,
            "project_id": "youtube-public-bot",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_secret": CLIENT_SECRET,
            "redirect_uris": [redirect_uri],
            "javascript_origins": [request.host_url.rstrip("/")],
        }
    }
    flow = Flow.from_client_config(config, scopes=SCOPES, redirect_uri=redirect_uri)
    return flow

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
        if not page_token:
            break

def iter_comments(thread):
    top = thread["snippet"]["topLevelComment"]
    yield (top["id"], top["snippet"].get("textDisplay", ""), top["snippet"].get("authorDisplayName", ""), False)
    for r in thread.get("replies", {}).get("comments", []):
        yield (r["id"], r["snippet"].get("textDisplay", ""), r["snippet"].get("authorDisplayName", ""), True)

def remove_comment(yt, cid: str):
    # Prefer moderation (rejected) -> then markAsSpam -> delete
    try:
        yt.comments().setModerationStatus(
            id=cid, moderationStatus="rejected", banAuthor=bool(BAN_AUTHOR)
        ).execute()
        return "rejected"
    except HttpError:
        try:
            yt.comments().markAsSpam(id=cid).execute()
            return "marked_spam"
        except HttpError:
            yt.comments().delete(id=cid).execute()
            return "deleted"

@app.get("/")
def index():
    acc_id = session.get("acc_id")
    if not acc_id:
        return render_template("index.html")
    with SessionLocal() as db:
        acc = db.get(Account, acc_id)
        return render_template("dashboard.html", acc=acc)

@app.get("/auth/login")
def auth_login():
    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
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
    if not items:
        return "Tidak dapat mengambil channel dari akun ini.", 400

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

def _send_webhook(summary: dict):
    if not LOG_WEBHOOK_URL:
        return
    try:
        data = json.dumps(summary).encode("utf-8")
        req = Request(LOG_WEBHOOK_URL, data=data, headers={"Content-Type":"application/json"})
        urlopen(req, timeout=10)
    except Exception:
        pass  # jangan ganggu flow utama

@app.post("/scan")
def scan_my_channel():
    acc_id = session.get("acc_id")
    if not acc_id:
        return jsonify({"error": "Not logged in"}), 401
    with SessionLocal() as db:
        acc = db.get(Account, acc_id)
        yt = yt_from_refresh(acc.refresh_token)

        flagged = []
        removed = {"rejected":0, "marked_spam":0, "deleted":0, "errors":0}
        scanned = 0

        for thread in list_channel_threads(yt, acc.channel_id):
            for cid, text, author, is_reply in iter_comments(thread):
                scanned += 1
                if is_spam(text):
                    item = {"comment_id": cid, "author": author, "text": text[:200], "is_reply": is_reply}
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
        acc.last_scan_at = datetime.utcnow()
        acc.last_scan_summary = json.dumps(summary)
        db.commit()

    _send_webhook(summary)
    return jsonify(summary)

@app.post("/cron/scan_all")
def cron_scan_all():
    key = request.args.get("key")
    if key != CRON_KEY:
        return jsonify({"error": "forbidden"}), 403
    results = []
    with SessionLocal() as db:
        for acc in db.query(Account).all():
            try:
                yt = yt_from_refresh(acc.refresh_token)
                flagged = 0
                removed = {"rejected":0, "marked_spam":0, "deleted":0, "errors":0}
                scanned = 0
                for thread in list_channel_threads(yt, acc.channel_id):
                    for cid, text, author, is_reply in iter_comments(thread):
                        scanned += 1
                        if is_spam(text):
                            flagged += 1
                            try:
                                how = remove_comment(yt, cid)
                                removed[how] = removed.get(how, 0) + 1
                            except Exception as e:
                                removed["errors"] += 1
                summary = {"channel_id": acc.channel_id, "scanned": scanned, "flagged": flagged, **removed, "ts": datetime.utcnow().isoformat()+"Z"}
                acc.last_scan_at = datetime.utcnow()
                acc.last_scan_summary = json.dumps(summary)
                db.commit()
                results.append({"channel_id": acc.channel_id, "ok": True, **summary})
            except Exception as e:
                results.append({"channel_id": acc.channel_id, "ok": False, "error": str(e)})
    # kirim ringkasan semua akun ke webhook sekali saja
    _send_webhook({"type":"scan_all", "results": results, "ts": datetime.utcnow().isoformat()+"Z"})
    return jsonify({"results": results})

@app.get("/health")
def health():
    return jsonify({"ok": True})

if __name__ == "__main__":
    if os.getenv("ENV", "dev") == "dev":
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
