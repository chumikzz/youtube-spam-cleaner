import os
import re
import unicodedata
from flask import Flask, jsonify, request
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# ---------- Config from env ----------
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("GOOGLE_REFRESH_TOKEN")
VIDEOS = [v.strip() for v in os.getenv("VIDEOS", "").split(",") if v.strip()]
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

# YouTube API scopes needed to manage/delete comments
SCOPES = ["https://www.googleapis.com/auth/youtube.force-ssl"]

# Local dev convenience (HTTP). Railway/production should use HTTPS by default.
if os.getenv("ENV", "dev") == "dev":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)

def build_youtube():
    """
    Build a YouTube API client using a pre-obtained refresh token.
    This avoids needing to run a web OAuth flow on the server.
    """
    if not (CLIENT_ID and CLIENT_SECRET and REFRESH_TOKEN):
        raise RuntimeError("Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN")

    creds = Credentials(
        None,
        refresh_token=REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=SCOPES,
    )
    # The client library will auto-refresh access_token when needed.
    return build("youtube", "v3", credentials=creds)

SPAM_PATTERNS = [
    r"judi\b", r"slot\b", r"togel\b", r"kasino\b|casino\b",
    r"\bmaxwin\b", r"scatter\b", r"rtp\b", r"pola\s+gacor",
    r"bonus\s+new\s+member", r"\bparlay\b",
    r"\b4d\b|\b3d\b|\b2d\b",
    r"\bwd\b", r"deposit\b.*(pulsa|e[-\s]?wallet)",
    r"\bbandar\b|\btaruhan\b|\bbet\b",
    r"pragmatic|habanero|pg\s*soft",
    r"(wa|whatsapp)[:\s]*\+?\d{8,}",
    r"http[s]?://\S+",
    r"link\s+alternatif",
]

SPAM_REGEX = re.compile("|".join(SPAM_PATTERNS), re.IGNORECASE)

def normalize_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s or "")

def is_spam(text: str) -> bool:
    t = normalize_text(text)
    return bool(SPAM_REGEX.search(t))

def list_comment_threads(youtube, video_id: str):
    """Yield top-level comment threads for a given video."""
    page_token = None
    while True:
        resp = youtube.commentThreads().list(
            part="snippet,replies",
            videoId=video_id,
            maxResults=100,
            textFormat="plainText",
            pageToken=page_token
        ).execute()
        for item in resp.get("items", []):
            yield item
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

def iter_all_comments(thread):
    """Yield (comment_id, text, author, is_reply) for a comment thread (top-level + replies)."""
    top = thread["snippet"]["topLevelComment"]
    yield (top["id"], top["snippet"].get("textDisplay", ""), top["snippet"].get("authorDisplayName", ""), False)
    for r in thread.get("replies", {}).get("comments", []) :
        yield (r["id"], r["snippet"].get("textDisplay", ""), r["snippet"].get("authorDisplayName", ""), True)

def delete_comment(youtube, comment_id: str):
    youtube.comments().delete(id=comment_id).execute()

@app.get("/health")
def health():
    return jsonify({"ok": True, "videos": len(VIDEOS), "dry_run": DRY_RUN})

@app.post("/clean")
def clean():
    """
    Body JSON (optional):
    {
      "videos": ["VIDEO_ID1", "VIDEO_ID2"],  # overrides env VIDEOS if given
      "dry_run": true
    }
    """
    data = request.get_json(silent=True) or {}
    videos = data.get("videos") or VIDEOS
    dry_run = bool(data.get("dry_run", DRY_RUN))

    if not videos:
        return jsonify({"error": "No video IDs provided. Set VIDEOS env or pass in body."}), 400

    yt = build_youtube()
    report = []
    total_scanned = 0
    total_deleted = 0

    for vid in videos:
        scanned = 0
        deleted = 0
        flagged = []
        for thread in list_comment_threads(yt, vid):
            for cid, text, author, is_reply in iter_all_comments(thread):
                scanned += 1
                if is_spam(text):
                    flagged.append({"comment_id": cid, "author": author, "text": text[:200], "is_reply": is_reply})
                    if not dry_run:
                        try:
                            delete_comment(yt, cid)
                            deleted += 1
                        except Exception as e:
                            flagged[-1]["delete_error"] = str(e)

        total_scanned += scanned
        total_deleted += deleted
        report.append({
            "video_id": vid,
            "scanned": scanned,
            "flagged": len(flagged),
            "deleted": deleted if not dry_run else 0,
            "dry_run": dry_run,
            "examples": flagged[:10],  # preview first 10
        })

    summary = {
        "total_videos": len(videos),
        "total_scanned": total_scanned,
        "total_flagged": sum(r["flagged"] for r in report),
        "total_deleted": total_deleted if not dry_run else 0,
        "dry_run": dry_run,
        "details": report,
    }
    return jsonify(summary)

# Simple GET alias for quick manual trigger (not recommended for production)
@app.get("/cron/clean")
def cron_clean():
    # ?videos=ID1,ID2&dry_run=true
    videos = request.args.get("videos", "")
    videos = [v.strip() for v in videos.split(",") if v.strip()] or VIDEOS
    dry_run = request.args.get("dry_run", str(DRY_RUN)).lower() == "true"
    return clean.__wrapped__(  # type: ignore
    )  # Reuse the same logic as POST by calling the function directly

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
