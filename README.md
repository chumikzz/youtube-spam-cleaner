# YouTube Spam Comment Cleaner (Railway-ready)

Minimal Flask service to scan your video comments and delete spam (judi/slot/togel, etc.).
Uses a pre-obtained **OAuth refresh token** so the server doesn't need to run an OAuth web flow.

## Quick Start (Railway)

1) **Get a refresh token (one-time on your PC)**
   - Create OAuth 2.0 Client **(Desktop App)** in Google Cloud Console.
   - Enable **YouTube Data API v3**.
   - Run a local helper (any sample) to obtain a refresh token with scope `https://www.googleapis.com/auth/youtube.force-ssl`.
     > Tip: I included only server code here; you can reuse Google's quickstart to get the refresh token once.

2) **Set Railway Variables**
   - `GOOGLE_CLIENT_ID` = from your OAuth client
   - `GOOGLE_CLIENT_SECRET` = from your OAuth client
   - `GOOGLE_REFRESH_TOKEN` = the refresh token you got locally
   - `VIDEOS` = comma separated video IDs to scan (e.g., `abc123,xyz789`)
   - `DRY_RUN` = `true` (test) or `false` (actually delete)
   - `ENV` = `prod` on Railway, `dev` locally

3) **Deploy**
   - Push these files to GitHub.
   - Create a Railway service from the repo.
   - Railway will detect the `Procfile` and run Gunicorn.

4) **Trigger a scan**
   - `POST https://<your-app>.railway.app/clean` with JSON body:
     ```json
     { "videos": ["abc123"], "dry_run": true }
     ```
   - Or GET: `https://<your-app>.railway.app/cron/clean?videos=abc123&dry_run=true`

## Notes

- Pattern list is in `SPAM_PATTERNS` inside `app.py`. Tweak as needed.
- The app paginates through all comment threads of each video.
- For **channel-wide** scan, you can periodically pass the latest video IDs.
- Consider an external scheduler (e.g., cron-job.org) to hit `/cron/clean` hourly.
- For production, store logs (e.g., to GCS, Drive, or a DB).

## Local Run

```bash
pip install -r requirements.txt
export ENV=dev
export GOOGLE_CLIENT_ID=...
export GOOGLE_CLIENT_SECRET=...
export GOOGLE_REFRESH_TOKEN=...
export VIDEOS=abc123
export DRY_RUN=true
python app.py
# then open http://localhost:8080/health
```
