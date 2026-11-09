# Deploying Olfa to production

One small server runs everything: the website, the scanner, the community database and the extension download.
Plan: a cheap VPS (1-2 GB RAM, Ubuntu) + a domain name + Docker. Everything below is copy-paste.

## Before you start (do these first)
0. This zip includes a ready `.env` with your existing Gemini key, so local runs and Docker work without further setup. Edit `OLFA_DOMAIN` and `OLFA_PUBLIC_URL` in it for your real domain. Keep `.env` private.
1. **Revoke the old Gemini key.** An earlier version of `app.py` had a key written in it. Treat that key as public.
   Create a new key in Google AI Studio, delete the old one, and put the new one only in `.env` (step 4).
2. **Pin your package versions.** The saved models are pickles and only load with matching package versions. On the PC where Olfa works:
       pip freeze > requirements.lock
   Put `requirements.lock` next to `Dockerfile`. If you skip this, the server may start but report `"ml_loaded": false`.
3. Run `pytest tests/` on your PC and fix any failure. Run the extension tests with `npm test` in the extension folder.

## 1. Server and domain
- Rent a VPS (Hetzner, DigitalOcean, AWS Lightsail all work). Ubuntu 24.04.
- Point your domain's **A record** to the server's IP address.
- Open ports 80 and 443 only (firewall: `sudo ufw allow 22,80,443/tcp && sudo ufw enable`).

## 2. Install Docker
    curl -fsSL https://get.docker.com | sh

## 3. Upload the project
    scp -r improvedML user@YOUR_SERVER_IP:~/olfa      # or git clone your private repo
    ssh user@YOUR_SERVER_IP && cd ~/olfa

## 4. Configure
    cp .env.example .env
    nano .env        # set OLFA_DOMAIN, OLFA_PUBLIC_URL (https://...), GEMINI_API_KEY

## 5. Start
    docker compose up -d --build
Caddy gets the HTTPS certificate on its own (it needs the domain pointing at the server first).

## 6. Check it works
- `https://YOUR_DOMAIN/health` shows `"ok": true` and `"ml_loaded": true`. If `ml_loaded` is false, see step 2 of "Before you start".
- Scan a safe link and a known-bad test link on the site.
- Get Extension > Download. Install the zip and confirm the popup footer says "Live".
- `docker compose logs -f olfa` shows requests and errors.

## 7. Running it
- **Update:** upload the new files, then `docker compose up -d --build`.
- **Back up:** `docker run --rm -v olfa_olfa-data:/d -v $PWD:/b alpine tar czf /b/olfa-data.tgz -C /d .` (do this weekly, cron it).
- **Restart after reboot:** automatic (`restart: unless-stopped`).
- **Extension update:** edit `extension/`, raise `version` in `extension/manifest.json`, redeploy. Users re-download.

## What is already protected
- Scans use an SSRF guard: the server only connects to public addresses it resolved itself.
- `/scan` is limited per visitor (30/min, 600/hour; change in `.env`). `/chat` is limited too.
- The app runs as a non-root user, and the HTTPS front end limits request size.
- The key is read only from the environment.

## Limits to know about
- **One worker.** Rate limits live in memory and the database is SQLite. This is fine for thousands of users a day. Beyond that, move the database to Postgres and the limits to Redis.
- **Open community reports.** Anyone can submit a report, and there is no login or moderation. Check the Community tab now and then, and consider a review step before reports affect verdicts.
- **No monitoring yet.** Add a free uptime check (UptimeRobot) on `/health` so you hear when it goes down.
- **Privacy.** Scanned links are sent to your server, and chat messages go to Google's Gemini. Add a short privacy notice to the site before a public launch.
- **Chrome Web Store.** Developer-mode install suits demos. For the public, publish the extension on the Chrome Web Store (one-time $5, review takes days) with your https address as the default service address.

## Cheaper or simpler options
- **Render / Railway / Fly.io:** use the Dockerfile, mount a disk at `/data`, set the same variables from `.env.example`. They provide HTTPS, so skip Caddy and `docker-compose.yml`.

## Ledger persistence and testnet anchoring (important on Render)
- The community database **and the ledger** live in one SQLite file (`OLFA_DB`, default `/data/olfa_intel.db`). If the host's disk is wiped on every deploy or restart, the ledger resets while anything already anchored on the testnet stays there, and the two will no longer match. On Render, attach a **persistent disk mounted at `/data`**, or move to a managed Postgres later. Check your plan's disk support first.
- Back up `/data/olfa_intel.db` regularly (see the backup command above); it is the only copy of the private commitment data.
- To turn anchoring on, follow `ANCHOR_SETUP.md` and set `OLFA_ANCHOR_RPC` and `OLFA_ANCHOR_KEY` as environment variables in the host's dashboard. Use a throwaway testnet wallet only; never commit the key.
- `eth-account` is installed separately in the Dockerfile (it is not in `requirements.lock`). If its install failed, the build log shows a WARNING and anchoring stays off.
