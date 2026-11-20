# 📦 PROJECT HANDOVER GUIDE
> **Project:** SIM Card Inventory Web Application
> **Last Updated:** November 20, 2026
> **For:** next developer / maintainer / AI assistant

---

## 1. Overview
Single-page **SIM Card Inventory** app (vanilla HTML/CSS/JS, no frontend framework) hosted on **Cloudflare Pages**, with a **Cloudflare Pages Function** API and a **Cloudflare D1** (SQLite) database. All users see the same shared inventory.

Features: brand tabs, search, brand/status filters, sorting, add/edit/delete, Excel (`.xlsx`) / CSV / paste import with auto column detection (custom in-browser ZIP/XML reader — no library), CSV export, JSON backup/restore, print, security log.

---

## 2. Files
```text
Sim Inventory/
├── index.html                 <-- Master source of the frontend
├── deploy/
│   ├── index.html             <-- Copy of index.html that gets deployed (keep identical)
│   └── _headers               <-- Security headers (anti-clickjacking, nosniff)
├── functions/api/[[route]].js <-- Server API (login + all data routes) — Pages Function
├── schema.sql                 <-- D1 tables (sims, brands, meta, auth_log, login_attempts, users)
├── wrangler.toml              <-- Cloudflare config (D1 binding "DB", output dir "deploy")
├── package.json               <-- npm scripts + Wrangler dev dependency
├── .dev.vars                  <-- LOCAL ONLY test secrets (git-ignored)
└── README.md / PROJECT_HANDOVER.md
```
`.wrangler/`, `node_modules/`, `.dev.vars` are git-ignored.

---

## 3. Cloudflare
| Item | Value |
|---|---|
| Pages project | `sim-inventory` → https://sim-inventory.pages.dev |
| Production branch | `main` |
| D1 database | `sim-inventory-db` (binding `DB`, id in `wrangler.toml`) |
| Secrets | `ADMIN_PASSWORD`, `TOKEN_SECRET` (encrypted, set via Wrangler) |
| Account | IT helpdesk Cloudflare account — check with `npm run whoami` |

Source code: https://github.com/hcducusinithelpdesk-ux/simventory
(Deploy is **manual** — pushing to GitHub does not deploy.)

---

## 4. Authentication & Roles (RBAC)
| Role | Can see | Can do |
|---|---|---|
| **Administrator** | all columns (Mobile, Account, SIM No., Brand, Status) | everything: add/edit/delete, import, export, backup/restore, print, brands, 👥 Users, 🛡️ Security log |
| **Viewer** | Mobile No. + Account No. only | search, brand tabs, brand/status filters, sort |

- Roles are enforced **by the server**: viewers get SIM No. stripped from `/api/state` and receive `403` on every write/admin route. Hiding in the UI is cosmetic only.
- **Built-in `administrator`** is checked against the `ADMIN_PASSWORD` secret (never stored in the DB, so it can't be locked out or deleted). Username is case-insensitive; surrounding spaces in passwords are ignored.
- **Other users** live in the D1 `users` table (PBKDF2-SHA256, 100k iterations, per-user salt). Admins manage them with the **👥 Users** button: add, change role, reset password, disable/enable, delete. Role/disable/delete take effect immediately (checked on every request).
- Server returns an HMAC-signed token (12h). The browser keeps it in `sessionStorage` and sends `Authorization: Bearer <token>` on every API call. Closing the tab ends the session.
- **Brute force:** 5 failed logins per IP → 5-minute lock (table `login_attempts`).
- **Idle logout:** 15 min of no activity (warning 2 min before).
- **Audit log:** every login attempt saved in `auth_log` (last 200 kept); 🛡️ button shows the last 20.
- **Change password:** `npm run set-password` (takes effect immediately; existing sessions stay valid until they expire — run `npm run set-token-secret` with a new value to force everyone to log in again).

---

## 5. API (`functions/api/[[route]].js`)
All routes need the Bearer token except login.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/login` | `{username,password}` → `{token,username,expiresAt}` |
| GET | `/api/state` | all SIMs + brands + version |
| GET | `/api/ver` | data version (frontend polls every 30s to auto-refresh) |
| GET | `/api/log` | last 20 login attempts (admin) |
| GET / POST | `/api/users` | list / create users (admin) |
| PUT / DELETE | `/api/users/:username` | change role/password/active, delete (admin) |
| POST | `/api/sims` | add SIM (409 if mobile no. or SIM no. already exists) |
| PUT / DELETE | `/api/sims/:id` | edit / delete SIM |
| POST | `/api/bulk` | import up to 500 SIMs (duplicates skipped) |
| POST | `/api/brands` | add brand |
| PUT / DELETE | `/api/brands/:name` | rename / delete brand (delete only if unused) |
| POST | `/api/clear` | delete everything (used by Restore) |

Uniqueness is enforced by the DB on normalized mobile no. and SIM no. (spaces/dashes removed).

---

## 6. Common tasks
> On Windows PowerShell, use `npm.cmd` if `npm` gives "running scripts is disabled".

```powershell
npm install                 # first time on a new PC
npm run login               # Cloudflare login (browser)
# edit index.html, then:
copy index.html deploy\index.html
npm run deploy
git add -A; git commit -m "describe change"; git push
```
Local testing: `npm run db:init-local` once, then `npm run dev` → http://localhost:8788 (uses `.dev.vars` test password).

Backup: use **Backup (JSON)** in the app, or
`npx wrangler d1 export sim-inventory-db --remote --output backup.sql`.

---

## 7. Migration from the old offline version
Older versions stored data in each browser's `localStorage`. On first login in a browser that still has that data, the app offers to upload it to the shared database (duplicates are skipped). The local copy is kept as a backup.

---

## 8. Ideas for next steps
- More roles (e.g. editor: add/edit but no delete or user management).
- Auto-deploy on GitHub push (connect repo in Cloudflare Pages or use GitHub Actions).
- Cloudflare Access (Zero Trust) in front of the site for SSO/OTP.

## 9. Notes for AI assistants
- Keep `index.html` and `deploy/index.html` identical.
- Don't break the in-browser XLSX parser (`unzip` / `readXlsx` / `parseSheet`).
- Never put passwords, hashes, or secrets in the repo — use Wrangler secrets.
