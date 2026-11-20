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
| GET | `/api/summary` | brands + per-brand counts + total + role (reads only the small `brands` table) |
| GET | `/api/sims?q&brand&status&sort&dir&page&size` | **one page** of SIMs (size ≤ 250), filtered/sorted in SQL |
| GET | `/api/ver` | data version (frontend polls every 30s; reloads summary + current page only when it changes) |
| GET | `/api/export?<filters>&after&limit` | keyset-paged dump, 2000/request (admin; CSV export + backup) |
| POST | `/api/lookup` | `{numbers,sims}` → which already exist (admin; import preview, 1000/request) |
| GET | `/api/log` | last 20 login attempts (admin) |
| GET / POST | `/api/users` | list / create users (admin) |
| PUT / DELETE | `/api/users/:username` | change role/password/active, delete (admin) |
| POST | `/api/sims` | add SIM (409 if mobile no. or SIM no. already exists) |
| PUT / DELETE | `/api/sims/:id` | edit / delete SIM |
| POST | `/api/bulk` | `{items,updates,brands}` up to 500 inserts + 500 updates per request (duplicates skipped) |
| POST | `/api/brands` | add brand |
| PUT / DELETE | `/api/brands/:name` | rename / delete brand (delete only if unused) |
| POST | `/api/clear` | delete everything (used by Restore) |

Uniqueness is enforced by the DB on normalized mobile no. and SIM no. (spaces/dashes removed).

### Scalability design
- The browser never downloads the whole table: it loads `/api/summary` (tabs/counts) + one page from `/api/sims`.
- **Per-brand counts** live in `brands.cnt`, maintained by triggers `trg_sims_ai`, `trg_sims_ad`, `trg_sims_au_brand` — so tab counts and unfiltered totals cost no table scan. Never update `brands.cnt` by hand; brand rename moves SIMs via `UPDATE sims` so the triggers move the counts.
- Indexes: unique `number_norm`, unique `sim_norm`, plus `brand`, `status`, `(brand,status)`, `(brand,number_norm)`, `account`.
- Search uses `LIKE '%…%'` (substring match on mobile/account/brand, and SIM no. for admins only), which scans rows. Search is debounced (350 ms). Fine for tens of thousands of rows; for millions, add D1 FTS5.
- Export/backup use keyset pagination (`id > after`), so they stay fast on big tables.
- Bulk counts use `RETURNING id` (D1 `meta.changes` also counts rows touched by triggers).
- Tested locally with 20,000 SIMs: page load ~10 ms, search ~50–80 ms, full export ~0.2 s.
- D1 free plan has daily read/write limits; for heavy use, the Workers Paid plan ($5/month) raises them a lot. Check current limits on Cloudflare's pricing page.

### Migrations
`schema.sql` = full schema for a new database. Changes to an existing DB go in `migrations/` and are run once:
`npx wrangler d1 execute sim-inventory-db --remote --file=migrations/<file>.sql`
(`002_scalability.sql` was applied to production on 2026-11-20.)

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
