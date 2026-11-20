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
| Secrets | `ADMIN_PASSWORD`, `TOKEN_SECRET`, `DATA_KEY` (encrypted, set via Wrangler) |
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

Uniqueness is enforced by the DB on blind indexes of the normalized mobile no. and SIM no. (spaces/dashes removed).

### Field-level encryption (mobile no., account no., SIM no.)
- Stored **AES-256-GCM encrypted** in `sims.payload` (one JSON blob per row, row id used as AAD so blobs can't be swapped between rows). Columns `number`, `account`, `sim_no` are always `''`.
- Key = **`DATA_KEY`** Pages secret (64 hex chars). Sub-keys derived with HKDF: one for AES, one for HMAC blind indexes.
- **Blind indexes** (HMAC-SHA256, truncated to 192 bits): `number_norm` (mobile), `sim_norm` (SIM no.), `account_idx` (account), `last4_idx` (last 4 digits of mobile). They make search and duplicate checks work without decrypting the table.
- **Search is exact-match**: full mobile no. (any format: `0917…`, `917…`, `+63917…`, with/without spaces), last 4 digits of mobile, full account no. (case/space/dash-insensitive), full SIM no. (admins only). Partial search like `0917 12` is not possible on encrypted data.
- **Sorting** by mobile/account/SIM no. is not possible; lists are ordered by date added (Brand and Status columns remain sortable).
- The API decrypts only the rows it returns (one page, or 1000 per export request).
- Rows saved before encryption are encrypted automatically by the API on its first request (`ensureEncrypted`, flag `meta.enc_v1 = 1`). Production was migrated on 2026-11-20 (133 SIMs).
- ⚠️ **If `DATA_KEY` is lost, the numbers cannot be recovered.** A copy is in `backups/DATA_KEY.txt` (git-ignored) — keep another copy offline (password manager / USB). `npm run set-data-key` re-uploads that same key; it never overwrites an existing key file.
- ⚠️ **Never change `DATA_KEY`** without a re-encryption plan: existing rows would become unreadable ("(hindi ma-decrypt)").
- Note: files in `backups/*.sql` made before 2026-11-20 16:11 contain **plaintext** numbers; JSON backups/CSV exports from the app are plaintext by design. Store them securely. D1 Time Travel may also retain pre-encryption states for up to 30 days.

### Scalability design
- The browser never downloads the whole table: it loads `/api/summary` (tabs/counts) + one page from `/api/sims`.
- **Per-brand counts** live in `brands.cnt`, maintained by triggers `trg_sims_ai`, `trg_sims_ad`, `trg_sims_au_brand` — so tab counts and unfiltered totals cost no table scan. Never update `brands.cnt` by hand; brand rename moves SIMs via `UPDATE sims` so the triggers move the counts.
- Indexes: unique `number_norm`, unique `sim_norm`, plus `account_idx`, `last4_idx`, `brand`, `status`, `(brand,status)`, `(created_at,id)`, `(brand,created_at,id)`.
- Search = exact match on blind indexes only (all indexed), so it stays fast at any size. Debounced 350 ms.
- Export/backup use keyset pagination (`id > after`), so they stay fast on big tables.
- Bulk counts use `RETURNING id` (D1 `meta.changes` also counts rows touched by triggers).
- Tested locally with 20,000 SIMs: page load ~10 ms, search ~50–80 ms, full export ~0.2 s.
- D1 free plan has daily read/write limits; for heavy use, the Workers Paid plan ($5/month) raises them a lot. Check current limits on Cloudflare's pricing page.

### Migrations
`schema.sql` = full schema for a new database. Changes to an existing DB go in `migrations/` and are run once:
`npx wrangler d1 execute sim-inventory-db --remote --file=migrations/<file>.sql`
(`002_scalability.sql` and `003_field_encryption.sql` were applied to production on 2026-11-20.)

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
