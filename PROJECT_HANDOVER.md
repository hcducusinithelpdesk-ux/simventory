# 📦 PROJECT TIME CAPSULE & DEVELOPER HANDOVER GUIDE
> **Project Name:** SIM Card Inventory Web Application  
> **Last Updated:** November 19, 2026  
> **Target Audience:** Next Developer / Maintainer / Any AI Assistant (Claude, ChatGPT, Gemini, Cursor, Copilot, etc.)

---

## 📌 1. Project Overview & Objective
This project is a lightweight, responsive, single-page **SIM Card Inventory Management System** built with vanilla HTML, CSS, and JavaScript (Zero external dependencies). It was designed to run offline-first via browser `localStorage` and hosted globally via **Cloudflare Pages**.

### Key Use-Cases:
- Tracking mobile numbers, account numbers, physical SIM card serial numbers (ICCID), and telecommunications brands (Globe, Smart, DITO, TNT, etc.).
- Parsing, importing, and auto-detecting Excel (`.xlsx`) and CSV files directly inside the browser using a custom internal ZIP/XML reader without heavy external libraries.
- Managing SIM inventories with brand tabs, instant search, sorting, printing, CSV export, and JSON backup/restore.
- Protecting the interface using a client-side authentication gate with brute-force lockout, session management, and security audit logs.

---

## 📂 2. Directory Structure & File Manifest

```text
Sim Inventory/
├── deploy/
│   └── index.html             <-- Production-ready file deployed to Cloudflare Pages
├── SIM_Inventory_FIXED_DragDrop_Import_Remove.html <-- Master source file (identical to deploy/index.html)
├── .wrangler/                  <-- Cloudflare Wrangler CLI cache and state
│   └── cache/
│       ├── pages.json
│       └── wrangler-account.json
├── README.md                   <-- Quick start guide
└── PROJECT_HANDOVER.md         <-- This time capsule document
```

---

## 🌐 3. Cloudflare Hosting & Deployment Status

- **Hosting Platform:** Cloudflare Pages (Free Tier)
- **Connected Cloudflare Account:** *(IT helpdesk Cloudflare account)*
- **Cloudflare Account ID:** *(tingnan sa `wrangler whoami`)*
- **Project Name:** `sim-inventory`
- **Live Production URL:** [https://sim-inventory.pages.dev](https://sim-inventory.pages.dev)
- **Deployment Command (Wrangler):**
  ```powershell
  cd "c:\Users\<USER>\Documents\Sim Inventory"
  wrangler pages deploy deploy --project-name sim-inventory
  ```

---

## 🔑 4. Authentication & Credentials

The application is protected by a login gate. The default administrator credentials are:

- **Username:** `administrator`
- **Password:** *(itanong sa system administrator — hindi naka-store sa repo)*

### How Authentication Works:
- **No Plaintext Passwords:** Passwords are not saved in plaintext inside the source code.
- **Combined SHA-256 Hashing:** 
  $$\text{Hash} = \text{SHA-256}(\text{username} + ":" + \text{password})$$
  $$\text{Hash of } \texttt{"administrator:<password>"} = \texttt{3f7d4c15aab6cbd482d837231a50430473c982c5bc1c423db3593ab73231cc13}$$
- **Storage:** Account credentials are encrypted/hashed and seeded into `localStorage['sim_auth_accounts']`.
- **Session Lifespan:** An active session token is stored in `sessionStorage['sim_auth_session']`. If the user closes the browser tab, the session terminates immediately.

---

## 🛡️ 5. Security & Pentest Implementation

A lightweight client-side security hardening was conducted to secure the web application:

1. **Brute-Force & Rate Limiting:**
   - Tracks failed attempts in `sessionStorage['sim_auth_lockout']`.
   - Max 5 failed attempts allowed before triggering a **5-minute lockout** with a live countdown timer.
2. **Session Inactivity & Auto-Logout:**
   - 15 minutes of user inactivity (mouse/keyboard) automatically logs the user out.
   - A warning notification toast pops up 2 minutes prior to session expiration.
3. **Content Security Policy (CSP):**
   - Configured via `<meta http-equiv="Content-Security-Policy">` to disallow external script execution, prevent framing/clickjacking (`frame-src 'none'`), and disable plugins (`object-src 'none'`).
4. **XSS Sanitization:**
   - Uses an HTML entity encoder (`escHtml` / `sanitize`) across all user-rendered data, inputs, and audit logs.
5. **Security Audit Log:**
   - Records the last 20 login attempts (timestamp, username, status, user agent) accessible through the `🛡️` button in the header.

---

## ⚙️ 6. How to Run & Maintain This Project in VS Code

### Prerequisites:
- **Node.js** (v18+ recommended)
- **Wrangler CLI** (Cloudflare CLI tool):
  ```powershell
  npm install -g wrangler
  ```

### Local Development / Testing:
1. Open the folder in VS Code:
   ```powershell
   code "c:\Users\<USER>\Documents\Sim Inventory"
   ```
2. You can preview `deploy/index.html` locally using VS Code's **Live Server** extension, or run:
   ```powershell
   npx wrangler pages dev deploy
   ```
   This will give you a local URL like `http://localhost:8788`.

### Updating the Code & Re-deploying:
1. Edit `deploy/index.html` (and copy changes to `SIM_Inventory_FIXED_DragDrop_Import_Remove.html`).
2. Deploy to Cloudflare Pages:
   ```powershell
   wrangler pages deploy deploy --project-name sim-inventory
   ```
3. If changing Cloudflare accounts:
   ```powershell
   wrangler logout
   wrangler login
   ```

---

## 🚀 7. Roadmap & Recommendations for the Next Developer

If you or a future AI model are tasked with taking this project to the next level, here is the recommended architecture roadmap:

1. **Transition from LocalStorage to Cloudflare D1 / KV Database:**
   - Currently, SIM records exist per client browser (`localStorage`).
   - The code already contains an `/api/` hooks skeleton (`/api/state`, `/api/sims`, `/api/bulk`, `/api/brands`).
   - You can create a Cloudflare Worker or Pages Function (`functions/api/[[route]].js`) attached to a Cloudflare D1 SQLite database to make the inventory shared and synced across multiple devices in real-time.
2. **Cloudflare Zero Trust / Cloudflare Access:**
   - For enterprise-grade protection, you can gate the entire domain `sim-inventory.pages.dev` behind **Cloudflare Zero Trust (Access)** with OTP email codes or Google Workspace SSO, removing the need for client-side password hashing.
3. **Role-Based Access Control (RBAC):**
   - Differentiate Admin (Read/Write/Delete) from Viewer (Read-only/Search).

---

## 🤖 8. Instructions for Future AI Models
> *If you are an AI assistant (Claude, ChatGPT, Gemini, Copilot, etc.) reading this file:*
> 
> - Treat this document as the single source of truth for the project state.
> - Always maintain the two identical files: `deploy/index.html` and `SIM_Inventory_FIXED_DragDrop_Import_Remove.html`.
> - Do not break the internal XLSX parser when refactoring JavaScript.
> - Preserved hashed authentication logic unless explicitly requested to connect a server-side database (e.g., Cloudflare D1/Workers).
