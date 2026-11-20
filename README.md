# 📶 SIM Card Inventory System

Live Website: [https://sim-inventory.pages.dev](https://sim-inventory.pages.dev)

---

## 🧭 Time Capsule & Handover Documentation
Kung ikaw ang susunod na developer o AI model na magpapatuloy ng project na ito sa VS Code, basahin ang buong handover documentation dito:

👉 **[PROJECT_HANDOVER.md](PROJECT_HANDOVER.md)**

Naglalaman ito ng:
1. **Overview & Purpose** ng system
2. **Directory Structure & Files**
3. **Cloudflare Deployment Details** & live URLs
4. **Login Credentials & Password Hash Algorithms**
5. **Security Implementations** (Brute-force lockout, CSP, XSS, Idle timeout, Session management)
6. **How to Run, Edit, & Deploy** gamit ang Wrangler CLI
7. **Future Roadmap** (Server-side Cloudflare D1/KV sync)
8. **Instructions for Future AI Models** (Prompting context)

---

## ⚡ Quick Start

### 1. Default Admin Login
- **Username:** `administrator`
- **Password:** *(itanong sa system administrator — hindi naka-store sa repo)*

### 2. Deploy to Cloudflare Pages
```powershell
wrangler pages deploy deploy --project-name sim-inventory
```
