# 📶 SIM Card Inventory System

Live Website: [https://sim-inventory.pages.dev](https://sim-inventory.pages.dev)

Shared SIM inventory — iisang listahan para sa lahat ng computer. Naka-save ang data sa **Cloudflare D1** database, at sa server ginagawa ang login.

👉 Buong detalye: **[PROJECT_HANDOVER.md](PROJECT_HANDOVER.md)**

---

## ⚡ Quick Start

### Login
- **Username:** `administrator`
- **Password:** *(itanong sa system administrator — naka-store bilang Cloudflare secret, wala sa repo)*

### Mga command (sa VS Code terminal, sa folder na ito)
> Kung may error na "running scripts is disabled", gamitin ang `npm.cmd` imbes na `npm`.

| Command | Gagawin |
|---|---|
| `npm install` | i-install ang Wrangler (isang beses lang) |
| `npm run login` | mag-login sa Cloudflare |
| `npm run deploy` | i-upload ang `deploy/` folder at API sa Cloudflare |
| `npm run set-password` | palitan ang admin password |
| `npm run dev` | i-test sa sariling computer (`http://localhost:8788`) |
