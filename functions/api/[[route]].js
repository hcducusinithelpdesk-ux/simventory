// ================================================================
//  SIM Inventory API — Cloudflare Pages Function + D1
//  Routes (all JSON, all require Bearer token except POST /api/login):
//    POST   /api/login            {username,password} -> {token,username,expiresAt}
//    GET    /api/summary          -> {brands:[{name,count}],total,ver,role,canEdit}
//    GET    /api/sims?q&brand&status&sort&dir&page&size -> one page {items,total,page,pages}
//    GET    /api/export?<filters>&after&limit  (admin) keyset-paged dump
//    POST   /api/lookup           {numbers,sims} (admin) existing SIMs for import
//    GET    /api/ver              -> {ver}
//    GET    /api/log              -> {log:[...]}  (last 20 login attempts)
//    POST   /api/sims             {number,account,simNo,brand,status}
//    PUT    /api/sims/:id         {number,account,simNo,brand,status}
//    DELETE /api/sims/:id
//    POST   /api/bulk             {items,updates,brands} -> {inserted,updated,skipped}
//    POST   /api/brands           {name}
//    PUT    /api/brands/:name     {name}   (rename)
//    DELETE /api/brands/:name     (only if no SIMs use it)
//    POST   /api/clear            (delete all SIMs + brands; used by Restore)
//
//  Field-level encryption: mobile no., account no. and SIM no. are stored
//  AES-256-GCM encrypted in sims.payload (key: DATA_KEY secret). Exact-match
//  search and uniqueness use HMAC blind indexes (number_norm, sim_norm,
//  account_idx, last4_idx). Plaintext columns number/account/sim_no stay ''.
// ================================================================

const TOKEN_TTL = 12 * 60 * 60 * 1000; // 12 hours
const MAX_FAILS = 5;
const LOCK_MS = 5 * 60 * 1000; // 5 minutes
const MAX_BULK = 500;

// ---------- helpers ----------
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
const err = (status, msg) => json({ error: msg }, status);

const enc = new TextEncoder();
function b64url(bytes) {
  let s = '';
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signToken(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)));
  return body + '.' + b64url(sig);
}
async function verifyToken(token, secret) {
  if (!token || token.indexOf('.') < 0) return null;
  const [body, sig] = token.split('.');
  let ok = false;
  try {
    ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64urlDecode(sig), enc.encode(body));
  } catch (e) {
    return null;
  }
  if (!ok) return null;
  try {
    const p = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    if (!p.exp || Date.now() > p.exp) return null;
    return p;
  } catch (e) {
    return null;
  }
}
// ---------- password hashing for DB users (PBKDF2-SHA256) ----------
const PBKDF2_ITER = 100000; // Workers maximum
const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
async function hashPassword(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/../g).map((h) => parseInt(h, 16))) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, key, 256);
  return { salt: toHex(salt), hash: toHex(new Uint8Array(bits)) };
}
const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;
const ROLES = ['admin', 'viewer'];

// constant-time string compare via SHA-256 digests
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b))),
  ]);
  const ax = new Uint8Array(x), ay = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < ax.length; i++) diff |= ax[i] ^ ay[i];
  return diff === 0;
}

const norm = (s) => String(s || '').replace(/[\s-]/g, '').toLowerCase();
const clean = (s, max = 100) => String(s == null ? '' : s).trim().slice(0, max);
function normalizeStatus(s) {
  const v = String(s || '').trim().toLowerCase();
  return v === '0' || v === 'no' || v === 'false' || /inactive|not ?active|deactivat|disabled|suspend|block|lost|terminat|expired|cancel/.test(v)
    ? 'Inactive'
    : 'Active';
}
function uid() {
  return Date.now().toString(36) + b64url(crypto.getRandomValues(new Uint8Array(6))).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 6);
}
function cleanRec(r) {
  return {
    number: clean(r.number, 40),
    account: clean(r.account, 60),
    simNo: clean(r.simNo, 40),
    brand: clean(r.brand, 40),
    status: normalizeStatus(r.status),
  };
}
async function body(request) {
  try {
    return await request.json();
  } catch (e) {
    return {};
  }
}

// ---------- db helpers ----------
const bumpVer = (db) => db.prepare("UPDATE meta SET v = v + 1 WHERE k = 'ver'");
const ensureBrand = (db, name) =>
  db.prepare('INSERT OR IGNORE INTO brands (name, pos) VALUES (?1, (SELECT COALESCE(MAX(pos),0)+1 FROM brands))').bind(name);
async function getVer(db) {
  const r = await db.prepare("SELECT v FROM meta WHERE k = 'ver'").first();
  return r ? r.v : 0;
}
function isUniqueErr(e) {
  return /UNIQUE constraint failed/i.test(String(e && e.message));
}

// ---------- field-level encryption (AES-256-GCM) + blind indexes (HMAC-SHA256) ----------
// DATA_KEY secret = 64 hex chars (32 random bytes). Two sub-keys are derived with HKDF:
//   aes  -> encrypts {number, account, simNo} as one JSON blob per row (row id = AAD)
//   mac  -> blind indexes for exact-match search / uniqueness (domain-separated by kind)
// LOSING DATA_KEY = LOSING THE NUMBERS. Keep a copy somewhere safe.
let _keys = null, _keysFor = null;
function hexToBytes(h) {
  h = String(h || '').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error('DATA_KEY must be 64 hex characters');
  return Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
}
async function getKeys(env) {
  if (_keys && _keysFor === env.DATA_KEY) return _keys;
  const base = await crypto.subtle.importKey('raw', hexToBytes(env.DATA_KEY), 'HKDF', false, ['deriveKey']);
  const hk = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) });
  const aes = await crypto.subtle.deriveKey(hk('sim-inventory/aes-gcm/v1'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const mac = await crypto.subtle.deriveKey(hk('sim-inventory/blind-index/v1'), base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
  _keys = { aes, mac };
  _keysFor = env.DATA_KEY;
  return _keys;
}
// blind index: kind = 'n' (mobile), 's' (SIM no.), 'a' (account), 'l4' (last 4 digits of mobile)
async function bidx(keys, kind, value) {
  if (!value) return '';
  const sig = await crypto.subtle.sign('HMAC', keys.mac, enc.encode(kind + ':' + value));
  return b64url(new Uint8Array(sig)).slice(0, 32); // 192 bits
}
async function seal(keys, id, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(id) }, keys.aes, enc.encode(JSON.stringify(obj)));
  return 'v1.' + b64url(iv) + '.' + b64url(new Uint8Array(ct));
}
async function unseal(keys, id, s) {
  const [v, iv, ct] = String(s).split('.');
  if (v !== 'v1') throw new Error('unknown payload version');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlDecode(iv), additionalData: enc.encode(id) }, keys.aes, b64urlDecode(ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
const digitsOnly = (s) => String(s || '').replace(/\D/g, '');
function validMobile(s) {
  s = String(s == null ? '' : s).trim();
  if (!s || !/^[\d\s\-+().]+$/.test(s)) return '';
  const d = s.replace(/\D/g, '');
  if (/^09\d{9}$/.test(d)) return d;
  if (/^9\d{9}$/.test(d)) return '0' + d;
  if (/^639\d{9}$/.test(d)) return '0' + d.slice(2);
  return '';
}
// all encrypted/indexed column values for one record
async function encFields(keys, id, r) {
  const d = digitsOnly(r.number);
  const [payload, n, s, a, l4] = await Promise.all([
    seal(keys, id, { number: r.number, account: r.account, simNo: r.simNo }),
    bidx(keys, 'n', norm(r.number)),
    r.simNo ? bidx(keys, 's', norm(r.simNo)) : '',
    r.account ? bidx(keys, 'a', norm(r.account)) : '',
    d.length >= 4 ? bidx(keys, 'l4', d.slice(-4)) : '',
  ]);
  return { payload, n, s, a, l4 };
}
async function insertStmt(db, keys, id, r, orIgnore) {
  const f = await encFields(keys, id, r);
  return db
    .prepare(
      'INSERT ' + (orIgnore ? 'OR IGNORE ' : '') +
        "INTO sims (id, number, number_norm, account, sim_no, sim_norm, brand, status, payload, account_idx, last4_idx) VALUES (?1,'',?2,'','',?3,?4,?5,?6,?7,?8)" +
        (orIgnore ? ' RETURNING id' : '')
    )
    .bind(id, f.n, f.s, r.brand, r.status, f.payload, f.a, f.l4);
}
async function updateStmt(db, keys, id, r, orIgnore) {
  const f = await encFields(keys, id, r);
  return db
    .prepare(
      'UPDATE ' + (orIgnore ? 'OR IGNORE ' : '') +
        "sims SET number='', number_norm=?2, account='', sim_no='', sim_norm=?3, brand=?4, status=?5, payload=?6, account_idx=?7, last4_idx=?8, updated_at=datetime('now') WHERE id=?1" +
        (orIgnore ? ' RETURNING id' : '')
    )
    .bind(id, f.n, f.s, r.brand, r.status, f.payload, f.a, f.l4);
}
const ROW_COLS = 'id, payload, number, account, sim_no, brand, status';
// decrypt DB rows -> API rows. Viewers never receive SIM card no.
async function decodeRows(keys, rows, isAdmin) {
  return Promise.all(
    rows.map(async (row) => {
      let p;
      if (row.payload) {
        try { p = await unseal(keys, row.id, row.payload); } catch (e) { p = { number: '(hindi ma-decrypt)', account: '', simNo: '' }; }
      } else {
        p = { number: row.number, account: row.account, simNo: row.sim_no }; // not yet migrated
      }
      const out = { id: row.id, number: p.number || '', account: p.account || '', brand: row.brand, status: row.status };
      if (isAdmin) out.simNo = p.simNo || '';
      return out;
    })
  );
}
// One-time migration of rows saved before encryption existed (runs in batches, cached per isolate).
let _encDone = false;
async function ensureEncrypted(db, keys) {
  if (_encDone) return;
  const flag = await db.prepare("SELECT v FROM meta WHERE k = 'enc_v1'").first();
  if (flag && flag.v === 1) { _encDone = true; return; }
  for (let round = 0; round < 10; round++) {
    const r = await db.prepare('SELECT id, number, account, sim_no AS simNo FROM sims WHERE payload IS NULL LIMIT 200').all();
    if (!r.results.length) {
      await db.prepare("INSERT INTO meta (k, v) VALUES ('enc_v1', 1) ON CONFLICT(k) DO UPDATE SET v = 1").run();
      _encDone = true;
      return;
    }
    const stmts = [];
    for (const row of r.results) {
      const f = await encFields(keys, row.id, { number: row.number, account: row.account, simNo: row.simNo });
      stmts.push(
        db
          .prepare("UPDATE sims SET payload=?2, number='', account='', sim_no='', number_norm=?3, sim_norm=?4, account_idx=?5, last4_idx=?6 WHERE id=?1 AND payload IS NULL")
          .bind(row.id, f.payload, f.n, f.s, f.a, f.l4)
      );
    }
    await db.batch(stmts);
  }
}

// ---------- query helpers (pagination / search / filters) ----------
const MAX_PAGE = 250;
const EXPORT_PAGE = 1000;
const MAX_LOOKUP = 1000;

// Build WHERE clause. Search is exact-match on blind indexes (all indexed -> fast at any size):
//   full mobile no. (any format: 0917..., 917..., +63917...), last 4 digits of mobile,
//   full account no., and (admins only) full SIM card no.
async function buildFilter(sp, isAdmin, keys) {
  const conds = [], args = [];
  const brand = clean(sp.get('brand'), 40);
  const status = sp.get('status') === 'Active' || sp.get('status') === 'Inactive' ? sp.get('status') : '';
  const q = clean(sp.get('q'), 60);
  if (brand) { conds.push('brand = ?'); args.push(brand); }
  if (status) { conds.push('status = ?'); args.push(status); }
  if (q) {
    const qn = norm(q), mob = validMobile(q);
    const parts = ['number_norm = ?', 'account_idx = ?'];
    args.push(await bidx(keys, 'n', mob || qn), await bidx(keys, 'a', qn));
    if (/^\d{4}$/.test(qn)) { parts.push('last4_idx = ?'); args.push(await bidx(keys, 'l4', qn)); }
    if (isAdmin) { parts.push('sim_norm = ?'); args.push(await bidx(keys, 's', qn)); }
    conds.push('(' + parts.join(' OR ') + ')');
  }
  return { where: conds.length ? ' WHERE ' + conds.join(' AND ') : '', args, brand, status, hasSearch: !!q };
}
// encrypted columns can't be sorted in SQL -> they sort by date added
function sortColumn(key) {
  const map = { brand: 'brand', status: 'status', created: 'created_at' };
  return map[key] || 'created_at';
}
async function dupErr(db, keys, r, selfId) {
  const n = await bidx(keys, 'n', norm(r.number));
  const s = r.simNo ? await bidx(keys, 's', norm(r.simNo)) : '';
  const row = await db
    .prepare("SELECT " + ROW_COLS + " FROM sims WHERE (number_norm = ?1 OR (?2 <> '' AND sim_norm = ?2)) AND id <> ?3 LIMIT 1")
    .bind(n, s, selfId)
    .first();
  const c = row ? (await decodeRows(keys, [row], true))[0] : null;
  return json({ error: 'Duplicate', conflict: c ? { number: c.number, brand: c.brand } : null }, 409);
}

// ---------- login ----------
async function handleLogin(request, env) {
  const db = env.DB;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ua = clean(request.headers.get('User-Agent'), 100);
  const now = Date.now();

  const att = (await db.prepare('SELECT fails, locked_until FROM login_attempts WHERE ip = ?1').bind(ip).first()) || { fails: 0, locked_until: 0 };
  if (att.locked_until > now) {
    return json({ error: 'locked', lockedUntil: att.locked_until }, 429);
  }

  const b = await body(request);
  const username = clean(b.username, 60);
  // Trim surrounding whitespace/CR/LF on both sides: secrets set from a Windows
  // terminal can pick up a stray "\r" or space that the user never sees.
  const password = String(b.password || '').trim();
  const expectedUser = String(env.ADMIN_USER || 'administrator').trim();
  const expectedPass = String(env.ADMIN_PASSWORD || '').trim();

  let ok = false, role = null, loginName = username.toLowerCase();
  if (await safeEqual(loginName, expectedUser.toLowerCase())) {
    // built-in super-admin (password = ADMIN_PASSWORD secret)
    ok = expectedPass.length > 0 && password.length > 0 && (await safeEqual(password, expectedPass));
    role = 'admin';
    loginName = expectedUser;
  } else {
    const u = await db.prepare('SELECT username, role, pw_salt, pw_hash, active FROM users WHERE username = ?1').bind(loginName).first();
    if (u && u.active && password.length > 0) {
      const h = await hashPassword(password, u.pw_salt);
      ok = await safeEqual(h.hash, u.pw_hash);
      role = u.role;
    } else {
      await hashPassword(password || 'x'); // keep timing similar for unknown users
    }
  }

  await db.prepare('INSERT INTO auth_log (username, success, ip, user_agent) VALUES (?1, ?2, ?3, ?4)').bind(username, ok ? 1 : 0, ip, ua).run();
  await db.prepare('DELETE FROM auth_log WHERE id NOT IN (SELECT id FROM auth_log ORDER BY id DESC LIMIT 200)').run();

  if (!ok) {
    const fails = (att.locked_until && att.locked_until <= now ? 0 : att.fails) + 1;
    const lockedUntil = fails >= MAX_FAILS ? now + LOCK_MS : 0;
    await db
      .prepare('INSERT INTO login_attempts (ip, fails, locked_until) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET fails = ?2, locked_until = ?3')
      .bind(ip, lockedUntil ? 0 : fails, lockedUntil)
      .run();
    if (lockedUntil) return json({ error: 'locked', lockedUntil }, 429);
    return json({ error: 'invalid', remaining: MAX_FAILS - fails }, 401);
  }

  await db.prepare('DELETE FROM login_attempts WHERE ip = ?1').bind(ip).run();
  const expiresAt = now + TOKEN_TTL;
  const token = await signToken({ u: loginName, r: role, exp: expiresAt }, env.TOKEN_SECRET);
  return json({ token, username: loginName, role, expiresAt });
}

// Resolve the caller's current role. DB users are re-checked on every request so
// deactivating/deleting a user or changing their role takes effect immediately.
async function currentUser(token, env) {
  const p = await verifyToken(token, env.TOKEN_SECRET);
  if (!p) return null;
  const adminName = String(env.ADMIN_USER || 'administrator').trim();
  if (p.u === adminName) return { name: p.u, role: 'admin', builtin: true };
  const u = await env.DB.prepare('SELECT role, active FROM users WHERE username = ?1').bind(p.u).first();
  if (!u || !u.active) return null;
  return { name: p.u, role: u.role, builtin: false };
}

// ---------- main router ----------
export async function onRequest(context) {
  const { request, env, params } = context;
  const db = env.DB;
  const method = request.method.toUpperCase();
  const parts = (params.route || []).map((p) => decodeURIComponent(p));
  const [res, id] = parts;

  if (!db || !env.ADMIN_PASSWORD || !env.TOKEN_SECRET || !env.DATA_KEY) {
    return err(500, 'Server not configured (missing DB binding or secrets).');
  }

  try {
    const keys = await getKeys(env);
    await ensureEncrypted(db, keys); // one-time: encrypt any plaintext rows left from before encryption

    if (res === 'login' && method === 'POST') return await handleLogin(request, env);

    // --- auth required beyond this point ---
    const auth = request.headers.get('Authorization') || '';
    const user = await currentUser(auth.replace(/^Bearer\s+/i, ''), env);
    if (!user) return err(401, 'Kailangang mag-login ulit.');
    const isAdmin = user.role === 'admin';

    // GET /api/ver  (all roles)
    if (res === 'ver' && method === 'GET') return json({ ver: await getVer(db) });

    // GET /api/summary  (all roles) — brand tabs + counts, cheap (reads brands table only)
    if (res === 'summary' && method === 'GET') {
      const [b, ver] = await Promise.all([db.prepare('SELECT name, cnt FROM brands ORDER BY pos, name').all(), getVer(db)]);
      const brands = b.results.map((x) => ({ name: x.name, count: Math.max(0, x.cnt || 0) }));
      const total = brands.reduce((s, x) => s + x.count, 0);
      return json({ brands, total, ver, role: user.role, canEdit: isAdmin, user: user.name });
    }

    // GET /api/sims?q=&brand=&status=&sort=&dir=&page=&size=  (all roles) — one page
    if (res === 'sims' && method === 'GET' && !id) {
      const url = new URL(request.url);
      const f = await buildFilter(url.searchParams, isAdmin, keys);
      const sortCol = sortColumn(url.searchParams.get('sort'));
      const dir = url.searchParams.get('dir') === 'desc' ? 'DESC' : 'ASC';
      const size = Math.min(MAX_PAGE, Math.max(1, parseInt(url.searchParams.get('size'), 10) || 100));
      const page = Math.max(1, parseInt(url.searchParams.get('page'), 10) || 1);

      // total: use maintained counters when possible (no table scan)
      let total;
      if (!f.hasSearch && !f.status) {
        const r = f.brand
          ? await db.prepare('SELECT cnt AS n FROM brands WHERE name = ?1').bind(f.brand).first()
          : await db.prepare('SELECT COALESCE(SUM(cnt),0) AS n FROM brands').first();
        total = r ? Math.max(0, r.n) : 0;
      } else {
        const r = await db.prepare('SELECT COUNT(*) AS n FROM sims' + f.where).bind(...f.args).first();
        total = r ? r.n : 0;
      }
      const pages = Math.max(1, Math.ceil(total / size));
      const p = Math.min(page, pages);
      const rows = await db
        .prepare('SELECT ' + ROW_COLS + ' FROM sims' + f.where + ' ORDER BY ' + sortCol + ' ' + dir + ', id ' + dir + ' LIMIT ? OFFSET ?')
        .bind(...f.args, size, (p - 1) * size)
        .all();
      const items = await decodeRows(keys, rows.results, isAdmin);
      return json({ items, total, page: p, pages, size, ver: await getVer(db) });
    }

    // ---------- everything below is admin-only ----------
    if (!isAdmin) return err(403, 'Bawal: pang-administrator lang ito.');

    // /api/users  (user management)
    if (res === 'users') {
      if (method === 'GET' && !id) {
        const r = await db.prepare('SELECT username, role, active, created_at AS createdAt FROM users ORDER BY username').all();
        return json({ users: r.results.map((u) => ({ ...u, active: !!u.active })), builtin: String(env.ADMIN_USER || 'administrator').trim() });
      }
      if (method === 'POST' && !id) {
        const b = await body(request);
        const username = clean(b.username, 32).toLowerCase();
        const password = String(b.password || '').trim();
        const role = ROLES.includes(b.role) ? b.role : 'viewer';
        if (!USERNAME_RE.test(username)) return err(400, 'Username: 3-32 characters, letters/numbers/._- lang.');
        if (username === String(env.ADMIN_USER || 'administrator').trim().toLowerCase()) return err(409, 'Reserved na ang username na iyan.');
        if (password.length < 8) return err(400, 'Password: kahit 8 characters.');
        const h = await hashPassword(password);
        try {
          await db.prepare('INSERT INTO users (username, role, pw_salt, pw_hash) VALUES (?1, ?2, ?3, ?4)').bind(username, role, h.salt, h.hash).run();
        } catch (e) {
          if (isUniqueErr(e)) return err(409, 'May user na ganyan ang username.');
          throw e;
        }
        return json({ ok: true });
      }
      if (method === 'PUT' && id) {
        const b = await body(request);
        const name = id.toLowerCase();
        const u = await db.prepare('SELECT username FROM users WHERE username = ?1').bind(name).first();
        if (!u) return err(404, 'Walang ganyang user.');
        const stmts = [];
        if (b.role !== undefined) {
          if (!ROLES.includes(b.role)) return err(400, 'Invalid role.');
          stmts.push(db.prepare("UPDATE users SET role = ?2, updated_at = datetime('now') WHERE username = ?1").bind(name, b.role));
        }
        if (b.active !== undefined) {
          stmts.push(db.prepare("UPDATE users SET active = ?2, updated_at = datetime('now') WHERE username = ?1").bind(name, b.active ? 1 : 0));
        }
        if (b.password !== undefined) {
          const pw = String(b.password || '').trim();
          if (pw.length < 8) return err(400, 'Password: kahit 8 characters.');
          const h = await hashPassword(pw);
          stmts.push(db.prepare("UPDATE users SET pw_salt = ?2, pw_hash = ?3, updated_at = datetime('now') WHERE username = ?1").bind(name, h.salt, h.hash));
        }
        if (!stmts.length) return err(400, 'Walang babaguhin.');
        await db.batch(stmts);
        return json({ ok: true });
      }
      if (method === 'DELETE' && id) {
        const out = await db.prepare('DELETE FROM users WHERE username = ?1').bind(id.toLowerCase()).run();
        if (!out.meta.changes) return err(404, 'Walang ganyang user.');
        return json({ ok: true });
      }
    }

    // GET /api/log
    if (res === 'log' && method === 'GET') {
      const r = await db.prepare('SELECT username, success, ip, user_agent AS userAgent, ts AS timestamp FROM auth_log ORDER BY id DESC LIMIT 20').all();
      return json({ log: r.results.map((x) => ({ ...x, success: !!x.success })) });
    }

    // GET /api/export?<filters>&after=<id>&limit=  — keyset-paged full dump for CSV / backup
    if (res === 'export' && method === 'GET') {
      const url = new URL(request.url);
      const f = await buildFilter(url.searchParams, true, keys);
      const limit = Math.min(EXPORT_PAGE, Math.max(1, parseInt(url.searchParams.get('limit'), 10) || EXPORT_PAGE));
      const after = url.searchParams.get('after') || '';
      const where = f.where ? f.where + ' AND id > ?' : ' WHERE id > ?';
      const rows = await db
        .prepare('SELECT ' + ROW_COLS + ' FROM sims' + where + ' ORDER BY id LIMIT ?')
        .bind(...f.args, after, limit)
        .all();
      const items = await decodeRows(keys, rows.results, true);
      return json({ items, next: items.length === limit ? items[items.length - 1].id : null });
    }

    // POST /api/lookup {numbers:[...], sims:[...]} — find existing SIMs for import preview
    // (client sends normalized plaintext; we compare blind indexes and return decrypted rows)
    if (res === 'lookup' && method === 'POST') {
      const b = await body(request);
      const nums = (Array.isArray(b.numbers) ? b.numbers : []).map(norm).filter(Boolean).slice(0, MAX_LOOKUP);
      const sims = (Array.isArray(b.sims) ? b.sims : []).map(norm).filter(Boolean).slice(0, MAX_LOOKUP);
      const [nh, sh] = await Promise.all([Promise.all(nums.map((x) => bidx(keys, 'n', x))), Promise.all(sims.map((x) => bidx(keys, 's', x)))]);
      const r = await db
        .prepare(
          'SELECT ' + ROW_COLS + ' FROM sims ' +
            'WHERE number_norm IN (SELECT value FROM json_each(?1)) ' +
            "OR (sim_norm <> '' AND sim_norm IN (SELECT value FROM json_each(?2)))"
        )
        .bind(JSON.stringify(nh), JSON.stringify(sh))
        .all();
      const items = (await decodeRows(keys, r.results, true)).map((x) => ({ ...x, numberNorm: norm(x.number), simNorm: norm(x.simNo) }));
      return json({ items });
    }

    // /api/sims (write)
    if (res === 'sims') {
      if (method === 'POST' && !id) {
        const r = cleanRec(await body(request));
        if (!r.number || !r.brand) return err(400, 'Kailangan ang Mobile No. at Brand.');
        try {
          await db.batch([await insertStmt(db, keys, uid(), r, false), bumpVer(db)]);
        } catch (e) {
          if (isUniqueErr(e)) return dupErr(db, keys, r, '');
          throw e;
        }
        return json({ ok: true });
      }
      if (method === 'PUT' && id) {
        const r = cleanRec(await body(request));
        if (!r.number || !r.brand) return err(400, 'Kailangan ang Mobile No. at Brand.');
        let out;
        try {
          out = await db.batch([await updateStmt(db, keys, id, r, false), bumpVer(db)]);
        } catch (e) {
          if (isUniqueErr(e)) return dupErr(db, keys, r, id);
          throw e;
        }
        if (!out[0].meta.changes) return err(404, 'Hindi nahanap ang SIM.');
        return json({ ok: true });
      }
      if (method === 'DELETE' && id) {
        const out = await db.batch([db.prepare('DELETE FROM sims WHERE id = ?1').bind(id), bumpVer(db)]);
        if (!out[0].meta.changes) return err(404, 'Hindi nahanap ang SIM.');
        return json({ ok: true });
      }
    }

    // POST /api/bulk {items:[new...], updates:[{id,...}], brands:[...]} -> {inserted, updated, skipped}
    if (res === 'bulk' && method === 'POST') {
      const b = await body(request);
      const items = (Array.isArray(b.items) ? b.items : []).slice(0, MAX_BULK).map(cleanRec).filter((r) => r.number && r.brand);
      const updates = (Array.isArray(b.updates) ? b.updates : [])
        .slice(0, MAX_BULK)
        .map((u) => ({ id: clean(u.id, 40), ...cleanRec(u) }))
        .filter((u) => u.id && u.number && u.brand);
      const newBrands = Array.isArray(b.brands) ? b.brands.map((x) => clean(x, 40)).filter(Boolean) : [];
      const stmts = newBrands.map((name) => ensureBrand(db, name));
      const firstIns = stmts.length;
      stmts.push(...(await Promise.all(items.map((r) => insertStmt(db, keys, uid(), r, true)))));
      const firstUpd = stmts.length;
      stmts.push(...(await Promise.all(updates.map((u) => updateStmt(db, keys, u.id, u, true)))));
      stmts.push(bumpVer(db));
      const out = await db.batch(stmts);
      let inserted = 0, updated = 0;
      // count via RETURNING rows — meta.changes also includes rows touched by the counter triggers
      for (let i = firstIns; i < firstUpd; i++) inserted += (out[i].results || []).length;
      for (let i = firstUpd; i < firstUpd + updates.length; i++) updated += (out[i].results || []).length;
      return json({ inserted, updated, skipped: items.length - inserted + (updates.length - updated) });
    }

    // /api/brands
    if (res === 'brands') {
      if (method === 'POST' && !id) {
        const name = clean((await body(request)).name, 40);
        if (!name) return err(400, 'Kailangan ang pangalan ng brand.');
        const exists = await db.prepare('SELECT 1 FROM brands WHERE lower(name) = lower(?1)').bind(name).first();
        if (exists) return err(409, 'Nandiyan na ang brand na iyon.');
        await db.batch([ensureBrand(db, name), bumpVer(db)]);
        return json({ ok: true });
      }
      if (method === 'PUT' && id) {
        const name = clean((await body(request)).name, 40);
        if (!name) return err(400, 'Kailangan ang bagong pangalan.');
        const old = await db.prepare('SELECT pos FROM brands WHERE name = ?1').bind(id).first();
        if (!old) return err(404, 'Walang ganitong brand.');
        const clash = await db.prepare('SELECT 1 FROM brands WHERE lower(name) = lower(?1) AND name <> ?2').bind(name, id).first();
        if (clash) return err(409, 'Mayroon nang brand na ganito ang pangalan.');
        if (name === id) return json({ ok: true });
        // create new brand row at the same position, move SIMs (triggers move the counts), drop old row
        await db.batch([
          db.prepare('INSERT INTO brands (name, pos, cnt) VALUES (?1, ?2, 0)').bind(name, old.pos),
          db.prepare("UPDATE sims SET brand = ?2, updated_at = datetime('now') WHERE brand = ?1").bind(id, name),
          db.prepare('DELETE FROM brands WHERE name = ?1').bind(id),
          bumpVer(db),
        ]);
        return json({ ok: true });
      }
      if (method === 'DELETE' && id) {
        const used = await db.prepare('SELECT cnt FROM brands WHERE name = ?1').bind(id).first();
        if (used && used.cnt > 0) return err(409, 'May SIM pa sa brand na ito.');
        await db.batch([db.prepare('DELETE FROM brands WHERE name = ?1').bind(id), bumpVer(db)]);
        return json({ ok: true });
      }
    }

    // POST /api/clear
    if (res === 'clear' && method === 'POST') {
      await db.batch([db.prepare('DELETE FROM sims'), db.prepare('DELETE FROM brands'), bumpVer(db)]);
      return json({ ok: true });
    }

    return err(404, 'Not found');
  } catch (e) {
    return err(500, 'Server error: ' + (e && e.message ? e.message : 'unknown'));
  }
}
