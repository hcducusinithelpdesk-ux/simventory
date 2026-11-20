// ================================================================
//  SIM Inventory API — Cloudflare Pages Function + D1
//  Routes (all JSON, all require Bearer token except POST /api/login):
//    POST   /api/login            {username,password} -> {token,username,expiresAt}
//    GET    /api/state            -> {data,brands,canEdit,protected,ver}
//    GET    /api/ver              -> {ver}
//    GET    /api/log              -> {log:[...]}  (last 20 login attempts)
//    POST   /api/sims             {number,account,simNo,brand,status}
//    PUT    /api/sims/:id         {number,account,simNo,brand,status}
//    DELETE /api/sims/:id
//    POST   /api/bulk             {items:[...], brands:[...]} -> {inserted}
//    POST   /api/brands           {name}
//    PUT    /api/brands/:name     {name}   (rename)
//    DELETE /api/brands/:name     (only if no SIMs use it)
//    POST   /api/clear            (delete all SIMs + brands; used by Restore)
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
  const password = String(b.password || '');
  const expectedUser = env.ADMIN_USER || 'administrator';

  const okUser = await safeEqual(username, expectedUser);
  const okPass = await safeEqual(password, env.ADMIN_PASSWORD);
  const ok = okUser && okPass && password.length > 0;

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
  const token = await signToken({ u: expectedUser, exp: expiresAt }, env.TOKEN_SECRET);
  return json({ token, username: expectedUser, expiresAt });
}

// ---------- main router ----------
export async function onRequest(context) {
  const { request, env, params } = context;
  const db = env.DB;
  const method = request.method.toUpperCase();
  const parts = (params.route || []).map((p) => decodeURIComponent(p));
  const [res, id] = parts;

  if (!db || !env.ADMIN_PASSWORD || !env.TOKEN_SECRET) {
    return err(500, 'Server not configured (missing DB binding or secrets).');
  }

  try {
    if (res === 'login' && method === 'POST') return await handleLogin(request, env);

    // --- auth required beyond this point ---
    const auth = request.headers.get('Authorization') || '';
    const user = await verifyToken(auth.replace(/^Bearer\s+/i, ''), env.TOKEN_SECRET);
    if (!user) return err(401, 'Kailangang mag-login ulit.');

    // GET /api/ver
    if (res === 'ver' && method === 'GET') return json({ ver: await getVer(db) });

    // GET /api/state
    if (res === 'state' && method === 'GET') {
      const [sims, brands, ver] = await Promise.all([
        db.prepare('SELECT id, number, account, sim_no AS simNo, brand, status FROM sims ORDER BY created_at, id').all(),
        db.prepare('SELECT name FROM brands ORDER BY pos, name').all(),
        getVer(db),
      ]);
      return json({ data: sims.results, brands: brands.results.map((b) => b.name), canEdit: true, protected: false, ver, user: user.u });
    }

    // GET /api/log
    if (res === 'log' && method === 'GET') {
      const r = await db.prepare('SELECT username, success, ip, user_agent AS userAgent, ts AS timestamp FROM auth_log ORDER BY id DESC LIMIT 20').all();
      return json({ log: r.results.map((x) => ({ ...x, success: !!x.success })) });
    }

    // /api/sims
    if (res === 'sims') {
      if (method === 'POST' && !id) {
        const r = cleanRec(await body(request));
        if (!r.number || !r.brand) return err(400, 'Kailangan ang Mobile No. at Brand.');
        try {
          await db.batch([
            ensureBrand(db, r.brand),
            db
              .prepare('INSERT INTO sims (id, number, number_norm, account, sim_no, sim_norm, brand, status) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)')
              .bind(uid(), r.number, norm(r.number), r.account, r.simNo, norm(r.simNo), r.brand, r.status),
            bumpVer(db),
          ]);
        } catch (e) {
          if (isUniqueErr(e)) return err(409, 'Duplicate');
          throw e;
        }
        return json({ ok: true });
      }
      if (method === 'PUT' && id) {
        const r = cleanRec(await body(request));
        if (!r.number || !r.brand) return err(400, 'Kailangan ang Mobile No. at Brand.');
        let out;
        try {
          out = await db.batch([
            ensureBrand(db, r.brand),
            db
              .prepare("UPDATE sims SET number=?2, number_norm=?3, account=?4, sim_no=?5, sim_norm=?6, brand=?7, status=?8, updated_at=datetime('now') WHERE id=?1")
              .bind(id, r.number, norm(r.number), r.account, r.simNo, norm(r.simNo), r.brand, r.status),
            bumpVer(db),
          ]);
        } catch (e) {
          if (isUniqueErr(e)) return err(409, 'Duplicate');
          throw e;
        }
        if (!out[1].meta.changes) return err(404, 'Hindi nahanap ang SIM.');
        return json({ ok: true });
      }
      if (method === 'DELETE' && id) {
        const out = await db.batch([db.prepare('DELETE FROM sims WHERE id = ?1').bind(id), bumpVer(db)]);
        if (!out[0].meta.changes) return err(404, 'Hindi nahanap ang SIM.');
        return json({ ok: true });
      }
    }

    // POST /api/bulk
    if (res === 'bulk' && method === 'POST') {
      const b = await body(request);
      const items = Array.isArray(b.items) ? b.items.slice(0, MAX_BULK) : [];
      const newBrands = Array.isArray(b.brands) ? b.brands.map((x) => clean(x, 40)).filter(Boolean) : [];
      const stmts = [];
      const brandSet = new Set(newBrands);
      const recs = items.map(cleanRec).filter((r) => r.number && r.brand);
      recs.forEach((r) => brandSet.add(r.brand));
      brandSet.forEach((name) => stmts.push(ensureBrand(db, name)));
      const firstSim = stmts.length;
      recs.forEach((r) => {
        stmts.push(
          db
            .prepare('INSERT OR IGNORE INTO sims (id, number, number_norm, account, sim_no, sim_norm, brand, status) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)')
            .bind(uid(), r.number, norm(r.number), r.account, r.simNo, norm(r.simNo), r.brand, r.status)
        );
      });
      stmts.push(bumpVer(db));
      const out = await db.batch(stmts);
      let inserted = 0;
      for (let i = firstSim; i < firstSim + recs.length; i++) inserted += out[i].meta.changes || 0;
      return json({ inserted, skipped: recs.length - inserted });
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
        const clash = await db.prepare('SELECT 1 FROM brands WHERE lower(name) = lower(?1) AND name <> ?2').bind(name, id).first();
        if (clash) return err(409, 'Mayroon nang brand na ganito ang pangalan.');
        const out = await db.batch([
          db.prepare('UPDATE brands SET name = ?2 WHERE name = ?1').bind(id, name),
          db.prepare("UPDATE sims SET brand = ?2, updated_at = datetime('now') WHERE brand = ?1").bind(id, name),
          bumpVer(db),
        ]);
        if (!out[0].meta.changes) return err(404, 'Walang ganitong brand.');
        return json({ ok: true });
      }
      if (method === 'DELETE' && id) {
        const used = await db.prepare('SELECT COUNT(*) AS n FROM sims WHERE brand = ?1').bind(id).first();
        if (used && used.n > 0) return err(409, 'May SIM pa sa brand na ito.');
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
