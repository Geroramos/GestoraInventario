'use strict';
// Gestora · API única (Vercel Function). Rutas: register, login, logout, me,
// products, movements, reports. Cada cuenta ve solo sus propios datos.
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

const DB_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || '';
const sql = DB_URL ? neon(DB_URL) : null;
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('gestora|' + DB_URL).digest('hex');
const COOKIE = 'gestora_session';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 días

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id SERIAL PRIMARY KEY,
     username TEXT NOT NULL UNIQUE,
     password_hash TEXT NOT NULL,
     created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
  `CREATE TABLE IF NOT EXISTS products (
     id SERIAL PRIMARY KEY,
     user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     code TEXT NOT NULL,
     category TEXT,
     supplier TEXT,
     stock INT NOT NULL DEFAULT 0,
     min_stock INT NOT NULL DEFAULT 0,
     price NUMERIC(12,2) NOT NULL DEFAULT 0,
     created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
     updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
     UNIQUE (user_id, code))`,
  `CREATE TABLE IF NOT EXISTS movements (
     id SERIAL PRIMARY KEY,
     user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
     type TEXT NOT NULL CHECK (type IN ('entrada','salida')),
     qty INT NOT NULL,
     note TEXT,
     created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
  `CREATE INDEX IF NOT EXISTS idx_movements_user_date ON movements (user_id, created_at DESC)`,
];

let ready = null;
function ensureSchema() {
  if (!ready) {
    ready = (async () => { for (const q of SCHEMA) await sql.query(q); })()
      .catch((e) => { ready = null; throw e; });
  }
  return ready;
}

// --- Contraseñas (scrypt, sin dependencias) ---
const scrypt = (pw, salt) => new Promise((ok, no) =>
  crypto.scrypt(pw, salt, 64, (e, k) => (e ? no(e) : ok(k))));
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(pw, salt)).toString('hex');
}
async function checkPassword(pw, stored) {
  const [s, h] = String(stored).split(':');
  if (!s || !h) return false;
  const k = await scrypt(pw, Buffer.from(s, 'hex'));
  const b = Buffer.from(h, 'hex');
  return b.length === k.length && crypto.timingSafeEqual(k, b);
}
const DUMMY_HASH = '00'.repeat(16) + ':' + '00'.repeat(64);

// --- Sesión: cookie firmada (HMAC) ---
const sign = (data) => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
function makeToken(user) {
  const body = Buffer.from(JSON.stringify({
    id: user.id, u: user.username, exp: Date.now() + MAX_AGE * 1000,
  })).toString('base64url');
  return body + '.' + sign(body);
}
function readSession(req) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig) return null;
  const good = sign(body);
  if (sig.length !== good.length ||
      !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try {
    const s = JSON.parse(Buffer.from(body, 'base64url').toString());
    return s.exp > Date.now() ? s : null;
  } catch { return null; }
}
function setCookie(res, value, maxAge) {
  res.setHeader('Set-Cookie',
    `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
}

// --- Validación ---
const str = (v, n) => { const s = String(v ?? '').trim().slice(0, n); return s || null; };
const int = (v) => { const n = Math.floor(Number(v)); return Number.isFinite(n) && n > 0 ? Math.min(n, 2147483647) : 0; };
const num = (v) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.min(n, 9999999999) : 0; };
function productFields(d) {
  const name = str(d.name, 150), code = str(d.code, 50);
  if (!name || !code) return null;
  return [name, code, str(d.category, 100), str(d.supplier, 150),
          int(d.stock), int(d.min_stock), num(d.price)];
}
const PCOLS = 'id, name, code, category, supplier, stock, min_stock, price::float8 AS price';

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const send = (status, data) => res.status(status).json(data);
  const route = String(req.query.route || '');
  const method = req.method;
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const notAllowed = () => send(405, { error: 'Método no soportado.' });

  try {
    if (route === 'me') {
      const s = readSession(req);
      return send(200, s ? { logged_in: true, username: s.u } : { logged_in: false });
    }
    if (route === 'logout') {
      if (method !== 'POST') return notAllowed();
      setCookie(res, '', 0);
      return send(200, { ok: true });
    }
    if (!sql) return send(500, { error: 'Falta conectar la base de datos.' });
    await ensureSchema();

    if (route === 'register') {
      if (method !== 'POST') return notAllowed();
      const username = String(body.username || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!/^[a-z0-9._-]{3,40}$/.test(username)) {
        return send(422, { error: 'El usuario debe tener entre 3 y 40 caracteres (letras, números, punto, guion o guion bajo).' });
      }
      if (password.length < 8 || password.length > 200) {
        return send(422, { error: 'La contraseña debe tener al menos 8 caracteres.' });
      }
      try {
        const rows = await sql.query(
          'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
          [username, await hashPassword(password)]);
        setCookie(res, makeToken(rows[0]), MAX_AGE);
        return send(201, { ok: true, username });
      } catch (e) {
        if (e.code === '23505') return send(409, { error: 'Ese nombre de usuario ya existe.' });
        throw e;
      }
    }

    if (route === 'login') {
      if (method !== 'POST') return notAllowed();
      const username = String(body.username || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!username || !password) return send(422, { error: 'Usuario y contraseña son obligatorios.' });
      const rows = await sql.query('SELECT id, username, password_hash FROM users WHERE username = $1', [username]);
      const user = rows[0];
      const ok = await checkPassword(password.slice(0, 200), user ? user.password_hash : DUMMY_HASH);
      if (!user || !ok) return send(401, { error: 'Usuario o contraseña incorrectos.' });
      setCookie(res, makeToken(user), MAX_AGE);
      return send(200, { ok: true, username: user.username });
    }

    // Todo lo de abajo exige sesión y solo toca los datos del usuario.
    const session = readSession(req);
    if (!session) return send(401, { error: 'No autenticado.' });
    const uid = session.id;
    const id = Number(req.query.id);

    if (route === 'products') {
      if (method === 'GET') {
        if (req.query.id !== undefined) {
          const rows = await sql.query(`SELECT ${PCOLS} FROM products WHERE id = $1 AND user_id = $2`, [id, uid]);
          return rows[0] ? send(200, rows[0]) : send(404, { error: 'Producto no encontrado.' });
        }
        const q = req.query.q ? '%' + String(req.query.q).replace(/[\\%_]/g, '\\$&') + '%' : null;
        const cat = req.query.category || null;
        const rows = await sql.query(
          `SELECT ${PCOLS} FROM products
           WHERE user_id = $1 AND ($2::text IS NULL OR name ILIKE $2 OR code ILIKE $2)
             AND ($3::text IS NULL OR category = $3)
           ORDER BY name ASC`, [uid, q, cat]);
        return send(200, rows);
      }
      if (method === 'POST') {
        const f = productFields(body);
        if (!f) return send(422, { error: 'Nombre y código son obligatorios.' });
        try {
          const rows = await sql.query(
            `INSERT INTO products (user_id, name, code, category, supplier, stock, min_stock, price)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`, [uid, ...f]);
          return send(201, { id: rows[0].id });
        } catch (e) {
          if (e.code === '23505') return send(409, { error: 'Ese código de producto ya existe.' });
          throw e;
        }
      }
      if (method === 'PUT') {
        if (!Number.isInteger(id)) return send(422, { error: 'Falta el id del producto.' });
        const f = productFields(body);
        if (!f) return send(422, { error: 'Nombre y código son obligatorios.' });
        try {
          const rows = await sql.query(
            `UPDATE products SET name = $3, code = $4, category = $5, supplier = $6,
               stock = $7, min_stock = $8, price = $9, updated_at = now()
             WHERE id = $1 AND user_id = $2 RETURNING id`, [id, uid, ...f]);
          return rows[0] ? send(200, { ok: true }) : send(404, { error: 'Producto no encontrado.' });
        } catch (e) {
          if (e.code === '23505') return send(409, { error: 'Ese código de producto ya existe.' });
          throw e;
        }
      }
      if (method === 'DELETE') {
        if (!Number.isInteger(id)) return send(422, { error: 'Falta el id del producto.' });
        await sql.query('DELETE FROM products WHERE id = $1 AND user_id = $2', [id, uid]);
        return send(200, { ok: true });
      }
      return notAllowed();
    }

    if (route === 'movements') {
      if (method === 'GET') {
        const pid = Number.isInteger(Number(req.query.product_id)) && req.query.product_id ? Number(req.query.product_id) : null;
        const rows = await sql.query(
          `SELECT m.id, m.product_id, m.type, m.qty, m.note,
                  to_char(m.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
                  p.name AS product_name
           FROM movements m JOIN products p ON p.id = m.product_id
           WHERE m.user_id = $1 AND ($2::int IS NULL OR m.product_id = $2)
           ORDER BY m.created_at DESC, m.id DESC LIMIT 200`, [uid, pid]);
        return send(200, rows);
      }
      if (method === 'POST') {
        const productId = Number(body.product_id);
        const qty = int(body.qty);
        const type = body.type;
        if (!Number.isInteger(productId) || !['entrada', 'salida'].includes(type) || qty <= 0) {
          return send(422, { error: 'Datos inválidos. Se necesita product_id, type (entrada/salida) y qty > 0.' });
        }
        // Una sola sentencia: ajusta el stock y registra el movimiento de forma atómica.
        const rows = await sql.query(
          `WITH upd AS (
             UPDATE products SET stock = GREATEST(0, stock + $3::int), updated_at = now()
             WHERE id = $1 AND user_id = $2 RETURNING id, stock
           ), ins AS (
             INSERT INTO movements (user_id, product_id, type, qty, note)
             SELECT $2::int, id, $4::text, $5::int, $6::text FROM upd RETURNING id
           )
           SELECT stock AS new_stock FROM upd`,
          [productId, uid, type === 'entrada' ? qty : -qty, type, qty, str(body.note, 255)]);
        if (!rows[0]) return send(404, { error: 'Producto no encontrado.' });
        return send(201, { ok: true, new_stock: rows[0].new_stock });
      }
      return notAllowed();
    }

    if (route === 'reports') {
      if (method !== 'GET') return notAllowed();
      const [t] = await sql.query(
        `SELECT COALESCE(SUM(stock * price), 0)::float8 AS total_value,
                COALESCE(SUM(stock), 0)::int AS total_units,
                COUNT(*)::int AS total_products
         FROM products WHERE user_id = $1`, [uid]);
      const low = await sql.query(
        `SELECT id, name, code, stock, min_stock FROM products
         WHERE user_id = $1 AND stock <= min_stock ORDER BY stock ASC`, [uid]);
      return send(200, { ...t, low_stock: low });
    }

    return send(404, { error: 'Ruta no encontrada.' });
  } catch (e) {
    console.error('gestora api error:', route, e);
    return send(500, { error: 'Error interno del servidor.' });
  }
};
