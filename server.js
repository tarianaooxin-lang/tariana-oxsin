const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET environment variable is missing.');
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL environment variable is missing.');
  process.exit(1);
}

app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000
});

pool.on('error', (err) => {
  console.error('Database pool error:', err.message);
});

const seed = require('./seed-data.json');

async function q(sql, params = []) {
  return pool.query(sql, params);
}

function productId(p) {
  const s = p.name + '|' + (p.category || '');
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return 'p' + Math.abs(h);
}

async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    national_id TEXT UNIQUE,
    national_id_type TEXT,
    phone TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    status TEXT NOT NULL DEFAULT 'pending',
    requested_tier TEXT,
    tier TEXT,
    province TEXT,
    city TEXT,
    postal_code TEXT,
    address TEXT,
    receiver TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT,
    price TEXT,
    stock TEXT,
    updated TEXT,
    tiers JSONB NOT NULL DEFAULT '{}'::jsonb,
    package_count TEXT
  )`);

  await q(`CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    order_number TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'new',
    items JSONB NOT NULL,
    total_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`);

  const count = await q('SELECT COUNT(*)::int AS n FROM products');

  if (Number(count.rows[0].n) === 0) {
    for (const p of seed.catalog) {
      await q(
        `INSERT INTO products
        (id, name, category, price, stock, updated, tiers, package_count)
        VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
        ON CONFLICT (id) DO NOTHING`,
        [
          productId(p),
          p.name,
          p.category || '',
          String(p.price || ''),
          String(p.stock || 'موجود'),
          String(p.updated || ''),
          JSON.stringify(p.tiers || {}),
          String(p.package_count || '')
        ]
      );
    }
  }

  const admin = await q(
    `SELECT id FROM users WHERE role = 'admin' LIMIT 1`
  );

  if (admin.rows.length === 0) {
    const initialPassword = process.env.ADMIN_INITIAL_PASSWORD;

    if (!initialPassword) {
      throw new Error(
        'ADMIN_INITIAL_PASSWORD must be configured in Render.'
      );
    }

    const hash = await bcrypt.hash(initialPassword, 12);

    await q(
      `INSERT INTO users
      (id, name, phone, password_hash, role, status, tier)
      VALUES ('admin', 'مدیر سیستم', 'admin', $1, 'admin', 'approved', 'admin')
      ON CONFLICT (id) DO NOTHING`,
      [hash]
    );
  }

  console.log('Database initialized successfully.');
}

function normalizeDigits(value) {
  return String(value || '')
    .replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d))
    .replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
}

function validId(type, id) {
  id = normalizeDigits(id).replace(/\D/g, '');
  return type === 'national'
    ? /^\d{10}$/.test(id)
    : /^\d{11,16}$/.test(id);
}

function sign(user, kind) {
  return jwt.sign(
    { sub: user.id, role: user.role, kind },
    JWT_SECRET,
    { expiresIn: kind === 'admin' ? '12h' : '30d' }
  );
}

function pubUser(u) {
  return {
    id: u.id,
    name: u.name,
    nationalId: u.national_id,
    nationalIdType: u.national_id_type,
    phone: u.phone,
    role: u.role,
    status: u.status,
    requestedTier: u.requested_tier,
    tier: u.tier,
    province: u.province,
    city: u.city,
    postalCode: u.postal_code,
    address: u.address,
    receiver: u.receiver
  };
}

function pubProduct(p) {
  return {
    id: p.id,
    name: p.name,
    category: p.category,
    price: p.price,
    stock: p.stock,
    updated: p.updated,
    tiers: p.tiers || {},
    package_count: p.package_count
  };
}

function auth(kind) {
  return async (req, res, next) => {
    try {
      const raw = (req.headers.authorization || '')
        .replace(/^Bearer\s+/i, '');

      if (!raw) {
        return res.status(401).json({
          message: 'نیاز به ورود دارید.'
        });
      }

      const token = jwt.verify(raw, JWT_SECRET);

      if (token.kind !== kind) {
        throw new Error('Invalid token type');
      }

      const result = await q(
        'SELECT * FROM users WHERE id = $1',
        [token.sub]
      );

      if (!result.rows[0]) {
        throw new Error('User not found');
      }

      req.user = result.rows[0];
      next();
    } catch (err) {
      return res.status(401).json({
        message: 'نشست شما معتبر نیست؛ دوباره وارد شوید.'
      });
    }
  };
}

/* Health check: no database details are exposed publicly. */
app.get('/health', async (req, res) => {
  try {
    await q('SELECT 1');
    res.status(200).json({
      ok: true,
      service: 'tariana-oxsin-backend'
    });
  } catch (err) {
    console.error('Health check failed:', err.message);
    res.status(503).json({
      ok: false,
      message: 'Database unavailable'
    });
  }
});

/* Catalog */
app.get('/api/bootstrap', async (req, res) => {
  try {
    const result = await q(
      'SELECT * FROM products ORDER BY id'
    );

    res.json({
      catalog: result.rows.map(pubProduct),
      groups: [...new Set(
        result.rows.map(p => p.category).filter(Boolean)
      )]
    });
  } catch (err) {
    console.error('Bootstrap error:', err.message);
    res.status(500).json({

:::
