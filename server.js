const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || !DATABASE_URL) {
  console.error('ERROR: JWT_SECRET and DATABASE_URL must be configured.');
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

pool.on('error', err => {
  console.error('Database pool error:', err.message);
});

const seed = require('./seed-data.json');

const q = (sql, params = []) => pool.query(sql, params);

function normalizeDigits(value) {
  return String(value || '')
    .replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d))
    .replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
}

function productId(p) {
  const s = p.name + '|' + (p.category || '');
  let h = 0;

  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }

  return 'p' + Math.abs(h);
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
    receiver: u.receiver,
    createdAt: u.created_at
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

const customerAuth = auth('customer');
const adminAuth = auth('admin');

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
    for (const p of seed.catalog || []) {
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

  const admins = await q(
    "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
  );

  if (admins.rows.length === 0) {
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
      VALUES ('admin','مدیر سیستم','admin',$1,'admin','approved','admin')
      ON CONFLICT (id) DO NOTHING`,
      [hash]
    );
  }

  console.log('Database initialized successfully.');
}

/* Health */
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

/* Public catalog */
app.get('/api/bootstrap', async (req, res) => {
  try {
    const result = await q('SELECT * FROM products ORDER BY id');

    res.json({
      catalog: result.rows.map(pubProduct),
      groups: [...new Set(
        result.rows.map(p => p.category).filter(Boolean)
      )]
    });
  } catch (err) {
    console.error('Bootstrap error:', err.message);
    res.status(500).json({
      message: 'خطا در دریافت فهرست کالاها.'
    });
  }
});

/* Registration */
async function register(req, res) {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    const phone = normalizeDigits(b.phone).replace(/\D/g, '');
    const password = String(b.password || '');
    const nationalId = normalizeDigits(
      b.nationalId || b.national_id || ''
    ).replace(/\D/g, '');
    const idType = b.nationalIdType || b.national_id_type || 'national';

    if (!name || phone.length < 8 || password.length < 4) {
      return res.status(400).json({
        message: 'نام، شماره تماس و رمز عبور معتبر لازم است.'
      });
    }

    if (nationalId && !validId(idType, nationalId)) {
      return res.status(400).json({
        message: 'کد ملی یا شناسه ملی معتبر نیست.'
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const id = 'u' + Date.now().toString(36) +
      Math.random().toString(36).slice(2, 7);

    const result = await q(
      `INSERT INTO users
      (id,name,national_id,national_id_type,phone,password_hash,
       role,status,requested_tier)
      VALUES ($1,$2,$3,$4,$5,$6,'customer','pending',$7)
      RETURNING *`,
      [
        id,
        name,
        nationalId || null,
        idType,
        phone,
        hash,
        b.requestedTier || b.requested_tier || b.tier || null
      ]
    );

    res.status(201).json({
      message: 'درخواست ثبت‌نام ارسال شد و در انتظار تأیید است.',
      user: pubUser(result.rows[0])
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({
        message: 'شماره تماس یا شناسه قبلاً ثبت شده است.'
      });
    }

    console.error('Register error:', err.message);
    res.status(500).json({
      message: 'ثبت‌نام انجام نشد.'
    });
  }
}

app.post('/api/register', register);
app.post('/api/auth/register', register);

/* Customer login */
async function login(req, res) {
  try {
    const phone = normalizeDigits(
      req.body?.phone || req.body?.username
    ).replace(/\D/g, '');
    const password = String(req.body?.password || '');

    const result = await q(
      'SELECT * FROM users WHERE phone = $1',
      [phone]
    );

    const user = result.rows[0];

    if (!user || user.role !== 'customer' ||
        !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        message: 'شماره تماس یا رمز عبور اشتباه است.'
      });
    }

    if (user.status !== 'approved') {
      return res.status(403).json({
        message: 'حساب شما هنوز تأیید نشده است.'
      });
    }

    res.json({
      token: sign(user, 'customer'),
      user: pubUser(user)
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({
      message: 'ورود انجام نشد.'
    });
  }
}

app.post('/api/login', login);
app.post('/api/auth/login', login);

/* Current user */
app.get('/api/me', customerAuth, (req, res) => {
  res.json({ user: pubUser(req.user) });
});

/* Update profile */
app.put('/api/me', customerAuth, async (req, res) => {
  try {
    const b = req.body || {};

    const result = await q(
      `UPDATE users SET
       name = COALESCE($1,name),
       province = COALESCE($2,province),
       city = COALESCE($3,city),
       postal_code = COALESCE($4,postal_code),
       address = COALESCE($5,address),
       receiver = COALESCE($6,receiver)
       WHERE id = $7 RETURNING *`,
      [
        b.name ? String(b.name).trim() : null,
        b.province ?? null,
        b.city ?? null,
        b.postalCode ?? b.postal_code ?? null,
        b.address ?? null,
        b.receiver ?? null,
        req.user.id
      ]
    );

    res.json({ user: pubUser(result.rows[0]) });
  } catch (err) {
    console.error('Profile error:', err.message);
    res.status(500).json({
      message: 'به‌روزرسانی پروفایل انجام نشد.'
    });
  }
});

/* Customer password */
app.put('/api/me/password', customerAuth, async (req, res) => {
  try {
    const oldPassword = String(req.body?.oldPassword || '');
    const newPassword = String(req.body?.newPassword || '');

    if (newPassword.length < 4) {
      return res.status(400).json({
        message: 'رمز جدید باید حداقل ۴ کاراکتر باشد.'
      });
    }

    if (!(await bcrypt.compare(oldPassword, req.user.password_hash))) {
      return res.status(400).json({
        message: 'رمز فعلی صحیح نیست.'
      });
    }

    const hash = await bcrypt.hash(newPassword, 12);

    await q(
      'UPDATE users SET password_hash=$1 WHERE id=$2',
      [hash, req.user.id]
    );

    res.json({ message: 'رمز عبور تغییر کرد.' });
  } catch (err) {
    console.error('Customer password error:', err.message);
    res.status(500).json({
      message: 'تغییر رمز انجام نشد.'
    });
  }
});

/* Admin login */
app.post('/api/admin/login', async (req, res) => {
  try {
    const username = String(req.body?.username || 'admin').trim();
    const password = String(req.body?.password || '');

    const result = await q(
      "SELECT * FROM users WHERE role='admin' AND phone=$1 LIMIT 1",
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        message: 'نام کاربری یا رمز مدیر اشتباه است.'
      });
    }

    res.json({
      token: sign(user, 'admin'),
      user: pubUser(user)
    });
  } catch (err) {
    console.error('Admin login error:', err.message);
    res.status(500).json({
      message: 'ورود مدیر انجام نشد.'
    });
  }
});

/* Admin catalog */
app.get('/api/admin/catalog', adminAuth, async (req, res) => {
  try {
    const result = await q('SELECT * FROM products ORDER BY name');
    res.json({ catalog: result.rows.map(pubProduct) });
  } catch (err) {
    console.error('Admin catalog error:', err.message);
    res.status(500).json({
      message: 'دریافت کالاها انجام نشد.'
    });
  }
});

/* Update product */
app.put('/api/admin/products/:id', adminAuth, async (req, res) => {
  try {
    const b = req.body || {};

    const result = await q(
      `UPDATE products SET
       name=COALESCE($1,name),
       category=COALESCE($2,category),
       price=COALESCE($3,price),
       stock=COALESCE($4,stock),
       updated=COALESCE($5,updated),
       tiers=COALESCE($6::jsonb,tiers),
       package_count=COALESCE($7,package_count)
       WHERE id=$8 RETURNING *`,
      [
        b.name ?? null,
        b.category ?? null,
        b.price == null ? null : String(b.price),
        b.stock == null ? null : String(b.stock),
        b.updated ?? null,
        b.tiers == null ? null : JSON.stringify(b.tiers),
        b.package_count == null ? null : String(b.package_count),
        req.params.id
      ]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        message: 'کالا پیدا نشد.'
      });
    }

    res.json({ product: pubProduct(result.rows[0]) });
  } catch (err) {
    console.error('Product update error:', err.message);
    res.status(500).json({
      message: 'ویرایش کالا انجام نشد.'
    });
  }
});

/* Admin users */
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const result = await q(
      `SELECT * FROM users ORDER BY created_at DESC`
    );

    res.json({
      users: result.rows.map(pubUser)
    });
  } catch (err) {
    console.error('Admin users error:', err.message);
    res.status(500).json({
      message: 'دریافت کاربران انجام نشد.'
    });
  }
});

/* Approve or reject customer */
app.put('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const status = String(req.body?.status || '');

    if (!['approved', 'pending', 'rejected'].includes(status)) {
      return res.status(400).json({
        message: 'وضعیت کاربر معتبر نیست.'
      });
    }

    const result = await q(
      `UPDATE users SET status=$1
       WHERE id=$2 AND role='customer'
       RETURNING *`,
      [status, req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        message: 'کاربر پیدا نشد.'
      });
    }

    res.json({ user: pubUser(result.rows[0]) });
  } catch (err) {
    console.error('User update error:', err.message);
    res.status(500).json({
      message: 'تغییر وضعیت کاربر انجام نشد.'
    });
  }
});

/* Change admin password */
app.put('/api/admin/password', adminAuth, async (req, res) => {
  try {
    const oldPassword = String(req.body?.oldPassword || '');
    const newPassword = String(req.body?.newPassword || '');

    if (newPassword.length < 4) {
      return res.status(400).json({
        message: 'رمز جدید باید حداقل ۴ کاراکتر باشد.'
      });
    }

    if (!(await bcrypt.compare(oldPassword, req.user.password_hash))) {
      return res.status(400).json({
        message: 'رمز فعلی صحیح نیست.'
      });
    }

    const hash = await bcrypt.hash(newPassword, 12);

    await q(
      'UPDATE users SET password_hash=$1 WHERE id=$2',
      [hash, req.user.id]
    );

    res.json({ message: 'رمز مدیر تغییر کرد.' });
  } catch (err) {
    console.error('Admin password error:', err.message);
    res.status(500).json({
      message: 'تغییر رمز مدیر انجام نشد.'
    });
  }
});

/* Create order */
app.post('/api/orders', customerAuth, async (req, res) => {
  try {
    const items = req.body?.items;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        message: 'سبد خرید خالی است.'
      });
    }

    const ids = [...new Set(
      items.map(i => String(i.productId || i.id || ''))
    )];

    const found = await q(
      'SELECT * FROM products WHERE id = ANY($1::text[])',
      [ids]
    );

    const products = new Map(found.rows.map(p => [p.id, p]));
    const normalizedItems = [];
    let total = 0;

    for (const item of items) {
      const id = String(item.productId || item.id || '');
      const product = products.get(id);
      const quantity = Number(item.quantity || item.qty);

      if (!product || !Number.isInteger(quantity) ||
          quantity < 1 || quantity > 10000) {
        return res.status(400).json({
          message: 'کالا یا تعداد آن معتبر نیست.'
        });
      }

      const price = Number(
        normalizeDigits(product.price).replace(/[^\d.]/g, '')
      );

      if (Number.isFinite(price)) {
        total += price * quantity;
      }

      normalizedItems.push({
        productId: product.id,
        name: product.name,
        quantity,
        price: product.price
      });
    }

    const orderNumber = 'TO-' + Date.now();
    const result = await q(
      `INSERT INTO orders
       (id,order_number,user_id,status,items,total_text)
       VALUES ($1,$2,$3,'new',$4::jsonb,$5)
       RETURNING *`,
      [
        'o' + Date.now().toString(36),
        orderNumber,
        req.user.id,
        JSON.stringify(normalizedItems),
        String(total)
      ]
    );

    const order = result.rows[0];

    res.status(201).json({
      order: {
        id: order.id,
        orderNumber: order.order_number,
        userId: order.user_id,
        status: order.status,
        items: order.items,
        total: order.total_text,
        createdAt: order.created_at
      }
    });
  } catch (err) {
    console.error('Create order error:', err.message);
    res.status(500).json({
      message: 'ثبت سفارش انجام نشد.'
    });
  }
});

/* Customer orders */
app.get('/api/orders', customerAuth, async (req, res) => {
  try {
    const result = await q(
      'SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC',
      [req.user.id]
    );

    res.json({
      orders: result.rows.map(o => ({
        id: o.id,
        orderNumber: o.order_number,
        userId: o.user_id,
        status: o.status,
        items: o.items,
        total: o.total_text,
        createdAt: o.created_at
      }))
    });
  } catch (err) {
    console.error('Orders error:', err.message);
    res.status(500).json({
      message: 'دریافت سفارش‌ها انجام نشد.'
    });
  }
});

/* Admin orders */
app.get('/api/admin/orders', adminAuth, async (req, res) => {
  try {
    const result = await q(
      `SELECT orders.*, users.name AS customer_name,
       users.phone AS customer_phone
       FROM orders
       JOIN users ON users.id=orders.user_id
       ORDER BY orders.created_at DESC`
    );

    res.json({ orders: result.rows });
  } catch (err) {
    console.error('Admin orders error:', err.message);
    res.status(500).json({
      message: 'دریافت سفارش‌ها انجام نشد.'
    });
  }
});

/* Update order status */
app.put('/api/admin/orders/:id', adminAuth, async (req, res) => {
  try {
    const status = String(req.body?.status || '');
    const allowed = [
      'new',
      'processing',
      'sent',
      'completed',
      'cancelled'
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        message: 'وضعیت سفارش معتبر نیست.'
      });
    }

    const result = await q(
      'UPDATE orders SET status=$1 WHERE id=$2 RETURNING *',
      [status, req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        message: 'سفارش پیدا نشد.'
      });
    }

    res.json({ order: result.rows[0] });
  } catch (err) {
    console.error('Order update error:', err.message);
    res.status(500).json({
      message: 'تغییر سفارش انجام نشد.'
    });
  }
});

/* Error handler */
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    message: 'خطای داخلی سرور رخ داد.'
  });
});

/* Frontend fallback for Express 5 */
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* Start only after database initialization */
async function start() {
  try {
    await initDb();

    app.listen(PORT, '0.0.0.0', () => {
      console.log('Server listening on port ' + PORT);
    });
  } catch (err) {
    console.error('Server startup failed:', err);
    process.exit(1);
  }
}

start();
