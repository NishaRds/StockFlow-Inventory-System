const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./db');
require('./seed')(db);

const app = express();
app.set('trust proxy', 1);

// ---------- CORS ----------
// Local testing: allows everything.
// Online: set FRONTEND_ORIGIN to your website address, e.g. https://stockflow.netlify.app
// (several addresses can be separated by commas)
const allowedOrigins = (process.env.FRONTEND_ORIGIN || '')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors(allowedOrigins.length ? { origin: allowedOrigins } : {}));
app.use(express.json({ limit: '5mb' }));

// ---------- LOGIN TOKENS (no extra package needed) ----------
// Online: set JWT_SECRET as an environment variable so logins survive restarts.
function loadSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const file = path.join(__dirname, '.jwt-secret');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(file, secret);
  return secret;
}
const SECRET = loadSecret();
const TOKEN_DAYS = 7;

function signToken(payload) {
  const body = Buffer.from(JSON.stringify({
    ...payload,
    exp: Date.now() + TOKEN_DAYS * 24 * 60 * 60 * 1000
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifyToken(token) {
  try {
    const [body, sig] = String(token || '').split('.');
    if (!body || !sig) return null;
    const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (e) { return null; }
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const payload = verifyToken(header.startsWith('Bearer ') ? header.slice(7) : '');
  if (!payload) return res.status(401).json({ error: 'Please log in again.' });
  // a removed staff member is blocked straight away
  const still = db.prepare('SELECT id FROM users WHERE id = ?').get(payload.id);
  if (!still) return res.status(401).json({ error: 'Account no longer exists.' });
  req.user = payload;
  next();
}

// a user may only touch their own shop's data
function sameShop(req, res, next) {
  if (req.params.shopId !== req.user.shopId)
    return res.status(403).json({ error: 'Not allowed.' });
  next();
}

function ownerOnly(req, res, next) {
  if (req.user.role !== 'owner')
    return res.status(403).json({ error: 'Only the shop owner can do this.' });
  next();
}

// ---------- LOGIN ATTEMPT LIMIT ----------
const attempts = new Map();
const MAX_ATTEMPTS = 10;
const WINDOW_MS = 15 * 60 * 1000;

function tooManyAttempts(key) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now - entry.first > WINDOW_MS) return false;
  return entry.count >= MAX_ATTEMPTS;
}
function noteFailure(key) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now - entry.first > WINDOW_MS) attempts.set(key, { count: 1, first: now });
  else entry.count++;
}

// ---------- CHECKS ON SAVED DATA ----------
const isNum = v => typeof v === 'number' ? Number.isFinite(v) : (v !== '' && v !== null && Number.isFinite(Number(v)));

function checkProducts(list) {
  for (const p of list) {
    if (!p || typeof p.name !== 'string' || !p.name.trim()) return 'Every product needs a name.';
    if (!isNum(p.price) || Number(p.price) < 0) return 'Invalid price for ' + p.name + '.';
    if (!isNum(p.qty) || Number(p.qty) < 0 || !Number.isInteger(Number(p.qty))) return 'Invalid stock quantity for ' + p.name + '.';
    if (!isNum(p.lowLimit) || Number(p.lowLimit) < 0) return 'Invalid low-stock limit for ' + p.name + '.';
  }
  return null;
}

function checkCustomers(list) {
  for (const c of list) {
    if (!c || typeof c.name !== 'string' || !c.name.trim()) return 'Every customer needs a name.';
  }
  return null;
}

function checkSales(list) {
  for (const s of list) {
    if (!s || !s.id) return 'A bill is missing its ID.';
    if (!isNum(s.total) || Number(s.total) < 0) return 'Invalid total on bill ' + s.id + '.';
    if (!Array.isArray(s.items)) return 'Bill ' + s.id + ' has no items.';
    for (const i of s.items) {
      if (!isNum(i.quantity) || Number(i.quantity) <= 0 || !Number.isInteger(Number(i.quantity)))
        return 'Invalid quantity on bill ' + s.id + '.';
      if (!isNum(i.price) || Number(i.price) < 0) return 'Invalid price on bill ' + s.id + '.';
    }
    if (s.paid !== undefined) {
      if (!isNum(s.paid) || Number(s.paid) < 0 || Number(s.paid) > Number(s.total) + 0.01)
        return 'Invalid paid amount on bill ' + s.id + '.';
    }
  }
  return null;
}

// ---------- OPEN ROUTES ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/register', (req, res) => {
  const u = req.body || {};
  if (!u.username || !u.email || !u.password)
    return res.status(400).json({ error: 'Missing fields' });
  if (String(u.password).length < 6)
    return res.status(400).json({ error: 'Password must contain at least 6 characters.' });

  const exists = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?')
    .get(u.username.toLowerCase(), u.email.toLowerCase());
  if (exists) return res.status(400).json({ error: 'Username or email already used' });

  const id = Date.now().toString();
  db.prepare(`INSERT INTO users (id, role, shopName, ownerName, shopType, ownerPhone,
    phone, address, pincode, email, username, password)
    VALUES (?, 'owner', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, u.shopName, u.ownerName, u.shopType, u.ownerPhone, u.phone,
      u.address, u.pincode, u.email.toLowerCase(), u.username.toLowerCase(),
      bcrypt.hashSync(u.password, 10));
  res.json({ ok: true, id });
});

app.post('/api/login', (req, res) => {
  const loginId = String(req.body.loginId || '').toLowerCase();
  const key = req.ip + '|' + loginId;
  if (tooManyAttempts(key))
    return res.status(429).json({ error: 'Too many wrong attempts. Please try again after 15 minutes.' });

  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?')
    .get(loginId, loginId);
  if (!user || !bcrypt.compareSync(req.body.password || '', user.password)) {
    noteFailure(key);
    return res.status(401).json({ error: 'Incorrect username, email or password.' });
  }
  attempts.delete(key);
  delete user.password;

  const shopId = user.role === 'staff' ? user.ownerId : user.id;
  const token = signToken({ id: user.id, role: user.role, shopId });
  res.json({ ...user, token });
});

// ---------- PROTECTED ROUTES (login required) ----------
app.use('/api', requireAuth);

// products
app.get('/api/products/:shopId', sameShop, (req, res) => {
  res.json(db.prepare('SELECT * FROM products WHERE shopId = ?').all(req.params.shopId));
});

app.put('/api/products-sync/:shopId', sameShop, (req, res) => {
  const list = req.body;
  if (!Array.isArray(list)) return res.status(400).json({ error: 'Send a list' });
  const problem = checkProducts(list);
  if (problem) return res.status(400).json({ error: problem });
  const shopId = req.params.shopId;

  const save = db.transaction(() => {
    db.prepare('DELETE FROM products WHERE shopId = ?').run(shopId);
    const insert = db.prepare(`INSERT INTO products
      (id, shopId, name, category, price, qty, lowLimit, expiry)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    list.forEach(p => insert.run(String(p.id), shopId, p.name, p.category || '',
      Number(p.price), Number(p.qty), Number(p.lowLimit), p.expiry || ''));
  });
  try { save(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: 'Could not save products.' }); }
});

// customers
app.get('/api/customers/:shopId', sameShop, (req, res) => {
  res.json(db.prepare('SELECT * FROM customers WHERE shopId = ?').all(req.params.shopId));
});

app.put('/api/customers-sync/:shopId', sameShop, (req, res) => {
  const list = req.body;
  if (!Array.isArray(list)) return res.status(400).json({ error: 'Send a list' });
  const problem = checkCustomers(list);
  if (problem) return res.status(400).json({ error: problem });
  const shopId = req.params.shopId;

  const save = db.transaction(() => {
    db.prepare('DELETE FROM customers WHERE shopId = ?').run(shopId);
    const insert = db.prepare('INSERT INTO customers (id, shopId, name, phone) VALUES (?, ?, ?, ?)');
    list.forEach(c => insert.run(String(c.id), shopId, c.name, c.phone || ''));
  });
  try { save(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: 'Could not save customers.' }); }
});

// sales
app.get('/api/sales/:shopId', sameShop, (req, res) => {
  const rows = db.prepare('SELECT * FROM sales WHERE shopId = ? ORDER BY date DESC')
    .all(req.params.shopId);
  res.json(rows.map(r => ({ ...r, items: JSON.parse(r.items), payments: JSON.parse(r.payments) })));
});

app.put('/api/sales-sync/:shopId', sameShop, (req, res) => {
  const list = req.body;
  if (!Array.isArray(list)) return res.status(400).json({ error: 'Send a list' });
  const problem = checkSales(list);
  if (problem) return res.status(400).json({ error: problem });
  const shopId = req.params.shopId;

  const save = db.transaction(() => {
    db.prepare('DELETE FROM sales WHERE shopId = ?').run(shopId);
    const insert = db.prepare(`INSERT INTO sales (id, shopId, customerId, customerName,
      customerPhone, items, total, staff, date, paid, paymentType, payments)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    list.forEach(s => {
      const total = Number(s.total);
      const paid = s.paid === undefined ? total : Number(s.paid);
      const payments = s.payments || [{ amount: total, date: s.date }];
      insert.run(String(s.id), shopId, s.customerId || '', s.customerName || '',
        s.customerPhone || '', JSON.stringify(s.items || []), total, s.staff || '',
        s.date, paid, s.paymentType || 'Paid', JSON.stringify(payments));
    });
  });
  try { save(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: 'Could not save sales.' }); }
});

// staff accounts (owner only)
app.get('/api/staff/:ownerId', ownerOnly, (req, res) => {
  if (req.params.ownerId !== req.user.id) return res.status(403).json({ error: 'Not allowed.' });
  res.json(db.prepare("SELECT id, ownerName, username FROM users WHERE role = 'staff' AND ownerId = ?")
    .all(req.user.id));
});

app.post('/api/staff', ownerOnly, (req, res) => {
  const { name, username, password } = req.body || {};
  if (!name || !username || !password || password.length < 6)
    return res.status(400).json({ error: 'Fill all fields. Password needs 6+ characters.' });

  const owner = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'owner'").get(req.user.id);
  if (!owner) return res.status(400).json({ error: 'Owner not found.' });

  const uname = username.trim().toLowerCase();
  const taken = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(uname, uname);
  if (taken) return res.status(400).json({ error: 'This username is already used. Please choose another one.' });

  const id = Date.now().toString();
  db.prepare(`INSERT INTO users (id, role, ownerId, shopName, ownerName, shopType, ownerPhone,
    phone, address, pincode, email, username, password)
    VALUES (?, 'staff', ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`)
    .run(id, owner.id, owner.shopName, name, owner.shopType, owner.ownerPhone,
      owner.phone, owner.address, owner.pincode, uname, bcrypt.hashSync(password, 10));
  res.json({ id });
});

app.delete('/api/staff/:id', ownerOnly, (req, res) => {
  db.prepare("DELETE FROM users WHERE id = ? AND role = 'staff' AND ownerId = ?")
    .run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// any unexpected error: send a clean message instead of a crash page
app.use((err, req, res, next) => {
  console.log('SERVER ERROR:', err.message);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', err => {
  if (err) return console.log('ERROR:', err.message);
  console.log('Running on port ' + PORT);
});
