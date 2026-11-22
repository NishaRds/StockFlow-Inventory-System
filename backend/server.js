const express = require('express');
const cors = require('cors');
const db = require('./db');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- USERS ----------
app.post('/api/register', (req, res) => {
  const u = req.body;
  if (!u.username || !u.email || !u.password)
    return res.status(400).json({ error: 'Missing fields' });

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
  const loginId = (req.body.loginId || '').toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?')
    .get(loginId, loginId);
  if (!user || !bcrypt.compareSync(req.body.password || '', user.password))
    return res.status(401).json({ error: 'Incorrect username, email or password.' });
  delete user.password;
  res.json(user);
});

// ---------- PRODUCTS ----------
app.get('/api/products/:shopId', (req, res) => {
  res.json(db.prepare('SELECT * FROM products WHERE shopId = ?').all(req.params.shopId));
});

app.post('/api/products', (req, res) => {
  const p = req.body;
  const id = Date.now().toString();
  db.prepare(`INSERT INTO products (id, shopId, name, category, price, qty, lowLimit, expiry)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, p.shopId, p.name, p.category, p.price, p.qty, p.lowLimit, p.expiry || '');
  res.json({ id });
});

app.put('/api/products/:id', (req, res) => {
  const p = req.body;
  db.prepare(`UPDATE products SET name=?, category=?, price=?, qty=?, lowLimit=?, expiry=?
    WHERE id=?`)
    .run(p.name, p.category, p.price, p.qty, p.lowLimit, p.expiry || '', req.params.id);
  res.json({ ok: true });
});

app.delete('/api/products/:id', (req, res) => {
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});
// ---------- CUSTOMERS ----------
app.get('/api/customers/:shopId', (req, res) => {
  res.json(db.prepare('SELECT * FROM customers WHERE shopId = ?').all(req.params.shopId));
});

app.post('/api/customers', (req, res) => {
  const c = req.body;
  const dup = db.prepare('SELECT id FROM customers WHERE shopId = ? AND phone = ?')
    .get(c.shopId, c.phone);
  if (dup) return res.status(400).json({ error: 'A customer with this phone number already exists.', id: dup.id });
  const id = Date.now().toString();
  db.prepare('INSERT INTO customers (id, shopId, name, phone) VALUES (?, ?, ?, ?)')
    .run(id, c.shopId, c.name, c.phone);
  res.json({ id });
});

app.delete('/api/customers/:id', (req, res) => {
  db.prepare('DELETE FROM customers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- SALES ----------
app.get('/api/sales/:shopId', (req, res) => {
  const rows = db.prepare('SELECT * FROM sales WHERE shopId = ? ORDER BY date DESC')
    .all(req.params.shopId);
  res.json(rows.map(r => ({ ...r, items: JSON.parse(r.items), payments: JSON.parse(r.payments) })));
});

app.post('/api/sales', (req, res) => {
  const s = req.body;
  const id = 'SF' + Date.now().toString().slice(-8);

  const saveSale = db.transaction(() => {
    db.prepare(`INSERT INTO sales (id, shopId, customerId, customerName, customerPhone,
      items, total, staff, date, paid, paymentType, payments)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, s.shopId, s.customerId || '', s.customerName, s.customerPhone || '',
        JSON.stringify(s.items), s.total, s.staff, s.date || new Date().toISOString(),
        s.paid, s.paymentType, JSON.stringify(s.payments || []));

    s.items.forEach(item => {
      const r = db.prepare('UPDATE products SET qty = qty - ? WHERE id = ? AND qty >= ?')
        .run(item.quantity, item.productId, item.quantity);
      if (r.changes === 0) throw new Error('Not enough stock for ' + item.name);
    });
  });

  try { saveSale(); res.json({ id }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
// ---------- DASHBOARD ----------
app.get('/api/dashboard/:shopId', (req, res) => {
  const shopId = req.params.shopId;
  const sales = db.prepare('SELECT * FROM sales WHERE shopId = ?').all(shopId);
  const day = d => new Date(d).toLocaleDateString('en-CA');

  // last 7 days, oldest first
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    days.push({ date: day(d), total: 0, units: 0 });
  }

  const customers = {};
  sales.forEach(s => {
    const items = JSON.parse(s.items);

    const slot = days.find(x => x.date === day(s.date));
    if (slot) {
      slot.total += s.total;
      slot.units += items.reduce((n, i) => n + i.quantity, 0);
    }

    const c = customers[s.customerName] ||
      (customers[s.customerName] = { name: s.customerName, total: 0, items: {} });
    c.total += s.total;
    items.forEach(i => { c.items[i.name] = (c.items[i.name] || 0) + i.quantity; });
  });

  const lowStock = db.prepare('SELECT * FROM products WHERE shopId = ? AND qty <= lowLimit')
    .all(shopId);

  res.json({ days, customers: Object.values(customers), lowStock });
});
app.put('/api/products-sync/:shopId', (req, res) => {
  const list = req.body;
  if (!Array.isArray(list)) return res.status(400).json({ error: 'Send a list' });
  const shopId = req.params.shopId;

  const save = db.transaction(() => {
    db.prepare('DELETE FROM products WHERE shopId = ?').run(shopId);
    const insert = db.prepare(`INSERT INTO products
      (id, shopId, name, category, price, qty, lowLimit, expiry)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    list.forEach(p => insert.run(String(p.id), shopId, p.name, p.category,
      Number(p.price), Number(p.qty), Number(p.lowLimit), p.expiry || ''));
  });
  save();
  res.json({ ok: true });
});
app.get('/api/staff/:ownerId', (req, res) => {
  res.json(db.prepare("SELECT id, ownerName, username FROM users WHERE role = 'staff' AND ownerId = ?")
    .all(req.params.ownerId));
});

app.post('/api/staff', (req, res) => {
  const { ownerId, name, username, password } = req.body;
  if (!name || !username || !password || password.length < 6)
    return res.status(400).json({ error: 'Fill all fields. Password needs 6+ characters.' });

  const owner = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'owner'").get(ownerId);
  if (!owner) return res.status(400).json({ error: 'Owner not found.' });

  const uname = username.trim().toLowerCase();
  const taken = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(uname, uname);
  if (taken) return res.status(400).json({ error: 'This username is already used. Please choose another one.' });

  const id = Date.now().toString();
  db.prepare(`INSERT INTO users (id, role, ownerId, shopName, ownerName, shopType, ownerPhone,
    phone, address, pincode, email, username, password)
    VALUES (?, 'staff', ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`)
    .run(id, ownerId, owner.shopName, name, owner.shopType, owner.ownerPhone,
      owner.phone, owner.address, owner.pincode, uname, bcrypt.hashSync(password, 10));
  res.json({ id });
});

app.delete('/api/staff/:id', (req, res) => {
  db.prepare("DELETE FROM users WHERE id = ? AND role = 'staff'").run(req.params.id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', err => {
  if (err) return console.log('ERROR:', err.message);
  console.log('Running on port ' + PORT);
});