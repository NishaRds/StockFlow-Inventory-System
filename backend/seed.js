// Demo data for hosting on a free plan where the database is wiped on restart.
// Only runs when the environment variable DEMO_SEED=true.
// Demo login:  username  demo   |   password  demo123
const bcrypt = require('bcryptjs');

module.exports = function seed(db) {
  if (process.env.DEMO_SEED !== 'true') return;

  const exists = db.prepare("SELECT id FROM users WHERE id = 'demo'").get();
  if (exists) return;

  db.prepare(`INSERT INTO users (id, role, shopName, ownerName, shopType, ownerPhone,
    phone, address, pincode, email, username, password)
    VALUES ('demo', 'owner', 'Demo General Store', 'Demo Owner', 'General Store',
    '9999999999', '9999999999', 'Mangaluru', '575001', 'demo@example.com', 'demo', ?)`)
    .run(bcrypt.hashSync('demo123', 10));

  const products = [
    ['Rice 1kg', 'Grocery', 60, 100, 15, ''],
    ['Wheat Flour 1kg', 'Grocery', 45, 80, 15, ''],
    ['Sugar 1kg', 'Grocery', 48, 90, 15, ''],
    ['Salt 1kg', 'Grocery', 22, 70, 10, ''],
    ['Tea Powder 250g', 'Grocery', 95, 40, 10, ''],
    ['Biscuits', 'Snacks', 10, 8, 10, ''],
    ['Soap', 'Personal Care', 35, 60, 10, ''],
    ['Toothpaste', 'Personal Care', 80, 5, 8, '']
  ];
  const insert = db.prepare(`INSERT INTO products
    (id, shopId, name, category, price, qty, lowLimit, expiry)
    VALUES (?, 'demo', ?, ?, ?, ?, ?, ?)`);
  products.forEach((p, i) => insert.run('demo-p' + (i + 1), ...p));

  console.log('Demo data created (login: demo / demo123)');
};
