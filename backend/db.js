const Database = require('better-sqlite3');
const db = new Database('stockflow.db');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, role TEXT DEFAULT 'owner', ownerId TEXT,
  shopName TEXT, ownerName TEXT, shopType TEXT, ownerPhone TEXT, phone TEXT,
  address TEXT, pincode TEXT, email TEXT, username TEXT UNIQUE, password TEXT
);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY, shopId TEXT, name TEXT, category TEXT,
  price REAL, qty INTEGER, lowLimit INTEGER, expiry TEXT
);
CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY, shopId TEXT, name TEXT, phone TEXT
);
CREATE TABLE IF NOT EXISTS sales (
  id TEXT PRIMARY KEY, shopId TEXT, customerId TEXT, customerName TEXT,
  customerPhone TEXT, items TEXT, total REAL, staff TEXT, date TEXT,
  paid REAL, paymentType TEXT, payments TEXT
);
`);

module.exports = db;