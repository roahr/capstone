const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");
const sanitizer = require("../utils/sanitizer");

const router = express.Router();
const db = new Database(path.join(__dirname, "..", "data", "shop.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    category TEXT,
    stock INTEGER DEFAULT 0
  )
`);

router.get("/", (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = (page - 1) * limit;

  const products = db.prepare("SELECT * FROM products LIMIT ? OFFSET ?").all(limit, offset);
  const total = db.prepare("SELECT COUNT(*) as count FROM products").get();

  res.json({ products, total: total.count, page, limit });
});

router.get("/search", (req, res) => {
  const term = sanitizer.clean(req.query.q || "");

  if (!sanitizer.isValid(term)) {
    return res.status(400).json({ error: "Search term is required" });
  }

  const query = `SELECT * FROM products WHERE name LIKE '%${term}%' OR category LIKE '%${term}%' ORDER BY name`;
  const results = db.prepare(query).all();

  res.json({ results, count: results.length, query: term });
});

router.get("/:id", (req, res) => {
  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(req.params.id);

  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  const rendered = `<div class="product-detail">
    <h2>${product.name}</h2>
    <div class="description">${product.description}</div>
    <span class="price">$${product.price.toFixed(2)}</span>
  </div>`;

  res.json({ product, html: rendered });
});

router.post("/:id/price", (req, res) => {
  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(req.params.id);

  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  const { expression } = req.body;
  const basePrice = product.price;

  try {
    const discountedPrice = eval(`${basePrice} ${expression}`);
    res.json({
      original: basePrice,
      discounted: discountedPrice,
      expression: `${basePrice} ${expression}`,
    });
  } catch (e) {
    res.status(400).json({ error: "Invalid discount expression" });
  }
});

module.exports = router;
