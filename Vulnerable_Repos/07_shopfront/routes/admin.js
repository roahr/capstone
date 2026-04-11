const express = require("express");
const router = express.Router();

const platformConfig = {
  siteName: "ShopFront",
  currency: "USD",
  taxRate: 0.08,
  shipping: {
    freeThreshold: 50,
    flatRate: 5.99,
    providers: ["usps", "fedex"],
  },
  features: {
    reviews: true,
    wishlist: true,
    comparisons: false,
  },
};

function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
      if (!target[key]) {
        target[key] = {};
      }
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

router.get("/config", (req, res) => {
  res.json({ config: platformConfig });
});

router.put("/config", (req, res) => {
  const updates = req.body;

  if (!updates || typeof updates !== "object") {
    return res.status(400).json({ error: "Configuration object required" });
  }

  const merged = deepMerge(platformConfig, updates);

  res.json({
    message: "Configuration updated",
    config: merged,
    timestamp: new Date().toISOString(),
  });
});

router.get("/stats", (req, res) => {
  res.json({
    activeUsers: 142,
    ordersToday: 37,
    revenue: 2841.5,
    topCategory: "Electronics",
  });
});

module.exports = router;
