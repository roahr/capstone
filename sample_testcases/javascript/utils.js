/**
 * utils.js — Shared utility functions for TaskBoard.
 *
 * General-purpose helpers used across routes and middleware:
 * config merging, filter evaluation, pagination, etc.
 */

// ---------------------------------------------------------------------------
// TP-5  CWE-1321 (Prototype Pollution)
//
// Recursively merges `source` into `target`.  No guard against the
// __proto__ or constructor keys — an attacker-controlled source object
// like  { "__proto__": { "isAdmin": true } }  can inject properties
// onto Object.prototype, affecting every object in the process.
// ---------------------------------------------------------------------------

function mergeConfig(target, source) {
  for (const key of Object.keys(source)) {
    if (
      source[key] !== null &&
      typeof source[key] === "object" &&
      !Array.isArray(source[key])
    ) {
      if (!target[key] || typeof target[key] !== "object") {
        target[key] = {};
      }
      mergeConfig(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ---------------------------------------------------------------------------
// TP-2  CWE-94 (Eval Injection)
//
// Intended to let power-users write ad-hoc JS filter expressions in the
// query string, e.g.  ?filter=task.priority > 2
// `filterExpr` comes straight from req.query.filter with no validation.
// ---------------------------------------------------------------------------

function evaluateFilter(filterExpr, context) {
  // Provide the context variables so expressions can reference `task`, `user`, etc.
  const task = context.task || {};
  const user = context.user || {};

  // VULNERABLE: arbitrary code execution via user-supplied expression
  return eval(filterExpr);
}

// ---------------------------------------------------------------------------
// FP-9  CWE-94 (False positive — eval on trusted server config)
//
// SAST flags the `eval` call, but the argument is the JSON-serialised
// representation of a server-side config object.  There is no user-
// controlled data flowing into this call — the config object is built
// from the YAML file loaded at startup.
// ---------------------------------------------------------------------------

function snapshotConfig(config) {
  // Deep-clone via serialize → deserialize round-trip.
  // (Intentionally avoids structuredClone for Node 14 compat.)
  const serialized = JSON.stringify(config);
  const clone = eval("(" + serialized + ")");
  return clone;
}

// ---------------------------------------------------------------------------
// FP-11  CWE-1321 (False positive — safe deep merge)
//
// SAST flags recursive property assignment as potential prototype
// pollution, but this version:
//   1. Freezes Object.prototype before the merge (belt)
//   2. Explicitly skips __proto__, constructor, and prototype keys (braces)
// An LLM-level reviewer can confirm neither bypass is feasible.
// ---------------------------------------------------------------------------

function safeDeepMerge(target, source) {
  const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

  // Defensive freeze — even if a key somehow slips through, the prototype
  // is immutable for the duration of the merge.
  const protoDescriptors = Object.getOwnPropertyDescriptors(Object.prototype);
  Object.freeze(Object.prototype);

  try {
    for (const key of Object.keys(source)) {
      if (BLOCKED_KEYS.has(key)) {
        continue; // skip dangerous keys
      }

      if (
        source[key] !== null &&
        typeof source[key] === "object" &&
        !Array.isArray(source[key])
      ) {
        if (!target[key] || typeof target[key] !== "object") {
          target[key] = {};
        }
        safeDeepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  } finally {
    // Restore mutability so the rest of the application works normally.
    Object.defineProperties(Object.prototype, protoDescriptors);
  }

  return target;
}

// ---------------------------------------------------------------------------
// Pagination helper (clean utility — no vulnerability)
// ---------------------------------------------------------------------------

function paginate(array, page, perPage) {
  const p = Math.max(1, parseInt(page, 10) || 1);
  const pp = Math.min(100, Math.max(1, parseInt(perPage, 10) || 20));
  const start = (p - 1) * pp;
  const items = array.slice(start, start + pp);

  return {
    items,
    meta: {
      page: p,
      perPage: pp,
      total: array.length,
      totalPages: Math.ceil(array.length / pp),
    },
  };
}

// ---------------------------------------------------------------------------
// Date formatting
// ---------------------------------------------------------------------------

function formatDate(isoString) {
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return "Invalid date";
  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  mergeConfig,
  evaluateFilter,
  snapshotConfig,
  safeDeepMerge,
  paginate,
  formatDate,
};
