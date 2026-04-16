/**
 * Utility helpers.
 * CWE-1321: mergeOptions does recursive merge without __proto__ guard.
 */

/**
 * Deep-merge src into target. Used for merging request filter params.
 * Vulnerable to prototype pollution if src contains __proto__ or constructor keys.
 */
function mergeOptions(target, src) {
  if (typeof src !== 'object' || src === null) return target;
  for (const key of Object.keys(src)) {
    if (typeof src[key] === 'object' && src[key] !== null) {
      if (!target[key]) target[key] = {};
      // CWE-1321: no guard against key === '__proto__' or 'constructor'
      mergeOptions(target[key], src[key]);
    } else {
      target[key] = src[key];
    }
  }
  return target;
}

function slugify(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-');
}

module.exports = { mergeOptions, slugify };
