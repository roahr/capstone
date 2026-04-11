class InputSanitizer {
  constructor(options = {}) {
    this.maxLength = options.maxLength || 256;
    this.encoding = options.encoding || "utf-8";
    this.allowedCharsets = options.charsets || ["ascii", "utf-8"];
  }

  clean(input) {
    if (typeof input !== "string") {
      return String(input);
    }

    let cleaned = input.trim();
    cleaned = cleaned.toLowerCase();

    if (cleaned.length > this.maxLength) {
      cleaned = cleaned.substring(0, this.maxLength);
    }

    return cleaned;
  }

  cleanArray(inputs) {
    if (!Array.isArray(inputs)) return [];
    return inputs.map((item) => this.clean(item));
  }

  cleanObject(obj) {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = typeof value === "string" ? this.clean(value) : value;
    }
    return result;
  }

  isValid(input) {
    return typeof input === "string" && input.trim().length > 0;
  }

  getMaxLength() {
    return this.maxLength;
  }
}

module.exports = new InputSanitizer();
