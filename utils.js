const crypto = require('crypto');

const CODE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function generateCode(length = 8) {
  let code = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) code += CODE_CHARS[bytes[i] % CODE_CHARS.length];
  return code;
}

function generateReceiptHash() {
  return crypto.randomBytes(16).toString('hex');
}

function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function isValidUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function sanitizeInput(str, maxLen) {
  if (typeof str !== 'string') return null;
  const trimmed = str.trim();
  if (trimmed.length === 0) return null;
  return maxLen ? trimmed.substring(0, maxLen) : trimmed;
}

module.exports = {
  generateCode,
  generateReceiptHash,
  generateCSRFToken,
  escapeHtml,
  isValidUrl,
  sanitizeInput,
  CODE_CHARS
};
