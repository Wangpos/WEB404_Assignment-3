// Validation helpers for the secure upload endpoint.
// Each function returns null when the check passes, or a reason string when it fails.
const path = require('path');
const { ALLOWED_TYPES, MAX_FILENAME_LENGTH } = require('./config');

// Extensions that must never appear anywhere in a filename (double-extension
// attacks such as shell.php.jpg or invoice.pdf.exe).
const DANGEROUS_EXTENSIONS = new Set([
  'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'pht', 'phps',
  'asp', 'aspx', 'ashx', 'asmx', 'cer', 'jsp', 'jspx', 'jsw', 'jsv',
  'cgi', 'pl', 'py', 'rb', 'sh', 'bash', 'exe', 'dll', 'bat', 'cmd', 'com',
  'ps1', 'vbs', 'js', 'mjs', 'html', 'htm', 'xhtml', 'shtml', 'svg', 'xml',
  'swf', 'htaccess', 'config', 'jar', 'war',
]);

// Magic-byte signatures of each allowed MIME type
const SIGNATURES = {
  'image/jpeg': [[0xff, 0xd8, 0xff]],
  'image/png': [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  'image/gif': [Buffer.from('GIF87a'), Buffer.from('GIF89a')],
  'application/pdf': [Buffer.from('%PDF-')],
};

// Server-side code / script markers that should never be inside an image or PDF.
// Catches polyglot files such as a valid GIF header followed by PHP code.
const SUSPICIOUS_PATTERNS = [
  /<\?php/i,
  /<script/i,
  /<%@\s*page/i,
  /runat\s*=\s*["']?server/i,
  /\beval\s*\(/i,
  /\b(system|passthru|shell_exec|exec)\s*\(/i,
  /<html/i,
  /<svg/i,
];

// Active content inside a PDF (JavaScript, auto-launch actions, embedded files)
const SUSPICIOUS_PDF_PATTERNS = [/\/JavaScript/, /\/JS\b/, /\/Launch/, /\/EmbeddedFile/, /\/OpenAction/];

function checkFilename(name) {
  if (typeof name !== 'string' || name.length === 0) return 'Missing filename';
  if (name.length > MAX_FILENAME_LENGTH) return 'Filename too long';
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(name)) return 'Filename contains control/null characters';
  if (/[/\\]/.test(name) || name.includes('..')) return 'Filename contains path traversal characters';
  if (name.startsWith('.')) return 'Hidden/dot files are not allowed';

  const parts = name.toLowerCase().split('.');
  if (parts.length < 2) return 'File has no extension';
  for (const part of parts.slice(1)) {
    if (DANGEROUS_EXTENSIONS.has(part.trim())) return `Dangerous extension ".${part}" in filename`;
  }
  return null;
}

function checkExtension(name) {
  const ext = path.extname(name).toLowerCase();
  if (!Object.hasOwn(ALLOWED_TYPES, ext)) return `Extension "${ext}" is not allowed`;
  return null;
}

function checkDeclaredMime(name, mimetype) {
  const expected = ALLOWED_TYPES[path.extname(name).toLowerCase()];
  if (mimetype !== expected) return `Content-Type "${mimetype}" does not match extension`;
  return null;
}

function detectMime(buffer) {
  for (const [mime, sigs] of Object.entries(SIGNATURES)) {
    for (const sig of sigs) {
      if (buffer.length >= sig.length && sig.every((byte, i) => buffer[i] === byte)) return mime;
    }
  }
  return null;
}

function checkMagicBytes(name, buffer) {
  const expected = ALLOWED_TYPES[path.extname(name).toLowerCase()];
  const actual = detectMime(buffer);
  if (!actual) return 'File content does not match any allowed file type';
  if (actual !== expected) return `File content is ${actual} but extension claims ${expected}`;
  return null;
}

function checkContent(buffer, mime) {
  const text = buffer.toString('latin1');
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(text)) return `Embedded script/code detected (${pattern})`;
  }
  if (mime === 'application/pdf') {
    for (const pattern of SUSPICIOUS_PDF_PATTERNS) {
      if (pattern.test(text)) return `Active content detected in PDF (${pattern})`;
    }
  }
  return null;
}

// Safe version of the original name, used only for display / download name
function sanitizeDisplayName(name) {
  return name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, MAX_FILENAME_LENGTH);
}

module.exports = {
  checkFilename,
  checkExtension,
  checkDeclaredMime,
  checkMagicBytes,
  checkContent,
  detectMime,
  sanitizeDisplayName,
};
