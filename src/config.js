const path = require('path');

const ROOT = path.join(__dirname, '..');

module.exports = {
  // Inside the web root -> anything stored here is directly reachable by URL
  PUBLIC_UPLOAD_DIR: path.join(ROOT, 'public', 'uploads'),
  // Outside the web root -> only reachable through the controlled download route
  SECURE_STORAGE_DIR: path.join(ROOT, 'storage', 'secure'),
  LOG_DIR: path.join(ROOT, 'logs'),

  MAX_FILE_SIZE: 2 * 1024 * 1024, // 2 MB
  MAX_FILENAME_LENGTH: 100,

  // Allow-list: extension -> the only MIME type accepted for it
  ALLOWED_TYPES: {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.pdf': 'application/pdf',
  },

  RATE_LIMIT_WINDOW_MS: 60 * 1000,
  RATE_LIMIT_MAX: Number(process.env.RATE_LIMIT_MAX) || 20, // uploads per IP per window
};
