// Hardened file upload implementation (defence in depth).
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  SECURE_STORAGE_DIR, LOG_DIR, MAX_FILE_SIZE, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX,
} = require('./config');
const v = require('./validators');

const router = express.Router();
const SECURITY_LOG = path.join(LOG_DIR, 'security.log');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function logEvent(req, event, detail) {
  const line = JSON.stringify({
    time: new Date().toISOString(), ip: req.ip, event, ...detail,
  });
  fs.appendFile(SECURITY_LOG, line + '\n', () => {});
  console.log(`[security] ${event}`, detail);
}

// Simple in-memory per-IP rate limiter (prevents upload flooding / DoS)
const hits = new Map();
function rateLimit(req, res, next) {
  const now = Date.now();
  const entry = hits.get(req.ip) || { count: 0, start: now };
  if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
    entry.count = 0;
    entry.start = now;
  }
  entry.count += 1;
  hits.set(req.ip, entry);
  if (entry.count > RATE_LIMIT_MAX) {
    logEvent(req, 'RATE_LIMITED', { count: entry.count });
    res.set('Retry-After', Math.ceil(RATE_LIMIT_WINDOW_MS / 1000));
    return res.status(429).json({ error: 'Too many uploads, try again later' });
  }
  next();
}

// Kept in memory (never touches disk) until every check has passed
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
    fields: 0,
    parts: 1,
  },
  // Cheap checks first, before the body is even buffered
  fileFilter: (req, file, cb) => {
    const reason = v.checkFilename(file.originalname)
      || v.checkExtension(file.originalname)
      || v.checkDeclaredMime(file.originalname, file.mimetype);
    if (reason) {
      const err = new Error(reason);
      err.code = 'VALIDATION_FAILED';
      err.filename = file.originalname;
      return cb(err);
    }
    cb(null, true);
  },
});

router.post('/upload', rateLimit, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      const reason = err instanceof multer.MulterError ? multerMessage(err) : err.message;
      logEvent(req, 'UPLOAD_REJECTED', { stage: 'request', reason, filename: err.filename });
      // Known validation errors are safe to echo; anything else stays generic
      const known = err instanceof multer.MulterError || err.code === 'VALIDATION_FAILED';
      return res.status(known && err.code === 'LIMIT_FILE_SIZE' ? 413 : 400)
        .json({ error: known ? reason : 'Upload failed' });
    }
    if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name must be "file")' });

    const { originalname, buffer } = req.file;
    const reason = v.checkMagicBytes(originalname, buffer)
      || v.checkContent(buffer, v.detectMime(buffer));
    if (reason) {
      logEvent(req, 'UPLOAD_REJECTED', { stage: 'content', reason, filename: originalname });
      return res.status(400).json({ error: reason });
    }

    // Server-generated random name: the user never controls the path or extension
    const id = crypto.randomUUID();
    const mime = v.detectMime(buffer);
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const meta = {
      id,
      originalName: v.sanitizeDisplayName(originalname),
      mime,
      size: buffer.length,
      sha256,
      uploadedAt: new Date().toISOString(),
    };

    try {
      // 0o640: owner read/write, group read, never executable
      fs.writeFileSync(path.join(SECURE_STORAGE_DIR, id), buffer, { mode: 0o640, flag: 'wx' });
      fs.writeFileSync(path.join(SECURE_STORAGE_DIR, `${id}.json`), JSON.stringify(meta), { mode: 0o640, flag: 'wx' });
    } catch (e) {
      console.error('[secure] write failed', e);
      return res.status(500).json({ error: 'Upload failed' });
    }

    logEvent(req, 'UPLOAD_ACCEPTED', { id, mime, size: meta.size, sha256 });
    res.status(201).json({
      message: 'File uploaded securely',
      id,
      originalName: meta.originalName,
      mime,
      size: meta.size,
      sha256,
      url: `/secure/files/${id}`,
    });
  });
});

router.get('/files', (req, res) => {
  const files = fs.readdirSync(SECURE_STORAGE_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(SECURE_STORAGE_DIR, f), 'utf8')))
    .map((m) => ({ ...m, url: `/secure/files/${m.id}` }));
  res.json(files);
});

// Controlled download route - the only way to reach a stored file
router.get('/files/:id', (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid file id' });

  const metaPath = path.join(SECURE_STORAGE_DIR, `${id}.json`);
  if (!fs.existsSync(metaPath)) return res.status(404).json({ error: 'File not found' });
  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));

  res.set({
    'Content-Type': meta.mime, // type detected at upload, not guessed from a name
    'Content-Disposition': `attachment; filename="${meta.originalName}"`,
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'Cache-Control': 'private, no-store',
  });
  res.sendFile(path.join(SECURE_STORAGE_DIR, id));
});

function multerMessage(err) {
  switch (err.code) {
    case 'LIMIT_FILE_SIZE': return `File too large (max ${MAX_FILE_SIZE / 1024 / 1024} MB)`;
    case 'LIMIT_FILE_COUNT': return 'Only one file may be uploaded at a time';
    case 'LIMIT_UNEXPECTED_FILE': return 'Unexpected field (use the field name "file")';
    case 'LIMIT_PART_COUNT':
    case 'LIMIT_FIELD_COUNT': return 'Too many form parts';
    default: return 'Upload rejected';
  }
}

module.exports = router;
