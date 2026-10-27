// !!! INTENTIONALLY VULNERABLE - FOR EDUCATIONAL DEMONSTRATION ONLY !!!
// This router shows the common mistakes behind file upload vulnerabilities:
//   1. Only the client-supplied Content-Type header is checked (trivially spoofed)
//   2. The user-supplied filename is kept as-is (dangerous extensions, overwrites)
//   3. Files are saved inside the public web root and served directly
//   4. No size limit, no rate limit
//   5. Verbose errors disclose internal paths and stack traces
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { PUBLIC_UPLOAD_DIR } = require('./config');

const router = express.Router();

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, PUBLIC_UPLOAD_DIR),
  // Mistake: trusting the original filename
  filename: (req, file, cb) => cb(null, file.originalname),
});

const upload = multer({
  storage,
  // Mistake: "validation" based only on the Content-Type the client sent
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      return cb(null, true);
    }
    cb(new Error(`File type ${file.mimetype} not allowed`));
  },
});

router.post('/upload', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      // Mistake: leaking internals (stack trace + absolute paths)
      return res.status(400).json({ error: err.message, stack: err.stack });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({
      message: 'File uploaded successfully',
      storedAt: req.file.path, // Mistake: absolute server path disclosed
      url: `/uploads/${encodeURIComponent(req.file.filename)}`,
      size: req.file.size,
      mimetype: req.file.mimetype,
    });
  });
});

router.get('/files', (req, res) => {
  const files = fs.readdirSync(PUBLIC_UPLOAD_DIR).filter((f) => f !== '.gitkeep');
  res.json(files.map((name) => ({
    name,
    url: `/uploads/${encodeURIComponent(name)}`,
    size: fs.statSync(path.join(PUBLIC_UPLOAD_DIR, name)).size,
  })));
});

module.exports = router;
