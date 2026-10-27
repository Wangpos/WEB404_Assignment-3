// WEB404 Practical 3 - File Upload Vulnerability & Secure File Handling
// Runs two upload endpoints side by side so the difference can be demonstrated:
//   /vulnerable/upload  -> intentionally insecure (for learning only)
//   /secure/upload      -> hardened implementation
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');

const vulnerableRouter = require('./src/vulnerable');
const secureRouter = require('./src/secure');
const { PUBLIC_UPLOAD_DIR, SECURE_STORAGE_DIR, LOG_DIR } = require('./src/config');

const PORT = process.env.PORT || 3000;
const app = express();

for (const dir of [PUBLIC_UPLOAD_DIR, SECURE_STORAGE_DIR, LOG_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

// Do not advertise the framework (information disclosure, 2.4)
app.disable('x-powered-by');

// Security headers for the application pages. The vulnerable static
// directory below is deliberately mounted WITHOUT these headers.
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: null, // lab runs on plain http://localhost
    },
  },
});

// ---------------- VULNERABLE: uploaded files served from the web root -------
// Files are served with a Content-Type guessed from the user-chosen extension,
// so an uploaded .html / .svg runs JavaScript in our origin (stored XSS).
app.use('/uploads', express.static(PUBLIC_UPLOAD_DIR));
app.use('/vulnerable', vulnerableRouter);

// ---------------- SECURE ----------------------------------------------------
app.use(securityHeaders);
app.use('/secure', secureRouter);

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Generic error handler: never leak stack traces to the client (2.4.2)
app.use((err, req, res, next) => {
  console.error('[error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`File upload lab running on http://localhost:${PORT}`);
  console.log(`  Vulnerable endpoint: POST http://localhost:${PORT}/vulnerable/upload`);
  console.log(`  Secure endpoint:     POST http://localhost:${PORT}/secure/upload`);
});
