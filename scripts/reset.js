// Removes all uploaded files and logs so the lab can be re-run from a clean state.
const fs = require('fs');
const path = require('path');
const { PUBLIC_UPLOAD_DIR, SECURE_STORAGE_DIR, LOG_DIR } = require('../src/config');

for (const dir of [PUBLIC_UPLOAD_DIR, SECURE_STORAGE_DIR, LOG_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
  for (const name of fs.readdirSync(dir)) {
    if (name === '.gitkeep') continue;
    fs.rmSync(path.join(dir, name), { recursive: true, force: true });
  }
  console.log(`cleared ${path.relative(process.cwd(), dir)}`);
}
