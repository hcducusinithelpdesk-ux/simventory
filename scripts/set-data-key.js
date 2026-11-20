// Creates (once) the DATA_KEY used to encrypt mobile/account/SIM numbers and
// uploads it to Cloudflare as an encrypted Pages secret.
//
//   npm run set-data-key
//
// - If backups/DATA_KEY.txt already exists, that SAME key is re-uploaded
//   (it never generates a new key over an existing one — a new key would make
//   all existing encrypted numbers unreadable).
// - Keep a copy of backups/DATA_KEY.txt somewhere safe (password manager / USB).
//   If both the file and the Cloudflare secret are lost, the numbers are lost.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const dir = path.join(__dirname, '..', 'backups');
const file = path.join(dir, 'DATA_KEY.txt');
fs.mkdirSync(dir, { recursive: true });

let key;
if (fs.existsSync(file)) {
  key = fs.readFileSync(file, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/i.test(key)) {
    console.error('backups/DATA_KEY.txt exists but is not a valid 64-hex key. Not touching anything.');
    process.exit(1);
  }
  console.log('Using EXISTING key from backups/DATA_KEY.txt');
} else {
  key = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(file, key + '\n', { flag: 'wx' });
  console.log('Generated NEW key -> backups/DATA_KEY.txt  (back this file up!)');
}

const r = spawnSync('npx', ['wrangler', 'pages', 'secret', 'put', 'DATA_KEY', '--project-name', 'sim-inventory'], {
  input: key,
  stdio: ['pipe', 'inherit', 'inherit'],
  shell: true,
});
process.exit(r.status || 0);
