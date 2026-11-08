import { randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCallback);

const password = process.argv[2];
if (!password || password.length < 14) {
  console.error('استخدمي كلمة مرور بطول 14 محرفًا على الأقل: npm run hash-password -- "كلمة-مرور-قوية"');
  process.exit(1);
}
const salt = randomBytes(16);
const hash = await scrypt(password, salt, 64);
console.log(`scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`);
