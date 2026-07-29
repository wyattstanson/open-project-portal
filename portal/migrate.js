/*
 * One-time migration on data/db.json:
 *   - gives every faculty a school/department (for the student faculty view)
 *   - creates the admin account (username: admin, password: admin@123, hashed)
 * Idempotent: safe to run more than once. Does NOT re-hash student passwords.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vault = require('./crypto-vault.js');
const DB = path.join(__dirname, 'data', 'db.json');
const DEPTS = ['SCOPE', 'SENSE', 'SELECT', 'SMEC', 'SCHEME', 'SCE', 'SBST'];

const db = JSON.parse(fs.readFileSync(DB, 'utf8'));

db.faculty.forEach((f, i) => {
  if (!f.school) f.school = f.email === 'teacher@domain' ? 'SCOPE' : DEPTS[i % DEPTS.length];
});
if (!db.admin) {
  db.admin = { username: 'admin', passHash: vault.hashPasswordSync('admin@123') };
}

fs.writeFileSync(DB, JSON.stringify(db));
console.log('Migrated: ' + db.faculty.length + ' faculty have a school; admin account ' + (db.admin ? 'present' : 'missing') + '.');
