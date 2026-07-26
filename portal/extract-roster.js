/*
 * Reads db.json, decrypts emails with the vault, derives each account's initial
 * password (students: full name lowercase no spaces; faculty: teacher@domain ->
 * teach123, facultyNNN -> faculty<number>), and prints a curated demo set while
 * writing the full students/faculty lists to CSV. Local, presentation-only.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vault = require('./crypto-vault.js');
const db = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'db.json'), 'utf8'));

const stPass = (name) => String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
const facPass = (email) => {
  if (email === 'teacher@domain') return 'teach123';
  const m = email.match(/^faculty0*(\d+)@/);
  return m ? 'faculty' + m[1] : '(set on server)';
};
const q = (s) => '"' + String(s).replace(/"/g, '""') + '"';

// curated: the first 4 seeded groups (each already a valid 2+3 team) with logins
const groups = db.groups.slice(0, 4).map((g) => ({
  id: g.id,
  members: g.members.map((reg) => {
    const s = db.students[reg];
    return { reg, name: s.name, school: s.school, scope: s.scope, email: vault.decrypt(s.email), password: stPass(s.name) };
  }),
}));
// faculty sample: demo account + first six generated faculty
const faculty = db.faculty.slice(0, 7).map((f) => ({ email: f.email, name: f.name, password: facPass(f.email), capacity: f.capacity }));

console.log(JSON.stringify({ groups, faculty, totals: { students: Object.keys(db.students).length, faculty: db.faculty.length, groups: db.groups.length } }, null, 2));

// full lists to CSV for handover
const sCsv = ['reg,name,school,type,email,password'];
for (const reg in db.students) {
  const s = db.students[reg];
  sCsv.push([reg, q(s.name), q(s.school), s.scope ? 'SCOPE' : 'Other', vault.decrypt(s.email), stPass(s.name)].join(','));
}
fs.writeFileSync(path.join(__dirname, 'data', 'students-list.csv'), sCsv.join('\n'));
const fCsv = ['email,name,password,max_groups'];
db.faculty.forEach((f) => fCsv.push([f.email, q(f.name), facPass(f.email), f.capacity].join(',')));
fs.writeFileSync(path.join(__dirname, 'data', 'faculty-list.csv'), fCsv.join('\n'));
console.error('Wrote students-list.csv (' + Object.keys(db.students).length + ') and faculty-list.csv (' + db.faculty.length + ')');
