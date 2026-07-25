/*
 * ============================================================================
 *  DATABASE GENERATOR
 * ============================================================================
 *  Builds data/db.json with:
 *    - 10,000 students   email = firstname.surname2024@vitstudent.ac.in
 *                        initial password = full name, lowercase, no spaces
 *    - 160 faculty       each limited to 3 groups (capacity: 3)
 *    - some pending groups so the faculty view has content
 *
 *  SECURITY (this is the important part):
 *    - EMAILS are ENCRYPTED with AES-256 (reversible: the backend can read
 *      them back; other students only ever get a masked form).
 *    - PASSWORDS are HASHED with scrypt (one-way: NOBODY, not even us, can
 *      read them back). We only ever compare hashes. This is why "encrypt the
 *      password" is the wrong ask; a readable password is a leak waiting to
 *      happen. A change-password flow just writes a new hash.
 *
 *  Run:  node gen-database.js         (writes portal/data/db.json)
 * ============================================================================
 */
'use strict';
const fs = require('fs');
const path = require('path');
const engine = require('../engine.js');
const vault = require('./crypto-vault.js');
const MAP = engine.DEFAULT_MAP;
const OUT = path.join(__dirname, 'data', 'db.json');

const STUDENTS = 10000;
const FACULTY = 160;
const FACULTY_CAP = 3;
const PENDING_GROUPS = 80;

const FIRST = ['Aarav','Aditya','Akshay','Ananya','Aryan','Ayush','Deepak','Divya','Gaurav','Harsh',
  'Ishaan','Isha','Kabir','Kavya','Krish','Lakshmi','Manish','Meera','Naveen','Neha',
  'Nikhil','Nisha','Pooja','Pranav','Priya','Rahul','Riya','Rohan','Sahil','Sanya',
  'Shivani','Shreya','Siddharth','Simran','Sneha','Tanvi','Varun','Vedant','Vikram','Yash',
  'Anand','Farhan','Gauri','Imran','Jhanvi','Karan','Mitali','Payal','Reyansh','Tara'];
const SUR = ['Agarwal','Bansal','Bose','Chandra','Desai','Gupta','Iyer','Jain','Kapoor','Khanna',
  'Kumar','Malhotra','Mehta','Menon','Nair','Pillai','Rao','Reddy','Sharma','Shah',
  'Sinha','Verma','Yadav','Chopra','Das','Ghosh','Joshi','Nanda','Pandey','Saxena'];

const rint = (n) => (Math.random() * n) | 0;
const pick = (a) => a[rint(a.length)];
const clean = (s) => String(s).normalize('NFKD').replace(/[^a-zA-Z]/g, '');

function genStudents() {
  const codes = Object.keys(MAP);
  const sc = codes.filter((c) => MAP[c][1]);
  const oc = codes.filter((c) => !MAP[c][1]);
  const students = {};
  const usedReg = new Set();
  const usedEmail = new Set();

  // a known demo student so you can log in immediately after generation
  addStudent(students, usedReg, usedEmail, '24BCE2312', 'Aryansh', 'Sinha');

  let count = 1;
  while (count < STUDENTS) {
    const scope = Math.random() < 0.45;                 // ~45% SCOPE
    const code = scope ? pick(sc) : pick(oc);
    const reg = '24' + code + (1000 + rint(9000));
    if (usedReg.has(reg)) continue;
    const fn = clean(pick(FIRST)) || 'Student';
    const sn = clean(pick(SUR)) || 'Kumar';
    addStudent(students, usedReg, usedEmail, reg, fn, sn);
    count++;
    if (count % 1000 === 0) console.error('  hashed ' + count + ' / ' + STUDENTS + ' students');
  }
  return students;
}

function addStudent(students, usedReg, usedEmail, reg, fn, sn) {
  usedReg.add(reg);
  let email = (fn + '.' + sn + '2024').toLowerCase() + '@vitstudent.ac.in';
  if (usedEmail.has(email)) {                            // keep emails unique
    let k = 2;
    while (usedEmail.has((fn + '.' + sn + k + '2024').toLowerCase() + '@vitstudent.ac.in')) k++;
    email = (fn + '.' + sn + k + '2024').toLowerCase() + '@vitstudent.ac.in';
  }
  usedEmail.add(email);
  const password = (fn + sn).toLowerCase();              // initial password rule
  const info = engine.schoolOf(reg.slice(2, 5), MAP);
  students[reg] = {
    reg, name: fn + ' ' + sn, school: info.school, scope: info.scope,
    email: vault.encrypt(email),         // AES, reversible (backend only)
    emailHash: vault.hashEmail(email),   // keyed hash, for O(1) login lookup
    passwordHash: vault.hashPassword(password),  // scrypt, one-way
    changedPassword: false,
  };
}

function genFaculty() {
  const faculty = [{ email: 'teacher@domain', name: 'Dr. Demo Faculty', passHash: vault.hashPassword('teach123'), capacity: FACULTY_CAP }];
  for (let i = 1; i < FACULTY; i++) {
    const fn = clean(pick(FIRST)) || 'Prof', sn = clean(pick(SUR)) || 'Rao';
    faculty.push({
      email: 'faculty' + String(i).padStart(3, '0') + '@vit.ac.in',
      name: 'Prof. ' + fn + ' ' + sn,
      passHash: vault.hashPassword('faculty' + i),        // demo password: faculty<i>
      capacity: FACULTY_CAP,
    });
  }
  return faculty;
}

console.error('Generating ' + STUDENTS + ' students + ' + FACULTY + ' faculty (scrypt hashing, please wait)...');
const t0 = Date.now();
const students = genStudents();
const faculty = genFaculty();

// pending groups so faculty have something to review
const roster = Object.values(students).map((s) => ({ reg: s.reg, code: s.reg.slice(2, 5), name: s.name }));
const formed = engine.formTeams(roster, MAP, { distinct: true });
const groups = formed.teams.slice(0, PENDING_GROUPS).map((t, i) => ({
  id: 'G' + String(i + 1).padStart(4, '0'),
  members: t.members, status: 'pending', faculty: null,
  submittedBy: t.members[0], createdAt: Date.now() - (PENDING_GROUPS - i) * 60000,
}));

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify({ students, groups, faculty }, null, 0));
console.error('Done in ' + ((Date.now() - t0) / 1000).toFixed(0) + 's. ' +
  Object.keys(students).length + ' students, ' + faculty.length + ' faculty, ' +
  groups.length + ' pending groups. Possible teams total: ' + formed.teams.length);
