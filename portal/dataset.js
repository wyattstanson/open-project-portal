/*
 * ============================================================================
 *  DATASET IMPORTER  (a)
 * ============================================================================
 *  Reads a real roster from CSV and loads it into the portal, encrypting every
 *  email through the vault on the way in. Nothing is ever stored in plaintext.
 *
 *  Expected columns (header row, any order, case-insensitive):
 *      reg, name, email
 *
 *  Usage as a module:  const ds = require('./dataset'); ds.loadFromCSV(file)
 *  Usage from CLI:      node dataset.js path/to/students.csv   (rewrites db.json)
 * ============================================================================
 */
'use strict';
const fs = require('fs');
const path = require('path');
const engine = require('../engine.js');
const vault = require('./crypto-vault.js');
const MAP = engine.DEFAULT_MAP;

// Minimal RFC-ish CSV parser: handles quotes, escaped quotes, commas, newlines.
function parseCSV(text) {
  const rows = [];
  let field = '', row = [], inQ = false;
  text = String(text).replace(/\r\n?/g, '\n');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((x) => String(x).trim() !== ''));
}

// Turn CSV text/rows into the portal's {students, groups} shape.
function loadFromCSV(file, opts) {
  const rows = parseCSV(fs.readFileSync(file, 'utf8'));
  if (!rows.length) return null;
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const iReg = header.indexOf('reg'), iName = header.indexOf('name'), iEmail = header.indexOf('email');
  if (iReg < 0) throw new Error('CSV needs a "reg" column');

  const students = {}, order = [], skipped = [];
  for (let r = 1; r < rows.length; r++) {
    const cols = rows[r];
    const p = engine.parseReg(cols[iReg] || '');
    if (!p) { skipped.push((cols[iReg] || '').trim()); continue; }
    if (students[p.reg]) continue;                        // ignore duplicate reg
    const name = (iName >= 0 ? cols[iName] : '').trim();
    const email = (iEmail >= 0 ? cols[iEmail] : '').trim();
    const info = engine.schoolOf(p.code, MAP);
    const pw = (name || p.reg).toLowerCase().replace(/[^a-z0-9]/g, '');  // initial password: full name, no spaces
    students[p.reg] = {
      reg: p.reg, name, school: info.school, scope: info.scope,
      email: email ? vault.encrypt(email) : null,          // encrypted at rest
      emailHash: email ? vault.hashEmail(email) : null,     // for login lookup
      passwordHash: vault.hashPasswordSync(pw),                 // scrypt, one-way
      changedPassword: false,
    };
    order.push(p.reg);
  }

  // sort into valid pending groups using the same constraint engine
  const roster = order.map((reg) => ({ reg, code: reg.slice(2, 5), name: students[reg].name }));
  const formed = engine.formTeams(roster, MAP, { distinct: true });
  const take = opts && opts.groups != null ? opts.groups : formed.teams.length;
  const groups = formed.teams.slice(0, take).map((t, i) => ({
    id: 'G' + String(i + 1).padStart(3, '0'),
    members: t.members, status: 'pending', faculty: null,
    submittedBy: t.members[0], createdAt: Date.now() - (formed.teams.length - i) * 3600e3,
  }));

  return { students, groups, skipped, imported: order.length, teamsPossible: formed.teams.length };
}

// CLI: rewrite data/db.json from a CSV, keeping the existing faculty accounts.
if (require.main === module) {
  const file = process.argv[2];
  if (!file) { console.error('usage: node dataset.js <students.csv>'); process.exit(1); }
  const DB = path.join(__dirname, 'data', 'db.json');
  const base = loadFromCSV(file, { groups: 8 });
  let faculty = [{ email: 'teacher@domain', name: 'Dr. Demo Faculty', passHash: vault.hashPasswordSync('teach123'), capacity: 5 }];
  try { faculty = JSON.parse(fs.readFileSync(DB, 'utf8')).faculty || faculty; } catch (e) {}
  fs.mkdirSync(path.dirname(DB), { recursive: true });
  fs.writeFileSync(DB, JSON.stringify({ students: base.students, groups: base.groups, faculty }, null, 2));
  console.log('Imported ' + base.imported + ' students, ' + base.groups.length + ' groups. Skipped ' + base.skipped.length + ' bad rows.');
}

module.exports = { parseCSV, loadFromCSV };
