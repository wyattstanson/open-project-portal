/*
 * ============================================================================
 *  STORE  -  SQLite (node:sqlite, built into Node 22.5+/24, ZERO dependencies)
 * ============================================================================
 *  A proper relational database with ACID transactions and indexes, in a single
 *  file (data/portal.db). No external DB server to install or connect. WAL mode
 *  gives many concurrent readers with fast serialized writers.
 *
 *  The server keeps the working set in memory for O(1) reads (fast at 10k rows)
 *  and writes THROUGH to SQLite per change, so nothing is a whole-file rewrite
 *  and no data is lost on a crash. On first run it imports the seed (db.json).
 *
 *  For multi-instance horizontal scale you would swap this file for a Postgres
 *  client; the tables and the server above are otherwise identical.
 * ============================================================================
 */
'use strict';
// Postgres when DATABASE_URL is set (durable, server-backed); otherwise the
// zero-dependency built-in SQLite below. The rest of the app is identical.
if (process.env.DATABASE_URL) { module.exports = require('./store-pg.js'); return; }
const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

let db;
const DB_PATH = path.join(__dirname, 'data', 'portal.db');

function init(seeder) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = NORMAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS students(
      reg TEXT PRIMARY KEY, name TEXT, school TEXT, scope INTEGER, email TEXT,
      emailHash TEXT, passwordHash TEXT, changedPassword INTEGER, passwordResetNotice INTEGER);
    CREATE INDEX IF NOT EXISTS idx_students_emailhash ON students(emailHash);
    CREATE TABLE IF NOT EXISTS faculty(
      email TEXT PRIMARY KEY, name TEXT, school TEXT, capacity INTEGER, passHash TEXT, fidx INTEGER, cabin TEXT);
    CREATE TABLE IF NOT EXISTS admin(username TEXT PRIMARY KEY, passHash TEXT);
    CREATE TABLE IF NOT EXISTS messages(
      id TEXT PRIMARY KEY, thread TEXT, reg TEXT, facEmail TEXT, fromRole TEXT, body TEXT, createdAt INTEGER,
      readByStudent INTEGER, readByFaculty INTEGER);
    CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(thread, createdAt);
    CREATE TABLE IF NOT EXISTS teams(
      id TEXT PRIMARY KEY, status TEXT, faculty TEXT, requestedFaculty TEXT, submittedBy TEXT, createdAt INTEGER);
    CREATE TABLE IF NOT EXISTS team_members(
      groupId TEXT, reg TEXT, ord INTEGER, consent TEXT, PRIMARY KEY(groupId, reg));
    CREATE INDEX IF NOT EXISTS idx_tm_reg ON team_members(reg);
    CREATE TABLE IF NOT EXISTS queries(
      id TEXT PRIMARY KEY, reg TEXT, name TEXT, topic TEXT, message TEXT, status TEXT, createdAt INTEGER);
  `);
  // migration: password-uniqueness fingerprint column (added M4). Ignore if present.
  try { db.exec('ALTER TABLE students ADD COLUMN pwFp TEXT'); } catch (e) {}
  // migration: team-formation timestamps (added M5) — when a faculty was requested / approved.
  try { db.exec('ALTER TABLE teams ADD COLUMN requestedAt INTEGER'); } catch (e) {}
  try { db.exec('ALTER TABLE teams ADD COLUMN approvedAt INTEGER'); } catch (e) {}
  // migration: faculty cabin number (read from the admin's Excel upload).
  try { db.exec('ALTER TABLE faculty ADD COLUMN cabin TEXT'); } catch (e) {}
  const n = db.prepare('SELECT COUNT(*) AS c FROM students').get().c;
  if (n === 0 && seeder) importAll(seeder());
}

function importAll(data) {
  const insStu = db.prepare('INSERT OR REPLACE INTO students(reg,name,school,scope,email,emailHash,passwordHash,changedPassword,passwordResetNotice) VALUES(?,?,?,?,?,?,?,?,?)');
  const insFac = db.prepare('INSERT OR REPLACE INTO faculty(email,name,school,capacity,passHash,fidx,cabin) VALUES(?,?,?,?,?,?,?)');
  const insGrp = db.prepare('INSERT OR REPLACE INTO teams(id,status,faculty,requestedFaculty,submittedBy,createdAt,requestedAt,approvedAt) VALUES(?,?,?,?,?,?,?,?)');
  const insMem = db.prepare('INSERT OR REPLACE INTO team_members(groupId,reg,ord,consent) VALUES(?,?,?,?)');
  const insQ = db.prepare('INSERT OR REPLACE INTO queries(id,reg,name,topic,message,status,createdAt) VALUES(?,?,?,?,?,?,?)');
  const insM = db.prepare('INSERT OR REPLACE INTO messages(id,thread,reg,facEmail,fromRole,body,createdAt,readByStudent,readByFaculty) VALUES(?,?,?,?,?,?,?,?,?)');
  db.exec('BEGIN');
  try {
    for (const reg in data.students) { const s = data.students[reg];
      insStu.run(reg, s.name, s.school, s.scope ? 1 : 0, s.email || null, s.emailHash || null, s.passwordHash || null, s.changedPassword ? 1 : 0, s.passwordResetNotice ? 1 : 0); }
    (data.faculty || []).forEach((f, i) => insFac.run(f.email, f.name, f.school || null, f.capacity, f.passHash, i, f.cabin || null));
    if (data.admin) db.prepare('INSERT OR REPLACE INTO admin(username,passHash) VALUES(?,?)').run(data.admin.username, data.admin.passHash);
    (data.groups || []).forEach((g) => {
      insGrp.run(g.id, g.status, g.faculty || null, g.requestedFaculty || null, g.submittedBy || null, g.createdAt || Date.now(), g.requestedAt || null, g.approvedAt || null);
      g.members.forEach((reg, ord) => insMem.run(g.id, reg, ord, (g.consent && g.consent[reg]) || 'accepted'));
    });
    (data.queries || []).forEach((q) => insQ.run(q.id, q.reg, q.name, q.topic, q.message, q.status, q.createdAt));
    (data.messages || []).forEach((m) => insM.run(m.id, m.thread, m.reg, m.facEmail, m.fromRole, m.body, m.createdAt, m.readByStudent ? 1 : 0, m.readByFaculty ? 1 : 0));
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

// Load the whole database into the same in-memory shape the server already uses.
function loadAll() {
  const students = {};
  for (const r of db.prepare('SELECT * FROM students').all()) {
    students[r.reg] = { reg: r.reg, name: r.name, school: r.school, scope: !!r.scope, email: r.email,
      emailHash: r.emailHash, passwordHash: r.passwordHash, changedPassword: !!r.changedPassword, passwordResetNotice: !!r.passwordResetNotice, pwFp: r.pwFp || null };
  }
  const faculty = db.prepare('SELECT * FROM faculty ORDER BY fidx').all()
    .map((r) => ({ email: r.email, name: r.name, school: r.school, capacity: r.capacity, passHash: r.passHash, cabin: r.cabin || null }));
  const adminRow = db.prepare('SELECT * FROM admin LIMIT 1').get();
  const admin = adminRow ? { username: adminRow.username, passHash: adminRow.passHash } : null;
  const memByGroup = {};
  for (const m of db.prepare('SELECT * FROM team_members ORDER BY groupId, ord').all()) {
    (memByGroup[m.groupId] || (memByGroup[m.groupId] = [])).push(m);
  }
  const groups = db.prepare('SELECT * FROM teams').all().map((r) => {
    const mems = memByGroup[r.id] || []; const consent = {}; mems.forEach((m) => { consent[m.reg] = m.consent; });
    return { id: r.id, status: r.status, faculty: r.faculty, requestedFaculty: r.requestedFaculty,
      submittedBy: r.submittedBy, createdAt: r.createdAt, requestedAt: r.requestedAt, approvedAt: r.approvedAt, members: mems.map((m) => m.reg), consent };
  });
  const queries = db.prepare('SELECT * FROM queries').all()
    .map((r) => ({ id: r.id, reg: r.reg, name: r.name, topic: r.topic, message: r.message, status: r.status, createdAt: r.createdAt }));
  const messages = db.prepare('SELECT * FROM messages ORDER BY createdAt').all()
    .map((r) => ({ id: r.id, thread: r.thread, reg: r.reg, facEmail: r.facEmail, fromRole: r.fromRole, body: r.body,
      createdAt: r.createdAt, readByStudent: !!r.readByStudent, readByFaculty: !!r.readByFaculty }));
  return { students, faculty, admin, groups, queries, messages };
}

// ---- targeted, durable writes (called alongside the in-memory mutation) ----
function saveStudent(s) {
  db.prepare('UPDATE students SET passwordHash=?, changedPassword=?, passwordResetNotice=?, pwFp=? WHERE reg=?')
    .run(s.passwordHash, s.changedPassword ? 1 : 0, s.passwordResetNotice ? 1 : 0, s.pwFp || null, s.reg);
}
function saveGroup(g) {
  db.exec('BEGIN');
  try {
    db.prepare('INSERT OR REPLACE INTO teams(id,status,faculty,requestedFaculty,submittedBy,createdAt,requestedAt,approvedAt) VALUES(?,?,?,?,?,?,?,?)')
      .run(g.id, g.status, g.faculty || null, g.requestedFaculty || null, g.submittedBy || null, g.createdAt, g.requestedAt || null, g.approvedAt || null);
    db.prepare('DELETE FROM team_members WHERE groupId=?').run(g.id);
    const ins = db.prepare('INSERT INTO team_members(groupId,reg,ord,consent) VALUES(?,?,?,?)');
    g.members.forEach((reg, ord) => ins.run(g.id, reg, ord, (g.consent && g.consent[reg]) || 'accepted'));
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); }
}
function deleteGroup(id) {
  db.exec('BEGIN');
  try { db.prepare('DELETE FROM team_members WHERE groupId=?').run(id); db.prepare('DELETE FROM teams WHERE id=?').run(id); db.exec('COMMIT'); }
  catch (e) { db.exec('ROLLBACK'); }
}
function saveQuery(q) {
  db.prepare('INSERT OR REPLACE INTO queries(id,reg,name,topic,message,status,createdAt) VALUES(?,?,?,?,?,?,?)')
    .run(q.id, q.reg, q.name, q.topic, q.message, q.status, q.createdAt);
}
function saveQueryStatus(id, status) { db.prepare('UPDATE queries SET status=? WHERE id=?').run(status, id); }
function saveFacultyCapacity(email, capacity) { db.prepare('UPDATE faculty SET capacity=? WHERE email=?').run(capacity, email); }
function saveMessage(m) {
  db.prepare('INSERT OR REPLACE INTO messages(id,thread,reg,facEmail,fromRole,body,createdAt,readByStudent,readByFaculty) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(m.id, m.thread, m.reg, m.facEmail, m.fromRole, m.body, m.createdAt, m.readByStudent ? 1 : 0, m.readByFaculty ? 1 : 0);
}
function markThreadRead(thread, role) {
  const col = role === 'faculty' ? 'readByFaculty' : 'readByStudent';
  db.prepare('UPDATE messages SET ' + col + '=1 WHERE thread=?').run(thread);
}
// Replace the whole student roster (admin Excel upload). Preserves the teams that
// reference these regs — only the students table is rewritten.
function replaceStudents(students) {
  db.exec('BEGIN');
  try {
    db.exec('DELETE FROM students');
    const ins = db.prepare('INSERT OR REPLACE INTO students(reg,name,school,scope,email,emailHash,passwordHash,changedPassword,passwordResetNotice,pwFp) VALUES(?,?,?,?,?,?,?,?,?,?)');
    for (const reg in students) { const s = students[reg];
      ins.run(reg, s.name, s.school, s.scope ? 1 : 0, s.email || null, s.emailHash || null, s.passwordHash || null, s.changedPassword ? 1 : 0, s.passwordResetNotice ? 1 : 0, s.pwFp || null); }
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}
// Replace the whole faculty list (admin Excel upload). Keeps fidx = array order.
function replaceFaculty(faculty) {
  db.exec('BEGIN');
  try {
    db.exec('DELETE FROM faculty');
    const ins = db.prepare('INSERT OR REPLACE INTO faculty(email,name,school,capacity,passHash,fidx,cabin) VALUES(?,?,?,?,?,?,?)');
    faculty.forEach((f, i) => ins.run(f.email, f.name, f.school || null, f.capacity, f.passHash, i, f.cabin || null));
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}
// wipe every team + membership (admin "reset all allocations"); students/faculty/admin stay
function deleteAllGroups() {
  db.exec('BEGIN');
  try { db.exec('DELETE FROM team_members'); db.exec('DELETE FROM teams'); db.exec('COMMIT'); }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}

module.exports = { driver: 'sqlite', init, loadAll, saveStudent, saveGroup, deleteGroup, saveQuery, saveQueryStatus, saveFacultyCapacity, deleteAllGroups, saveMessage, markThreadRead, replaceStudents, replaceFaculty };
