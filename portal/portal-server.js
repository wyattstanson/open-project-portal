/*
 * ============================================================================
 *  PORTAL BACKEND
 * ============================================================================
 *  Ties together:
 *    - engine.js       -> the O(n) allocation / constraint logic
 *    - crypto-vault.js  -> email encryption + faculty passwords
 *
 *  Roles:
 *    STUDENT  -> logs in with their email, submits a group of 5, sees all
 *                groups but every email masked (a****@...).
 *    FACULTY  -> logs in with teacher@domain, sees pending groups WITH the
 *                real (decrypted) emails, accepts or rejects. Accepting uses a
 *                seat; the server owns the seat count so it can never oversell.
 *
 *  Storage: data/db.json (students, groups, faculty). Sessions live in memory.
 *  No external packages. Run:  node portal-server.js
 * ============================================================================
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const engine = require('../engine.js');
const vault = require('./crypto-vault.js');
const dataset = require('./dataset.js');

const PORT = process.env.PORT || 4000;
const PUBLIC = path.join(__dirname, 'public');
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const MAP = engine.DEFAULT_MAP;

// ---------------------------------------------------------------- database
const sessions = new Map();               // token -> { email, name }

function load() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { return seed(); }
}
function persist() {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ---- seed the store on first run, from data/sample-students.csv if present ----
function seed() {
  const faculty = [{
    email: 'teacher@domain',
    name: 'Dr. Demo Faculty',
    passHash: vault.hashPassword('teach123'),   // DEMO credential
    capacity: 5,
  }];
  const csv = path.join(__dirname, 'data', 'sample-students.csv');
  if (fs.existsSync(csv)) {
    const base = dataset.loadFromCSV(csv, { groups: 8 });   // real import path (a)
    return { students: base.students, groups: base.groups, faculty };
  }
  return { students: {}, groups: [], faculty };             // empty fallback
}

// initialise the store (seeds + writes db.json on first run)
let db = load();
if (!fs.existsSync(DB_FILE)) persist();

// ---------------------------------------------------------------- helpers
function findFaculty(email) { return db.faculty.find((f) => f.email.toLowerCase() === String(email).toLowerCase()); }
function auth(req) {
  const h = req.headers['authorization'] || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  return sessions.get(tok) || null;
}
function facultyAuth(req) { const s = auth(req); return s && s.role === 'faculty' ? s : null; }
function studentAuth(req) { const s = auth(req); return s && s.role === 'student' ? s : null; }
function findStudentByEmail(email) {
  const h = vault.hashEmail(email);
  return Object.values(db.students).find((s) => s.emailHash === h) || null;
}
function seatsUsed(email) { return db.groups.filter((g) => g.status === 'accepted' && g.faculty === email).length; }

// Independent server-side constraint check: 2 SCOPE + 3 distinct other schools.
function validateGroup(members) {
  const seen = new Set();
  const people = members.map((reg) => {
    const st = db.students[reg];
    const info = engine.schoolOf(reg.slice(2, 5), MAP);
    return { reg, name: st ? st.name : '', school: info.school, scope: info.scope, known: info.known, inRoster: !!st };
  });
  const problems = [];
  if (members.length !== 5) problems.push('A group must have exactly 5 members.');
  if (new Set(members).size !== members.length) problems.push('The same registration number appears twice.');
  const scope = people.filter((p) => p.scope);
  const other = people.filter((p) => !p.scope && p.known);
  const unknown = people.filter((p) => !p.known);
  if (scope.length !== 2) problems.push('Needs exactly 2 SCOPE members (has ' + scope.length + ').');
  if (other.length !== 3) problems.push('Needs exactly 3 other-school members (has ' + other.length + ').');
  if (unknown.length) problems.push(unknown.length + ' member(s) have an unknown branch code.');
  const schools = other.map((p) => p.school);
  if (schools.length && new Set(schools).size !== schools.length) problems.push('The 3 other-school members must each be from a different school.');
  return { valid: problems.length === 0, problems, people };
}

// Build a group view. opts.reveal (faculty) shows every real email.
// opts.selfReg (a student) shows only that student's own real email; all
// teammates stay masked. Default: everything masked.
function groupView(g, opts) {
  opts = opts || {};
  const v = validateGroup(g.members);
  return {
    id: g.id, status: g.status, faculty: g.faculty, createdAt: g.createdAt,
    valid: v.valid, problems: v.problems,
    members: v.people.map((p) => {
      const st = db.students[p.reg];
      let email = null;
      if (st) {
        const plain = vault.decrypt(st.email);
        const showReal = opts.reveal || (opts.selfReg && p.reg === opts.selfReg);
        email = showReal ? plain : vault.mask(plain || '');
      }
      return { reg: p.reg, name: p.name, school: p.school, scope: p.scope, known: p.known, email };
    }),
  };
}

// ---------------------------------------------------------------- responses
function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = ''; req.on('data', (c) => { b += c; if (b.length > 5e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch (e) { resolve({}); } });
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
function serveStatic(res, pathname) {
  const rel = pathname === '/' ? '/index.html' : pathname;
  const file = path.join(PUBLIC, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file)) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  res.end(fs.readFileSync(file));
}

// ---------------------------------------------------------------- routes
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;

  if (p === '/api/health') return sendJSON(res, 200, { ok: true, students: Object.keys(db.students).length, groups: db.groups.length });

  // ---- FACULTY login ----
  if (p === '/api/faculty/login' && req.method === 'POST') {
    const { email, password } = await readBody(req);
    const f = findFaculty(email);
    if (!f || !vault.verifyPassword(password, f.passHash)) return sendJSON(res, 401, { error: 'Invalid credentials.' });
    const tok = vault.newToken();
    sessions.set(tok, { role: 'faculty', email: f.email, name: f.name });
    return sendJSON(res, 200, { token: tok, name: f.name, email: f.email, capacity: f.capacity, seatsUsed: seatsUsed(f.email) });
  }

  // ---- FACULTY view groups (real emails) ----
  if (p === '/api/faculty/groups' && req.method === 'GET') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const f = findFaculty(sess.email);
    const groups = db.groups
      .filter((g) => g.status === 'pending' || g.faculty === sess.email)
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((g) => groupView(g, { reveal: true }));
    return sendJSON(res, 200, { groups, capacity: f.capacity, seatsUsed: seatsUsed(f.email) });
  }

  // ---- FACULTY accept / reject ----
  if (p === '/api/faculty/decision' && req.method === 'POST') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const f = findFaculty(sess.email);
    const { groupId, decision } = await readBody(req);
    const g = db.groups.find((x) => x.id === groupId);
    if (!g) return sendJSON(res, 404, { error: 'Group not found.' });
    if (decision === 'accept') {
      if (g.status === 'accepted') return sendJSON(res, 409, { error: 'Already accepted.' });
      const v = validateGroup(g.members);
      if (!v.valid) return sendJSON(res, 422, { error: 'Group does not pass the constraints.', problems: v.problems });
      if (seatsUsed(f.email) >= f.capacity) return sendJSON(res, 409, { error: 'No seats left. You are at capacity.' });
      g.status = 'accepted'; g.faculty = f.email;
    } else if (decision === 'reject') {
      g.status = 'rejected'; g.faculty = null;
    } else return sendJSON(res, 400, { error: 'decision must be accept or reject.' });
    persist();
    return sendJSON(res, 200, { ok: true, group: groupView(g, { reveal: true }), seatsUsed: seatsUsed(f.email), capacity: f.capacity });
  }

  // ---- STUDENT login (email only): issues a token bound to their reg ----
  if (p === '/api/student/login' && req.method === 'POST') {
    const { email } = await readBody(req);
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return sendJSON(res, 400, { error: 'Enter a valid email.' });
    const st = findStudentByEmail(email);
    if (!st) return sendJSON(res, 404, { error: 'No student on record with that email. Ask your coordinator to add you.' });
    const tok = vault.newToken();
    sessions.set(tok, { role: 'student', reg: st.reg, name: st.name });
    return sendJSON(res, 200, { token: tok, reg: st.reg, name: st.name, school: st.school });
  }

  // ---- STUDENT: only THEIR OWN group(s); own email real, teammates masked ----
  if (p === '/api/student/mygroups' && req.method === 'GET') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const groups = db.groups
      .filter((g) => g.members.includes(sess.reg))
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((g) => groupView(g, { selfReg: sess.reg }));
    return sendJSON(res, 200, { reg: sess.reg, name: sess.name, groups });
  }

  // ---- STUDENT submit a group (must include yourself) ----
  if (p === '/api/student/submit' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const { members } = await readBody(req);
    const regs = (members || []).map((m) => String(m).trim().toUpperCase().replace(/\s+/g, '')).filter(Boolean);
    if (!regs.includes(sess.reg)) return sendJSON(res, 422, { error: 'Your own registration number must be in the group.' });
    const v = validateGroup(regs);
    if (!v.valid) return sendJSON(res, 422, { error: 'Group does not pass the constraints.', problems: v.problems });
    const g = { id: 'G' + String(db.groups.length + 1).padStart(3, '0'), members: regs, status: 'pending', faculty: null, submittedBy: sess.reg, createdAt: Date.now() };
    db.groups.push(g); persist();
    return sendJSON(res, 200, { ok: true, group: groupView(g, { selfReg: sess.reg }) });
  }

  // ---- roster (masked, no emails) so the student form can pick real regs ----
  if (p === '/api/roster' && req.method === 'GET') {
    const list = Object.values(db.students).map((s) => ({ reg: s.reg, name: s.name, school: s.school, scope: s.scope }));
    return sendJSON(res, 200, { students: list });
  }

  if (p.startsWith('/api/')) return sendJSON(res, 404, { error: 'Unknown endpoint.' });
  return serveStatic(res, p);
});

server.listen(PORT, () => {
  console.log('Portal backend on http://localhost:' + PORT);
  console.log('Faculty demo login: teacher@domain / teach123');
  console.log('Students: ' + Object.keys(db.students).length + ' | pending groups: ' + db.groups.filter((g) => g.status === 'pending').length);
});
