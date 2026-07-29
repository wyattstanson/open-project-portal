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
// Widen the libuv thread pool BEFORE anything touches it, so many password
// hashes (scrypt) and file writes run in parallel instead of queueing 4-at-a-time.
// This is what keeps thousands of concurrent logins from stalling each other.
process.env.UV_THREADPOOL_SIZE = process.env.UV_THREADPOOL_SIZE || '64';
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
function persistNow() {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db));
}
// Non-blocking, coalesced persistence. With a 10k-record db.json, rewriting the
// whole file on every accept would block the event loop; instead we mark the
// store dirty and flush at most once every 400ms, off the request path. For a
// truly large deployment this JSON store is swapped for SQLite/Postgres, but the
// server code above it does not change (same read/write calls).
let dirty = false, flushQueued = false, flushing = false;
function flush() {
  if (flushing || !dirty) { flushQueued = false; return; }
  dirty = false; flushing = true; flushQueued = false;
  // write to a temp file then rename = atomic, never leaves a half-written db
  const tmp = DB_FILE + '.tmp';
  fs.promises.writeFile(tmp, JSON.stringify(db)).then(() => fs.promises.rename(tmp, DB_FILE))
    .catch(() => {}).finally(() => { flushing = false; if (dirty) persist(); });
}
function persist() {
  dirty = true;
  if (flushQueued || flushing) return;
  flushQueued = true;
  setTimeout(flush, 800);   // coalesce bursts; at 5k concurrent this is ~1 write/sec
}

// ---- seed the store on first run, from data/sample-students.csv if present ----
function seed() {
  const faculty = [{
    email: 'teacher@domain',
    name: 'Dr. Demo Faculty',
    passHash: vault.hashPasswordSync('teach123'),   // DEMO credential (sync: startup path)
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
if (!Array.isArray(db.queries)) db.queries = [];   // student -> admin support queries
if (!fs.existsSync(DB_FILE)) persistNow();

// Lock the vault to whichever key actually decrypts this database, so a wrong
// or stale VAULT_KEY env var can never break email lookup / login.
(function lockKey() {
  const first = Object.values(db.students)[0];
  if (first && first.email && !vault.selectKeyFor(first.email)) {
    console.warn('WARNING: no available key decrypts the student emails; check VAULT_KEY / .vault_key');
  }
})();

// O(1) login lookup: emailHash -> student. Built once at startup so a login on
// a 10,000-row roster is a single hash-map hit, not a scan of every record.
const emailIndex = new Map();
function reindex() {
  emailIndex.clear();
  for (const reg in db.students) {
    const s = db.students[reg];
    if (s.emailHash) emailIndex.set(s.emailHash, s);
  }
}
reindex();

// The documented INITIAL passwords. We never store plaintext; these are the
// known defaults, shown to admin (who can also reset an account). Current
// passwords stay one-way hashed and are unreadable by anyone.
function initialStudentPw(name) { return String(name).toLowerCase().replace(/[^a-z0-9]/g, ''); }
function initialFacultyPw(email) {
  if (email === 'teacher@domain') return 'teach123';
  const m = String(email).match(/^faculty0*(\d+)@/);
  return m ? 'faculty' + m[1] : '';
}

// In-memory, pre-decrypted student array for fast admin/faculty listing + search.
// Decrypting all emails once at boot (server memory only, never sent to students)
// turns each search into a linear scan over plain strings instead of 10k AES ops
// per query. Build: O(n) once. Search: O(n) over ~10k = a few ms.
let studentArr = [];
const studentArrByReg = new Map();
function buildStudentArr() {
  studentArr = []; studentArrByReg.clear();
  for (const reg in db.students) {
    const s = db.students[reg];
    const e = { reg, name: s.name, school: s.school, scope: s.scope,
      email: vault.decrypt(s.email) || '', changed: !!s.changedPassword,
      _hay: (reg + ' ' + s.name).toLowerCase() };
    studentArr.push(e); studentArrByReg.set(reg, e);
  }
}
buildStudentArr();

// distinct non-SCOPE SCHOOLS (keyed by school, so SMEC counts once) for the guide
let OTHER_SCHOOLS = [...new Set(studentArr.filter((s) => !s.scope).map((s) => engine.schoolKey(s.school)))].sort();
// all distinct branches/schools (incl. SCOPE) for the "sort by branch" filters
let BRANCHES = [...new Set(studentArr.map((s) => engine.schoolKey(s.school)))].sort();

// paginate + optional substring search over a pre-lowercased haystack
function pageOf(arr, q, page, size) {
  size = Math.min(200, Math.max(1, parseInt(size, 10) || 50));
  page = Math.max(1, parseInt(page, 10) || 1);
  let list = arr;
  const needle = String(q || '').toLowerCase().trim();
  if (needle) list = arr.filter((e) => e._hay.indexOf(needle) >= 0 || (e.email && e.email.indexOf(needle) >= 0));
  const total = list.length;
  const start = (page - 1) * size;
  return { total, page, size, pages: Math.max(1, Math.ceil(total / size)), rows: list.slice(start, start + size) };
}

// ---------------------------------------------------------------- helpers
function findFaculty(email) { return db.faculty.find((f) => f.email.toLowerCase() === String(email).toLowerCase()); }
function auth(req) {
  const h = req.headers['authorization'] || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  return sessions.get(tok) || null;
}
function facultyAuth(req) { const s = auth(req); return s && s.role === 'faculty' ? s : null; }
function studentAuth(req) { const s = auth(req); return s && s.role === 'student' ? s : null; }
function adminAuth(req) { const s = auth(req); return s && s.role === 'admin' ? s : null; }
function findStudentByEmail(email) {
  return emailIndex.get(vault.hashEmail(email)) || null;   // O(1)
}
function seatsUsed(email) { return db.groups.filter((g) => g.status === 'accepted' && g.faculty === email).length; }
// slots held: a selection (requested) OR an acceptance both consume an available slot
function facultyLoad(email) { return db.groups.filter((g) => g.status !== 'rejected' && (g.faculty === email || g.requestedFaculty === email)).length; }

// one-student-one-group: the active (non-rejected) group a reg belongs to, if any
function activeGroupOf(reg) { return db.groups.find((g) => g.status !== 'rejected' && g.members.includes(reg)); }
// consent: seeded groups (no consent map) are treated as already accepted
function consentOf(g, reg) { if (!g.consent) return 'accepted'; return g.consent[reg] || 'pending'; }
function groupReady(g) { return g.members.every((r) => consentOf(g, r) === 'accepted'); }
function branchFilter(arr, branch) { return branch ? arr.filter((e) => engine.schoolKey(e.school) === branch) : arr; }
function groupedRegSet() {
  const s = new Set();
  for (const g of db.groups) if (g.status !== 'rejected') for (const r of g.members) s.add(r);
  return s;
}
function nextGroupId() {
  const maxN = db.groups.reduce((m, g) => Math.max(m, parseInt(String(g.id).replace(/\D/g, ''), 10) || 0), 0);
  return 'G' + String(maxN + 1).padStart(4, '0');
}

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
  const schools = other.map((p) => engine.schoolKey(p.school));   // key by school, not program
  if (schools.length && new Set(schools).size !== schools.length) problems.push('The 3 other-school members must each be from a different school.');
  return { valid: problems.length === 0, problems, people };
}

// Build a group view. opts.reveal (faculty) shows every real email.
// opts.selfReg (a student) shows only that student's own real email; all
// teammates stay masked. Default: everything masked.
function groupView(g, opts) {
  opts = opts || {};
  const v = validateGroup(g.members);
  const rfIdx = g.requestedFaculty ? db.faculty.findIndex((f) => f.email === g.requestedFaculty) : -1;
  const rf = rfIdx >= 0 ? db.faculty[rfIdx] : null;
  const asg = g.faculty ? db.faculty.find((f) => f.email === g.faculty) : null;
  return {
    id: g.id, status: g.status, faculty: g.faculty, facultyName: asg ? asg.name : null, createdAt: g.createdAt,
    requestedFaculty: g.requestedFaculty || null, requestedFacultyName: rf ? rf.name : null, requestedFacultyId: rfIdx >= 0 ? rfIdx : null,
    leader: g.submittedBy, ready: groupReady(g),
    valid: v.valid, problems: v.problems,
    members: v.people.map((p) => {
      const st = db.students[p.reg];
      let email = null;
      if (st) {
        const plain = vault.decrypt(st.email);
        const showReal = opts.reveal || (opts.selfReg && p.reg === opts.selfReg);
        email = showReal ? plain : vault.mask(plain || '');
      }
      return { reg: p.reg, name: p.name, school: p.school, scope: p.scope, known: p.known, email,
        isLeader: g.submittedBy === p.reg, consent: consentOf(g, p.reg) };
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
    if (!f || !(await vault.verifyPassword(password, f.passHash))) return sendJSON(res, 401, { error: 'Invalid credentials.' });
    const tok = vault.newToken();
    sessions.set(tok, { role: 'faculty', email: f.email, name: f.name });
    return sendJSON(res, 200, { token: tok, name: f.name, email: f.email, capacity: f.capacity, seatsUsed: seatsUsed(f.email) });
  }

  // ---- FACULTY view groups (real emails) ----
  if (p === '/api/faculty/groups' && req.method === 'GET') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const f = findFaculty(sess.email);
    // a group only reaches faculty once every member has accepted (ready).
    // Show groups that selected me (or my accepted ones), leader-approved.
    const groups = db.groups
      .filter((g) => g.faculty === sess.email ||
        (g.status === 'pending' && groupReady(g) && (!g.requestedFaculty || g.requestedFaculty === sess.email)))
      .sort((a, b) => (b.requestedFaculty === sess.email ? 1 : 0) - (a.requestedFaculty === sess.email ? 1 : 0) || a.createdAt - b.createdAt)
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
      if (g.requestedFaculty && g.requestedFaculty !== f.email) return sendJSON(res, 409, { error: 'This group selected a different faculty.' });
      if (!groupReady(g)) return sendJSON(res, 409, { error: 'Not all members have accepted the group yet.' });
      if (seatsUsed(f.email) >= f.capacity) return sendJSON(res, 409, { error: 'No seats left. You are at capacity.' });
      g.status = 'accepted'; g.faculty = f.email;
    } else if (decision === 'reject') {
      g.status = 'rejected'; g.faculty = null;
    } else return sendJSON(res, 400, { error: 'decision must be accept or reject.' });
    persist();
    return sendJSON(res, 200, { ok: true, group: groupView(g, { reveal: true }), seatsUsed: seatsUsed(f.email), capacity: f.capacity });
  }

  // ---- STUDENT login (registration number + password). Emails are never used
  //      by students; only teachers and admin ever see email addresses. ----
  if (p === '/api/student/login' && req.method === 'POST') {
    const body = await readBody(req);
    const raw = String(body.reg || body.email || body.id || '').trim();
    const password = body.password;
    const st = raw.includes('@') ? findStudentByEmail(raw) : db.students[raw.toUpperCase().replace(/\s+/g, '')];
    const ok = st && st.passwordHash && await vault.verifyPassword(password || '', st.passwordHash);
    if (!ok) return sendJSON(res, 401, { error: 'Incorrect registration number or password.' });
    const tok = vault.newToken();
    sessions.set(tok, { role: 'student', reg: st.reg, name: st.name });
    const wasReset = !!st.passwordResetNotice;
    if (wasReset) { st.passwordResetNotice = false; persist(); }   // one-time notice
    return sendJSON(res, 200, { token: tok, reg: st.reg, name: st.name, school: st.school, changedPassword: !!st.changedPassword, passwordReset: wasReset });
  }

  // ---- STUDENT change password (writes a new one-way hash) ----
  if (p === '/api/student/password' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in first.' });
    const st = db.students[sess.reg]; if (!st) return sendJSON(res, 404, { error: 'Account not found.' });
    const { currentPassword, newPassword } = await readBody(req);
    if (!(await vault.verifyPassword(currentPassword || '', st.passwordHash))) return sendJSON(res, 403, { error: 'Current password is incorrect.' });
    if (!newPassword || String(newPassword).length < 6) return sendJSON(res, 400, { error: 'New password must be at least 6 characters.' });
    st.passwordHash = await vault.hashPassword(newPassword);   // old password is unrecoverable
    st.changedPassword = true;
    const ce = studentArrByReg.get(sess.reg); if (ce) ce.changed = true;
    persist();
    return sendJSON(res, 200, { ok: true });
  }

  // ---- STUDENT: directory of other students (names + reg + school). NO emails. ----
  if (p === '/api/student/directory' && req.method === 'GET') {
    if (!studentAuth(req)) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const arr = branchFilter(studentArr, url.searchParams.get('branch'));
    const r = pageOf(arr, url.searchParams.get('q'), url.searchParams.get('page'), url.searchParams.get('size'));
    const grouped = groupedRegSet();
    const rows = r.rows.map((e) => ({ reg: e.reg, name: e.name, school: e.school, scope: e.scope, grouped: grouped.has(e.reg) })); // no email
    return sendJSON(res, 200, { total: r.total, page: r.page, pages: r.pages, size: r.size, rows, branches: BRANCHES });
  }

  // ---- STUDENT: live team composition ("jug filling"): which school slots are
  //      filled, and which schools you may or may not still add. NO emails. ----
  if (p === '/api/student/compose' && req.method === 'POST') {
    if (!studentAuth(req)) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const { members } = await readBody(req);
    const regs = [...new Set((members || []).map((m) => String(m).trim().toUpperCase().replace(/\s+/g, '')).filter(Boolean))];
    const people = regs.map((reg) => {
      const info = engine.schoolOf(reg.slice(2, 5), MAP);
      const st = db.students[reg];
      return { reg, name: st ? st.name : '', school: info.school, scope: info.scope, known: info.known, inRoster: !!st };
    });
    const scope = people.filter((x) => x.scope);
    const other = people.filter((x) => !x.scope && x.known);
    const usedSchools = [...new Set(other.map((x) => engine.schoolKey(x.school)))];
    const remainingOtherSlots = Math.max(0, 3 - usedSchools.length);
    const schools = OTHER_SCHOOLS.map((s) => ({
      school: s, used: usedSchools.includes(s),
      selectable: !usedSchools.includes(s) && remainingOtherSlots > 0,
    }));
    const v = validateGroup(regs);
    return sendJSON(res, 200, {
      count: regs.length, people,
      scopeCount: scope.length, scopeNeeded: 2, canAddScope: scope.length < 2,
      otherFilled: usedSchools.length, otherNeeded: 3, usedSchools, schools,
      valid: regs.length === 5 && v.valid, problems: v.problems,
    });
  }

  // ---- STUDENT: faculty directory (name, school, slots remaining). No emails.
  //      `id` is the db index, used only as an opaque handle to select a faculty. ----
  if (p === '/api/faculty-directory' && req.method === 'GET') {
    if (!studentAuth(req)) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    // slotsRemaining reflects live selections + acceptances, so picking a faculty
    // immediately reduces their available slots for everyone else.
    const rows = db.faculty.map((f, id) => ({
      id, name: f.name, school: f.school, capacity: f.capacity,
      slotsRemaining: Math.max(0, f.capacity - facultyLoad(f.email)),
    })).sort((a, b) => a.school.localeCompare(b.school) || b.slotsRemaining - a.slotsRemaining);
    return sendJSON(res, 200, { rows, branches: BRANCHES });
  }

  // ---- STUDENT: select (request) a faculty for your group. Holds a slot. ----
  if (p === '/api/student/select-faculty' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const { facultyId } = await readBody(req);
    const g = db.groups.find((x) => x.members.includes(sess.reg) && x.status !== 'rejected');
    if (!g) return sendJSON(res, 404, { error: 'Submit your group first, then pick a faculty.' });
    if (g.status === 'accepted') return sendJSON(res, 409, { error: 'Your group is already accepted; faculty is locked.' });
    if (g.submittedBy !== sess.reg) return sendJSON(res, 403, { error: 'Only the team leader can choose the faculty.' });
    let email = null, name = null;
    if (facultyId !== '' && facultyId != null) {
      const f = db.faculty[Number(facultyId)];
      if (!f) return sendJSON(res, 404, { error: 'Faculty not found.' });
      // count this faculty's load excluding this group's own current hold
      const otherLoad = db.groups.filter((x) => x !== g && x.status !== 'rejected' && (x.faculty === f.email || x.requestedFaculty === f.email)).length;
      if (otherLoad >= f.capacity) return sendJSON(res, 409, { error: 'That faculty has no slots left. Please pick another.' });
      email = f.email; name = f.name;
    }
    g.requestedFaculty = email; persist();
    return sendJSON(res, 200, { ok: true, requestedFacultyName: name });
  }

  // ---- FACULTY: searchable, paginated student directory (real emails) ----
  if (p === '/api/faculty/students' && req.method === 'GET') {
    if (!facultyAuth(req)) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const arr = branchFilter(studentArr, url.searchParams.get('branch'));
    const r = pageOf(arr, url.searchParams.get('q'), url.searchParams.get('page'), url.searchParams.get('size'));
    const rows = r.rows.map((e) => ({ reg: e.reg, name: e.name, school: e.school, scope: e.scope, email: e.email }));
    return sendJSON(res, 200, { total: r.total, page: r.page, pages: r.pages, size: r.size, rows, branches: BRANCHES });
  }

  // ---- ADMIN login ----
  if (p === '/api/admin/login' && req.method === 'POST') {
    const { username, password } = await readBody(req);
    const a = db.admin;
    if (!a || String(username || '').toLowerCase() !== a.username) return sendJSON(res, 401, { error: 'Incorrect username or password.' });
    if (!(await vault.verifyPassword(password || '', a.passHash))) return sendJSON(res, 401, { error: 'Incorrect username or password.' });
    const tok = vault.newToken();
    sessions.set(tok, { role: 'admin', username: a.username });
    return sendJSON(res, 200, { token: tok, username: a.username });
  }

  // ---- ADMIN: all students, searchable + paginated (email + initial password) ----
  if (p === '/api/admin/students' && req.method === 'GET') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const arr = branchFilter(studentArr, url.searchParams.get('branch'));
    const r = pageOf(arr, url.searchParams.get('q'), url.searchParams.get('page'), url.searchParams.get('size'));
    const rows = r.rows.map((e) => ({ reg: e.reg, name: e.name, school: e.school, scope: e.scope, email: e.email,
      initialPassword: e.changed ? null : initialStudentPw(e.name), changed: e.changed }));
    return sendJSON(res, 200, { total: r.total, page: r.page, pages: r.pages, size: r.size, rows, branches: BRANCHES });
  }

  // ---- ADMIN: all faculty with slots (used = selections + acceptances) ----
  if (p === '/api/admin/faculty' && req.method === 'GET') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const rows = db.faculty.map((f) => {
      const used = facultyLoad(f.email);
      return { email: f.email, name: f.name, school: f.school, capacity: f.capacity, used, remaining: Math.max(0, f.capacity - used), initialPassword: initialFacultyPw(f.email) };
    });
    return sendJSON(res, 200, { rows });
  }

  // ---- ADMIN: download all student-faculty allocations as CSV ----
  if (p === '/api/admin/export' && req.method === 'GET') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const rows = [['Group', 'Status', 'Assigned faculty', 'Selected faculty', 'Slot', 'Reg no', 'Name', 'School', 'Type', 'Email']];
    for (const g of db.groups) {
      const asg = g.faculty ? (db.faculty.find((f) => f.email === g.faculty) || {}).name || g.faculty : '';
      const reqName = g.requestedFaculty ? (db.faculty.find((f) => f.email === g.requestedFaculty) || {}).name || g.requestedFaculty : '';
      g.members.forEach((reg, i) => {
        const s = db.students[reg] || {};
        const info = engine.schoolOf(reg.slice(2, 5), MAP);
        rows.push([g.id, g.status, asg, reqName, i + 1, reg, s.name || '', info.school, info.scope ? 'SCOPE' : 'Other', s.email ? vault.decrypt(s.email) : '']);
      });
    }
    const csv = rows.map((r) => r.map((x) => '"' + String(x).replace(/"/g, '""') + '"').join(',')).join('\r\n');
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="allocations.csv"',
      'Access-Control-Allow-Origin': '*',
    });
    return res.end(csv);
  }

  // ---- ADMIN: reset a student to their initial password ----
  if (p === '/api/admin/reset-password' && req.method === 'POST') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const { reg } = await readBody(req);
    const s = db.students[reg]; if (!s) return sendJSON(res, 404, { error: 'Student not found.' });
    const pw = initialStudentPw(s.name);
    s.passwordHash = await vault.hashPassword(pw); s.changedPassword = false;
    s.passwordResetNotice = true;   // student is told on their next login
    const e = studentArrByReg.get(reg); if (e) e.changed = false;
    persist();
    return sendJSON(res, 200, { ok: true, initialPassword: pw });
  }

  // ---- STUDENT: contact admin / raise a support query ----
  if (p === '/api/student/query' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const { topic, message } = await readBody(req);
    const t = String(topic || '').trim(), m = String(message || '').trim();
    if (!t && !m) return sendJSON(res, 400, { error: 'Please describe the problem.' });
    const q = { id: 'Q' + String(db.queries.length + 1).padStart(4, '0'), reg: sess.reg, name: sess.name, topic: t, message: m, status: 'open', createdAt: Date.now() };
    db.queries.push(q); persist();
    return sendJSON(res, 200, { ok: true, id: q.id });
  }

  // ---- PUBLIC: forgot password -> files a reset request for the admin.
  //      Always returns ok so it can't be used to probe which regs exist. ----
  if (p === '/api/request-reset' && req.method === 'POST') {
    const { reg } = await readBody(req);
    const key = String(reg || '').trim().toUpperCase().replace(/\s+/g, '');
    const st = db.students[key];
    if (st && !db.queries.some((q) => q.reg === key && q.topic === 'Password reset request' && q.status === 'open')) {
      db.queries.push({ id: 'Q' + String(db.queries.length + 1).padStart(4, '0'), reg: key, name: st.name, topic: 'Password reset request', message: 'Student used "Forgot password" and needs a reset.', status: 'open', createdAt: Date.now() });
      persist();
    }
    return sendJSON(res, 200, { ok: true });
  }

  // ---- ADMIN: view student queries ----
  if (p === '/api/admin/queries' && req.method === 'GET') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const rows = db.queries.slice().sort((a, b) => b.createdAt - a.createdAt);
    return sendJSON(res, 200, { rows, open: rows.filter((q) => q.status === 'open').length });
  }

  // ---- ADMIN: toggle a query open/resolved ----
  if (p === '/api/admin/query-resolve' && req.method === 'POST') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const { id } = await readBody(req);
    const q = db.queries.find((x) => x.id === id); if (!q) return sendJSON(res, 404, { error: 'Query not found.' });
    q.status = q.status === 'open' ? 'resolved' : 'open'; persist();
    return sendJSON(res, 200, { ok: true, status: q.status });
  }

  // ---- STUDENT: only THEIR OWN group(s). All emails masked (students never
  //      see email addresses; only teachers and admin do). ----
  if (p === '/api/student/mygroups' && req.method === 'GET') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const groups = db.groups
      .filter((g) => g.members.includes(sess.reg))
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((g) => groupView(g, {}));
    return sendJSON(res, 200, { reg: sess.reg, name: sess.name, groups });
  }

  // ---- STUDENT submit a group (must include yourself) ----
  if (p === '/api/student/submit' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const me = db.students[sess.reg];
    if (!me || !me.scope) return sendJSON(res, 403, { error: 'Only a SCOPE student can create and lead a group.' });
    const { members } = await readBody(req);
    const regs = [...new Set((members || []).map((m) => String(m).trim().toUpperCase().replace(/\s+/g, '')).filter(Boolean))];
    if (!regs.includes(sess.reg)) return sendJSON(res, 422, { error: 'Your own registration number must be in the group.' });

    // one student, one group. You may replace your own PENDING group; everyone
    // else in the new group must be free (not already in another active group).
    const mine = activeGroupOf(sess.reg);
    if (mine && mine.status === 'accepted') return sendJSON(res, 409, { error: 'Your group is already accepted; it cannot be changed.' });
    const clash = [];
    for (const reg of regs) {
      const gg = activeGroupOf(reg);
      if (gg && gg !== mine) clash.push(reg);
    }
    if (clash.length) return sendJSON(res, 409, { error: 'Each student can be in only one group. Already in a group: ' + clash.join(', ') + '.' });

    const v = validateGroup(regs);
    if (!v.valid) return sendJSON(res, 422, { error: 'Group does not pass the constraints.', problems: v.problems });

    if (mine) db.groups = db.groups.filter((x) => x !== mine);   // replace the old pending group
    // leader (submitter, a SCOPE student) auto-accepts; every teammate must consent
    const consent = {};
    regs.forEach((r) => { consent[r] = r === sess.reg ? 'accepted' : 'pending'; });
    const g = { id: nextGroupId(), members: regs, status: 'pending', faculty: null, requestedFaculty: null, submittedBy: sess.reg, consent, createdAt: Date.now() };
    db.groups.push(g); persist();
    return sendJSON(res, 200, { ok: true, group: groupView(g, {}) });
  }

  // ---- STUDENT accept / decline being part of their group ----
  if (p === '/api/student/consent' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const { decision } = await readBody(req);
    const g = activeGroupOf(sess.reg);
    if (!g) return sendJSON(res, 404, { error: 'You are not in a group.' });
    if (g.submittedBy === sess.reg) return sendJSON(res, 400, { error: 'You are the team leader; you cannot decline your own group.' });
    if (g.status === 'accepted') return sendJSON(res, 409, { error: 'This group has already been approved.' });
    if (!g.consent) g.consent = {};
    g.consent[sess.reg] = decision === 'accept' ? 'accepted' : 'declined';
    persist();
    return sendJSON(res, 200, { ok: true, consent: g.consent[sess.reg], ready: groupReady(g) });
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
