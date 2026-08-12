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
const store = require('./store.js');
const xlsx = require('./xlsx-lite.js');

const PORT = process.env.PORT || 4000;
const PUBLIC = path.join(__dirname, 'public');
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const MAP = engine.DEFAULT_MAP;

// ---------------------------------------------------------------- database
const sessions = new Map();               // token -> { email, name }

// Seed data for a brand-new SQLite database: the committed db.json (10k students,
// faculty, admin, groups), else a small CSV fallback.
function initialData() {
  try {
    const j = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!Array.isArray(j.queries)) j.queries = [];
    return j;
  } catch (e) {
    const csv = path.join(__dirname, 'data', 'sample-students.csv');
    const base = fs.existsSync(csv) ? dataset.loadFromCSV(csv, { groups: 8 }) : { students: {}, groups: [] };
    return {
      students: base.students, groups: base.groups, queries: [],
      faculty: [{ email: 'teacher@domain', name: 'Dr. Demo Faculty', passHash: vault.hashPasswordSync('teach123'), capacity: 5, school: 'SCOPE', cabin: 'SJT-201' }],
      admin: { username: 'admin', passHash: vault.hashPasswordSync('admin@123') },
    };
  }
}

// The store (SQLite by default, Postgres when DATABASE_URL is set) is opened in
// boot() at the bottom — its init/loadAll are async so a real DB connection works.
// Reads are served from `db` in memory (O(1)); every write goes THROUGH to the store.
let db;

// Lock the vault to whichever key actually decrypts this database, so a wrong
// or stale VAULT_KEY env var can never break email lookup / login.
function lockKey() {
  const first = Object.values(db.students)[0];
  if (first && first.email && !vault.selectKeyFor(first.email)) {
    console.warn('WARNING: no available key decrypts the student emails; check VAULT_KEY / .vault_key');
  }
}

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

// The documented INITIAL passwords. We never store plaintext; these are the
// known defaults, shown to admin (who can also reset an account). Current
// passwords stay one-way hashed and are unreadable by anyone.
function initialStudentPw(name) { return String(name).toLowerCase().replace(/[^a-z0-9]/g, ''); }
function initialFacultyPw(email) {
  if (email === 'teacher@domain') return 'teach123';
  const m = String(email).match(/^faculty0*(\d+)@/);
  if (m) return 'faculty' + m[1];
  // uploaded faculty (arbitrary email): a stable, unguessable initial password the
  // admin can read off the Faculty tab and hand over. Deterministic from the email.
  return 'vit-' + vault.hashkeyFor('FACPW:' + String(email).toLowerCase()).slice(0, 8);
}

// ---- student registration & password rules (M4) ----
// A student's self-password must be strong: 8+ chars with lower + upper + digit + '_'.
function passwordProblems(pw) {
  pw = String(pw || ''); const p = [];
  if (pw.length < 8) p.push('at least 8 characters');
  if (!/[a-z]/.test(pw)) p.push('a lowercase letter');
  if (!/[A-Z]/.test(pw)) p.push('an uppercase letter');
  if (!/[0-9]/.test(pw)) p.push('a number');
  if (!/_/.test(pw)) p.push('an underscore ( _ )');
  return p;
}
// "Password unique to all": fingerprint -> reg, so we can reject a password already
// used by another student WITHOUT ever storing anything reversible.
const pwFingerprints = new Map();
function rebuildPwFingerprints() {
  pwFingerprints.clear();
  for (const reg in db.students) { const fp = db.students[reg].pwFp; if (fp) pwFingerprints.set(fp, reg); }
}
// Apply a new self-password to a student (shared by registration + change-password):
// validates strength + global uniqueness, hashes it, and marks them registered.
async function applySelfPassword(st, newPassword) {
  const probs = passwordProblems(newPassword);
  if (probs.length) return { error: 'Your password needs ' + probs.join(', ') + '.', problems: probs, code: 400 };
  const fp = vault.pwFingerprint(newPassword);
  const owner = pwFingerprints.get(fp);
  if (owner && owner !== st.reg) return { error: 'That password is already in use by another student. Please choose a different one.', code: 409 };
  st.passwordHash = await vault.hashPassword(newPassword);
  if (st.pwFp) pwFingerprints.delete(st.pwFp);
  st.pwFp = fp; pwFingerprints.set(fp, st.reg);
  st.changedPassword = true;                              // registered = has a self-password
  const ce = studentArrByReg.get(st.reg); if (ce) ce.changed = true;
  store.saveStudent(st);
  return { ok: true };
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
// distinct non-SCOPE SCHOOLS (keyed by school, so SMEC counts once) for the guide,
// and all distinct branches/schools (incl. SCOPE) for the "sort by branch" filters.
// Computed in boot() once the roster is loaded.
let OTHER_SCHOOLS = [], BRANCHES = [];
function computeSchoolLists() {
  OTHER_SCHOOLS = [...new Set(studentArr.filter((s) => !s.scope).map((s) => engine.schoolKey(s.school)))].sort();
  BRANCHES = [...new Set(studentArr.map((s) => engine.schoolKey(s.school)))].sort();
}

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
// format an epoch-ms instant as an India-time (IST, UTC+5:30) wall-clock string
function istStamp(ms) {
  if (!ms) return '';
  const d = new Date(ms + 5.5 * 3600 * 1000); const p = (n) => String(n).padStart(2, '0');
  return d.getUTCFullYear() + '-' + p(d.getUTCMonth() + 1) + '-' + p(d.getUTCDate()) + ' ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) + ':' + p(d.getUTCSeconds()) + ' IST';
}
function empIdFor(idx) { return idx >= 0 ? 'EMP' + String(idx + 1).padStart(4, '0') : ''; }
// hashkeys may only be sent to an institutional VIT address, never a personal one
const PROCTOR_EMAIL_DOMAIN = process.env.PROCTOR_EMAIL_DOMAIN || 'vit.ac.in';
function isInstitutionalEmail(email) {
  return new RegExp('^[^@\\s]+@' + PROCTOR_EMAIL_DOMAIN.replace(/\./g, '\\.') + '$', 'i').test(String(email || '').trim());
}
// slots held: a selection (requested) OR an acceptance both consume an available slot
function facultyLoad(email) { return db.groups.filter((g) => g.status !== 'rejected' && (g.faculty === email || g.requestedFaculty === email)).length; }

// one-student-one-group: the active (non-rejected) group a reg belongs to, if any
function activeGroupOf(reg) { return db.groups.find((g) => g.status !== 'rejected' && g.members.includes(reg)); }
// invitation model: a SCOPE student's own team, created lazily the first time they
// invite someone. The leader is a member with consent already 'accepted'.
function ensureGroupFor(reg) {
  const existing = activeGroupOf(reg);
  if (existing) return existing;
  const st = db.students[reg];
  if (!st || !st.scope) return null;                 // only SCOPE students can lead a team
  const g = { id: nextGroupId(), members: [reg], status: 'pending', faculty: null,
    requestedFaculty: null, submittedBy: reg, consent: { [reg]: 'accepted' }, createdAt: Date.now() };
  db.groups.push(g); store.saveGroup(g);
  return g;
}
// can `target` be invited into group `g` without breaking 2 SCOPE + 3 distinct schools?
// Returns an error string, or null if the invite is allowed.
function inviteBlock(g, target) {
  const info = engine.schoolOf(target.slice(2, 5), MAP);
  const cur = g.members.map((r) => engine.schoolOf(r.slice(2, 5), MAP));
  const scopeCount = cur.filter((x) => x.scope).length;
  const usedSchools = new Set(cur.filter((x) => !x.scope && x.known).map((x) => engine.schoolKey(x.school)));
  if (info.scope) { if (scopeCount >= 2) return 'Your team already has its 2 SCOPE members.'; return null; }
  if (!info.known) return 'That student has an unknown branch code and cannot be placed.';
  const key = engine.schoolKey(info.school);
  if (usedSchools.has(key)) return 'Your team already has a member from that school.';
  if (usedSchools.size >= 3) return 'Your team already has 3 different schools.';
  return null;
}
// a pending team that has lost a member should not keep holding a faculty slot
function clearStaleRequest(g) {
  if (g && g.status === 'pending' && g.requestedFaculty && !(groupReady(g) && validateGroup(g.members).valid)) {
    g.requestedFaculty = null; return true;
  }
  return false;
}
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

// The full list of team constraints, each with its current pass/fail state. Used to
// render a checklist that shows EVERY rule and highlights the ones not yet met.
function constraintChecks(members) {
  const people = members.map((reg) => engine.schoolOf(String(reg).slice(2, 5), MAP));
  const scope = people.filter((p) => p.scope);
  const other = people.filter((p) => !p.scope && p.known);
  const unknown = people.filter((p) => !p.known);
  const otherSchools = other.map((p) => engine.schoolKey(p.school));
  const distinct = new Set(otherSchools);
  return [
    { key: 'size', label: 'Exactly 5 members', ok: members.length === 5, detail: members.length + ' / 5' },
    { key: 'unique', label: 'No repeated registration number', ok: new Set(members).size === members.length },
    { key: 'scope', label: 'Exactly 2 SCOPE members', ok: scope.length === 2, detail: scope.length + ' / 2' },
    { key: 'other', label: 'Exactly 3 members from other schools', ok: other.length === 3, detail: other.length + ' / 3' },
    { key: 'known', label: 'Every member has a recognised branch code', ok: unknown.length === 0, detail: unknown.length ? unknown.length + ' unknown' : '' },
    { key: 'distinct', label: 'The 3 other-school members are from 3 different schools', ok: distinct.size === otherSchools.length, detail: otherSchools.length ? distinct.size + ' distinct' : '' },
  ];
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
    id: g.id, status: g.status, faculty: g.faculty, facultyName: asg ? asg.name : null, facultyCabin: asg ? (asg.cabin || null) : null, createdAt: g.createdAt,
    requestedFaculty: g.requestedFaculty || null, requestedFacultyName: rf ? rf.name : null, requestedFacultyCabin: rf ? (rf.cabin || null) : null, requestedFacultyId: rfIdx >= 0 ? rfIdx : null,
    leader: g.submittedBy, ready: groupReady(g),
    valid: v.valid, problems: v.problems, checks: constraintChecks(g.members),
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

// ---------------------------------------------------------------- roster upload
// Read the first non-empty value among a set of accepted header names (case-insensitive,
// already lower-cased by the parser), so an admin's column can be "Reg", "Reg No.", etc.
function pick(row, keys) { for (const k of keys) { const v = row[k]; if (v != null && String(v).trim() !== '') return String(v).trim(); } return ''; }

// Turn parsed rows into the student map. Emails are encrypted at rest exactly like
// the seed. A reg that already registered (set a self-password) keeps its login —
// re-uploading the roster never wipes a student's account.
function ingestStudents(rows) {
  const out = {}; let brandNew = 0, preserved = 0, skipped = 0;
  for (const row of rows) {
    const reg = pick(row, ['reg', 'reg no', 'reg no.', 'regno', 'registration', 'registration number', 'registration no', 'register number']).toUpperCase().replace(/\s+/g, '');
    const name = pick(row, ['name', 'student name', 'full name']);
    const email = pick(row, ['email', 'email id', 'e-mail', 'mail', 'email address']);
    if (!reg || !name) { skipped++; continue; }
    const info = engine.schoolOf(reg.slice(2, 5), MAP);
    const typeStr = pick(row, ['type', 'category', 'scope']);
    const scope = info.known ? info.scope : /scope/i.test(typeStr);
    const school = info.known ? info.school : (pick(row, ['school', 'branch', 'department']) || 'Unknown School');
    const prev = db.students[reg];
    out[reg] = {
      reg, name, school, scope,
      email: email ? vault.encrypt(email) : (prev ? prev.email : null),
      emailHash: email ? vault.hashEmail(email) : (prev ? prev.emailHash : null),
      passwordHash: prev ? prev.passwordHash : null,
      changedPassword: prev ? !!prev.changedPassword : false,
      passwordResetNotice: prev ? !!prev.passwordResetNotice : false,
      pwFp: prev ? (prev.pwFp || null) : null,
    };
    if (prev && prev.changedPassword) preserved++; else brandNew++;
  }
  return { students: out, total: Object.keys(out).length, brandNew, preserved, skipped };
}

// Turn parsed rows into the faculty list. Cabin number is read here. An existing
// faculty (same email) keeps their password; a new one gets the deterministic
// initial password shown on the admin Faculty tab.
async function ingestFaculty(rows) {
  const list = []; const seen = new Set(); let skipped = 0;
  for (const row of rows) {
    const email = pick(row, ['email', 'email id', 'e-mail', 'mail', 'email address']).toLowerCase();
    const name = pick(row, ['name', 'faculty name', 'full name', 'guide name']);
    if (!email || !name) { skipped++; continue; }
    if (seen.has(email)) { skipped++; continue; }
    seen.add(email);
    const school = pick(row, ['school', 'department', 'dept', 'branch']);
    const cabin = pick(row, ['cabin', 'cabin no', 'cabin no.', 'cabin number', 'cabin_no', 'room', 'room no', 'room no.', 'room number']);
    const capRaw = parseInt(pick(row, ['max_groups', 'capacity', 'slots', 'max groups', 'groups', 'limit']), 10);
    const capacity = Number.isFinite(capRaw) ? Math.max(0, Math.min(50, capRaw)) : 3;
    const prev = db.faculty.find((f) => f.email.toLowerCase() === email);
    const passHash = prev ? prev.passHash : await vault.hashPassword(initialFacultyPw(email));
    list.push({ email, name, school, capacity, cabin, passHash });
  }
  return { faculty: list, total: list.length, skipped };
}

// Swap in a freshly uploaded roster and rebuild every in-memory index so the change
// is live immediately (no restart). Persisted through the store in the same call.
function applyStudents(map) {
  db.students = map;
  store.replaceStudents(map);
  lockKey(); reindex(); buildStudentArr(); computeSchoolLists(); rebuildPwFingerprints();
}
function applyFaculty(list) {
  db.faculty = list;
  store.replaceFaculty(list);
}

// ---------------------------------------------------------------- chat
let msgSeq = 0;
function nextMsgId() { return 'M' + Date.now().toString(36) + (++msgSeq).toString(36); }
function threadKey(reg, facEmail) { return String(reg).toUpperCase() + '||' + String(facEmail).toLowerCase(); }
// A student's guide is the faculty their team is with (accepted) or has applied to
// (pending selection). That is who the chat connects them to.
function guideFacultyOf(reg) {
  const g = activeGroupOf(reg);
  if (!g) return null;
  const em = g.faculty || g.requestedFaculty;
  if (!em) return null;
  const f = db.faculty.find((x) => x.email === em);
  return f ? { faculty: f, status: g.faculty ? 'accepted' : 'requested', team: g } : null;
}
function threadMessages(reg, facEmail) {
  const key = threadKey(reg, facEmail);
  return db.messages.filter((m) => m.thread === key).sort((a, b) => a.createdAt - b.createdAt)
    .map((m) => ({ id: m.id, from: m.fromRole, body: m.body, at: m.createdAt, atText: istStamp(m.createdAt) }));
}
function addMessage(reg, facEmail, fromRole, body) {
  const m = { id: nextMsgId(), thread: threadKey(reg, facEmail), reg: String(reg).toUpperCase(), facEmail: String(facEmail).toLowerCase(),
    fromRole, body: String(body).slice(0, 2000), createdAt: Date.now(),
    readByStudent: fromRole === 'student', readByFaculty: fromRole === 'faculty' };
  db.messages.push(m); store.saveMessage(m);
  return m;
}
// every reg that can chat with this faculty: members of teams that chose/were accepted
// by them, plus anyone who already has a message thread with them.
function facultyThreads(facEmail) {
  const regs = new Set();
  for (const g of db.groups) {
    if (g.status === 'rejected') continue;
    if (g.faculty === facEmail || g.requestedFaculty === facEmail) g.members.forEach((r) => regs.add(r));
  }
  for (const m of db.messages) if (m.facEmail === facEmail) regs.add(m.reg);
  return [...regs].map((reg) => {
    const st = db.students[reg] || {};
    const msgs = db.messages.filter((m) => m.facEmail === facEmail && m.reg === reg);
    const last = msgs.length ? msgs[msgs.length - 1] : null;
    const unread = msgs.filter((m) => m.fromRole === 'student' && !m.readByFaculty).length;
    const g = db.groups.find((x) => x.status !== 'rejected' && x.members.includes(reg) && (x.faculty === facEmail || x.requestedFaculty === facEmail));
    return { reg, name: st.name || reg, teamId: g ? g.id : null, teamStatus: g ? g.status : null,
      lastBody: last ? last.body : '', lastAt: last ? last.createdAt : 0, lastAtText: last ? istStamp(last.createdAt) : '', unread };
  }).sort((a, b) => b.lastAt - a.lastAt || String(a.reg).localeCompare(String(b.reg)));
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
// A bigger, buffered JSON reader for file uploads (base64 payloads can be several MB).
// Kept separate from readBody so ordinary login/API bodies stay capped small.
function readJSONLarge(req, maxBytes) {
  maxBytes = maxBytes || 48e6;
  return new Promise((resolve) => {
    const chunks = []; let len = 0; let tooBig = false;
    req.on('data', (c) => { len += c.length; if (len > maxBytes) { tooBig = true; req.destroy(); return; } chunks.push(c); });
    req.on('end', () => { if (tooBig) return resolve(null); try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { resolve(null); } });
    req.on('error', () => resolve(null));
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
async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;

  if (p === '/api/health') return sendJSON(res, 200, { ok: true, students: Object.keys(db.students).length, groups: db.groups.length, pid: process.pid });

  // ---- PUBLIC: live headline stats for the landing "Allocation overview" ----
  if (p === '/api/stats' && req.method === 'GET') {
    const students = studentArr.length;
    const faculty = db.faculty.length;
    const formed = db.groups.filter((g) => g.status !== 'rejected').length;
    const accepted = db.groups.filter((g) => g.status === 'accepted').length;
    const scopeCount = studentArr.filter((s) => s.scope).length;
    const otherCount = students - scopeCount;
    const maxTeams = Math.min(Math.floor(scopeCount / 2), Math.floor(otherCount / 3));
    const grouped = groupedRegSet().size;
    return sendJSON(res, 200, { students, faculty, formed, accepted, maxTeams, grouped });
  }

  // ---- FACULTY login ----
  if (p === '/api/faculty/login' && req.method === 'POST') {
    const { email, password } = await readBody(req);
    const f = findFaculty(email);
    if (!f || !(await vault.verifyPassword(password, f.passHash))) return sendJSON(res, 401, { error: 'Invalid credentials.' });
    const tok = vault.newToken();
    sessions.set(tok, { role: 'faculty', email: f.email, name: f.name });
    return sendJSON(res, 200, { token: tok, name: f.name, email: f.email, capacity: f.capacity, cabin: f.cabin || null, seatsUsed: seatsUsed(f.email) });
  }

  // ---- FACULTY view groups (real emails) ----
  if (p === '/api/faculty/groups' && req.method === 'GET') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const f = findFaculty(sess.email);
    // A team reaches a faculty ONLY when it explicitly chose that faculty, is complete
    // (all members accepted), and satisfies the constraints. This is what makes "request
    // sent to faculty" reliably land with the right person (and stops unselected teams
    // flooding every faculty's queue).
    const groups = db.groups
      .filter((g) => g.faculty === sess.email ||
        (g.status === 'pending' && g.requestedFaculty === sess.email && groupReady(g) && validateGroup(g.members).valid))
      .sort((a, b) => (a.faculty === sess.email ? 1 : 0) - (b.faculty === sess.email ? 1 : 0) || a.createdAt - b.createdAt)
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
      g.status = 'accepted'; g.faculty = f.email; g.approvedAt = Date.now();   // "approved" timestamp
    } else if (decision === 'reject') {
      g.status = 'rejected'; g.faculty = null;
    } else return sendJSON(res, 400, { error: 'decision must be accept or reject.' });
    store.saveGroup(g);
    return sendJSON(res, 200, { ok: true, group: groupView(g, { reveal: true }), seatsUsed: seatsUsed(f.email), capacity: f.capacity });
  }

  // ---- FACULTY: set my own limit — how many teams I am willing to take on ----
  if (p === '/api/faculty/capacity' && req.method === 'POST') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const f = findFaculty(sess.email);
    const { capacity } = await readBody(req);
    const cap = parseInt(capacity, 10);
    if (!Number.isFinite(cap)) return sendJSON(res, 400, { error: 'Enter a whole number.' });
    const clamped = Math.max(0, Math.min(50, cap));
    const used = seatsUsed(f.email);
    if (clamped < used) return sendJSON(res, 409, { error: 'You have already accepted ' + used + ' team(s); your limit cannot be below that.' });
    f.capacity = clamped; store.saveFacultyCapacity(f.email, clamped);
    return sendJSON(res, 200, { ok: true, capacity: clamped, seatsUsed: used });
  }

  // ---- STUDENT login (registration number + password). Emails are never used
  //      by students; only teachers and admin ever see email addresses. ----
  if (p === '/api/student/login' && req.method === 'POST') {
    const body = await readBody(req);
    const raw = String(body.reg || body.email || body.id || '').trim();
    const secret = body.password;                          // their password, OR (first time) their hashkey
    const st = raw.includes('@') ? findStudentByEmail(raw) : db.students[raw.toUpperCase().replace(/\s+/g, '')];
    if (!st) return sendJSON(res, 401, { error: 'Incorrect registration number.' });
    const registered = !!st.changedPassword;               // registered = has set a self-password
    let mustRegister = false;
    if (registered) {
      if (!(await vault.verifyPassword(secret || '', st.passwordHash))) return sendJSON(res, 401, { error: 'Incorrect registration number or password.' });
    } else {
      // first login: authenticate with the one-time hashkey collected from the proctor
      if (!vault.hashkeyMatches(st.reg, secret)) return sendJSON(res, 401, { error: 'Incorrect hashkey. Collect your hashkey from your proctor, then set your password.' });
      mustRegister = true;                                 // force them to set a self-password now
    }
    const tok = vault.newToken();
    sessions.set(tok, { role: 'student', reg: st.reg, name: st.name, mustRegister });
    const wasReset = !!st.passwordResetNotice;
    if (wasReset) { st.passwordResetNotice = false; store.saveStudent(st); }   // one-time notice
    return sendJSON(res, 200, { token: tok, reg: st.reg, name: st.name, school: st.school, scope: !!st.scope, changedPassword: registered, mustRegister: mustRegister, passwordReset: wasReset });
  }

  // ---- STUDENT change password (writes a new one-way hash) ----
  if (p === '/api/student/password' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in first.' });
    const st = db.students[sess.reg]; if (!st) return sendJSON(res, 404, { error: 'Account not found.' });
    const { currentPassword, newPassword } = await readBody(req);
    if (!(await vault.verifyPassword(currentPassword || '', st.passwordHash))) return sendJSON(res, 403, { error: 'Current password is incorrect.' });
    const r = await applySelfPassword(st, newPassword);        // strength + global uniqueness
    if (r.error) return sendJSON(res, r.code, { error: r.error, problems: r.problems });
    return sendJSON(res, 200, { ok: true });
  }

  // ---- STUDENT: complete first-time registration by setting a self-password.
  //      Used right after a hashkey login (session flagged mustRegister). ----
  if (p === '/api/student/set-password' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in first.' });
    const st = db.students[sess.reg]; if (!st) return sendJSON(res, 404, { error: 'Account not found.' });
    const { newPassword } = await readBody(req);
    const r = await applySelfPassword(st, newPassword);        // strength + global uniqueness
    if (r.error) return sendJSON(res, r.code, { error: r.error, problems: r.problems });
    sess.mustRegister = false;                                 // registration complete
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
      valid: regs.length === 5 && v.valid, problems: v.problems, checks: constraintChecks(regs),
    });
  }

  // ---- STUDENT: faculty directory (name, school, slots remaining). No emails.
  //      `id` is the db index, used only as an opaque handle to select a faculty. ----
  if (p === '/api/faculty-directory' && req.method === 'GET') {
    if (!studentAuth(req)) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    // slotsRemaining reflects live selections + acceptances, so picking a faculty
    // immediately reduces their available slots for everyone else.
    const rows = db.faculty.map((f, id) => ({
      id, name: f.name, school: f.school, capacity: f.capacity, cabin: f.cabin || null,
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
      // a team can only be sent to a faculty once it is complete and everyone has accepted
      if (!groupReady(g)) return sendJSON(res, 409, { error: 'All members must accept before you can send the team to a faculty.' });
      const gv = validateGroup(g.members);
      if (!gv.valid) return sendJSON(res, 422, { error: 'Your team must have 2 SCOPE + 3 members from different schools first.', problems: gv.problems });
      const f = db.faculty[Number(facultyId)];
      if (!f) return sendJSON(res, 404, { error: 'Faculty not found.' });
      // count this faculty's load excluding this group's own current hold
      const otherLoad = db.groups.filter((x) => x !== g && x.status !== 'rejected' && (x.faculty === f.email || x.requestedFaculty === f.email)).length;
      if (otherLoad >= f.capacity) return sendJSON(res, 409, { error: 'That faculty has no slots left. Please pick another.' });
      email = f.email; name = f.name;
    }
    g.requestedFaculty = email;
    g.requestedAt = email ? Date.now() : null;             // "applied" timestamp
    store.saveGroup(g);
    return sendJSON(res, 200, { ok: true, requestedFacultyName: name });
  }

  // ---- STUDENT (leader): invite one student into the team. One invite at a time:
  //      the target must be free (no pending invite / not in any team). ----
  if (p === '/api/student/invite' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const me = db.students[sess.reg];
    if (!me || !me.scope) return sendJSON(res, 403, { error: 'Only a SCOPE student can lead a team and invite members.' });
    const g = ensureGroupFor(sess.reg);
    if (!g) return sendJSON(res, 403, { error: 'Only a SCOPE student can lead a team.' });
    if (g.submittedBy !== sess.reg) return sendJSON(res, 403, { error: 'Only the team leader can invite members.' });
    if (g.status === 'accepted') return sendJSON(res, 409, { error: 'Your team is already approved; it is locked.' });
    const { reg } = await readBody(req);
    const target = String(reg || '').trim().toUpperCase().replace(/\s+/g, '');
    const st = db.students[target];
    if (!st) return sendJSON(res, 404, { error: 'Student not found.' });
    if (target === sess.reg) return sendJSON(res, 400, { error: 'You are already in your own team.' });
    if (g.members.includes(target)) return sendJSON(res, 409, { error: 'That student is already in your team.' });
    if (g.members.length >= 5) return sendJSON(res, 409, { error: 'Your team already has 5 members.' });
    // one invitation at a time — cannot poach someone who already has a pending invite or a team
    if (activeGroupOf(target)) return sendJSON(res, 409, { error: 'That student already has a pending invite or is already in a team.' });
    const block = inviteBlock(g, target);
    if (block) return sendJSON(res, 409, { error: block });
    g.members.push(target);
    if (!g.consent) g.consent = {};
    g.consent[target] = 'pending';                    // they must accept
    store.saveGroup(g);
    return sendJSON(res, 200, { ok: true, invited: target, group: groupView(g, {}) });
  }

  // ---- STUDENT (leader): withdraw an invite / remove a member, freeing them. ----
  if (p === '/api/student/uninvite' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const { reg } = await readBody(req);
    const target = String(reg || '').trim().toUpperCase().replace(/\s+/g, '');
    const g = activeGroupOf(sess.reg);
    if (!g || g.submittedBy !== sess.reg) return sendJSON(res, 403, { error: 'Only the team leader can remove members.' });
    if (g.status === 'accepted') return sendJSON(res, 409, { error: 'Your team is already approved; it is locked.' });
    if (target === sess.reg) return sendJSON(res, 400, { error: 'You are the leader; you cannot remove yourself.' });
    if (!g.members.includes(target)) return sendJSON(res, 404, { error: 'That student is not in your team.' });
    g.members = g.members.filter((r) => r !== target);
    if (g.consent) delete g.consent[target];
    clearStaleRequest(g);                              // dropping a member releases any faculty hold
    store.saveGroup(g);
    return sendJSON(res, 200, { ok: true, removed: target, group: groupView(g, {}) });
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
      hashkey: vault.hashkeyFor(e.reg), registered: e.changed }));
    return sendJSON(res, 200, { total: r.total, page: r.page, pages: r.pages, size: r.size, rows, branches: BRANCHES });
  }

  // ---- ADMIN: all faculty with slots (used = selections + acceptances) ----
  if (p === '/api/admin/faculty' && req.method === 'GET') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const rows = db.faculty.map((f) => {
      const used = facultyLoad(f.email);
      return { email: f.email, name: f.name, school: f.school, capacity: f.capacity, cabin: f.cabin || null, used, remaining: Math.max(0, f.capacity - used), initialPassword: initialFacultyPw(f.email) };
    });
    return sendJSON(res, 200, { rows });
  }

  // ---- ADMIN: download all student-faculty allocations as CSV ----
  if (p === '/api/admin/export' && req.method === 'GET') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    // One row PER TEAM (team-wise), with member lists, the guide's details, and the
    // team-formation timestamps in IST (when applied for a faculty, when approved).
    const rows = [['Team ID', 'Status', 'Members', 'Reg numbers', 'Schools',
      'Guide name', 'Guide ID', 'Guide employee ID', 'Guide school',
      'Formed (IST)', 'Applied to faculty (IST)', 'Approved (IST)']];
    const sep = ' | ';
    // arrange by faculty: all of a guide's teams together, accepted ones first;
    // teams with no guide yet fall to the bottom.
    const guideNameOf = (g) => { const em = g.faculty || g.requestedFaculty; if (!em) return '~~~'; const f = db.faculty.find((x) => x.email === em); return (f ? f.name : em).toLowerCase(); };
    const ordered = db.groups.slice().sort((a, b) => {
      const ga = guideNameOf(a), gb = guideNameOf(b);
      if (ga !== gb) return ga < gb ? -1 : 1;
      const sa = a.status === 'accepted' ? 0 : 1, sb = b.status === 'accepted' ? 0 : 1;
      return sa - sb || String(a.id).localeCompare(String(b.id));
    });
    for (const g of ordered) {
      const guideEmail = g.faculty || g.requestedFaculty || null;
      const gi = guideEmail ? db.faculty.findIndex((f) => f.email === guideEmail) : -1;
      const guide = gi >= 0 ? db.faculty[gi] : null;
      const names = [], regs = [], schools = [];
      g.members.forEach((reg) => {
        const s = db.students[reg] || {}; const info = engine.schoolOf(reg.slice(2, 5), MAP);
        names.push(s.name || reg); regs.push(reg); schools.push(engine.schoolKey(info.school));
      });
      rows.push([
        g.id, g.status, names.join(sep), regs.join(sep), schools.join(sep),
        guide ? guide.name : '', gi >= 0 ? gi : '', empIdFor(gi), guide ? (guide.school || '') : '',
        istStamp(g.createdAt), istStamp(g.requestedAt), istStamp(g.approvedAt),
      ]);
    }
    const csv = rows.map((r) => r.map((x) => '"' + String(x).replace(/"/g, '""') + '"').join(',')).join('\r\n');
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="allocations.csv"',
      'Access-Control-Allow-Origin': '*',
    });
    return res.end(csv);
  }

  // ---- ADMIN: teams grouped under their faculty guide + formation progress ----
  if (p === '/api/admin/allocations' && req.method === 'GET') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const teamView = (g) => ({
      id: g.id, status: g.status, ready: groupReady(g), valid: validateGroup(g.members).valid,
      approvedAt: g.approvedAt ? istStamp(g.approvedAt) : null, requestedAt: g.requestedAt ? istStamp(g.requestedAt) : null,
      members: g.members.map((reg) => { const s = db.students[reg] || {}; const info = engine.schoolOf(reg.slice(2, 5), MAP); return { reg, name: s.name || '', school: engine.schoolKey(info.school), scope: info.scope }; }),
    });
    const byFac = {}; const unassigned = [];
    for (const g of db.groups) {
      if (g.status === 'rejected') continue;
      const em = g.faculty || g.requestedFaculty;
      if (em) { const f = db.faculty.find((x) => x.email === em);
        (byFac[em] || (byFac[em] = { email: em, name: f ? f.name : em, school: f ? f.school : '', accepted: 0, teams: [] })); }
      if (em) { byFac[em].teams.push(teamView(g)); if (g.status === 'accepted') byFac[em].accepted++; }
      else unassigned.push(teamView(g));
    }
    const faculties = Object.values(byFac).sort((a, b) => a.name.localeCompare(b.name));
    // progress: a team needs 2 SCOPE + 3 others, so total capacity is bounded by both pools
    const formed = db.groups.filter((g) => g.status !== 'rejected').length;
    const scopeCount = studentArr.filter((s) => s.scope).length;
    const otherCount = studentArr.length - scopeCount;
    const maxTeams = Math.min(Math.floor(scopeCount / 2), Math.floor(otherCount / 3));
    const grouped = groupedRegSet().size;
    return sendJSON(res, 200, {
      faculties, unassigned,
      stats: { formed, maxTeams, remaining: Math.max(0, maxTeams - formed), grouped, ungrouped: studentArr.length - grouped, students: studentArr.length },
    });
  }

  // ---- ADMIN: prepare a proctor's hashkey sheet. Recipient MUST be an institutional
  //      VIT address (no personal ids). Returns the list to hand out; delivery is done
  //      by the admin (or an SMTP integration) — see DEPLOY notes. ----
  if (p === '/api/admin/proctor-hashkeys' && req.method === 'POST') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const { email, branch } = await readBody(req);
    if (!isInstitutionalEmail(email)) return sendJSON(res, 400, { error: 'Enter a VIT institutional email (…@' + PROCTOR_EMAIL_DOMAIN + '). Personal email ids are not allowed.' });
    const arr = branch ? studentArr.filter((e) => engine.schoolKey(e.school) === branch) : studentArr;
    const rows = arr.map((e) => ({ reg: e.reg, name: e.name, hashkey: vault.hashkeyFor(e.reg), registered: e.changed }));
    return sendJSON(res, 200, { ok: true, email: String(email).trim(), branch: branch || 'all', count: rows.length, rows });
  }

  // ---- ADMIN: reset a student's registration. Clears their self-password so they
  //      log in again with their hashkey (from the proctor) and set a new password. ----
  if (p === '/api/admin/reset-password' && req.method === 'POST') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const { reg } = await readBody(req);
    const s = db.students[reg]; if (!s) return sendJSON(res, 404, { error: 'Student not found.' });
    s.passwordHash = null; s.changedPassword = false;         // un-register
    s.passwordResetNotice = true;                             // student is told on next login
    if (s.pwFp) { pwFingerprints.delete(s.pwFp); s.pwFp = null; }
    const e = studentArrByReg.get(reg); if (e) e.changed = false;
    store.saveStudent(s);
    return sendJSON(res, 200, { ok: true, hashkey: vault.hashkeyFor(reg) });
  }

  // ---- PUBLIC: the demo student's reg + hashkey, so the landing page can show a
  //      working first-time-registration example (synthetic data only). ----
  if (p === '/api/registration-demo' && req.method === 'GET') {
    const reg = '24BCE2312'; const s = db.students[reg];
    return sendJSON(res, 200, { reg, hashkey: s ? vault.hashkeyFor(reg) : null, registered: !!(s && s.changedPassword) });
  }

  // ---- ADMIN: reset ALL allocations — wipe every team so a fresh round can start.
  //      Guarded: the caller must type the exact word RESETALL. ----
  if (p === '/api/admin/reset-all' && req.method === 'POST') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const { confirm } = await readBody(req);
    if (String(confirm) !== 'RESETALL') return sendJSON(res, 400, { error: 'Type RESETALL exactly to confirm.' });
    const cleared = db.groups.length;
    db.groups = [];
    store.deleteAllGroups();
    return sendJSON(res, 200, { ok: true, cleared });
  }

  // ---- STUDENT: contact admin / raise a support query ----
  if (p === '/api/student/query' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const { topic, message } = await readBody(req);
    const t = String(topic || '').trim(), m = String(message || '').trim();
    if (!t && !m) return sendJSON(res, 400, { error: 'Please describe the problem.' });
    const q = { id: 'Q' + String(db.queries.length + 1).padStart(4, '0'), reg: sess.reg, name: sess.name, topic: t, message: m, status: 'open', createdAt: Date.now() };
    db.queries.push(q); store.saveQuery(q);
    return sendJSON(res, 200, { ok: true, id: q.id });
  }

  // ---- PUBLIC: forgot password -> files a reset request for the admin.
  //      Always returns ok so it can't be used to probe which regs exist. ----
  if (p === '/api/request-reset' && req.method === 'POST') {
    const { reg } = await readBody(req);
    const key = String(reg || '').trim().toUpperCase().replace(/\s+/g, '');
    const st = db.students[key];
    if (st && !db.queries.some((q) => q.reg === key && q.topic === 'Password reset request' && q.status === 'open')) {
      const q = { id: 'Q' + String(db.queries.length + 1).padStart(4, '0'), reg: key, name: st.name, topic: 'Password reset request', message: 'Student used "Forgot password" and needs a reset.', status: 'open', createdAt: Date.now() };
      db.queries.push(q); store.saveQuery(q);
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
    q.status = q.status === 'open' ? 'resolved' : 'open'; store.saveQueryStatus(q.id, q.status);
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
    return sendJSON(res, 200, { reg: sess.reg, name: sess.name, scope: !!(db.students[sess.reg] || {}).scope, groups });
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

    if (mine) { db.groups = db.groups.filter((x) => x !== mine); store.deleteGroup(mine.id); }   // replace the old pending group
    // leader (submitter, a SCOPE student) auto-accepts; every teammate must consent
    const consent = {};
    regs.forEach((r) => { consent[r] = r === sess.reg ? 'accepted' : 'pending'; });
    const g = { id: nextGroupId(), members: regs, status: 'pending', faculty: null, requestedFaculty: null, submittedBy: sess.reg, consent, createdAt: Date.now() };
    db.groups.push(g); store.saveGroup(g);
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
    if (decision === 'accept') {
      g.consent[sess.reg] = 'accepted';
      store.saveGroup(g);
      return sendJSON(res, 200, { ok: true, consent: 'accepted', ready: groupReady(g) });
    }
    // decline: leave the team entirely, which frees you and reopens the slot for the leader
    g.members = g.members.filter((r) => r !== sess.reg);
    delete g.consent[sess.reg];
    clearStaleRequest(g);                              // an incomplete team releases its faculty hold
    store.saveGroup(g);
    return sendJSON(res, 200, { ok: true, left: true });
  }

  // ---- roster (masked, no emails) so the student form can pick real regs ----
  if (p === '/api/roster' && req.method === 'GET') {
    const list = Object.values(db.students).map((s) => ({ reg: s.reg, name: s.name, school: s.school, scope: s.scope }));
    return sendJSON(res, 200, { students: list });
  }

  // ---- ADMIN: upload the student roster (.xlsx or .csv). Replaces the roster and
  //      updates every index live. Columns: reg, name, email (school/type optional). ----
  if (p === '/api/admin/upload-students' && req.method === 'POST') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const body = await readJSONLarge(req);
    if (!body || !body.dataBase64) return sendJSON(res, 400, { error: 'No file received (or it was too large).' });
    let parsed;
    try { parsed = xlsx.parse(Buffer.from(body.dataBase64, 'base64'), body.filename || ''); }
    catch (e) { return sendJSON(res, 400, { error: 'Could not read that file: ' + (e && e.message || 'unknown format') + '. Upload a .xlsx or .csv.' }); }
    if (!parsed.rows.length) return sendJSON(res, 400, { error: 'That file had no data rows.' });
    if (!parsed.headers.includes('reg') && !parsed.headers.some((h) => /^reg/.test(h) || h.includes('registration'))) {
      return sendJSON(res, 400, { error: 'Missing a "reg" column. Expected headers include: reg, name, email.', headers: parsed.headers });
    }
    const r = ingestStudents(parsed.rows);
    if (!r.total) return sendJSON(res, 400, { error: 'No valid students found (each row needs a reg and a name).' });
    applyStudents(r.students);
    return sendJSON(res, 200, { ok: true, total: r.total, brandNew: r.brandNew, preserved: r.preserved, skipped: r.skipped });
  }

  // ---- ADMIN: upload the faculty list (.xlsx or .csv). Replaces the faculty and
  //      updates live. Columns: email, name, school, cabin, max_groups. ----
  if (p === '/api/admin/upload-faculty' && req.method === 'POST') {
    if (!adminAuth(req)) return sendJSON(res, 401, { error: 'Sign in as admin first.' });
    const body = await readJSONLarge(req);
    if (!body || !body.dataBase64) return sendJSON(res, 400, { error: 'No file received (or it was too large).' });
    let parsed;
    try { parsed = xlsx.parse(Buffer.from(body.dataBase64, 'base64'), body.filename || ''); }
    catch (e) { return sendJSON(res, 400, { error: 'Could not read that file: ' + (e && e.message || 'unknown format') + '. Upload a .xlsx or .csv.' }); }
    if (!parsed.rows.length) return sendJSON(res, 400, { error: 'That file had no data rows.' });
    if (!parsed.headers.includes('email') && !parsed.headers.some((h) => h.includes('email') || h.includes('mail'))) {
      return sendJSON(res, 400, { error: 'Missing an "email" column. Expected headers include: email, name, school, cabin, max_groups.', headers: parsed.headers });
    }
    const r = await ingestFaculty(parsed.rows);
    if (!r.total) return sendJSON(res, 400, { error: 'No valid faculty found (each row needs an email and a name).' });
    applyFaculty(r.faculty);
    return sendJSON(res, 200, { ok: true, total: r.total, skipped: r.skipped });
  }

  // ---- STUDENT: chat with your guide (the faculty your team is with / applied to) ----
  if (p === '/api/student/chat' && req.method === 'GET') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const guide = guideFacultyOf(sess.reg);
    if (!guide) return sendJSON(res, 200, { hasGuide: false });
    store.markThreadRead(threadKey(sess.reg, guide.faculty.email), 'student');
    db.messages.forEach((m) => { if (m.thread === threadKey(sess.reg, guide.faculty.email)) m.readByStudent = true; });
    return sendJSON(res, 200, {
      hasGuide: true, status: guide.status,
      faculty: { name: guide.faculty.name, school: guide.faculty.school || '', cabin: guide.faculty.cabin || null },
      messages: threadMessages(sess.reg, guide.faculty.email),
    });
  }
  if (p === '/api/student/chat/send' && req.method === 'POST') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as a student first.' });
    const guide = guideFacultyOf(sess.reg);
    if (!guide) return sendJSON(res, 409, { error: 'Pick a faculty for your team first — then you can message them.' });
    const { body } = await readBody(req);
    const text = String(body || '').trim();
    if (!text) return sendJSON(res, 400, { error: 'Type a message first.' });
    addMessage(sess.reg, guide.faculty.email, 'student', text);
    return sendJSON(res, 200, { ok: true, messages: threadMessages(sess.reg, guide.faculty.email) });
  }
  // student's unread count (for the nav badge)
  if (p === '/api/student/chat/unread' && req.method === 'GET') {
    const sess = studentAuth(req); if (!sess) return sendJSON(res, 200, { unread: 0 });
    const guide = guideFacultyOf(sess.reg);
    if (!guide) return sendJSON(res, 200, { unread: 0 });
    const key = threadKey(sess.reg, guide.faculty.email);
    const unread = db.messages.filter((m) => m.thread === key && m.fromRole === 'faculty' && !m.readByStudent).length;
    return sendJSON(res, 200, { unread });
  }

  // ---- FACULTY: chat threads with students on teams that chose them ----
  if (p === '/api/faculty/threads' && req.method === 'GET') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const threads = facultyThreads(sess.email);
    return sendJSON(res, 200, { threads, unread: threads.reduce((n, t) => n + t.unread, 0) });
  }
  if (p === '/api/faculty/chat' && req.method === 'GET') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const reg = String(url.searchParams.get('reg') || '').toUpperCase().replace(/\s+/g, '');
    const st = db.students[reg]; if (!st) return sendJSON(res, 404, { error: 'Student not found.' });
    store.markThreadRead(threadKey(reg, sess.email), 'faculty');
    db.messages.forEach((m) => { if (m.thread === threadKey(reg, sess.email)) m.readByFaculty = true; });
    return sendJSON(res, 200, { reg, name: st.name, messages: threadMessages(reg, sess.email) });
  }
  if (p === '/api/faculty/chat/send' && req.method === 'POST') {
    const sess = facultyAuth(req); if (!sess) return sendJSON(res, 401, { error: 'Sign in as faculty first.' });
    const { reg, body } = await readBody(req);
    const target = String(reg || '').toUpperCase().replace(/\s+/g, '');
    const st = db.students[target]; if (!st) return sendJSON(res, 404, { error: 'Student not found.' });
    // only students who selected / were accepted by this faculty, or already in a thread
    const canChat = db.groups.some((g) => g.status !== 'rejected' && g.members.includes(target) && (g.faculty === sess.email || g.requestedFaculty === sess.email))
      || db.messages.some((m) => m.facEmail === sess.email && m.reg === target);
    if (!canChat) return sendJSON(res, 403, { error: 'You can only message students whose team chose you.' });
    const text = String(body || '').trim();
    if (!text) return sendJSON(res, 400, { error: 'Type a message first.' });
    addMessage(target, sess.email, 'faculty', text);
    return sendJSON(res, 200, { ok: true, messages: threadMessages(target, sess.email) });
  }

  if (p.startsWith('/api/')) return sendJSON(res, 404, { error: 'Unknown endpoint.' });
  return serveStatic(res, p);
}

// Every request is wrapped: an error in any endpoint returns 500 and the
// process stays alive. One bad request can never crash the server.
const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.error('request error on', req.url, '-', e && e.message);
    if (!res.headersSent) { try { sendJSON(res, 500, { error: 'Something went wrong. Please try again.' }); } catch (_) { try { res.end(); } catch (_) {} } }
  });
});

// Last-resort safety nets so an unexpected error never takes the process down.
process.on('uncaughtException', (e) => console.error('uncaughtException:', e && e.stack || e));
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e && e.stack || e));
process.on('SIGTERM', () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 5000); });

// ---- pending faculty requests expire at IST midnight ----
// A team that selected a faculty but wasn't accepted by midnight (India time) releases
// that hold, so slots don't stay locked overnight. The team can re-request next day.
const IST_OFFSET_MS = 5.5 * 3600 * 1000;
function msUntilNextISTMidnight() {
  const dayMs = 24 * 3600 * 1000;
  const istNow = Date.now() + IST_OFFSET_MS;              // IST wall-clock as ms
  return Math.ceil(istNow / dayMs) * dayMs - istNow;      // to the next IST midnight
}
function sweepExpiredRequests() {
  let n = 0;
  for (const g of db.groups) {
    if (g.status === 'pending' && g.requestedFaculty) { g.requestedFaculty = null; store.saveGroup(g); n++; }
  }
  if (n) console.log('[midnight sweep] released ' + n + ' pending faculty request(s)');
  scheduleMidnightSweep();
}
function scheduleMidnightSweep() { setTimeout(sweepExpiredRequests, msUntilNextISTMidnight() + 1000).unref(); }

// Boot: open the store (async — Postgres connect or SQLite open), load the working
// set into memory, build every index, then start serving. `await` works whether the
// store returns a promise (Postgres) or a value (SQLite), so one path fits both.
async function boot() {
  await store.init(initialData);
  db = await store.loadAll();
  if (!Array.isArray(db.messages)) db.messages = [];
  msgSeq = db.messages.length;
  lockKey();
  reindex();
  buildStudentArr();
  rebuildPwFingerprints();   // seed the "unique password" index from any already-registered students
  computeSchoolLists();
  scheduleMidnightSweep();
  server.listen(PORT, () => {
    console.log('Portal backend [' + (store.driver || 'sqlite') + '] on http://localhost:' + PORT + ' (pid ' + process.pid + ')');
  });
}
boot().catch((e) => { console.error('startup failed:', (e && e.stack) || e); process.exit(1); });
