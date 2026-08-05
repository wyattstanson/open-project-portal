/*
 * ============================================================================
 *  STORE (Postgres)  -  durable, server-backed alternative to node:sqlite
 * ============================================================================
 *  Same interface as store.js (the SQLite store), selected automatically when
 *  DATABASE_URL is set. The server keeps the working set in memory for O(1)
 *  reads and writes THROUGH to Postgres per change, exactly like the SQLite path.
 *
 *  init() and loadAll() are async (a real DB connection); the per-change writes
 *  are enqueued on a serialized chain so they persist in order without the
 *  request handler having to await them (the in-memory copy is already updated).
 *
 *  NOTE on horizontal scale: Postgres makes the data durable and shareable, but
 *  running MORE THAN ONE portal instance against it is still not safe with the
 *  current in-memory cache — each instance would serve its own stale copy. True
 *  multi-instance needs the cache dropped or invalidated across instances. Until
 *  then, run ONE instance (behind nginx) with Postgres for durability.
 * ============================================================================
 */
'use strict';
const { Pool, types } = require('pg');
// epoch-ms timestamps are stored as BIGINT; parse them back to Number (safe < 2^53)
types.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));

let pool;
let writeChain = Promise.resolve();
// serialize writes in order; log (don't crash) on failure — the in-memory copy is authoritative
function enqueue(fn) {
  writeChain = writeChain.then(fn).catch((e) => console.error('[pg write]', e && e.message));
  return writeChain;
}

async function init(seeder) {
  pool = new Pool({ connectionString: process.env.DATABASE_URL, max: Number(process.env.PG_POOL || 10) });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS students(
      reg TEXT PRIMARY KEY, name TEXT, school TEXT, scope INTEGER, email TEXT,
      "emailHash" TEXT, "passwordHash" TEXT, "changedPassword" INTEGER, "passwordResetNotice" INTEGER, "pwFp" TEXT);
    CREATE INDEX IF NOT EXISTS idx_students_emailhash ON students("emailHash");
    CREATE TABLE IF NOT EXISTS faculty(
      email TEXT PRIMARY KEY, name TEXT, school TEXT, capacity INTEGER, "passHash" TEXT, fidx INTEGER);
    CREATE TABLE IF NOT EXISTS admin(username TEXT PRIMARY KEY, "passHash" TEXT);
    CREATE TABLE IF NOT EXISTS teams(
      id TEXT PRIMARY KEY, status TEXT, faculty TEXT, "requestedFaculty" TEXT, "submittedBy" TEXT,
      "createdAt" BIGINT, "requestedAt" BIGINT, "approvedAt" BIGINT);
    CREATE TABLE IF NOT EXISTS team_members(
      "groupId" TEXT, reg TEXT, ord INTEGER, consent TEXT, PRIMARY KEY("groupId", reg));
    CREATE INDEX IF NOT EXISTS idx_tm_reg ON team_members(reg);
    CREATE TABLE IF NOT EXISTS queries(
      id TEXT PRIMARY KEY, reg TEXT, name TEXT, topic TEXT, message TEXT, status TEXT, "createdAt" BIGINT);
  `);
  const n = (await pool.query('SELECT COUNT(*)::int AS c FROM students')).rows[0].c;
  if (n === 0 && seeder) await importAll(seeder());
}

// batched multi-row insert helper
async function bulkInsert(client, table, cols, rows, conflictKey) {
  if (!rows.length) return;
  const quoted = cols.map((c) => '"' + c + '"').join(',');
  const CHUNK = 500;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const slice = rows.slice(i, i + CHUNK);
    const params = []; const tuples = [];
    slice.forEach((r, ri) => {
      const ph = cols.map((_, ci) => '$' + (ri * cols.length + ci + 1));
      tuples.push('(' + ph.join(',') + ')'); params.push(...r);
    });
    await client.query('INSERT INTO ' + table + '(' + quoted + ') VALUES ' + tuples.join(',') +
      ' ON CONFLICT(' + conflictKey + ') DO NOTHING', params);
  }
}

async function importAll(data) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const stu = Object.keys(data.students || {}).map((reg) => {
      const s = data.students[reg];
      return [reg, s.name, s.school, s.scope ? 1 : 0, s.email || null, s.emailHash || null,
        s.passwordHash || null, s.changedPassword ? 1 : 0, s.passwordResetNotice ? 1 : 0, s.pwFp || null];
    });
    await bulkInsert(client, 'students',
      ['reg', 'name', 'school', 'scope', 'email', 'emailHash', 'passwordHash', 'changedPassword', 'passwordResetNotice', 'pwFp'], stu, 'reg');
    const fac = (data.faculty || []).map((f, i) => [f.email, f.name, f.school || null, f.capacity, f.passHash, i]);
    await bulkInsert(client, 'faculty', ['email', 'name', 'school', 'capacity', 'passHash', 'fidx'], fac, 'email');
    if (data.admin) await client.query('INSERT INTO admin(username,"passHash") VALUES($1,$2) ON CONFLICT(username) DO NOTHING', [data.admin.username, data.admin.passHash]);
    const teams = [], mems = [];
    (data.groups || []).forEach((g) => {
      teams.push([g.id, g.status, g.faculty || null, g.requestedFaculty || null, g.submittedBy || null, g.createdAt || Date.now(), g.requestedAt || null, g.approvedAt || null]);
      g.members.forEach((reg, ord) => mems.push([g.id, reg, ord, (g.consent && g.consent[reg]) || 'accepted']));
    });
    await bulkInsert(client, 'teams', ['id', 'status', 'faculty', 'requestedFaculty', 'submittedBy', 'createdAt', 'requestedAt', 'approvedAt'], teams, 'id');
    await bulkInsert(client, 'team_members', ['groupId', 'reg', 'ord', 'consent'], mems, '"groupId", reg');
    const qs = (data.queries || []).map((q) => [q.id, q.reg, q.name, q.topic, q.message, q.status, q.createdAt]);
    await bulkInsert(client, 'queries', ['id', 'reg', 'name', 'topic', 'message', 'status', 'createdAt'], qs, 'id');
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}

async function loadAll() {
  const students = {};
  for (const r of (await pool.query('SELECT * FROM students')).rows) {
    students[r.reg] = { reg: r.reg, name: r.name, school: r.school, scope: !!r.scope, email: r.email,
      emailHash: r.emailHash, passwordHash: r.passwordHash, changedPassword: !!r.changedPassword, passwordResetNotice: !!r.passwordResetNotice, pwFp: r.pwFp || null };
  }
  const faculty = (await pool.query('SELECT * FROM faculty ORDER BY fidx')).rows
    .map((r) => ({ email: r.email, name: r.name, school: r.school, capacity: r.capacity, passHash: r.passHash }));
  const adminRow = (await pool.query('SELECT * FROM admin LIMIT 1')).rows[0];
  const admin = adminRow ? { username: adminRow.username, passHash: adminRow.passHash } : null;
  const memByGroup = {};
  for (const m of (await pool.query('SELECT * FROM team_members ORDER BY "groupId", ord')).rows) {
    (memByGroup[m.groupId] || (memByGroup[m.groupId] = [])).push(m);
  }
  const groups = (await pool.query('SELECT * FROM teams')).rows.map((r) => {
    const ms = memByGroup[r.id] || []; const consent = {}; ms.forEach((m) => { consent[m.reg] = m.consent; });
    return { id: r.id, status: r.status, faculty: r.faculty, requestedFaculty: r.requestedFaculty,
      submittedBy: r.submittedBy, createdAt: r.createdAt, requestedAt: r.requestedAt, approvedAt: r.approvedAt, members: ms.map((m) => m.reg), consent };
  });
  const queries = (await pool.query('SELECT * FROM queries')).rows
    .map((r) => ({ id: r.id, reg: r.reg, name: r.name, topic: r.topic, message: r.message, status: r.status, createdAt: r.createdAt }));
  return { students, faculty, admin, groups, queries };
}

// ---- targeted, durable writes (enqueued; called alongside the in-memory mutation) ----
function saveStudent(s) {
  return enqueue(() => pool.query(
    'UPDATE students SET "passwordHash"=$1,"changedPassword"=$2,"passwordResetNotice"=$3,"pwFp"=$4 WHERE reg=$5',
    [s.passwordHash, s.changedPassword ? 1 : 0, s.passwordResetNotice ? 1 : 0, s.pwFp || null, s.reg]));
}
function saveGroup(g) {
  return enqueue(async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'INSERT INTO teams(id,status,faculty,"requestedFaculty","submittedBy","createdAt","requestedAt","approvedAt") VALUES($1,$2,$3,$4,$5,$6,$7,$8)' +
        ' ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,faculty=EXCLUDED.faculty,"requestedFaculty"=EXCLUDED."requestedFaculty",' +
        '"submittedBy"=EXCLUDED."submittedBy","createdAt"=EXCLUDED."createdAt","requestedAt"=EXCLUDED."requestedAt","approvedAt"=EXCLUDED."approvedAt"',
        [g.id, g.status, g.faculty || null, g.requestedFaculty || null, g.submittedBy || null, g.createdAt, g.requestedAt || null, g.approvedAt || null]);
      await client.query('DELETE FROM team_members WHERE "groupId"=$1', [g.id]);
      for (let ord = 0; ord < g.members.length; ord++) {
        const reg = g.members[ord];
        await client.query('INSERT INTO team_members("groupId",reg,ord,consent) VALUES($1,$2,$3,$4)',
          [g.id, reg, ord, (g.consent && g.consent[reg]) || 'accepted']);
      }
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  });
}
function deleteGroup(id) {
  return enqueue(async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM team_members WHERE "groupId"=$1', [id]);
      await client.query('DELETE FROM teams WHERE id=$1', [id]);
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  });
}
function saveQuery(q) {
  return enqueue(() => pool.query(
    'INSERT INTO queries(id,reg,name,topic,message,status,"createdAt") VALUES($1,$2,$3,$4,$5,$6,$7)' +
    ' ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status',
    [q.id, q.reg, q.name, q.topic, q.message, q.status, q.createdAt]));
}
function saveQueryStatus(id, status) { return enqueue(() => pool.query('UPDATE queries SET status=$1 WHERE id=$2', [status, id])); }
function saveFacultyCapacity(email, capacity) { return enqueue(() => pool.query('UPDATE faculty SET capacity=$1 WHERE email=$2', [capacity, email])); }
function deleteAllGroups() {
  return enqueue(async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM team_members');
      await client.query('DELETE FROM teams');
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  });
}

module.exports = { driver: 'postgres', init, loadAll, saveStudent, saveGroup, deleteGroup, saveQuery, saveQueryStatus, saveFacultyCapacity, deleteAllGroups };
