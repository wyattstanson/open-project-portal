/*
 * ============================================================================
 *  ALLOCATION ENGINE  (pure logic, no UI, no server)
 * ============================================================================
 *  This is "the engine". It knows nothing about HTML, buttons, or HTTP.
 *  It takes plain data in and gives plain data out. The exact same file runs:
 *    - in the browser  (the deployed static page imports these ideas), and
 *    - in Node          (server.js below calls these functions).
 *
 *  Why it is efficient, in one line: every stage is O(n), driven by hash
 *  maps and hash sets, so 10,000 students is one quick linear pass, not a
 *  slow pairwise scan.
 *
 *  Stage           Data structure          Cost        What it buys
 *  --------------  ----------------------  ----------  -------------------------
 *  parse           string slicing          O(1)/row    decode reg -> school
 *  dedup           Set (hash set)          O(n)        "seen this reg?" in O(1)
 *  bucket          Map (hash map)          O(n)        group by school in O(1)
 *  form teams      greedy over buckets     O(n)        2 SCOPE + 3 distinct
 *  seat faculty    Map of counters         O(1)/team   FFCS first-come seating
 * ============================================================================
 */

'use strict';

// Only BCE is certain. The rest are editable defaults. [label, isScope]
const DEFAULT_MAP = {
  BCE: ['SCOPE: Computer Science and Engineering', true],
  BAI: ['SCOPE: CSE, AI and Machine Learning', true],
  BCI: ['SCOPE: CSE, AI and Robotics', true],
  BPS: ['SCOPE: CSE specialization', true],
  BDS: ['SCOPE: CSE, Data Science', true],
  BKT: ['SCOPE: CSE specialization', true],
  BEC: ['SENSE: Electronics and Communication', false],
  BEE: ['SELECT: Electrical and Electronics', false],
  BME: ['SMEC: Mechanical Engineering', false],
  BMD: ['SMEC: Mechatronics', false],
  BCH: ['SCHEME: Chemical Engineering', false],
  BCV: ['SCE: Civil Engineering', false],
  BBT: ['SBST: Biotechnology', false],
};

const TEAM_SIZE = 5, SCOPE_NEEDED = 2, OTHER_NEEDED = 3;

// Decode one registration number. O(1). Returns null if malformed.
function parseReg(raw) {
  const reg = String(raw).trim().toUpperCase().replace(/\s+/g, '');
  if (reg.length !== 9) return null;
  const y = reg.slice(0, 2), c = reg.slice(2, 5), r = reg.slice(5);
  if (!/^\d{2}$/.test(y) || !/^[A-Z]{3}$/.test(c) || !/^\d{4}$/.test(r)) return null;
  return { reg, code: c };
}

function schoolOf(code, map) {
  const e = map[code];
  if (!e) return { known: false, scope: false, school: 'Unknown code' };
  return { known: true, scope: !!e[1], school: e[0] };
}

/*
 * buildRoster: clean the raw input and DROP duplicates.
 * The hash Set `seen` answers "already have this reg?" in O(1), so the whole
 * clean-up is a single O(n) pass instead of comparing every pair (O(n^2)).
 * Also returns an index Map (reg -> student) so later lookups are O(1).
 */
function buildRoster(rows, map) {
  const seen = new Set();
  const index = new Map();
  const roster = [];
  const duplicates = [], invalid = [], unknown = new Set();

  for (let i = 0; i < rows.length; i++) {
    const line = String(rows[i]).trim();
    if (!line) continue;
    const parts = line.split(/[,;\t]/);
    const p = parseReg(parts[0]);
    if (!p) { invalid.push(line); continue; }
    if (seen.has(p.reg)) { duplicates.push(p.reg); continue; }  // O(1) dup check
    seen.add(p.reg);
    const student = { reg: p.reg, code: p.code, name: parts.slice(1).join(',').trim() };
    roster.push(student);
    index.set(p.reg, student);                                  // O(1) index insert
    if (!map[p.code]) unknown.add(p.code);
  }
  return { roster, index, duplicates, invalid, unknown: [...unknown] };
}

/*
 * formTeams: greedy build of 2 SCOPE + 3 other-school members.
 * One O(n) pass buckets everyone by school. Then each team draws 2 from the
 * SCOPE pile and 3 from the currently-largest distinct other-school buckets.
 * Draining the biggest buckets keeps them balanced => most complete teams.
 * The bucket sort each round is over ~15 schools, i.e. constant, so O(n) total.
 */
function formTeams(roster, map, opts) {
  const distinct = !opts || opts.distinct !== false;
  const scope = [];
  const buckets = new Map();                 // school -> array of students
  for (let i = 0; i < roster.length; i++) {
    const info = schoolOf(roster[i].code, map);
    if (info.scope) scope.push(roster[i]);
    else if (info.known) {
      if (!buckets.has(info.school)) buckets.set(info.school, []);
      buckets.get(info.school).push(roster[i]);
    }
  }

  const teams = [];
  let n = 1, sp = 0;
  while (scope.length - sp >= SCOPE_NEEDED) {
    const live = [...buckets.keys()].filter((s) => buckets.get(s).length);
    if (distinct) {
      if (live.length < OTHER_NEEDED) break;
      live.sort((a, b) => buckets.get(b).length - buckets.get(a).length);
    } else {
      let total = 0; for (const s of live) total += buckets.get(s).length;
      if (total < OTHER_NEEDED) break;
      live.sort((a, b) => buckets.get(b).length - buckets.get(a).length);
    }
    const m = [scope[sp++], scope[sp++]];
    if (distinct) {
      for (let t = 0; t < OTHER_NEEDED; t++) m.push(buckets.get(live[t]).shift());
    } else {
      let need = OTHER_NEEDED, idx = 0;
      while (need > 0 && idx < live.length) {
        const b = buckets.get(live[idx]);
        if (b.length) { m.push(b.shift()); need--; } else idx++;
      }
    }
    teams.push({ id: 'T' + String(n++).padStart(4, '0'), members: m.map((x) => x.reg), faculty: null });
  }

  const leftover = scope.slice(sp).map((x) => x.reg);
  for (const arr of buckets.values()) for (const x of arr) leftover.push(x.reg);
  return { teams, leftover };
}

/*
 * allocateFaculty: FFCS-style seating. A Map of seat counters lets us check
 * and book a seat in O(1). Each team takes the faculty with the most seats
 * left (keeps mentors balanced); once a faculty hits 0 it is skipped. Teams
 * that arrive after all seats are gone are waitlisted, exactly like FFCS.
 */
function allocateFaculty(teams, faculty) {
  const seatsLeft = new Map();
  for (const f of faculty) seatsLeft.set(f.name, Math.max(0, parseInt(f.seats, 10) || 0));
  let seated = 0;
  for (const t of teams) {
    let best = null, bestLeft = 0;
    for (const f of faculty) {
      const l = seatsLeft.get(f.name);
      if (l > bestLeft) { bestLeft = l; best = f.name; }
    }
    if (best) { seatsLeft.set(best, seatsLeft.get(best) - 1); t.faculty = best; seated++; }
    else t.faculty = null;
  }
  return { seatsLeft, seated, waitlisted: teams.length - seated };
}

/*
 * allocate: the whole pipeline in one call, with timings. This is what a
 * backend endpoint invokes. Pure function: same input -> same output.
 */
function allocate(rows, options) {
  const opts = options || {};
  const map = opts.map || DEFAULT_MAP;
  const faculty = opts.faculty || [];
  const t0 = now();
  const built = buildRoster(rows, map);
  const t1 = now();
  const formed = formTeams(built.roster, map, { distinct: opts.distinct !== false });
  const t2 = now();
  const alloc = allocateFaculty(formed.teams, faculty);
  const t3 = now();

  let scopeCount = 0;
  for (const s of built.roster) if (schoolOf(s.code, map).scope) scopeCount++;

  return {
    stats: {
      inputRows: rows.length,
      uniqueStudents: built.roster.length,
      scopeStudents: scopeCount,
      duplicatesDropped: built.duplicates.length,
      invalidRows: built.invalid.length,
      unknownCodes: built.unknown,
      teams: formed.teams.length,
      studentsPlaced: formed.teams.length * TEAM_SIZE,
      unplaced: built.roster.length - formed.teams.length * TEAM_SIZE,
      seated: alloc.seated,
      waitlisted: alloc.waitlisted,
    },
    timingsMs: {
      dedup: +(t1 - t0).toFixed(2),
      formTeams: +(t2 - t1).toFixed(2),
      seatFaculty: +(t3 - t2).toFixed(2),
      total: +(t3 - t0).toFixed(2),
    },
    teams: formed.teams,
    duplicates: built.duplicates,
    leftover: formed.leftover,
  };
}

// high-resolution clock that works in Node and the browser
function now() {
  if (typeof performance !== 'undefined' && performance.now) return performance.now();
  const h = process.hrtime(); return h[0] * 1000 + h[1] / 1e6;
}

// Make a synthetic batch for benchmarking. scopeFrac ~ share of SCOPE students.
function synth(count, scopeFrac) {
  scopeFrac = scopeFrac == null ? 0.42 : scopeFrac;
  const codes = Object.keys(DEFAULT_MAP);
  const sc = codes.filter((c) => DEFAULT_MAP[c][1]);
  const ot = codes.filter((c) => !DEFAULT_MAP[c][1]);
  const out = [], used = new Set();
  while (out.length < count) {
    const c = Math.random() < scopeFrac ? sc[(Math.random() * sc.length) | 0] : ot[(Math.random() * ot.length) | 0];
    const reg = '24' + c + (1000 + ((Math.random() * 9000) | 0));
    if (used.has(reg)) continue;
    used.add(reg);
    out.push(reg + ', Student ' + out.length);
  }
  return out;
}

// export for Node; attach to window for the browser
const API = { DEFAULT_MAP, parseReg, schoolOf, buildRoster, formTeams, allocateFaculty, allocate, synth };
if (typeof module !== 'undefined' && module.exports) module.exports = API;
if (typeof window !== 'undefined') window.AllocationEngine = API;
