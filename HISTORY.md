# Project History — VIT Open-Project Team Allocation

A consolidated history of the VIT fresher open-project team-allocation system, from the
first Python prototype through the deployed portal. Assembled from the git commit timeline
and the original build session ("VIT fresher project team allocation", 2026-07-22 → 2026-08-04).

## The problem

Allocate ~10,000 first-year VIT students into open-project **teams of 5**, under two rules:

- Every team has **2 SCOPE students + 3 students from different schools** (key distinctness
  is by *school*, not program).
- Registration numbers encode the school: e.g. `24BCE2312` = year + branch code + roll;
  the branch code maps to a school.

Each team also picks a **faculty guide**, and every faculty member can accept at most
**3 groups** (capacity/slots).

---

## Phase 0 — Python prototype (2026-07-23, pre-git)

`vit_team_system.py` (18 KB) — the original standalone allocator: the "4 pieces" system that
parsed registration numbers → schools, ran greedy team formation (2 SCOPE + 3 cross-school),
and verified with a duplicate check that **no student landed in two teams**. This proved the
allocation logic before any web portal existed.

---

## Phase 1 — The portal (2026-07-24 → 2026-08-01, committed)

Migrated from a one-off script to a live multi-role web portal. Stack: **plain Node**
(built-in `http`, zero npm deps) + a single static `index.html` GUI — deliberately not
React/Express. Emails are **AES-256-GCM encrypted at rest**; passwords are **scrypt-hashed**
(one-way). O(1) hash-map indexes; O(n) greedy team formation.

Chronological feature timeline (one entry per commit):

| Date | Milestone |
|------|-----------|
| 07-24 | Portal foundation: encrypted email vault, per-student login, faculty accept/reject, Render deploy blueprint |
| 07-25 | Real data: **10k students + 160 faculty** DB; hashed-password login; change-password; non-blocking persistence; UI redesign |
| 07-27 | **Admin portal** (all accounts, password reset); faculty student directory; student faculty+slots view; searchable paginated tables with stale-response guard; vault key baked in for Render |
| 07-27 | **Self-healing vault key selection** — picks whichever key decrypts the DB, so a wrong `VAULT_KEY` env can't break login |
| 07-27 | Student directory (names + search, no emails); jug-filling school guide; key distinctness by **SCHOOL** not program; teal UI, responsive tables/topbar |
| 07-27 | Clear iconed sign-out button on every portal |
| 07-27 | Students **select a faculty** for their group (slots-aware, faculty sees requests); admin **CSV export** of allocations; password show/hide toggle; custom selects, toasts, transitions |
| 07-27 | **One-student-one-group** enforcement (submit blocks clashes, replaces own; directory flags grouped students); breezy light-first sky-palette redesign |
| 07-28 | Login by **registration number** (emails staff-only); contact-admin queries + admin Queries tab; professional navy 3D look |
| 07-28 | Sort students by branch; **group-membership consent** (accept/decline) with SCOPE team leader (crown); faculty selection routed by branch, slots reduce live; admin password reset notifies student on next login |
| 07-29 | **Scale + UX:** async password hashing (no login-storm stall), wider thread pool, atomic coalesced writes; persistent sessions (no logout on refresh); Enter-to-submit; theme icon; forgot-password to admin; confirm-button faculty selection; browser-back routing; Docker Compose + VIT-server/Postgres deploy guide |
| 07-29 | **Migrate storage to SQLite** (`node:sqlite`, zero-dep): ACID transactions, durable per-write persistence, indexes; imports `db.json` on first boot; writes survive restarts. Runtime bumped to **Node 22.5+** (Docker/Render/Procfile) |
| 07-29 | Set `NODE_OPTIONS=--experimental-sqlite` so `node:sqlite` loads regardless of start command (robust Render deploy) |
| 08-01 | **Azure/Fluent UI redesign:** Segoe UI, muted Azure blue on neutral grays, flat 2px surfaces, proper Azure dark mode; left-nav app-shell dashboards (student/faculty/admin); redesigned landing hero |

### Three portals (roles)

- **Student** — submit/track own group, see faculty + slots, change password. Own email
  visible; teammates' masked.
- **Faculty** — review groups, accept up to 3, searchable student directory.
- **Admin** — all students + faculty, initial passwords, reset student password. Because
  passwords are hashed, admin sees only the *initial* password (name, lowercase, no spaces)
  or "changed", plus a reset action — never the current password.

---

## Phase 2 — Scale & crash-hardening (2026-08-04 → 08-05)

Follow-up work on surviving a real 5,000-student event without going down.

**Diagnosis.** The "crash" seen earlier was **Render's free tier** (~0.1 CPU) starving under
concurrent scrypt hashing — a hardware limit, not a code defect. Two honest weaknesses for a
high-stakes event remained: the server was a **single process** (a crash = full outage) and
`node:sqlite` is an **experimental** module.

**What multi-core clustering would and wouldn't buy.** The one CPU-heavy operation — scrypt
password hashing — is *already* parallel across all cores: `portal-server.js` sets
`UV_THREADPOOL_SIZE=64` and hashes via async `crypto.scrypt` on that libuv pool. The main
event loop only does in-memory reads and fast, serialized SQLite writes (and serialized is
what you *want* for the faculty-slot-cap invariant). So a single process already uses the
whole machine for the expensive part. Meanwhile the server holds the entire DB **in memory**
(`store.loadAll`), so naive multi-worker clustering would give each worker its own stale copy
and **break** the core invariants (one-student-one-group, slot caps, consent). True
horizontal multi-*instance* therefore needs **Postgres** as a shared source of truth with the
in-memory cache dropped/invalidated — `store.js` is kept as a clean, swappable interface for
exactly that. *(Deferred: no Postgres available to build and test against yet.)*

**What was built and tested (done):**

- **Crash-hardening** (`portal-server.js`): the request handler is extracted into
  `handle(req, res)` and wrapped so any error returns a **500** instead of killing the
  process; added `uncaughtException` / `unhandledRejection` last-resort logs and a
  `SIGTERM` graceful `server.close`. *Tested:* 300 concurrent requests → 200 OK + 100 correct
  404s, process survived.
- **Auto-restart supervisor** (`portal/supervise.js`): a `cluster` primary that runs **one**
  worker and **respawns it on any crash** (with crash-loop backoff), forwarding SIGTERM/SIGINT
  for clean deploys. Worker count defaults to 1 and refuses N>1 unless `ALLOW_UNSAFE_WORKERS=1`,
  precisely because of the in-memory-cache constraint above. *Tested:* killed the live worker →
  supervisor respawned it in ~200 ms and `/api/health` came back on a fresh pid with no manual
  action. Wired into `npm start`, Procfile, render.yaml, and the Dockerfile.

Net effect for one strong VIT box: a bad request can't crash the service, and if the process
dies anyway it's back in milliseconds — without sacrificing the allocation-correctness
guarantees. The Postgres + N-instance path remains the next step for multi-machine scale.

---

## Deployment & locations

- **Live:** https://open-project-portal.onrender.com (Render free tier — cold starts,
  ephemeral disk resets to committed `db.json`).
- **Repo:** primary git repo at `C:\Users\Aryansh Sinha\vit-open-project`; working copy
  opened in VS Code at `D:\Grey-HP-Laptop-By-Aryansh\CODING 24-28 - Copy\vit-open-project`.
  Push to `main` auto-deploys.
- **Run locally:** `node portal/portal-server.js` (port 4000).
- **Regenerate DB:** `node portal/gen-database.js` (~7 min scrypt) → `portal/data/db.json`
  (~4.3 MB, committed).
- Separate static team-builder tool lives in `deploy/` (on Vercel).
- See `DEPLOY.md` for the full deploy guide.

### Demo logins

- Student — `aryansh.sinha2024@vitstudent.ac.in` / `aryanshsinha` (or by registration number)
- Faculty — `teacher@domain` / `teach123`
- Admin — `admin` / `admin@123`
