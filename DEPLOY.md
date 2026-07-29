# Deploying the portal

The portal is a **stateful** Node service: it holds an encryption key and a data
file. That changes where it should run.

- The earlier team-builder tool is a static page and is fine on Vercel.
- **This portal is not a good fit for Vercel.** Vercel functions are stateless
  and their filesystem is wiped between invocations, so `data/db.json` and the
  vault key would not survive, and sessions would drop. Use a host that runs a
  long-lived container or process: **Render, Railway, Fly.io, or any VPS.**

## Before you deploy: set a stable key

Emails are encrypted with `VAULT_KEY`. If it is missing the app generates one and
writes it to `portal/data/.vault_key`, which is fine locally but not on a host
with an ephemeral disk. Generate one and set it as an environment variable:

```
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Set that value as `VAULT_KEY` in your host's dashboard. Keep it secret and never
change it, or existing encrypted emails become unreadable.

## Option A: Docker (works on Render, Fly, Railway, a VPS)

From the project root (`vit-open-project`):

```
docker build -t open-project-portal .
docker run -p 4000:4000 -e VAULT_KEY=<your-64-hex-key> \
  -v "$PWD/portal/data:/app/portal/data" open-project-portal
```

The `-v` mount keeps `db.json` on the host so data persists across restarts.

## Option B: Render (no Docker needed)

1. Push this folder to a Git repo.
2. New Web Service on Render, point it at the repo.
3. Build command: none. Start command: `node portal/portal-server.js`.
4. Add environment variable `VAULT_KEY`.
5. Add a persistent disk mounted at `/app/portal/data` so data survives deploys.

## Option C: Railway / Fly.io

Both detect the `Procfile` (`web: node portal/portal-server.js`). Add `VAULT_KEY`
as a variable and attach a small volume at `portal/data`.

## Option D: VIT's own server (recommended for the real test)

Any Linux box with Docker, or with Node 18+, runs this. On the server:

```
git clone <your repo>
cd vit-open-project
docker compose up -d --build      # serves on :4000
```

Then point nginx/Apache at `http://127.0.0.1:4000` for TLS and a domain. No
Node/npm knowledge needed on the box beyond Docker. Without Docker:
`UV_THREADPOOL_SIZE=64 node portal/portal-server.js`.

## Running it for 5,000 concurrent students

What the code already does for scale:
- **Password hashing is async** (scrypt on the libuv thread pool), so a login
  rush never freezes the server. 100 simultaneous logins finish in well under a
  second; the event loop stays free for everyone else.
- **UV_THREADPOOL_SIZE=64** so 64 hashes run at once instead of 4.
- **Slot allocation is atomic** in the single Node process (check-and-set with no
  await between), so two students can never grab the same last faculty slot.
- **Writes are coalesced and atomic** (temp-file + rename), off the request path.

Sizing: a single instance with **2-4 vCPU and 2-4 GB RAM** comfortably serves a
few thousand students whose traffic is mostly reads plus occasional writes (which
is exactly this workload). Render's FREE tier (0.1 shared CPU) will NOT do it —
use a paid instance or a real VM/VIT server.

## The honest next step for true production scale + a proper DBMS

This build keeps all state in memory with a JSON snapshot on disk. That is fast
and simple, but it is **single-instance**: you cannot run several copies behind a
load balancer, because each copy would have its own state. For horizontal scale
and durability you move the store to **PostgreSQL**:

1. Tables: `students`, `faculty`, `groups`, `group_members`, `consents`,
   `queries`, `admin`. The team-formation/constraint logic in `engine.js` stays
   unchanged (it is pure JS over rows).
2. Replace the `db.*` in-memory reads/writes in `portal-server.js` with SQL. The
   endpoints and their shapes do not change, only the data layer beneath them.
3. Run N stateless instances behind nginx; Postgres handles concurrency and the
   atomic slot check becomes a single `UPDATE ... WHERE slots_used < capacity`.

That migration is a focused, self-contained piece of work. Connect a Postgres
instance (VIT's, or a managed one) and it can be done next.

## Loading your real roster

Put your CSV (`reg,name,email`) anywhere and run:

```
node portal/dataset.js path/to/your-students.csv
```

That rewrites `portal/data/db.json` with your students, every email encrypted,
and re-sorts them into valid pending groups. Redeploy (or restart) to serve it.
