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

## Loading your real roster

Put your CSV (`reg,name,email`) anywhere and run:

```
node portal/dataset.js path/to/your-students.csv
```

That rewrites `portal/data/db.json` with your students, every email encrypted,
and re-sorts them into valid pending groups. Redeploy (or restart) to serve it.
