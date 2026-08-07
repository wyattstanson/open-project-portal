# Deployment notes

The portal ships as a **Docker Compose stack**: `nginx` (reverse proxy, :80) →
`portal` (Node app) → `postgres` (durable store). One command brings it all up.

> **Run ONE portal instance.** The app holds its working set in memory and writes
> through to the store, so multiple instances would serve stale data even against a
> shared Postgres. Postgres gives durability, not horizontal scale (yet).

---

## 0. Prerequisites on the target server

- Linux with **Docker** + the **compose plugin**, daemon running:
  ```bash
  docker --version && docker compose version
  ```
  If Docker is missing:
  ```bash
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"   # log out/in so `docker` works without sudo
  ```
- ~**1–2 GB free RAM** (Postgres + seeding 10k scrypt-hashed rows).
- Port **80** reachable (open the firewall / security group).

---

## 1. Configure (optional for a demo)

```bash
cp .env.example .env
nano .env                 # set POSTGRES_PASSWORD, and VAULT_KEY for real data
```

Every key has a safe default (see `.env.example`), so a demo runs with no `.env`.
For **real student data**, set a stable `VAULT_KEY` (never change it afterwards):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## 2. Deploy to a server at an IP

From your machine, copy the project up (excludes `node_modules`, `.git`, local db):

```bash
rsync -az --delete \
  --exclude node_modules --exclude .git --exclude 'portal/data/portal.db*' \
  ./  USER@SERVER_IP:/opt/open-project-portal/
```

Then on the server, build and start the stack:

```bash
ssh USER@SERVER_IP
cd /opt/open-project-portal
docker compose up -d --build
```

First boot takes a minute: Postgres initialises and the app seeds ~10k students.

---

## 3. Verify

```bash
docker compose ps                         # all three services "running"/"healthy"
curl -s http://localhost/api/health        # {"ok":true,"students":10000,...}
docker compose logs -f portal              # watch the app; Ctrl-C to stop tailing
```

Open **`http://SERVER_IP/`** in a browser. Demo logins:
- **admin** — `admin` / `admin@123`
- **faculty** — `teacher@domain` / `teach123`
- **student** — reg `24BCE2312`, first-time hashkey shown on the landing page.

---

## 4. If Postgres misbehaves — fall back to SQLite (tested path)

The SQLite path is fully tested. To use it, drop `DATABASE_URL` from the `portal`
service in `docker-compose.yml` (comment out that one line) and:

```bash
docker compose up -d --build portal
```

The app then stores data in a single SQLite file inside the container.

---

## 5. Everyday operations

```bash
docker compose logs -f portal        # app logs
docker compose logs -f db            # postgres logs
docker compose restart portal        # restart just the app
docker compose down                  # stop the stack (keeps the pgdata volume)
docker compose down -v               # stop AND wipe the database (fresh start)
```

**Redeploy after a code change:** re-run the `rsync` from step 2, then
`docker compose up -d --build`.

**Back up the database:**
```bash
docker compose exec db pg_dump -U portal portal > backup-$(date +%F).sql
```

---

## 6. Loading your real roster

Replace the synthetic seed with your CSV (`reg,name,email`):

```bash
node portal/dataset.js path/to/your-students.csv    # rewrites portal/data/db.json
docker compose down -v && docker compose up -d --build   # reseed from the new data
```

Set a real `VAULT_KEY` in `.env` first, so emails are encrypted under your own key.

---

## 7. TLS / a domain (production)

Point your domain's A record at the server, then terminate TLS in `nginx.conf`
(add a `listen 443 ssl;` server block with your certificate and redirect 80→443).
The simplest route is to run Certbot/Caddy in front, or add a certbot companion
container. Until then the stack serves plain HTTP on port 80.

---

## Environment keys (all read by docker compose)

| Key | Default | Purpose |
|-----|---------|---------|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `portal` | Postgres credentials; `DATABASE_URL` is assembled from these |
| `UV_THREADPOOL_SIZE` | `64` | Parallel scrypt password hashing |
| `WORKERS` | `1` | Node workers — **keep at 1** |
| `PG_POOL` | `10` | Postgres connection-pool size |
| `PROCTOR_EMAIL_DOMAIN` | `vit.ac.in` | Hashkeys may only be sent to this email domain |
| `HTTP_PORT` | `80` | Host port nginx publishes on |
| `VAULT_KEY` | *(empty → demo key)* | AES-256 key for email encryption; set for real data |
