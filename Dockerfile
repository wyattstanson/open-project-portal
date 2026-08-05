# Portal backend (engine + encryptor + faculty/student API).
# Stateful: keep VAULT_KEY stable and mount /app/portal/data to persist data.
# Node 22.5+ required for the built-in SQLite (node:sqlite). Node 22 uses the
# --experimental-sqlite flag; the flag is harmless on newer versions.
FROM node:22-alpine
WORKDIR /app
# Install runtime deps first for better layer caching. The only dependency is `pg`,
# and it is loaded ONLY when DATABASE_URL is set; the SQLite path stays dependency-free.
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
ENV PORT=4000
ENV NODE_ENV=production
ENV UV_THREADPOOL_SIZE=64
ENV NODE_OPTIONS=--experimental-sqlite
EXPOSE 4000
CMD ["node", "--experimental-sqlite", "portal/supervise.js"]
