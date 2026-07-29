# Portal backend (engine + encryptor + faculty/student API).
# Stateful: keep VAULT_KEY stable and mount /app/portal/data to persist data.
# Node 22.5+ required for the built-in SQLite (node:sqlite). Node 22 uses the
# --experimental-sqlite flag; the flag is harmless on newer versions.
FROM node:22-alpine
WORKDIR /app
COPY . .
ENV PORT=4000
ENV NODE_ENV=production
ENV UV_THREADPOOL_SIZE=64
EXPOSE 4000
# no npm install needed: the app uses only Node built-ins (http, crypto, sqlite)
CMD ["node", "--experimental-sqlite", "portal/portal-server.js"]
