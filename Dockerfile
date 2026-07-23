# Portal backend (engine + encryptor + faculty/student API).
# Stateful: keep VAULT_KEY stable and mount /app/portal/data to persist data.
FROM node:20-alpine
WORKDIR /app
COPY . .
ENV PORT=4000
ENV NODE_ENV=production
EXPOSE 4000
# no npm install needed: the app uses only Node built-ins
CMD ["node", "portal/portal-server.js"]
