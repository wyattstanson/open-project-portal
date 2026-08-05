/*
 * ============================================================================
 *  SUPERVISOR  -  keeps the portal alive ("doesn't go down")
 * ============================================================================
 *  Forks the portal backend as a worker and RESPAWNS it if it ever dies, so an
 *  unexpected crash means ~milliseconds of downtime instead of a dead service
 *  until someone notices. Forwards SIGTERM/SIGINT so deploys shut down cleanly.
 *
 *  WORKER COUNT — read this before raising WORKERS above 1
 *  -------------------------------------------------------
 *  The backend keeps the whole database IN MEMORY (store.loadAll) and writes
 *  through to SQLite per change. With more than one worker each worker gets its
 *  OWN in-memory copy, so a group submitted on worker A is invisible to worker B
 *  until restart — which breaks the core invariants (one-student-one-group,
 *  faculty slot caps, consent). Scrypt password hashing is ALREADY parallel
 *  across all cores via the 64-thread libuv pool (see portal-server.js), so a
 *  single worker already uses the machine for the one expensive operation.
 *
 *  Therefore WORKERS defaults to 1. Running N>1 is only correct once the store
 *  is a SHARED source of truth (Postgres) with the in-memory cache dropped or
 *  invalidated — see HISTORY.md "Phase 2". Until then N>1 is refused unless you
 *  explicitly set ALLOW_UNSAFE_WORKERS=1 (for load-testing the socket layer).
 *
 *  Run:  node --experimental-sqlite portal/supervise.js
 * ============================================================================
 */
'use strict';
const cluster = require('node:cluster');

if (!cluster.isPrimary) {
  // Worker: just run the real server (it installs its own SIGTERM graceful close).
  require('./portal-server.js');
  return;
}

// ------------------------------------------------------------------ primary
let WORKERS = Math.max(1, parseInt(process.env.WORKERS || '1', 10));
if (WORKERS > 1 && process.env.ALLOW_UNSAFE_WORKERS !== '1') {
  console.warn(
    '[supervisor] WORKERS=' + WORKERS + ' ignored: the backend holds an in-memory ' +
    'cache, so multiple workers would serve stale/conflicting state. Staying at 1. ' +
    'Move the store to Postgres first (see HISTORY.md), or set ALLOW_UNSAFE_WORKERS=1 ' +
    'to override for socket-layer load testing only.');
  WORKERS = 1;
}

let shuttingDown = false;
const started = new Map();        // worker.id -> spawn timestamp
const RAPID_MS = 2000;            // a worker dying within this of spawn = "crash loop"
const MAX_BACKOFF_MS = 30000;
let backoff = 200;

function spawn() {
  const w = cluster.fork();
  started.set(w.id, Date.now());
}

for (let i = 0; i < WORKERS; i++) spawn();

cluster.on('online', (w) => console.log('[supervisor] worker ' + w.process.pid + ' online'));

cluster.on('exit', (w, code, signal) => {
  const bornAt = started.get(w.id) || Date.now();
  started.delete(w.id);
  if (shuttingDown) return;
  const why = signal ? 'signal ' + signal : 'code ' + code;
  const lived = Date.now() - bornAt;
  // If it died almost immediately it is probably crash-looping: back off so we
  // don't pin a CPU respawning a broken build. A worker that ran fine resets it.
  if (lived < RAPID_MS) { backoff = Math.min(backoff * 2, MAX_BACKOFF_MS); }
  else { backoff = 200; }
  console.error('[supervisor] worker ' + w.process.pid + ' exited (' + why + '); respawning in ' + backoff + 'ms');
  setTimeout(() => { if (!shuttingDown) spawn(); }, backoff);
});

function shutdown(sig) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('[supervisor] ' + sig + ' received; shutting workers down gracefully');
  for (const id in cluster.workers) {
    try { cluster.workers[id].process.kill(sig); } catch (_) {}
  }
  // Hard stop if a worker refuses to exit.
  setTimeout(() => process.exit(0), 6000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

console.log('[supervisor] up (pid ' + process.pid + '), supervising ' + WORKERS + ' worker' + (WORKERS > 1 ? 's' : ''));
