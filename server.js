/*
 * ============================================================================
 *  BACKEND SERVER  (optional, real HTTP API around the engine)
 * ============================================================================
 *  The deployed page does not need this: it runs the engine in the browser.
 *  You would run THIS when you want ONE central authority doing the allocation,
 *  the same shape real FFCS has: many students hit one server, and the server,
 *  not each browser, owns the seat counts so two teams can never grab the last
 *  seat at the same time.
 *
 *  No external packages. Node's built-in http only. Run:  node server.js
 *
 *  Endpoints:
 *    GET  /                      -> the tool (static index.html, if present)
 *    GET  /api/demo?n=10000      -> synthesize n students and run the pipeline
 *    POST /api/allocate          -> body: { rows, distinct, faculty, map }
 *                                   returns stats, timings, teams, duplicates
 * ============================================================================
 */

'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const engine = require('./engine');

const PORT = process.env.PORT || 3000;

// A default faculty pool so /api/demo seats teams out of the box.
const DEFAULT_FACULTY = Array.from({ length: 40 }, (_, i) => ({
  name: 'Prof_' + String(i + 1).padStart(2, '0'),
  seats: 60,
}));

function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');

  // ---- GET /api/demo?n=10000 : prove it scales, server-side ----
  if (req.method === 'GET' && url.pathname === '/api/demo') {
    const n = Math.min(200000, Math.max(1, parseInt(url.searchParams.get('n') || '10000', 10)));
    const rows = engine.synth(n, 0.42);
    // inject 2 duplicates so detection is visible
    rows.push(rows[0].split(',')[0], rows[1].split(',')[0]);
    const result = engine.allocate(rows, { faculty: DEFAULT_FACULTY, distinct: true });
    // trim the teams array in the response so the demo payload stays small
    return sendJSON(res, 200, { ...result, teams: result.teams.slice(0, 5), teamsTotal: result.stats.teams });
  }

  // ---- POST /api/allocate : real work on caller-supplied data ----
  if (req.method === 'POST' && url.pathname === '/api/allocate') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 50e6) req.destroy(); });
    req.on('end', () => {
      let payload;
      try { payload = JSON.parse(body || '{}'); }
      catch (e) { return sendJSON(res, 400, { error: 'Body must be JSON' }); }
      const rows = Array.isArray(payload.rows) ? payload.rows : [];
      if (!rows.length) return sendJSON(res, 400, { error: 'Provide rows: an array of registration numbers' });
      const result = engine.allocate(rows, {
        faculty: payload.faculty || DEFAULT_FACULTY,
        distinct: payload.distinct !== false,
        map: payload.map || engine.DEFAULT_MAP,
      });
      return sendJSON(res, 200, result);
    });
    return;
  }

  // ---- GET / : serve the tool if index.html is beside this file ----
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    const file = path.join(__dirname, 'deploy', 'index.html');
    if (fs.existsSync(file)) {
      const html = fs.readFileSync(file);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('Allocation backend running. Try /api/demo?n=10000');
  }

  sendJSON(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log('Allocation backend on http://localhost:' + PORT);
  console.log('Try:  http://localhost:' + PORT + '/api/demo?n=10000');
});
