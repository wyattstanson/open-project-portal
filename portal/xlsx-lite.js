/*
 * ============================================================================
 *  XLSX-LITE  -  a tiny, ZERO-DEPENDENCY reader for .xlsx (and .csv)
 * ============================================================================
 *  An .xlsx file is just a ZIP archive of XML parts. This reads the two parts we
 *  need — the shared-string table and the first worksheet — using only Node's
 *  built-in `zlib` (to inflate) and a little XML/regex parsing. No SheetJS, no
 *  npm install: it keeps the portal's zero-runtime-dependency promise.
 *
 *  Public API:
 *    parse(buffer, filename) -> { headers: [..lower-cased..], rows: [ {header: value} ] }
 *  Both .xlsx and .csv are accepted; the format is detected from the bytes
 *  (a ZIP starts with "PK") and the filename.
 * ============================================================================
 */
'use strict';
const zlib = require('zlib');

// ---- XML helpers ----------------------------------------------------------
function xmlUnescape(s) {
  return String(s)
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&amp;/g, '&');            // must be last
}

// ---- minimal ZIP reader (central-directory based, handles data descriptors) --
function readZipEntries(buf) {
  // locate the End Of Central Directory record (scan backwards for its signature)
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i >= buf.length - 22 - 65536; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a valid .xlsx/zip file (no end-of-directory record).');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);           // start of central directory
  const entries = {};
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const fnLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + fnLen);
    entries[name] = { method, compSize, localOff };
    p += 46 + fnLen + extraLen + commentLen;
  }
  return entries;
}
function readEntry(buf, e) {
  if (!e) return null;
  // the local header repeats the name/extra lengths; the data begins after them
  const fnLen = buf.readUInt16LE(e.localOff + 26);
  const extraLen = buf.readUInt16LE(e.localOff + 28);
  const start = e.localOff + 30 + fnLen + extraLen;
  const data = buf.subarray(start, start + e.compSize);
  if (e.method === 0) return data;                          // stored (no compression)
  return zlib.inflateRawSync(data);                         // method 8 = deflate
}

// column label ("A", "B", "AA") -> zero-based index
function colToIndex(ref) {
  const m = String(ref).match(/^([A-Z]+)/);
  if (!m) return 0;
  let n = 0;
  for (const ch of m[1]) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n - 1;
}

function parseXlsx(buf) {
  const entries = readZipEntries(buf);
  // shared strings table (values with t="s" are indexes into this)
  const shared = [];
  if (entries['xl/sharedStrings.xml']) {
    const xml = readEntry(buf, entries['xl/sharedStrings.xml']).toString('utf8');
    const sis = xml.match(/<si>[\s\S]*?<\/si>|<si\/>/g) || [];
    for (const si of sis) {
      const parts = si.match(/<t[^>]*>([\s\S]*?)<\/t>/g) || [];
      shared.push(parts.map((t) => xmlUnescape(t.replace(/<t[^>]*>/, '').replace(/<\/t>/, ''))).join(''));
    }
  }
  // first worksheet
  const sheetName = entries['xl/worksheets/sheet1.xml'] ? 'xl/worksheets/sheet1.xml'
    : Object.keys(entries).filter((k) => /^xl\/worksheets\/sheet\d+\.xml$/.test(k)).sort()[0];
  if (!sheetName) throw new Error('No worksheet found in the workbook.');
  const sheet = readEntry(buf, entries[sheetName]).toString('utf8');
  const rowXmls = sheet.match(/<row[\s\S]*?<\/row>|<row[^>]*\/>/g) || [];
  const grid = [];
  for (const rx of rowXmls) {
    const cells = rx.match(/<c[\s\S]*?<\/c>|<c[^>]*\/>/g) || [];
    const row = [];
    for (const cx of cells) {
      const ref = (cx.match(/\sr="([A-Z]+\d+)"/) || [])[1];
      const type = (cx.match(/\st="([^"]+)"/) || [])[1];
      let val = '';
      if (type === 'inlineStr') {
        const t = cx.match(/<t[^>]*>([\s\S]*?)<\/t>/);
        val = t ? xmlUnescape(t[1]) : '';
      } else {
        const v = cx.match(/<v[^>]*>([\s\S]*?)<\/v>/);
        const raw = v ? v[1] : '';
        if (type === 's') val = shared[parseInt(raw, 10)] || '';
        else val = xmlUnescape(raw);
      }
      const idx = ref ? colToIndex(ref) : row.length;
      row[idx] = val;
    }
    grid.push(row);
  }
  return grid;
}

// ---- CSV (RFC-4180-ish, handles quotes, commas and newlines in fields) ------
function parseCsv(text) {
  text = String(text).replace(/^﻿/, '');               // strip BOM
  const rows = []; let row = []; let field = ''; let i = 0; let inQ = false;
  while (i < text.length) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i += 2; continue; } inQ = false; i++; continue; }
      field += c; i++; continue;
    }
    if (c === '"') { inQ = true; i++; continue; }
    if (c === ',') { row.push(field); field = ''; i++; continue; }
    if (c === '\r') { i++; continue; }
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
    field += c; i++;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}

// grid (array of arrays) -> { headers, rows: [{header: value}] }
function grid2objects(grid) {
  // first non-empty row is the header
  let h = 0;
  while (h < grid.length && (grid[h] || []).every((c) => String(c == null ? '' : c).trim() === '')) h++;
  const headerRow = grid[h] || [];
  const headers = headerRow.map((x) => String(x == null ? '' : x).trim().toLowerCase());
  const rows = [];
  for (let r = h + 1; r < grid.length; r++) {
    const cells = grid[r] || [];
    if (cells.every((c) => String(c == null ? '' : c).trim() === '')) continue;   // skip blank lines
    const obj = {};
    headers.forEach((key, ci) => { if (key) obj[key] = String(cells[ci] == null ? '' : cells[ci]).trim(); });
    rows.push(obj);
  }
  return { headers: headers.filter(Boolean), rows };
}

function parse(buffer, filename) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const isZip = buf.length > 1 && buf[0] === 0x50 && buf[1] === 0x4b;             // "PK"
  const looksCsv = /\.csv$/i.test(String(filename || '')) || /\.tsv$/i.test(String(filename || ''));
  if (isZip && !looksCsv) return grid2objects(parseXlsx(buf));
  return grid2objects(parseCsv(buf.toString('utf8')));
}

module.exports = { parse };
