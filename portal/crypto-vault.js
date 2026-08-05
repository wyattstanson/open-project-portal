/*
 * ============================================================================
 *  CRYPTO VAULT  -  the "encryptor"
 * ============================================================================
 *  This is the whole reason the email feature needs a server. The AES key
 *  lives ONLY here, on the backend (in data/.vault_key or the VAULT_KEY env
 *  var). It is never sent to a browser. So:
 *    - student emails are stored ENCRYPTED at rest,
 *    - the public / student API only ever returns a MASKED form (a****@...),
 *    - only code running on this server, holding the key, can decrypt them.
 *
 *  Encryption : AES-256-GCM (authenticated, so tampering is detected).
 *  Passwords  : scrypt with a random salt (never stored in plain text).
 * ============================================================================
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_FILE = path.join(__dirname, 'data', '.vault_key');

function loadKey() {
  if (process.env.VAULT_KEY) return Buffer.from(process.env.VAULT_KEY, 'hex');
  try { return Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex'); } catch (e) {}
  const k = crypto.randomBytes(32);                      // 256-bit key
  fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true });
  fs.writeFileSync(KEY_FILE, k.toString('hex'), { mode: 0o600 });
  return k;
}
let KEY = loadKey();

function tryDecrypt(blob, key) {
  try {
    const [ivb, tagb, ctb] = String(blob).split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivb, 'base64'));
    d.setAuthTag(Buffer.from(tagb, 'base64'));
    return Buffer.concat([d.update(Buffer.from(ctb, 'base64')), d.final()]).toString('utf8');
  } catch (e) { return null; }
}

// Self-healing key selection: given a known ciphertext from the database, pick
// whichever available key (env var, committed .vault_key file, or the current
// one) actually decrypts it. This makes a deploy work even if VAULT_KEY is set
// to the wrong value, because the key that matches the data always wins.
function selectKeyFor(sampleBlob) {
  if (!sampleBlob) return false;
  const cands = [KEY];
  if (process.env.VAULT_KEY) { try { cands.push(Buffer.from(process.env.VAULT_KEY, 'hex')); } catch (e) {} }
  try { cands.push(Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex')); } catch (e) {}
  for (const k of cands) {
    if (k.length === 32 && tryDecrypt(sampleBlob, k) !== null) { KEY = k; return true; }
  }
  return false;
}

// Encrypt a string -> "iv:tag:ciphertext" (all base64). Backend only.
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return [iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
}

// Decrypt back to the original string. Returns null if wrong/tampered. Backend only.
function decrypt(blob) {
  try {
    const [ivb, tagb, ctb] = String(blob).split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(ivb, 'base64'));
    d.setAuthTag(Buffer.from(tagb, 'base64'));
    return Buffer.concat([d.update(Buffer.from(ctb, 'base64')), d.final()]).toString('utf8');
  } catch (e) { return null; }
}

// Deterministic keyed hash of an email, for O(1) lookup at login WITHOUT
// decrypting every stored record. Same email always gives the same hash, but
// the hash cannot be reversed to the address without the key.
function hashEmail(email) {
  return crypto.createHmac('sha256', KEY).update(String(email).trim().toLowerCase()).digest('hex');
}

// What students are allowed to see: first letter + domain only.
function mask(email) {
  const s = String(email); const at = s.indexOf('@');
  if (at < 1) return '****';
  return s[0] + '****' + s.slice(at);
}

// ---- password hashing ----
// SYNC variants: only for the offline generator/importer scripts.
function hashPasswordSync(pw) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(pw), salt, 32);
  return salt.toString('hex') + ':' + dk.toString('hex');
}
function verifyPasswordSync(pw, stored) {
  try {
    const [s, h] = String(stored).split(':');
    const dk = crypto.scryptSync(String(pw), Buffer.from(s, 'hex'), 32);
    return crypto.timingSafeEqual(dk, Buffer.from(h, 'hex'));
  } catch (e) { return false; }
}
// ASYNC variants: used by the live server so scrypt runs on the libuv thread
// pool and NEVER blocks the event loop. This is what lets thousands of logins
// happen at once without the whole server stalling.
function hashPassword(pw) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(String(pw), salt, 32, (err, dk) => {
      if (err) reject(err); else resolve(salt.toString('hex') + ':' + dk.toString('hex'));
    });
  });
}
function verifyPassword(pw, stored) {
  return new Promise((resolve) => {
    try {
      const [s, h] = String(stored).split(':');
      const hb = Buffer.from(h, 'hex');
      crypto.scrypt(String(pw), Buffer.from(s, 'hex'), 32, (err, dk) => {
        if (err) { resolve(false); return; }
        try { resolve(dk.length === hb.length && crypto.timingSafeEqual(dk, hb)); } catch (e) { resolve(false); }
      });
    } catch (e) { resolve(false); }
  });
}
function newToken() { return crypto.randomBytes(24).toString('hex'); }

// ---- registration hashkey ----
const HK_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// Deterministic one-time key (16–26 alphanumeric) the admin hands out via proctors.
// Derived from the reg number with the vault key as the secret: unique per student,
// stable across restarts, and unguessable without the server key.
function hashkeyFor(reg) {
  const mac = crypto.createHmac('sha256', KEY).update('HASHKEY:' + String(reg).trim().toUpperCase()).digest();
  const len = 16 + (mac[0] % 11);                       // 16..26 chars
  let out = '';
  for (let i = 0; i < len; i++) out += HK_ALPHABET[mac[i % mac.length] % 62];
  return out;
}
// Constant-time compare for the hashkey a student types in.
function hashkeyMatches(reg, given) {
  const a = Buffer.from(hashkeyFor(reg)); const b = Buffer.from(String(given || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// Keyed fingerprint of a password, used ONLY to enforce global uniqueness without
// storing anything reversible. Same password -> same fingerprint; not reversible.
function pwFingerprint(pw) {
  return crypto.createHmac('sha256', KEY).update('PWUNIQ:' + String(pw)).digest('hex');
}

module.exports = { encrypt, decrypt, mask, hashEmail, hashPassword, verifyPassword, hashPasswordSync, verifyPasswordSync, newToken, selectKeyFor, hashkeyFor, hashkeyMatches, pwFingerprint };
