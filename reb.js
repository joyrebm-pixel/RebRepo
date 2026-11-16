import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import mysql from 'mysql2/promise';
import Busboy from 'busboy';
import { findMpCmdRun, scanWithWindowsDefender } from './windows-defender.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const defaultDatabaseUrl = 'mysql://root@localhost:3306/virus_scanner';
const port = Number(process.env.PORT || 3000);
const MAX_BYTES = 25 * 1024 * 1024;
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };
const staticFiles = new Map([['/', 'index.html'], ['/index.html', 'index.html'], ['/styles.css', 'styles.css'], ['/app.js', 'app.js']]);
let pool;
let schemaPromise;

function loadEnvironmentFile() {
  let contents;
  try {
    contents = fs.readFileSync(path.join(root, '.env'), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      process.env.DATABASE_URL = process.env.DATABASE_URL || defaultDatabaseUrl;
      return;
    }
    throw error;
  }
  for (const line of contents.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '').trim();
    process.env[match[1]] = value;
  }
  process.env.DATABASE_URL = process.env.DATABASE_URL || defaultDatabaseUrl;
}

loadEnvironmentFile();

function getDatabaseConfig() {
  const databaseUrl = process.env.DATABASE_URL || defaultDatabaseUrl;
  const dbUrl = new URL(databaseUrl);
  const database = decodeURIComponent(dbUrl.pathname.replace(/^\//, '')) || 'virus_scanner';
  return {
    host: dbUrl.hostname,
    port: Number(dbUrl.port || 3306),
    user: decodeURIComponent(dbUrl.username),
    password: decodeURIComponent(dbUrl.password),
    database,
    ssl: dbUrl.hostname === 'localhost' || dbUrl.hostname === '127.0.0.1' ? undefined : { rejectUnauthorized: true }
  };
}

function getVirusTotalApiKey() {
  const apiKey = (process.env.VIRUSTOTAL_API_KEY || '').trim();
  if (!apiKey || /^(?:your|replace|insert|paste|example|placeholder|changeme)(?:[_-]|$)/i.test(apiKey) || /^<[^>]+>$/.test(apiKey)) return null;
  return apiKey;
}

function getScannerConfig() {
  if (getVirusTotalApiKey()) return { configured: true, id: 'virustotal', provider: 'VirusTotal' };
  if (findMpCmdRun()) return { configured: true, id: 'defender', provider: 'Microsoft Defender' };
  return { configured: false, id: null, provider: null };
}

async function ensureDatabase() {
  const config = getDatabaseConfig();
  const connection = await mysql.createConnection({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: undefined,
    ssl: config.ssl
  });
  try {
    const safeDbName = config.database.replace(/`/g, '``');
    await connection.execute(`CREATE DATABASE IF NOT EXISTS \`${safeDbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  } finally {
    await connection.end();
  }
}

function getPool() {
  if (pool) return pool;
  const config = getDatabaseConfig();
  pool = mysql.createPool({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: config.database,
    waitForConnections: true,
    connectionLimit: 5,
    ...(config.ssl ? { ssl: config.ssl } : {})
  });
  return pool;
}

async function ensureSchema() {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await ensureDatabase();
      const db = getPool();
      await db.query(`CREATE TABLE IF NOT EXISTS vs_users (
        open_id VARCHAR(191) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
      await db.query(`CREATE TABLE IF NOT EXISTS vs_credentials (
        open_id VARCHAR(191) NOT NULL PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_vs_credentials_user FOREIGN KEY (open_id) REFERENCES vs_users(open_id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
      await db.query(`CREATE TABLE IF NOT EXISTS vs_sessions (
        token_hash CHAR(64) NOT NULL PRIMARY KEY,
        open_id VARCHAR(191) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_vs_sessions_user (open_id),
        CONSTRAINT fk_vs_sessions_user FOREIGN KEY (open_id) REFERENCES vs_users(open_id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
      await db.query(`CREATE TABLE IF NOT EXISTS vs_scans (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        open_id VARCHAR(191) NOT NULL,
        file_name VARCHAR(255) NOT NULL,
        file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
        file_type VARCHAR(16) NOT NULL DEFAULT 'FILE',
        verdict VARCHAR(32) NOT NULL,
        status VARCHAR(32) NOT NULL,
        malicious_count INT NOT NULL DEFAULT 0,
        suspicious_count INT NOT NULL DEFAULT 0,
        analysis_id VARCHAR(255) NULL,
        error_message VARCHAR(500) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_vs_scans_user_created (open_id, created_at),
        CONSTRAINT fk_vs_scans_user FOREIGN KEY (open_id) REFERENCES vs_users(open_id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    })().catch((error) => { schemaPromise = null; throw error; });
  }
  return schemaPromise;
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map((part) => part.trim()).filter(Boolean).map((part) => {
    const index = part.indexOf('=');
    return [index === -1 ? part : part.slice(0, index), index === -1 ? '' : decodeURIComponent(part.slice(index + 1))];
  }));
}

function cookie(name, value, maxAge, req) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const secure = forwardedProto === 'https' || (!forwardedProto && Boolean(req.socket.encrypted));
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax;${secure ? ' Secure;' : ''}${maxAge === undefined ? '' : ` Max-Age=${maxAge};`}`;
}

function appendCookies(res, values) {
  res.setHeader('Set-Cookie', values);
}

async function currentUser(req) {
  const token = parseCookies(req).webdev_app_session;
  if (!token) return null;
  await ensureSchema();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const [rows] = await getPool().execute(`SELECT u.open_id, u.name, u.email, u.alerts_enabled
    FROM vs_sessions s JOIN vs_users u ON u.open_id = s.open_id
    WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP() LIMIT 1`, [tokenHash]);
  if (!rows[0]) return null;
  return { openId: rows[0].open_id, name: rows[0].name, email: rows[0].email, alertsEnabled: Boolean(rows[0].alerts_enabled) };
}

function hashPassword(password, salt = crypto.randomBytes(16)) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) return reject(error);
      resolve(`${salt.toString('hex')}:${derivedKey.toString('hex')}`);
    });
  });
}

async function verifyPassword(password, storedHash) {
  const [saltHex, hashHex] = storedHash.split(':');
  if (!/^[\da-f]{32}$/i.test(saltHex) || !/^[\da-f]{128}$/i.test(hashHex)) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await new Promise((resolve, reject) => {
    crypto.scrypt(password, Buffer.from(saltHex, 'hex'), expected.length, (error, derivedKey) => {
      if (error) return reject(error);
      resolve(derivedKey);
    });
  });
  return crypto.timingSafeEqual(actual, expected);
}

async function startSession(req, res, openId) {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await getPool().execute('DELETE FROM vs_sessions WHERE expires_at <= UTC_TIMESTAMP()');
  await getPool().execute('INSERT INTO vs_sessions (token_hash, open_id, expires_at) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY))', [tokenHash, openId]);
  appendCookies(res, [cookie('webdev_app_session', token, 30 * 24 * 60 * 60, req)]);
}

async function createAccount(req, res) {
  const body = await readJson(req);
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (name.length < 2 || name.length > 80) return json(res, 400, { error: 'Enter a name between 2 and 80 characters.' });
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { error: 'Enter a valid email address.' });
  if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 128) return json(res, 400, { error: 'Use a password between 8 and 128 bytes.' });
  await ensureSchema();
  const openId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  const connection = await getPool().getConnection();
  try {
    await connection.beginTransaction();
    await connection.execute('INSERT INTO vs_users (open_id, name, email) VALUES (?, ?, ?)', [openId, name, email]);
    await connection.execute('INSERT INTO vs_credentials (open_id, email, password_hash) VALUES (?, ?, ?)', [openId, email, passwordHash]);
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    if (error.code === 'ER_DUP_ENTRY') return json(res, 409, { error: 'An account with that email already exists. Sign in instead.' });
    throw error;
  } finally {
    connection.release();
  }
  await startSession(req, res, openId);
  const scanner = getScannerConfig();
  return json(res, 201, { user: { openId, name, email, alertsEnabled: true }, scannerConfigured: scanner.configured, scannerProvider: scanner.provider });
}

async function loginAccount(req, res) {
  const body = await readJson(req);
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password || Buffer.byteLength(password, 'utf8') > 128) {
    return json(res, 400, { error: 'Enter the email and password for your account.' });
  }
  await ensureSchema();
  const [rows] = await getPool().execute(`SELECT u.open_id, u.name, u.email, u.alerts_enabled, c.password_hash
    FROM vs_credentials c JOIN vs_users u ON u.open_id = c.open_id WHERE c.email = ? LIMIT 1`, [email]);
  if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) {
    return json(res, 401, { error: 'Email or password is incorrect.' });
  }
  await startSession(req, res, rows[0].open_id);
  const scanner = getScannerConfig();
  return json(res, 200, {
    user: { openId: rows[0].open_id, name: rows[0].name, email: rows[0].email, alertsEnabled: Boolean(rows[0].alerts_enabled) },
    scannerConfigured: scanner.configured,
    scannerProvider: scanner.provider
  });
}

async function logoutAccount(req, res) {
  const token = parseCookies(req).webdev_app_session;
  if (token) {
    await ensureSchema();
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await getPool().execute('DELETE FROM vs_sessions WHERE token_hash = ?', [tokenHash]);
  }
  appendCookies(res, [cookie('webdev_app_session', '', 0, req)]);
  return json(res, 200, { ok: true });
}

function parseUpload(req) {
  return new Promise((resolve, reject) => {
    const contentType = String(req.headers['content-type'] || '');
    if (!contentType.startsWith('multipart/form-data')) return reject(new Error('File upload must use multipart form data.'));
    const bb = Busboy({ headers: req.headers, limits: { files: 1, fileSize: MAX_BYTES } });
    let file;
    let tooLarge = false;
    bb.on('file', (field, stream, info) => {
      if (field !== 'file') { stream.resume(); return; }
      file = { name: info.filename || 'upload', mime: info.mimeType || 'application/octet-stream', chunks: [], size: 0 };
      stream.on('data', (chunk) => { file.chunks.push(chunk); file.size += chunk.length; });
      stream.on('limit', () => { tooLarge = true; });
    });
    bb.on('error', reject);
    bb.on('finish', () => {
      if (tooLarge) return reject(new Error('File is larger than the 25 MB limit.'));
      if (!file || !file.size) return reject(new Error('Choose a file before scanning.'));
      file.buffer = Buffer.concat(file.chunks);
      resolve(file);
    });
    req.pipe(bb);
  });
}

async function virusTotalScan(file) {
  const apiKey = getVirusTotalApiKey();
  if (!apiKey) throw new Error('VirusTotal is not configured.');
  const form = new FormData();
  form.append('file', new Blob([file.buffer], { type: file.mime }), file.name);
  const upload = await fetch('https://www.virustotal.com/api/v3/files', { method: 'POST', headers: { 'x-apikey': apiKey }, body: form });
  if (!upload.ok) throw new Error(`VirusTotal upload failed (${upload.status}).`);
  const uploaded = await upload.json();
  const analysisId = uploaded?.data?.id;
  if (!analysisId) throw new Error('VirusTotal did not return an analysis id.');
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const result = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, { headers: { 'x-apikey': apiKey } });
    if (!result.ok) throw new Error(`VirusTotal analysis failed (${result.status}).`);
    const analysis = await result.json();
    if (analysis?.data?.attributes?.status === 'completed') {
      const stats = analysis.data.attributes.stats || {};
      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      return { analysisId, malicious, suspicious, verdict: malicious > 0 ? 'threat' : suspicious > 0 ? 'warning' : 'clean', provider: 'VirusTotal' };
    }
  }
  throw new Error('VirusTotal analysis timed out.');
}

async function sendAlert(user, file, result) {
  if (!user.alertsEnabled || !user.email || !process.env.RESEND_API_KEY || !process.env.RESEND_FROM_EMAIL) return false;
  const label = result.verdict === 'threat' ? 'Threat detected' : 'Suspicious signal';
  const response = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: process.env.RESEND_FROM_EMAIL, to: [user.email], subject: `Virus Scanner alert: ${label}`, html: `<div style="font-family:Arial,sans-serif;line-height:1.5"><h2>${label}</h2><p>Virus Scanner completed a real analysis for <strong>${escapeHtml(file.name)}</strong>.</p><p>Malicious detections: <strong>${result.malicious}</strong><br>Suspicious detections: <strong>${result.suspicious}</strong></p><p>Review the file and its sender before opening it.</p></div>` }) });
  if (!response.ok) throw new Error(`Resend request failed (${response.status}).`);
  return true;
}

function escapeHtml(value) { return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;'); }

async function handleApi(req, res, url) {
  if (url.pathname === '/api/health') return json(res, 200, { ok: true, service: 'virus-scanner' });
  if (url.pathname === '/api/auth/status' && req.method === 'GET') {
    try {
      await ensureSchema();
      const scanner = getScannerConfig();
      return json(res, 200, { configured: true, scannerConfigured: scanner.configured, scannerProvider: scanner.provider });
    } catch (error) {
      console.error('Account database check failed:', error.message);
      return json(res, 503, { configured: false, error: 'The account database is not ready. Check DATABASE_URL in .env and make sure MySQL is running.' });
    }
  }
  if (url.pathname === '/api/auth/signup' && req.method === 'POST') {
    try { return await createAccount(req, res); }
    catch (error) {
      console.error('Account signup error:', error.message);
      return json(res, 503, { error: 'Could not reach the account database. Check DATABASE_URL in .env and make sure MySQL is running.' });
    }
  }
  if (url.pathname === '/api/auth/login' && req.method === 'POST') {
    try { return await loginAccount(req, res); }
    catch (error) {
      console.error('Account login error:', error.message);
      return json(res, 503, { error: 'Could not reach the account database. Check DATABASE_URL in .env and make sure MySQL is running.' });
    }
  }
  if (url.pathname === '/api/auth/logout' && req.method === 'POST') return logoutAccount(req, res);
  if (url.pathname === '/api/me' && req.method === 'GET') {
    try {
      const user = await currentUser(req);
      const scanner = getScannerConfig();
      return json(res, 200, { user, scannerConfigured: scanner.configured, scannerProvider: scanner.provider });
    }
    catch (error) { console.error('Account session lookup error:', error.message); return json(res, 503, { error: 'Account storage is not ready. Check DATABASE_URL in .env and make sure MySQL is running.' }); }
  }
  let user;
  try { user = await currentUser(req); } catch (error) { console.error('Database error:', error.message); return json(res, 503, { error: 'Account storage is not ready yet.' }); }
  if (!user) return json(res, 401, { error: 'Sign in is required for this action.' });
  if (url.pathname === '/api/scans' && req.method === 'GET') {
    const [rows] = await getPool().execute('SELECT id, file_name, file_size, file_type, verdict, status, malicious_count, suspicious_count, created_at FROM vs_scans WHERE open_id = ? ORDER BY created_at DESC LIMIT 50', [user.openId]);
    return json(res, 200, { scans: rows.map((row) => ({ id: String(row.id), name: row.file_name, size: Number(row.file_size), type: row.file_type, verdict: row.verdict, status: row.status, malicious: row.malicious_count, suspicious: row.suspicious_count, createdAt: row.created_at })) });
  }
  if (url.pathname === '/api/preferences' && req.method === 'POST') {
    const body = await readJson(req);
    await getPool().execute('UPDATE vs_users SET alerts_enabled = ? WHERE open_id = ?', [body.alertsEnabled !== false, user.openId]);
    return json(res, 200, { alertsEnabled: body.alertsEnabled !== false });
  }
  if (url.pathname === '/api/scans' && req.method === 'POST') {
    const scanner = getScannerConfig();
    if (!scanner.configured) {
      return json(res, 503, { error: 'No scanner is available. Configure a VirusTotal API key or run this app on Windows with Microsoft Defender installed.' });
    }
    let file;
    try { file = await parseUpload(req); } catch (error) { return json(res, 400, { error: error.message }); }
    const type = file.name.split('.').pop()?.toUpperCase().slice(0, 4) || 'FILE';
    const db = getPool();
    const [insert] = await db.execute('INSERT INTO vs_scans (open_id, file_name, file_size, file_type, verdict, status) VALUES (?, ?, ?, ?, ?, ?)', [user.openId, file.name, file.size, type, 'pending', 'processing']);
    const scanId = insert.insertId;
    try {
      const result = scanner.id === 'virustotal'
        ? await virusTotalScan(file)
        : await scanWithWindowsDefender(file.buffer, file.name);
      await db.execute('UPDATE vs_scans SET verdict = ?, status = ?, malicious_count = ?, suspicious_count = ?, analysis_id = ? WHERE id = ? AND open_id = ?', [result.verdict, 'complete', result.malicious, result.suspicious, result.analysisId, scanId, user.openId]);
      let alertSent = false;
      if (result.verdict !== 'clean') { try { alertSent = await sendAlert(user, file, result); } catch (error) { console.error('Alert error:', error.message); } }
      return json(res, 200, { scan: { id: String(scanId), name: file.name, size: file.size, type, verdict: result.verdict, status: 'complete', malicious: result.malicious, suspicious: result.suspicious, provider: result.provider, alertSent } });
    } catch (error) {
      console.error(`${scanner.provider} scan error:`, error.message);
      await db.execute('UPDATE vs_scans SET verdict = ?, status = ?, error_message = ? WHERE id = ? AND open_id = ?', ['error', 'error', error.message.slice(0, 500), scanId, user.openId]);
      const message = scanner.id === 'virustotal'
        ? error.message === 'VirusTotal upload failed (401).' || error.message === 'VirusTotal upload failed (403).'
          ? 'VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY in .env and restart the app.'
          : error.message === 'VirusTotal upload failed (429).' || error.message === 'VirusTotal analysis failed (429).'
            ? 'VirusTotal rate limit reached. Wait before trying again.'
            : error.message
        : error.message;
      return json(res, 502, { error: `The real scan could not be completed. ${message}` });
    }
  }
  return json(res, 404, { error: 'Not found' });
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; if (raw.length > 100_000) reject(new Error('Request is too large.')); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid JSON.')); } });
    req.on('error', reject);
  });
}

function serveStatic(req, res, url) {
  const fileName = staticFiles.get(url.pathname);
  if (!fileName) return json(res, 404, { error: 'Not found' });
  const filePath = path.join(root, fileName);
  fs.readFile(filePath, (error, data) => {
    if (error) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': mime[path.extname(filePath)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    if (req.method !== 'HEAD') res.end(data); else res.end();
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res, url);
    else json(res, 405, { error: 'Method not allowed' });
  } catch (error) {
    console.error('Request error:', error);
    if (!res.headersSent) json(res, 500, { error: 'Unexpected server error.' });
  }
});

ensureSchema().then(() => console.log('Database schema ready.')).catch((error) => console.warn(`Database schema will initialize on first use: ${error.message}`));
server.listen(port, '0.0.0.0', () => console.log(`Virus Scanner listening on 0.0.0.0:${port}`));
