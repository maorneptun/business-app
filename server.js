require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({ origin: '*', methods: ['GET','POST','OPTIONS'], allowedHeaders: ['Content-Type','x-app-token'] }));
const jsonSmall = express.json({ limit: '10mb' });
// קבצים (צילומי שעות וכו') מקבלים גבול גדול יותר — שאר הנתיבים נשארים עם 10MB
app.use((req, res, next) => ((req.path.startsWith('/api/files') || req.path === '/api/vat/doc' || req.path === '/api/vat/scan') ? next() : jsonSmall(req, res, next)));

// ===== MongoDB =====
const MONGO_URI = process.env.MONGODB_URI;
let db;

// מתחבר, ואם נכשל — מנסה שוב כל 30 שניות (כדי שתקלה רגעית לא תשאיר את השרת בלי מסד נתונים)
async function connectDB() {
  if (!MONGO_URI) { console.error('❌ MONGODB_URI חסר'); return; }
  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 15000 });
    await client.connect();
    db = client.db('neptun');
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message, '— מנסה שוב בעוד 30 שניות');
    setTimeout(connectDB, 30000);
  }
}
connectDB();

// ===== Static Frontend =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== AUTH (סיסמת כניסה) =====
const crypto = require('crypto');
function expectedToken() {
  const pw = process.env.APP_PASSWORD;
  return pw ? crypto.createHmac('sha256', pw).update('neptun-sync-v1').digest('hex') : null;
}
function tokenOk(req) {
  const exp = expectedToken();
  const got = String(req.get('x-app-token') || '');
  if (!exp || got.length !== exp.length) return false;
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(exp));
}
// כשמוגדרת סיסמה — כל נתיבי הנתונים דורשים התחברות
const PROTECTED = ['/api/files', '/api/state', '/api/data', '/api/clients', '/api/invoice', '/api/transactions', '/api/assistant', '/api/reminders/sync', '/api/green-invoice', '/api/vat', '/api/push'];
app.use((req, res, next) => {
  if (req.method === 'OPTIONS' || !process.env.APP_PASSWORD) return next();
  if (req.path === '/api/state/status') return next();
  if (!PROTECTED.some(p => req.path === p || req.path.startsWith(p + '/'))) return next();
  if (tokenOk(req)) return next();
  res.status(401).json({ error: 'auth' });
});

// הגנה מניחוש סיסמה: עד 10 ניסיונות כושלים ב-15 דקות לכל כתובת
const loginFails = new Map();
app.post('/api/auth/login', (req, res) => {
  if (!process.env.APP_PASSWORD) return res.status(503).json({ error: 'not_configured' });
  const ip = (req.get('x-forwarded-for') || req.ip || '').split(',')[0].trim();
  const now = Date.now();
  const f = loginFails.get(ip) || { n: 0, t: now };
  if (now - f.t > 15 * 60 * 1000) { f.n = 0; f.t = now; }
  if (f.n >= 10) return res.status(429).json({ error: 'יותר מדי ניסיונות. נסה שוב בעוד רבע שעה.' });
  const pw = String((req.body && req.body.password) || '');
  const a = crypto.createHash('sha256').update(pw).digest();
  const b = crypto.createHash('sha256').update(process.env.APP_PASSWORD).digest();
  if (!crypto.timingSafeEqual(a, b)) { f.n++; loginFails.set(ip, f); return res.status(401).json({ error: 'סיסמה שגויה' }); }
  loginFails.delete(ip);
  res.json({ token: expectedToken() });
});

// ===== כניסה עם זיהוי פנים / טביעת אצבע (Passkeys / WebAuthn) =====
// רישום: רק מי שכבר מחובר (token). כניסה: אימות חתימה של המכשיר → אותו token כמו בסיסמה.
// מפתחות ציבוריים נשמרים ב-collection 'passkeys'. בלי ספריות חיצוניות.
const PK_ORIGINS = (process.env.PASSKEY_ORIGINS || 'https://neptun-employees.onrender.com').split(',').map(x => x.trim()).filter(Boolean);
const pkChallenges = new Map(); // challenge → { kind, exp }
const b64u = buf => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = str => Buffer.from(String(str || '').replace(/-/g, '+').replace(/_/g, '/'), 'base64');
function pkNewChallenge(kind) {
  const c = b64u(crypto.randomBytes(32));
  pkChallenges.set(c, { kind, exp: Date.now() + 5 * 60 * 1000 });
  for (const [k, v] of pkChallenges) if (v.exp < Date.now()) pkChallenges.delete(k);
  return c;
}
function pkTakeChallenge(c, kind) {
  const v = pkChallenges.get(c); pkChallenges.delete(c);
  return !!(v && v.kind === kind && v.exp > Date.now());
}
function pkOrigin(req) { const o = String(req.get('origin') || ''); return PK_ORIGINS.includes(o) ? o : null; }
// מפענח CBOR מינימלי (מספיק ל-attestationObject ולמפתח COSE)
function cborDecode(buf) {
  let pos = 0;
  const readLen = ai => {
    if (ai < 24) return ai;
    if (ai === 24) return buf[pos++];
    if (ai === 25) { const v = buf.readUInt16BE(pos); pos += 2; return v; }
    if (ai === 26) { const v = buf.readUInt32BE(pos); pos += 4; return v; }
    if (ai === 27) { const v = Number(buf.readBigUInt64BE(pos)); pos += 8; return v; }
    throw new Error('cbor len');
  };
  const item = () => {
    const ib = buf[pos++]; const mt = ib >> 5; const ai = ib & 31;
    if (mt === 0) return readLen(ai);
    if (mt === 1) return -1 - readLen(ai);
    if (mt === 2) { const n = readLen(ai); const v = buf.subarray(pos, pos + n); pos += n; return v; }
    if (mt === 3) { const n = readLen(ai); const v = buf.subarray(pos, pos + n).toString('utf8'); pos += n; return v; }
    if (mt === 4) { const n = readLen(ai); const a = []; for (let i = 0; i < n; i++) a.push(item()); return a; }
    if (mt === 5) { const n = readLen(ai); const m = new Map(); for (let i = 0; i < n; i++) { const k = item(); m.set(k, item()); } return m; }
    if (mt === 7) { if (ai === 20) return false; if (ai === 21) return true; if (ai === 22) return null; }
    throw new Error('cbor type ' + mt);
  };
  const v = item();
  return { value: v, length: pos };
}
function coseToJwk(m) {
  const kty = m.get(1), alg = m.get(3);
  if (kty === 2 && alg === -7) return { alg: -7, jwk: { kty: 'EC', crv: 'P-256', x: b64u(m.get(-2)), y: b64u(m.get(-3)) } };
  if (kty === 3 && alg === -257) return { alg: -257, jwk: { kty: 'RSA', n: b64u(m.get(-1)), e: b64u(m.get(-2)) } };
  throw new Error('סוג מפתח לא נתמך');
}
function pkCheckClientData(cdjBuf, type, origin) {
  const cd = JSON.parse(cdjBuf.toString('utf8'));
  if (cd.type !== type) throw new Error('סוג בקשה שגוי');
  if (cd.origin !== origin) throw new Error('מקור לא מורשה');
  if (!pkTakeChallenge(cd.challenge, type)) throw new Error('האימות פג. נסה שוב.');
}
function pkCheckAuthData(ad, rpId) {
  if (!ad.subarray(0, 32).equals(crypto.createHash('sha256').update(rpId).digest())) throw new Error('rpId לא תואם');
  const flags = ad[32];
  if (!(flags & 0x01)) throw new Error('לא אושר במכשיר');
  return { flags, signCount: ad.readUInt32BE(33) };
}

app.get('/api/auth/passkey/status', async (req, res) => {
  try { res.json({ count: db ? await db.collection('passkeys').countDocuments() : 0 }); } catch (e) { res.json({ count: 0 }); }
});
app.post('/api/auth/passkey/register-options', (req, res) => {
  if (!tokenOk(req)) return res.status(401).json({ error: 'auth' });
  const origin = pkOrigin(req); if (!origin) return res.status(400).json({ error: 'מקור לא מורשה' });
  res.json({ challenge: pkNewChallenge('webauthn.create'), rpId: new URL(origin).hostname, userId: b64u(Buffer.from('neptun-owner')) });
});
app.post('/api/auth/passkey/register', async (req, res) => {
  try {
    if (!tokenOk(req)) return res.status(401).json({ error: 'auth' });
    if (!db) return res.status(503).json({ error: 'מסד הנתונים לא זמין' });
    const origin = pkOrigin(req); if (!origin) return res.status(400).json({ error: 'מקור לא מורשה' });
    const b = req.body || {};
    pkCheckClientData(fromB64u(b.clientDataJSON), 'webauthn.create', origin);
    const att = cborDecode(fromB64u(b.attestationObject)).value;
    const ad = att.get('authData');
    pkCheckAuthData(ad, new URL(origin).hostname);
    if (!(ad[32] & 0x40)) throw new Error('חסרים נתוני מפתח');
    const credLen = ad.readUInt16BE(53);
    const credId = ad.subarray(55, 55 + credLen);
    const key = coseToJwk(cborDecode(ad.subarray(55 + credLen)).value);
    await db.collection('passkeys').updateOne({ _id: b64u(credId) },
      { $set: { jwk: key.jwk, alg: key.alg, signCount: ad.readUInt32BE(33), name: String(b.name || '').slice(0, 60), createdAt: new Date() } }, { upsert: true });
    res.json({ ok: true });
  } catch (e) { console.error('passkey/register', e.message); res.status(400).json({ error: e.message }); }
});
app.post('/api/auth/passkey/login-options', async (req, res) => {
  const origin = pkOrigin(req); if (!origin) return res.status(400).json({ error: 'מקור לא מורשה' });
  if (!db) return res.status(503).json({ error: 'מסד הנתונים לא זמין' });
  const ids = (await db.collection('passkeys').find({}, { projection: { _id: 1 } }).toArray()).map(x => x._id);
  res.json({ challenge: pkNewChallenge('webauthn.get'), rpId: new URL(origin).hostname, ids });
});
app.post('/api/auth/passkey/login', async (req, res) => {
  const ip = (req.get('x-forwarded-for') || req.ip || '').split(',')[0].trim();
  const now = Date.now();
  const f = loginFails.get(ip) || { n: 0, t: now };
  if (now - f.t > 15 * 60 * 1000) { f.n = 0; f.t = now; }
  if (f.n >= 10) return res.status(429).json({ error: 'יותר מדי ניסיונות. נסה שוב בעוד רבע שעה.' });
  try {
    if (!process.env.APP_PASSWORD) return res.status(503).json({ error: 'not_configured' });
    if (!db) return res.status(503).json({ error: 'מסד הנתונים לא זמין' });
    const origin = pkOrigin(req); if (!origin) throw new Error('מקור לא מורשה');
    const b = req.body || {};
    const cred = await db.collection('passkeys').findOne({ _id: String(b.id || '') });
    if (!cred) throw new Error('המכשיר לא רשום. היכנס עם סיסמה והפעל זיהוי פנים מחדש.');
    const cdj = fromB64u(b.clientDataJSON);
    pkCheckClientData(cdj, 'webauthn.get', origin);
    const ad = fromB64u(b.authenticatorData);
    const { signCount } = pkCheckAuthData(ad, new URL(origin).hostname);
    const data = Buffer.concat([ad, crypto.createHash('sha256').update(cdj).digest()]);
    const keyObj = crypto.createPublicKey({ key: cred.jwk, format: 'jwk' });
    const ok = cred.alg === -257
      ? crypto.verify('sha256', data, { key: keyObj, padding: crypto.constants.RSA_PKCS1_PADDING }, fromB64u(b.signature))
      : crypto.verify('sha256', data, { key: keyObj, dsaEncoding: 'der' }, fromB64u(b.signature));
    if (!ok) throw new Error('האימות נכשל');
    if (signCount && cred.signCount && signCount <= cred.signCount) throw new Error('האימות נכשל (מונה)');
    await db.collection('passkeys').updateOne({ _id: cred._id }, { $set: { signCount, lastUsed: new Date() } });
    loginFails.delete(ip);
    res.json({ token: expectedToken() });
  } catch (e) {
    f.n++; loginFails.set(ip, f);
    res.status(401).json({ error: e.message || 'האימות נכשל' });
  }
});
app.post('/api/auth/passkey/clear', async (req, res) => {
  if (!tokenOk(req)) return res.status(401).json({ error: 'auth' });
  try { const r = await db.collection('passkeys').deleteMany({}); res.json({ ok: true, deleted: r.deletedCount }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ping', (req, res) => { res.json({ ok: true }); if (typeof pushSchedule === 'function') pushSchedule(); });

// ===== סנכרון נתונים בין מכשירים =====
// מסמך אחד: data = { מפתח: ערך JSON כטקסט }, kv = { מפתח: הגרסה שבה השתנה }
const STATE_ID = 'main';
const HISTORY_KEEP = 60;               // כמה גיבויים לשמור
const HISTORY_EVERY = 20 * 60 * 1000;  // גיבוי אוטומטי לכל היותר כל 20 דקות
const KEY_RE = /^nep_[A-Za-z0-9_\-]{1,80}$/;

async function getState() {
  return (await db.collection('appstate').findOne({ _id: STATE_ID })) || { _id: STATE_ID, version: 0, data: {}, kv: {} };
}
async function addHistory(state, kind, device) {
  if (!state || !state.version) return;
  const h = db.collection('appstate_history');
  await h.insertOne({ at: new Date(), kind, device: device || '', version: state.version, data: state.data });
  const old = await h.find({}, { projection: { _id: 1 } }).sort({ at: -1 }).skip(HISTORY_KEEP).toArray();
  if (old.length) await h.deleteMany({ _id: { $in: old.map(o => o._id) } });
}

app.get('/api/state/status', (req, res) => {
  res.json({ configured: !!process.env.APP_PASSWORD, db: !!db, authed: tokenOk(req) });
});

// משיכה: כל מה שהשתנה מאז גרסה since (0 = הכול)
app.get('/api/state', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const since = parseInt(req.query.since, 10) || 0;
    const st = await getState();
    const updates = {};
    for (const k of Object.keys(st.kv || {})) if ((st.kv[k] || 0) > since) updates[k] = st.data[k] === undefined ? null : st.data[k];
    res.json({ version: st.version, updates, updatedAt: st.updatedAt || null, device: st.device || '' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// דחיפה: changes = { מפתח: טקסט או null למחיקה }. נדחה אם מפתח השתנה בשרת מאז baseVersion
app.post('/api/state', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const base = parseInt(req.body && req.body.baseVersion, 10) || 0;
    const changes = (req.body && req.body.changes) || {};
    const device = String((req.body && req.body.device) || '').slice(0, 60);
    const keys = Object.keys(changes).filter(k => KEY_RE.test(k) && (changes[k] === null || typeof changes[k] === 'string'));
    for (let attempt = 0; attempt < 5; attempt++) {
      const st = await getState();
      const conflicts = keys.filter(k => (st.kv[k] || 0) > base);
      if (conflicts.length) return res.status(409).json({ error: 'conflict', version: st.version, conflicts });
      if (!keys.length) return res.json({ ok: true, version: st.version });
      const ver = st.version + 1;
      const $set = { version: ver, updatedAt: new Date(), device };
      const $unset = {};
      for (const k of keys) {
        if (changes[k] === null) $unset['data.' + k] = ''; else $set['data.' + k] = changes[k];
        $set['kv.' + k] = ver;
      }
      // גיבוי של המצב הקודם לפני השינוי
      const last = await db.collection('appstate_history').find({}, { projection: { at: 1 } }).sort({ at: -1 }).limit(1).toArray();
      if (!last.length || Date.now() - new Date(last[0].at).getTime() > HISTORY_EVERY) await addHistory(st, 'auto', device);
      const upd = { $set };
      if (Object.keys($unset).length) upd.$unset = $unset;
      const r = await db.collection('appstate').updateOne({ _id: STATE_ID, version: st.version }, upd, { upsert: st.version === 0 })
        .catch(e => (e.code === 11000 ? { matchedCount: 0, upsertedCount: 0 } : Promise.reject(e)));
      if (r.matchedCount || r.upsertedCount) return res.json({ ok: true, version: ver });
    }
    res.status(409).json({ error: 'busy' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// גיבוי של נתוני מכשיר (למשל לפני שמחליפים אותם בנתונים מהשרת)
app.post('/api/state/backup', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const data = {};
    const src = (req.body && req.body.data) || {};
    for (const k of Object.keys(src)) if (KEY_RE.test(k) && typeof src[k] === 'string') data[k] = src[k];
    await addHistory({ version: -1, data }, 'device', String((req.body && req.body.device) || '').slice(0, 60));
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/state/backups', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const list = await db.collection('appstate_history').find({}).sort({ at: -1 }).limit(HISTORY_KEEP).toArray();
    res.json(list.map(h => {
      let emp = 0;
      try { emp = JSON.parse((h.data || {}).nep_employees || '[]').length; } catch (e) {}
      return { id: String(h._id), at: h.at, kind: h.kind, device: h.device, employees: emp, size: JSON.stringify(h.data || {}).length };
    }));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// שחזור גיבוי — כל המכשירים יקבלו את הנתונים מחדש
app.post('/api/state/restore', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const { ObjectId } = require('mongodb');
    const h = await db.collection('appstate_history').findOne({ _id: new ObjectId(String(req.body && req.body.id)) });
    if (!h) return res.status(404).json({ error: 'גיבוי לא נמצא' });
    const st = await getState();
    await addHistory(st, 'before-restore', String((req.body && req.body.device) || ''));
    const ver = st.version + 1;
    const kv = {};
    for (const k of new Set([...Object.keys(st.data || {}), ...Object.keys(h.data || {})])) kv[k] = ver;
    await db.collection('appstate').updateOne({ _id: STATE_ID }, { $set: { version: ver, data: h.data || {}, kv, updatedAt: new Date(), device: 'שחזור' } }, { upsert: true });
    res.json({ ok: true, version: ver });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ===== קבצים מצורפים לעובד (דוחות שעות מצולמים / קבצים) =====
const FILE_MAX = 15 * 1024 * 1024;
app.post('/api/files', express.json({ limit: '25mb' }), async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const b = req.body || {};
    const empId = String(b.empId || '').slice(0, 60), month = String(b.month || '');
    if (!empId || !/^(\d{4}-\d{2}|101)$/.test(month)) return res.status(400).json({ error: 'חסר עובד או חודש' });
    if (typeof b.data !== 'string' || !b.data) return res.status(400).json({ error: 'אין קובץ' });
    const buf = Buffer.from(b.data, 'base64');
    if (!buf.length || buf.length > FILE_MAX) return res.status(413).json({ error: 'הקובץ גדול מדי (עד 15MB)' });
    const doc = { empId, month, name: String(b.name || 'קובץ').slice(0, 120), type: String(b.type || 'application/octet-stream').slice(0, 100),
      size: buf.length, data: buf, createdAt: new Date() };
    const r = await db.collection('files').insertOne(doc);
    res.json({ id: String(r.insertedId), name: doc.name, type: doc.type, size: doc.size, createdAt: doc.createdAt });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/files', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const q = { empId: String(req.query.empId || '') };
    if (req.query.month) q.month = String(req.query.month);
    const list = await db.collection('files').find(q, { projection: { data: 0 } }).sort({ createdAt: -1 }).limit(200).toArray();
    res.json(list.map(f => ({ id: String(f._id), name: f.name, type: f.type, size: f.size, month: f.month, createdAt: f.createdAt })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/files/:id', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const { ObjectId } = require('mongodb');
    const f = await db.collection('files').findOne({ _id: new ObjectId(String(req.params.id)) });
    if (!f) return res.status(404).json({ error: 'לא נמצא' });
    const buf = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data.buffer || f.data);
    res.set('Content-Type', f.type || 'application/octet-stream');
    res.set('Content-Disposition', "inline; filename*=UTF-8''" + encodeURIComponent(f.name || 'file'));
    res.send(buf);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/files/:id/delete', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const { ObjectId } = require('mongodb');
    await db.collection('files').deleteOne({ _id: new ObjectId(String(req.params.id)) });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// הנתיב הישן (/api/data) בוטל: הוא מחק והחליף נתונים בלי הגנה
app.all('/api/data', (req, res) => res.status(410).json({ error: 'הוחלף ב-/api/state' }));

// ===== GREEN INVOICE (MORNING) =====
// GREEN_INVOICE_BASE אפשר להפנות לסביבת הניסוי: https://sandbox.d.greeninvoice.co.il/api/v1
const GI_BASE = process.env.GREEN_INVOICE_BASE || 'https://api.greeninvoice.co.il/api/v1';

// ===== אימות מול מורנינג =====
// מאוקטובר 2026 מורנינג מנפיקה טוקן דרך OAuth (client credentials) ב-api.morning.co.
// הנתיב הישן /account/token מחזיר 404. מפתחות ה-API הקיימים (id/secret) ממשיכים לעבוד.
// קריאות ה-API עצמן נשארות ב-api.greeninvoice.co.il/api/v1.
const GI_AUTH_BASE = process.env.MORNING_AUTH_BASE || (/sandbox/.test(GI_BASE) ? 'https://api.sandbox.morning.dev' : 'https://api.morning.co');
let _giTok = { v: null, exp: 0 };
async function getGiToken(force) {
  if (!force && _giTok.v && Date.now() < _giTok.exp) return _giTok.v;
  const id = process.env.GREEN_INVOICE_API_KEY_ID, secret = process.env.GREEN_INVOICE_API_KEY_SECRET;
  if (!id || !secret) throw new Error('חסרים מפתחות API של מורנינג ב-Render');
  const url = `${GI_AUTH_BASE}/idp/v1/oauth/token`;
  const tryReq = async (asJson) => {
    const resp = await fetch(url, asJson
      ? { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ grant_type: 'client_credentials', client_id: id, client_secret: secret }) }
      : { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: id, client_secret: secret }).toString() });
    const text = await resp.text();
    let data = {}; try { data = text ? JSON.parse(text) : {}; } catch (e) {}
    return { resp, text, data, tok: data.accessToken || data.access_token || data.token };
  };
  let r = await tryReq(false);
  if (!r.tok) r = await tryReq(true);
  if (!r.resp.ok || !r.tok) {
    _giTok = { v: null, exp: 0 };
    const st = r.resp.status;
    const why = st === 400 || st === 401 || st === 403 ? 'מפתחות ה-API של מורנינג לא תקינים או בוטלו'
      : st === 429 ? 'מורנינג חסמה זמנית בגלל ריבוי בקשות' : 'מורנינג לא החזירה טוקן';
    const msg = r.data.errorMessage || r.data.error_description || r.data.error || (r.text && r.text.length < 160 ? r.text : '');
    throw new Error(why + ' (קוד ' + st + (msg ? ': ' + msg : '') + ')');
  }
  const ttl = Number(r.data.expiresIn || r.data.expires_in || 3600);
  _giTok = { v: r.tok, exp: Date.now() + Math.max(60, Math.min(ttl, 3600) - 300) * 1000 };
  return r.tok;
}

app.get('/api/health', async (req, res) => {
  try {
    const token = await getGiToken(!!req.query.fresh);
    res.json({ ok: !!token, mongo: !!db, base: GI_BASE, auth: GI_AUTH_BASE });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/clients', async (req, res) => {
  try {
    const token = await getGiToken();
    const resp = await fetch(`${GI_BASE}/clients/search`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ page: 1, pageSize: 100 })
});
const data = await resp.json();
res.json(data.items || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/invoice/create', async (req, res) => {
  try {
    const token = await getGiToken();
    const resp = await fetch(`${GI_BASE}/documents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(req.body)
    });
    const data = await resp.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== הפקת חשבונית חודשית ללקוח (מהכרטיס באפליקציה) =====
// גוף הבקשה: { clientGiId, clientName, month: 'YYYY-MM', type: 305|300, lines: [{description, quantity, price}], remarks?, force? }
// מחירים לפני מע"מ. מונע הפקה כפולה לאותו לקוח+חודש+סוג (אלא אם force).
app.post('/api/invoice/issue', async (req, res) => {
  try {
    const b = req.body || {};
    const type = parseInt(b.type, 10);
    if (![300, 305].includes(type)) return res.status(400).json({ error: 'סוג המסמך לא נתמך כאן (רק חשבונית מס או חשבון עסקה)' });
    if (!b.clientGiId) return res.status(400).json({ error: 'הלקוח לא מקושר למורנינג. ייבא את הלקוחות ממורנינג בדף הלקוחות.' });
    if (!/^\d{4}-\d{2}$/.test(String(b.month || ''))) return res.status(400).json({ error: 'חודש לא תקין' });
    const lines = Array.isArray(b.lines) ? b.lines : [];
    const income = lines.map(l => ({
      description: String(l.description || '').trim().slice(0, 300),
      quantity: Number(l.quantity),
      price: Number(l.price),
      currency: 'ILS',
      vatType: 0
    }));
    if (!income.length) return res.status(400).json({ error: 'אין שורות בחשבונית' });
    if (income.some(i => !i.description || !(i.quantity > 0) || !(i.price > 0))) return res.status(400).json({ error: 'בכל שורה צריך תיאור, כמות ומחיר גדולים מאפס' });
    if (!db) return res.status(503).json({ error: 'מסד הנתונים לא זמין כרגע, נסה שוב בעוד דקה' });

    const key = { clientGiId: String(b.clientGiId), month: b.month, type };
    const prev = await db.collection('invoices').findOne(key);
    if (prev && !b.force) return res.status(409).json({ error: 'כבר הופק מסמך ללקוח הזה לחודש הזה', prev: { number: prev.number, url: prev.url, createdAt: prev.createdAt } });

    const token = await getGiToken();
    if (!token) return res.status(502).json({ error: 'לא הצלחתי להתחבר למורנינג (בדוק את מפתחות ה-API ב-Render)' });
    const now = new Date();
    const today = new Date(now.getTime() + 2 * 3600 * 1000).toISOString().slice(0, 10); // בערך שעון ישראל
    const doc = {
      type, date: today, lang: 'he', currency: 'ILS', vatType: 0,
      description: String(b.description || '').slice(0, 200) || undefined,
      remarks: String(b.remarks || '').slice(0, 500) || undefined,
      client: { id: String(b.clientGiId), name: String(b.clientName || '') || undefined },
      income
    };
    const r = await fetch(`${GI_BASE}/documents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(doc)
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || data.errorCode || data.errorMessage) {
      console.error('GI issue failed', r.status, JSON.stringify(data).slice(0, 500));
      return res.status(502).json({ error: 'מורנינג החזירה שגיאה: ' + (data.errorMessage || data.message || r.status), gi: data });
    }
    const url = (data.url && (data.url.he || data.url.origin)) || data.url || null;
    const rec = { ...key, clientName: b.clientName || '', docId: data.id || null, number: data.number || null, url, total: income.reduce((s, i) => s + i.quantity * i.price, 0), createdAt: now };
    await db.collection('invoices').insertOne(rec);
    res.json({ ok: true, id: rec.docId, number: rec.number, url: rec.url });
  } catch (err) {
    console.error('invoice/issue', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== חשבוניות פתוחות של לקוח (מורנינג) =====
// GET /api/invoice/open?giId=... → [{ id, number, type, date, dueDate, total, url }]
// סטטוס 0 = פתוח (לא נסגר בקבלה). מסננים גם בצד שלנו לפי מזהה הלקוח, ליתר ביטחון.
app.get('/api/invoice/open', async (req, res) => {
  try {
    const giId = String(req.query.giId || '');
    if (!giId) return res.status(400).json({ error: 'חסר מזהה לקוח במורנינג' });
    const token = await getGiToken();
    if (!token) return res.status(502).json({ error: 'לא הצלחתי להתחבר למורנינג' });
    const all = await giSearchAll(token, { clientId: giId, status: [0], type: [300, 305, 320], sort: 'documentDate' }, 3);
    const items = all.filter(d => !d.client || !d.client.id || String(d.client.id) === giId).filter(d => d.status === undefined || d.status === 0);
    res.json(items.map(d => ({
      id: d.id, number: d.number, type: d.type,
      date: d.documentDate || d.creationDate || null,
      dueDate: d.dueDate || null,
      total: Number(d.amount != null ? d.amount : (d.total != null ? d.total : d.amountLocal)) || 0,
      url: (d.url && (d.url.he || d.url.origin)) || null
    })));
  } catch (err) {
    console.error('invoice/open', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== סיכום כסף ממורנינג: שולם (קבלות) מול פתוח (חשבוניות) =====
// GET /api/invoice/summary?month=YYYY-MM
// paid: קבלות (400) וחשבוניות מס/קבלה (320) שהופקו בחודש. last: התשלום האחרון של כל לקוח ב-6 החודשים האחרונים.
// open: חשבוניות מס / חשבונות עסקה (305/300) בסטטוס פתוח, לפי לקוח, כולל הוותיקה ביותר.
const _sumCache = new Map();
// העמוד הראשון בלי מספר עמוד (ברירת המחדל של מורנינג), ואז ממשיכים לפי מספר העמוד שמורנינג מחזירה — כך זה עובד בין אם הספירה מ-0 או מ-1
async function giSearchAll(token, body, maxPages = 5) {
  const out = [];
  let page = null;
  for (let i = 0; i < maxPages; i++) {
    const q = { ...body, pageSize: 100 };
    if (page !== null) q.page = page;
    const r = await fetch(`${GI_BASE}/documents/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(q)
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || data.errorCode) throw new Error('מורנינג החזירה שגיאה: ' + (data.errorMessage || r.status));
    const items = data.items || [];
    out.push(...items);
    const total = Number(data.total || 0);
    if (items.length < 100 || (total && out.length >= total)) break;
    const cur = typeof data.page === 'number' ? data.page : (page === null ? 1 : page);
    page = cur + 1;
  }
  return out;
}
app.get('/api/invoice/summary', async (req, res) => {
  try {
    const month = String(req.query.month || '');
    if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: 'חודש לא תקין' });
    const hit = _sumCache.get(month);
    if (hit && !req.query.fresh && Date.now() - hit.t < 5 * 60 * 1000) return res.json(hit.data);
    const token = await getGiToken();
    if (!token) return res.status(502).json({ error: 'לא הצלחתי להתחבר למורנינג' });
    const [y, m] = month.split('-').map(Number);
    const last = new Date(Date.UTC(y, m, 0)).toISOString().slice(0, 10);
    const from6 = new Date(Date.UTC(y, m - 6, 1)).toISOString().slice(0, 10);
    const prevMonth = new Date(Date.UTC(y, m - 2, 1)).toISOString().slice(0, 7);
    const amt = d => Number(d.amount != null ? d.amount : (d.total != null ? d.total : d.amountLocal)) || 0;
    const dt = d => String(d.documentDate || d.creationDate || '').slice(0, 10);
    const cid = d => (d.client && (d.client.id || d.client.name)) ? String(d.client.id || d.client.name) : '';
    const cname = d => (d.client && d.client.name) || '';

    const pStart = prevMonth + '-01';
    const pEnd = new Date(Date.UTC(y, m - 1, 0)).toISOString().slice(0, 10);
    const url = d => (d.url && (d.url.he || d.url.origin)) || (typeof d.url === 'string' ? d.url : null);
    // חשבוניות החודש הקודם (מופקות על חודש אחורה): פתוחות (0) מול שולמו/נסגרו (1, 2). מבוטלות (3, 4) לא נספרות.
    const invs = await giSearchAll(token, { type: [300, 305, 320], fromDate: pStart, toDate: pEnd, sort: 'documentDate' });
    const receipts = await giSearchAll(token, { type: [400, 320], fromDate: from6, toDate: last, sort: 'documentDate' });

    const lastPay = {};
    receipts.forEach(d => {
      const id = cid(d); const date = dt(d);
      if (id && date <= last && (!lastPay[id] || date > lastPay[id].date)) lastPay[id] = { date, total: amt(d), number: d.number || null };
    });
    const mk = () => ({ total: 0, count: 0, byClient: {} });
    const open = mk(), paid = mk();
    invs.forEach(d => {
      const st = d.status === undefined ? 0 : d.status;
      if (st === 3 || st === 4) return;
      const date = dt(d); if (!date.startsWith(prevMonth)) return;
      const bucket = st === 0 ? open : paid;
      const id = cid(d); const v = amt(d);
      bucket.total += v; bucket.count++;
      const c = bucket.byClient[id] || (bucket.byClient[id] = { name: cname(d), total: 0, count: 0, oldest: date, docs: [] });
      c.total += v; c.count++; if (date < c.oldest) c.oldest = date;
      if (c.docs.length < 20) c.docs.push({ number: d.number || null, type: d.type, date, total: v, url: url(d) });
    });
    const data = { month, openMonth: prevMonth, paid, open, last: lastPay, at: new Date().toISOString(), diag: { invoices: invs.length, receipts: receipts.length, statuses: invs.reduce((o, d) => { o[d.status] = (o[d.status] || 0) + 1; return o; }, {}) } };
    _sumCache.set(month, { t: Date.now(), data });
    res.json(data);
  } catch (err) {
    console.error('invoice/summary', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== CSV Upload =====
let lastTransactions = [];

app.post('/api/transactions/upload', upload.single('file'), (req, res) => {
  try {
    const content = req.file.buffer.toString('utf-8');
    const lines = content.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 2) return res.status(400).json({ error: 'קובץ ריק' });

    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    const rows = lines.slice(1).map(line => {
      const cols = line.split(',').map(c => c.trim().replace(/"/g, ''));
      const obj = {};
      headers.forEach((h, i) => obj[h] = cols[i] || '');
      return obj;
    }).filter(r => Object.values(r).some(v => v));

    lastTransactions = rows.map(r => {
      const dateField = r['תאריך'] || r['date'] || '';
      const descField = r['תיאור הפעולה'] || r['description'] || '';
      const detailField = r['פרטים'] || r['details'] || '';
      const creditField = r['זכות'] || r['credit'] || '';
      const debitField  = r['חובה'] || r['debit'] || '';
      const balField    = r['יתרה לאחר פעולה'] || r['balance'] || '';

      let clientName = '';
      const match = detailField.match(/המבצע[:\s]+([^|]+)/);
      if (match) {
        clientName = match[1].replace(/עבור:.*/, '').trim();
      } else {
        const systemWords = ['זיכוי מלאומי','זיכוי בינלאומי','זיכוי מהמזרחי','העברה',"העב'",'העברה/הפקדה','החזר'];
        if (!systemWords.some(w => descField.includes(w))) clientName = descField;
        else clientName = descField;
      }

      const credit = parseFloat(creditField.replace(/,/g,'')) || 0;
      const debit  = parseFloat(debitField.replace(/,/g,''))  || 0;
      const balance = parseFloat(balField.replace(/,/g,''))   || 0;

      return { date: dateField, description: descField, details: detailField, clientName, credit, debit, balance, raw: r };
    });

    res.json({ ok: true, count: lastTransactions.length, transactions: lastTransactions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/transactions', (req, res) => {
  res.json(lastTransactions);
});

app.post('/api/webhook', (req, res) => {
  console.log('Webhook received:', req.body);
  res.json({ ok: true });
});

// ===== AI ASSISTANT =====
const aiHits = new Map();
app.post('/api/assistant', async (req, res) => {
  try {
    const key = process.env.ANTHROPIC_API_KEY;
    const gKey = process.env.GEMINI_API_KEY;
    if (!key && !gKey) return res.status(500).json({ error: 'חסר מפתח AI בשרת (GEMINI_API_KEY או ANTHROPIC_API_KEY)' });
    // הגבלת קצב: 30 בקשות לשעה לכל IP
    const ip = req.ip || 'x';
    const now = Date.now();
    const arr = (aiHits.get(ip) || []).filter(t => now - t < 3600000);
    if (arr.length >= 30) return res.status(429).json({ error: 'יותר מדי בקשות, נסה מאוחר יותר' });
    arr.push(now); aiHits.set(ip, arr);

    const { text, today, weekday, employees = [], clients = [], context = {}, history = [] } = req.body || {};
    if (!text || typeof text !== 'string' || text.length > 2000) return res.status(400).json({ error: 'טקסט לא תקין' });

    const system = `אתה עוזר חכם בתוך מערכת ניהול עובדים של עסק ניקיון בעברית. התאריך היום: ${today} (${weekday}). אתה מדבר עם בעל העסק, מאור, בשפה קצרה וברורה.

נתוני המערכת (JSON):
עובדים פעילים: ${JSON.stringify(employees)}
לקוחות: ${JSON.stringify(clients)}
חודש פעיל: ${context.month || ''}
חיסורים בחודש הפעיל (כולל חילוף): ${JSON.stringify(context.absences || [])}
תזכורות פתוחות: ${JSON.stringify(context.reminders || [])}
חומרי ניקיון שנרשמו בחודש: ${JSON.stringify(context.supplies || [])}
מפרעות פעילות: ${JSON.stringify(context.advances || [])}

אתה עונה תמיד דרך הכלי submit_actions:
- reply: תשובה בעברית. אם זו שאלה על הנתונים – ענה מתוך הנתונים שלמעלה בלבד, בקצרה, ובלי להמציא. אם המידע לא קיים אצלך (למשל שעות עבודה רגילות), אמור שאין לך אותו. אם ביקשו פעולה – סכם במשפט מה הבנת.
- actions: פעולות לביצוע. ריק אם זו רק שאלה.
סוגי פעולות:
- add_notice: פתק קבוע בולט בדף הבית (text).
- add_absence: חיסור (empId, date YYYY-MM-DD). אם יש מחליף/ה – replacementId. hours רק אם צוין במפורש. client רק אם צוין. לטווח תאריכים או כמה ימים – החזר פעולה נפרדת לכל יום.
- delete_absence: ביטול חיסור קיים (absenceId מתוך רשימת החיסורים).
- add_reminder: תזכורת (text, date, time HH:MM רק אם צוינה שעה).
- delete_reminder: מחיקת תזכורת (reminderId).
- add_supply: חומרי ניקיון ללקוח (client מהרשימה בדיוק, text קצר כולל כמות).
- delete_supply: מחיקת רישום חומרים (supplyId).
- add_advance: מפרעה לעובד (empId, amount בש"ח, months מספר חודשי פריסה אם צוין, אחרת 1).
כללים: התאם עובדים ולקוחות לפי id/שם מהרשימות בלבד. אם יש כמה התאמות או שאין התאמה – אל תנחש; השאר actions ריק ובקש הבהרה ב-reply. תאריכים יחסיים ("מחר", "ביום שלישי הקרוב", "בשבוע הבא") חשב מהתאריך של היום. אם המשתמש מתקן אותך ("לא, התכוונתי ל...") – השתמש בהיסטוריית השיחה והחזר את הפעולות המתוקנות.`;

    const tool = {
      name: 'submit_actions',
      description: 'החזרת הפעולות לביצוע',
      input_schema: {
        type: 'object',
        properties: {
          reply: { type: 'string' },
          actions: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                type: { type: 'string', enum: ['add_notice', 'add_absence', 'delete_absence', 'add_reminder', 'delete_reminder', 'add_supply', 'delete_supply', 'add_advance'] },
                text: { type: 'string' },
                empId: { type: 'string' },
                date: { type: 'string' },
                time: { type: 'string' },
                replacementId: { type: 'string' },
                hours: { type: 'number' },
                client: { type: 'string' },
                absenceId: { type: 'string' },
                reminderId: { type: 'string' },
                supplyId: { type: 'string' },
                amount: { type: 'number' },
                months: { type: 'number' },
                note: { type: 'string' }
              },
              required: ['type']
            }
          }
        },
        required: ['reply', 'actions']
      }
    };

    const hist = (Array.isArray(history) ? history.slice(-6) : [])
      .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content)
      .map(m => ({ role: m.role, content: m.content.slice(0, 1500) }));

    if (key) {
      // ===== Claude =====
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({
          model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5',
          max_tokens: 2048,
          system,
          tools: [tool],
          tool_choice: { type: 'tool', name: 'submit_actions' },
          messages: hist.concat([{ role: 'user', content: text }])
        })
      });
      const data = await r.json();
      if (!r.ok) return res.status(502).json({ error: (data.error && data.error.message) || 'שגיאת AI' });
      const block = (data.content || []).find(b => b.type === 'tool_use');
      if (!block) return res.status(502).json({ error: 'תשובה לא צפויה' });
      return res.json(block.input);
    }

    // ===== Gemini (חינמי) =====
    const toGem = (s) => {
      if (Array.isArray(s)) return s.map(toGem);
      if (s && typeof s === 'object') {
        const o = {};
        for (const k of Object.keys(s)) o[k] = (k === 'type' && typeof s[k] === 'string') ? s[k].toUpperCase() : toGem(s[k]);
        return o;
      }
      return s;
    };
    const model = process.env.GEMINI_MODEL || 'gemini-3.8-flash';
    const gr = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
      method: 'POST',
      headers: { 'x-goog-api-key': gKey, 'content-type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: system }] },
        contents: hist.map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] }))
          .concat([{ role: 'user', parts: [{ text }] }]),
        tools: [{ functionDeclarations: [{ name: tool.name, description: tool.description, parameters: toGem(tool.input_schema) }] }],
        toolConfig: { functionCallingConfig: { mode: 'ANY', allowedFunctionNames: [tool.name] } }
      })
    });
    const gd = await gr.json().catch(() => ({}));
    if (!gr.ok) return res.status(502).json({ error: (gd.error && gd.error.message) || 'שגיאת AI' });
    const parts = (gd.candidates && gd.candidates[0] && gd.candidates[0].content && gd.candidates[0].content.parts) || [];
    const fc = parts.find(p => p.functionCall);
    if (!fc) return res.status(502).json({ error: 'תשובה לא צפויה מ-AI' });
    const args = fc.functionCall.args || {};
    return res.json({ reply: args.reply || '', actions: Array.isArray(args.actions) ? args.actions : [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== מע״מ: חשבוניות הכנסה מהתקופה + מסמכי הוצאות (צילום/סריקה/קובץ) =====
const VAT_RATE = Number(process.env.VAT_RATE || 0.18);
const VAT_CATS = ['חומרי ניקיון וציוד', 'דלק', 'רכב — טיפולים וחלקים', 'תקשורת', 'ביטוח', 'שכירות', 'שירותים מקצועיים', 'פרסום', 'ציוד משרדי ומחשוב', 'כיבוד ואירוח', 'אחר'];
const _ym = s => /^\d{4}-\d{2}$/.test(String(s || ''));
const _incCache = new Map();
// GET /api/vat/income?from=YYYY-MM&to=YYYY-MM — חשבוניות מס (305), מס/קבלה (320), זיכוי (330) לפי תאריך המסמך
app.get('/api/vat/income', async (req, res) => {
  try {
    const from = String(req.query.from || ''), to = String(req.query.to || from);
    if (!_ym(from) || !_ym(to) || to < from) return res.status(400).json({ error: 'תקופה לא תקינה' });
    const key = from + '_' + to, hit = _incCache.get(key);
    if (hit && !req.query.fresh && Date.now() - hit.t < 5 * 60 * 1000) return res.json(hit.data);
    const token = await getGiToken();
    if (!token) return res.status(502).json({ error: 'לא הצלחתי להתחבר למורנינג' });
    const [ty, tm] = to.split('-').map(Number);
    const fromDate = from + '-01', toDate = new Date(Date.UTC(ty, tm, 0)).toISOString().slice(0, 10);
    const docs = await giSearchAll(token, { type: [305, 320, 330], fromDate, toDate, sort: 'documentDate' }, 10);
    const r2 = n => Math.round(n * 100) / 100;
    const items = [];
    docs.forEach(d => {
      if (d.status === 3 || d.status === 4) return;
      const date = String(d.documentDate || d.creationDate || '').slice(0, 10);
      if (date < fromDate || date > toDate) return;
      const sign = d.type === 330 ? -1 : 1;
      const total = Math.abs(Number(d.amount != null ? d.amount : (d.total != null ? d.total : d.amountLocal)) || 0);
      let vat = d.vat != null ? Math.abs(Number(d.vat)) : null;
      if (vat == null && d.amountExcludeVat != null) vat = total - Math.abs(Number(d.amountExcludeVat));
      if (vat == null || isNaN(vat)) vat = total * VAT_RATE / (1 + VAT_RATE);
      items.push({ id: d.id, number: d.number || null, type: d.type, date, client: (d.client && d.client.name) || '', clientId: (d.client && d.client.id) || '',
        total: r2(sign * total), vat: r2(sign * vat), net: r2(sign * (total - vat)), url: (d.url && (d.url.he || d.url.origin)) || null });
    });
    const data = { from, to, items, at: new Date().toISOString() };
    _incCache.set(key, { t: Date.now(), data });
    res.json(data);
  } catch (err) { console.error('vat/income', err); res.status(500).json({ error: err.message }); }
});

const VAT_FILE_MAX = 15 * 1024 * 1024;
const _vatMeta = f => ({ id: String(f._id), claim: f.claim, supplier: f.supplier, date: f.date, number: f.number, total: f.total, vat: f.vat, category: f.category,
  note: f.note, name: f.name, type: f.type, size: f.size, createdAt: f.createdAt });
const _vatFields = b => {
  const o = {};
  if (b.supplier !== undefined) o.supplier = String(b.supplier || '').slice(0, 120);
  if (b.date !== undefined) o.date = /^\d{4}-\d{2}-\d{2}$/.test(b.date) ? b.date : '';
  if (b.number !== undefined) o.number = String(b.number || '').slice(0, 40);
  if (b.total !== undefined) o.total = Math.round((Number(b.total) || 0) * 100) / 100;
  if (b.vat !== undefined) o.vat = Math.round((Number(b.vat) || 0) * 100) / 100;
  if (b.category !== undefined) o.category = String(b.category || 'אחר').slice(0, 60);
  if (b.note !== undefined) o.note = String(b.note || '').slice(0, 300);
  if (b.claim !== undefined && _ym(b.claim)) o.claim = b.claim;
  return o;
};
app.post('/api/vat/doc', express.json({ limit: '25mb' }), async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const b = req.body || {};
    if (!_ym(b.claim)) return res.status(400).json({ error: 'חסר חודש' });
    const doc = { ..._vatFields(b), createdAt: new Date() };
    if (typeof b.data === 'string' && b.data) {
      const buf = Buffer.from(b.data, 'base64');
      if (!buf.length || buf.length > VAT_FILE_MAX) return res.status(413).json({ error: 'הקובץ גדול מדי (עד 15MB)' });
      Object.assign(doc, { name: String(b.name || 'מסמך').slice(0, 120), type: String(b.type || 'application/octet-stream').slice(0, 100), size: buf.length, data: buf });
    }
    const r = await db.collection('vatdocs').insertOne(doc);
    doc._id = r.insertedId;
    res.json(_vatMeta(doc));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/vat/docs', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const from = String(req.query.from || ''), to = String(req.query.to || from);
    if (!_ym(from) || !_ym(to)) return res.status(400).json({ error: 'תקופה לא תקינה' });
    const list = await db.collection('vatdocs').find({ claim: { $gte: from, $lte: to } }, { projection: { data: 0 } }).sort({ date: 1, createdAt: 1 }).limit(1000).toArray();
    res.json(list.map(_vatMeta));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/vat/doc/:id/file', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const { ObjectId } = require('mongodb');
    const f = await db.collection('vatdocs').findOne({ _id: new ObjectId(String(req.params.id)) });
    if (!f || !f.data) return res.status(404).json({ error: 'לא נמצא' });
    const buf = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data.buffer || f.data);
    res.set('Content-Type', f.type || 'application/octet-stream');
    res.set('Content-Disposition', "inline; filename*=UTF-8''" + encodeURIComponent(f.name || 'file'));
    res.send(buf);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/vat/doc/:id/update', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const { ObjectId } = require('mongodb');
    const set = _vatFields(req.body || {});
    const f = await db.collection('vatdocs').findOneAndUpdate({ _id: new ObjectId(String(req.params.id)) }, { $set: set }, { returnDocument: 'after', projection: { data: 0 } });
    const d = f && (f.value !== undefined ? f.value : f);
    if (!d) return res.status(404).json({ error: 'לא נמצא' });
    res.json(_vatMeta(d));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/vat/doc/:id/delete', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const { ObjectId } = require('mongodb');
    await db.collection('vatdocs').deleteOne({ _id: new ObjectId(String(req.params.id)) });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/vat/scan {data (base64), type} — קריאת פרטי המסמך עם AI (אם מוגדר מפתח)
app.post('/api/vat/scan', express.json({ limit: '25mb' }), async (req, res) => {
  try {
    const key = process.env.ANTHROPIC_API_KEY, gKey = process.env.GEMINI_API_KEY;
    if (!key && !gKey) return res.status(501).json({ error: 'no_ai' });
    const ip = req.ip || 'x', now = Date.now();
    const arr = (aiHits.get('scan_' + ip) || []).filter(t => now - t < 3600000);
    if (arr.length >= 60) return res.status(429).json({ error: 'יותר מדי סריקות, נסה מאוחר יותר' });
    arr.push(now); aiHits.set('scan_' + ip, arr);
    const b = req.body || {};
    const type = String(b.type || '');
    if (typeof b.data !== 'string' || !b.data || !/^(image\/(jpeg|png|webp|gif)|application\/pdf)$/.test(type)) return res.status(400).json({ error: 'סוג קובץ לא נתמך' });
    const prompt = `זה מסמך הוצאה (חשבונית/קבלה) של עסק ניקיון בישראל. חלץ את הפרטים. סכומים בשקלים כמספרים. total = הסכום הכולל לתשלום כולל מע"מ. vat = סכום המע"מ שמופיע במסמך (0 אם אין מע"מ, למשל ביטוח או עוסק פטור). date בפורמט YYYY-MM-DD. number = מספר החשבונית/הקבלה. supplier = שם העסק שהנפיק את המסמך (לא נפטון). category אחת מהרשימה. אם פרט לא מופיע – השאר ריק.`;
    const schema = { type: 'object', properties: { supplier: { type: 'string' }, date: { type: 'string' }, number: { type: 'string' }, total: { type: 'number' }, vat: { type: 'number' },
      category: { type: 'string', enum: VAT_CATS } }, required: ['supplier', 'total', 'category'] };
    let out = null;
    if (key) {
      const block = type === 'application/pdf' ? { type: 'document', source: { type: 'base64', media_type: type, data: b.data } } : { type: 'image', source: { type: 'base64', media_type: type, data: b.data } };
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST', headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5', max_tokens: 800,
          tools: [{ name: 'doc', description: 'פרטי המסמך', input_schema: schema }], tool_choice: { type: 'tool', name: 'doc' },
          messages: [{ role: 'user', content: [block, { type: 'text', text: prompt }] }] })
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) return res.status(502).json({ error: (data.error && data.error.message) || 'שגיאת AI' });
      const tb = (data.content || []).find(x => x.type === 'tool_use'); out = tb && tb.input;
    } else {
      const up = s => Array.isArray(s) ? s.map(up) : (s && typeof s === 'object') ? Object.fromEntries(Object.entries(s).map(([k, v]) => [k, k === 'type' && typeof v === 'string' ? v.toUpperCase() : up(v)])) : s;
      const model = process.env.GEMINI_MODEL || 'gemini-3.8-flash';
      const gr = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: 'POST', headers: { 'x-goog-api-key': gKey, 'content-type': 'application/json' },
        body: JSON.stringify({ contents: [{ role: 'user', parts: [{ inline_data: { mime_type: type, data: b.data } }, { text: prompt }] }],
          generationConfig: { responseMimeType: 'application/json', responseSchema: up(schema) } })
      });
      const gd = await gr.json().catch(() => ({}));
      if (!gr.ok) return res.status(502).json({ error: (gd.error && gd.error.message) || 'שגיאת AI' });
      const t = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
      try { out = JSON.parse((t.find(p => p.text) || {}).text || 'null'); } catch (e) { out = null; }
    }
    if (!out) return res.status(502).json({ error: 'לא הצלחתי לקרוא את המסמך' });
    if (out.category && !VAT_CATS.includes(out.category)) out.category = 'אחר';
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== REMINDERS + WHATSAPP (GREEN-API) =====
function israelNow() {
  const s = new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Jerusalem' }); // YYYY-MM-DD HH:MM:SS
  return { date: s.slice(0, 10), hm: s.slice(11, 16) };
}

// סנכרון תזכורות מהדפדפן (שומר waSent שכבר נקבע בשרת)
app.post('/api/reminders/sync', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const list = Array.isArray(req.body && req.body.reminders) ? req.body.reminders.slice(0, 500) : [];
    const col = db.collection('reminders');
    const ids = [];
    for (const r of list) {
      if (!r || !r.id || !r.text || !/^\d{4}-\d{2}-\d{2}$/.test(r.date || '')) continue;
      ids.push(String(r.id));
      const time = /^\d{2}:\d{2}$/.test(r.time || '') ? r.time : '';
      const set = { text: String(r.text).slice(0, 500), date: r.date, time, done: !!r.done, wa: r.wa !== false, repeat: r.repeat === 'daily' ? 'daily' : '' };
      const prev = await col.findOne({ id: String(r.id) });
      // תאריך/שעה השתנו (למשל תזכורת יומית שעברה ליום הבא) — לשלוח שוב
      if (!prev || prev.date !== set.date || (prev.time || '') !== time) { set.waSent = false; set.pushSent = false; }
      await col.updateOne({ id: String(r.id) }, { $set: set, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
    }
    await col.deleteMany({ id: { $nin: ids } });
    res.json({ ok: true, count: ids.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function greenApi(method, pathPart, body) {
  const base = process.env.GREEN_API_URL || 'https://api.green-api.com';
  const url = `${base}/waInstance${process.env.GREEN_API_INSTANCE}/${pathPart}/${process.env.GREEN_API_TOKEN}`;
  const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('Green-API ' + r.status + ' ' + JSON.stringify(data));
  return data;
}
function cronAuth(req, res) {
  if (!process.env.CRON_SECRET || req.query.secret !== process.env.CRON_SECRET) { res.status(401).json({ error: 'unauthorized' }); return false; }
  return true;
}

// נקרא כל דקה ע"י שירות cron חיצוני: שולח תזכורות שהגיע זמנן
app.get('/api/reminders/tick', async (req, res) => {
  try {
    if (!cronAuth(req, res)) return;
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    pushSchedule();
    const { date, hm } = israelNow();
    const defHour = (process.env.REMINDER_DEFAULT_TIME || '08:00');
    const due = await db.collection('reminders').find({ done: false, wa: true, date: { $lte: date }, $or: [{ waSent: { $ne: true } }, { repeat: 'daily' }] }).toArray();
    let sent = 0, skipped = 0;
    for (const r of due) {
      // תזכורת יומית — מתגלגלת להיום גם אם האתר לא נפתח
      if (r.repeat === 'daily' && r.date < date) {
        await db.collection('reminders').updateOne({ id: r.id }, { $set: { date, waSent: false, pushSent: false } });
        r.date = date; r.waSent = false;
      }
      if (r.waSent) continue;
      if (r.date < date) { await db.collection('reminders').updateOne({ id: r.id }, { $set: { waSent: true, waNote: 'old' } }); skipped++; continue; }
      const when = r.time || defHour;
      if (when > hm) continue;
      if (!process.env.WA_GROUP_ID || !process.env.GREEN_API_INSTANCE || !process.env.GREEN_API_TOKEN) { skipped++; continue; }
      try {
        await greenApi('POST', 'sendMessage', { chatId: process.env.WA_GROUP_ID, message: '⏰ תזכורת: ' + r.text });
        await db.collection('reminders').updateOne({ id: r.id }, { $set: { waSent: true, waSentAt: new Date() } });
        sent++;
      } catch (e) { console.error('WA send failed:', e.message); }
    }
    res.json({ ok: true, now: date + ' ' + hm, due: due.length, sent, skipped });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== התראות לטלפון (Web Push) =====
let webpush = null;
try { webpush = require('web-push'); } catch (e) { console.warn('web-push לא מותקן — התראות כבויות'); }
let _vapid = null;
async function vapidKeys() {
  if (_vapid) return _vapid;
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) _vapid = { publicKey: process.env.VAPID_PUBLIC_KEY, privateKey: process.env.VAPID_PRIVATE_KEY };
  else if (db && webpush) {
    const col = db.collection('config');
    let doc = await col.findOne({ _id: 'vapid' });
    if (!doc) { const k = webpush.generateVAPIDKeys(); doc = { _id: 'vapid', publicKey: k.publicKey, privateKey: k.privateKey }; await col.insertOne(doc); }
    _vapid = { publicKey: doc.publicKey, privateKey: doc.privateKey };
  }
  if (_vapid && webpush) webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'https://neptun-employees.onrender.com', _vapid.publicKey, _vapid.privateKey);
  return _vapid;
}
const PUSH_DEF = { inv: true, vat: true, open: false, rem: true };
const _pushId = ep => require('crypto').createHash('sha256').update(String(ep)).digest('hex').slice(0, 32);
const _pushPrefs = p => { const o = {}; Object.keys(PUSH_DEF).forEach(k => { o[k] = p && p[k] !== undefined ? !!p[k] : PUSH_DEF[k]; }); return o; };
app.get('/api/push/key', async (req, res) => {
  try { if (!webpush) return res.status(501).json({ error: 'השרת לא תומך בהתראות עדיין' }); const k = await vapidKeys(); if (!k) return res.status(503).json({ error: 'DB לא מוכן' }); res.json({ key: k.publicKey }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/push/subscribe', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const sub = req.body && req.body.sub;
    if (!sub || typeof sub.endpoint !== 'string' || !/^https:\/\//.test(sub.endpoint) || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return res.status(400).json({ error: 'מנוי לא תקין' });
    const id = _pushId(sub.endpoint), prefs = _pushPrefs(req.body.prefs);
    await db.collection('pushsubs').updateOne({ _id: id }, { $set: { sub: { endpoint: sub.endpoint, keys: { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) } }, prefs, device: String(req.body.device || '').slice(0, 60), updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
    res.json({ ok: true, id, prefs });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/push/prefs', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const id = _pushId(req.body && req.body.endpoint), prefs = _pushPrefs(req.body.prefs);
    const d = await db.collection('pushsubs').findOne({ _id: id });
    if (!d) return res.status(404).json({ error: 'המכשיר לא רשום להתראות' });
    await db.collection('pushsubs').updateOne({ _id: id }, { $set: { prefs, updatedAt: new Date() } });
    res.json({ ok: true, prefs });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/push/status', async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'DB לא מוכן' });
    const d = await db.collection('pushsubs').findOne({ _id: _pushId(req.body && req.body.endpoint) });
    res.json(d ? { on: true, prefs: _pushPrefs(d.prefs) } : { on: false, prefs: PUSH_DEF });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/push/unsubscribe', async (req, res) => {
  try { if (db) await db.collection('pushsubs').deleteOne({ _id: _pushId(req.body && req.body.endpoint) }); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
async function pushSend(kind, msg, onlyId) {
  if (!webpush || !db) return 0;
  await vapidKeys();
  const q = onlyId ? { _id: onlyId } : {};
  const subs = await db.collection('pushsubs').find(q).toArray();
  let n = 0;
  for (const s of subs) {
    if (!onlyId && kind && !_pushPrefs(s.prefs)[kind]) continue;
    try { await webpush.sendNotification(s.sub, JSON.stringify(msg), { TTL: 24 * 3600, urgency: 'high' }); n++; }
    catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) await db.collection('pushsubs').deleteOne({ _id: s._id });
      else console.error('push failed', e.statusCode, e.body || e.message);
    }
  }
  return n;
}
app.post('/api/push/test', async (req, res) => {
  try {
    const n = await pushSend(null, { title: 'נפטון', body: '✅ ההתראות עובדות במכשיר הזה', tag: 'test', url: './' }, _pushId(req.body && req.body.endpoint));
    if (!n) return res.status(404).json({ error: 'לא נשלח — נסה לכבות ולהדליק את ההתראות' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
// תזמון: חשבוניות ב-1 לחודש, מע״מ ב-10, חשבוניות פתוחות בימי ראשון, ותזכורות שהגיע זמנן
const PUSH_AT = process.env.PUSH_TIME || '09:00';
async function _pushOnce(key, fn) {
  const col = db.collection('pushlog');
  if (await col.findOne({ _id: key })) return;
  await col.insertOne({ _id: key, at: new Date() });
  try { await fn(); } catch (e) { console.error('push job', key, e.message); }
}
let _pushBusy = false;
async function pushSchedule() {
  if (!webpush || !db || _pushBusy) return;
  _pushBusy = true;
  try {
    if (!(await db.collection('pushsubs').countDocuments())) return;
    const { date, hm } = israelNow();
    const day = Number(date.slice(8, 10)), dow = new Date(date + 'T12:00:00Z').getUTCDay();
    const prevName = (() => { const [y, m] = date.split('-').map(Number); return new Date(Date.UTC(y, m - 2, 1)).toLocaleDateString('he-IL', { month: 'long', timeZone: 'UTC' }); })();
    if (hm >= PUSH_AT) {
      if (day === 1) await _pushOnce('inv_' + date, () => pushSend('inv', { title: 'הפקת חשבוניות', body: 'היום ה-1 לחודש — זמן להפיק חשבוניות על ' + prevName, tag: 'inv', url: './#clients' }));
      if (day === 10) await _pushOnce('vat_' + date, () => pushSend('vat', { title: 'דוח מע״מ', body: 'עד ה-15 צריך להגיש את דוח המע״מ. הדוח מוכן במסך מע״מ', tag: 'vat', url: './#vat' }));
      if (dow === 0) await _pushOnce('open_' + date, async () => {
        const token = await getGiToken(); if (!token) return;
        const d30 = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
        const docs = await giSearchAll(token, { type: [300, 305], status: [0], toDate: d30 }, 5);
        const open = docs.filter(x => x.status === 0 && String(x.documentDate || '').slice(0, 10) <= d30);
        if (!open.length) return;
        const sum = Math.round(open.reduce((s, x) => s + (Number(x.amount) || 0), 0));
        await pushSend('open', { title: 'חשבוניות פתוחות', body: open.length + ' חשבוניות פתוחות מעל 30 יום · ₪' + sum.toLocaleString('he-IL'), tag: 'open', url: './' });
      });
    }
    // תזכורות מהאפליקציה
    const defHour = (process.env.REMINDER_DEFAULT_TIME || '08:00');
    const old = await db.collection('reminders').find({ done: false, repeat: 'daily', date: { $lt: date } }).toArray();
    for (const r of old) await db.collection('reminders').updateOne({ id: r.id }, { $set: { date, waSent: false, pushSent: false } });
    const rems = await db.collection('reminders').find({ done: false, date }).toArray();
    for (const r of rems) {
      if (r.pushSent || (r.time || defHour) > hm) continue;
      await db.collection('reminders').updateOne({ id: r.id }, { $set: { pushSent: true } });
      await pushSend('rem', { title: 'תזכורת', body: r.text, tag: 'rem_' + r.id, url: './' });
    }
  } catch (e) { console.error('pushSchedule', e.message); }
  finally { _pushBusy = false; }
}
setInterval(pushSchedule, 60 * 1000);

// עזר: רשימת קבוצות וואטסאפ כדי למצוא את ה-chatId של הקבוצה
app.get('/api/wa/groups', async (req, res) => {
  try {
    if (!cronAuth(req, res)) return;
    const chats = await greenApi('GET', 'getChats');
    res.json((chats || []).filter(c => c.id && c.id.endsWith('@g.us')).map(c => ({ id: c.id, name: c.name })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== SPA Fallback =====
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));app.get('/api/green-invoice/items', async function(req, res) {
  try {
    const t = await getToken();
    const r = await axios.get(BASE + '/items?page=1&pageSize=200', { headers: { Authorization: 'Bearer ' + t } });
    res.json({ items: (r.data.items||[]).map(function(i){ return {id:i.id,name:i.name,price:i.price||0}; }) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
