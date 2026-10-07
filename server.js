require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({ origin: '*', methods: ['GET','POST','OPTIONS'] }));
app.use(express.json({ limit: '10mb' }));

// ===== MongoDB =====
const MONGO_URI = process.env.MONGODB_URI;
let db;

async function connectDB() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    db = client.db('neptun');
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
  }
}
connectDB();

// ===== Static Frontend =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== DATA SYNC API =====

// טען את כל הנתונים
app.get('/api/data', async (req, res) => {
  try {
    const employees = await db.collection('employees').find({}).toArray();
    const absences  = await db.collection('absences').find({}).toArray();
    const hoursLog  = await db.collection('hoursLog').find({}).toArray();
    res.json({ employees, absences, hoursLog });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// שמור את כל הנתונים (replace כל הקולקציה)
app.post('/api/data', async (req, res) => {
  try {
    const { employees = [], absences = [], hoursLog = [] } = req.body;

    // מחק והחלף
    await db.collection('employees').deleteMany({});
    await db.collection('absences').deleteMany({});
    await db.collection('hoursLog').deleteMany({});

    if (employees.length)  await db.collection('employees').insertMany(employees);
    if (absences.length)   await db.collection('absences').insertMany(absences);
    if (hoursLog.length)   await db.collection('hoursLog').insertMany(hoursLog);

    res.json({ ok: true, employees: employees.length, absences: absences.length, hoursLog: hoursLog.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== GREEN INVOICE (MORNING) =====
const GI_BASE = 'https://api.greeninvoice.co.il/api/v1';

async function getGiToken() {
  const resp = await fetch(`${GI_BASE}/account/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: process.env.GREEN_INVOICE_API_KEY_ID,
      secret: process.env.GREEN_INVOICE_API_KEY_SECRET
    })
  });
  const data = await resp.json();
  return data.token;
}

app.get('/api/health', async (req, res) => {
  try {
    const token = await getGiToken();
    res.json({ ok: !!token, mongo: !!db });
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
    if (!key) return res.status(500).json({ error: 'חסר ANTHROPIC_API_KEY בשרת' });
    // הגבלת קצב: 30 בקשות לשעה לכל IP
    const ip = req.ip || 'x';
    const now = Date.now();
    const arr = (aiHits.get(ip) || []).filter(t => now - t < 3600000);
    if (arr.length >= 30) return res.status(429).json({ error: 'יותר מדי בקשות, נסה מאוחר יותר' });
    arr.push(now); aiHits.set(ip, arr);

    const { text, today, weekday, employees = [], clients = [] } = req.body || {};
    if (!text || typeof text !== 'string' || text.length > 2000) return res.status(400).json({ error: 'טקסט לא תקין' });

    const system = `אתה עוזר בתוך מערכת ניהול עובדים של עסק ניקיון בעברית. התאריך היום: ${today} (${weekday}).
רשימת העובדים הפעילים (JSON): ${JSON.stringify(employees)}.
רשימת הלקוחות (JSON): ${JSON.stringify(clients)}.
המשתמש כותב טקסט חופשי. עליך להחזיר פעולות באמצעות הכלי submit_actions בלבד:
- add_notice: הודעה/תזכורת שתוצג בולטת בדף הבית. נסח אותה קצרה וברורה.
- add_absence: עובד/ת שנעדר/ת בתאריך מסוים. אם צוין מחליף/ה (חילוף) – מלא replacementId. חשב תאריך מדויק YYYY-MM-DD לפי התאריך של היום ("היום", "מחר", "אתמול", "ביום שלישי הקרוב" וכו').
- add_reminder: תזכורת לעתיד (text = מה להזכיר, date = YYYY-MM-DD מחושב לפי היום, time = HH:MM בפורמט 24 שעות רק אם צוינה שעה). הבדל מ-add_notice: תזכורת קשורה לזמן מסוים; הודעה היא פתק קבוע בדף הבית.
- add_supply: רישום חומרי ניקיון שנמסרו ללקוח (client = שם לקוח מהרשימה בדיוק, text = מה נרשם, בניסוח קצר כפי שנכתב, כולל כמות, למשל "3 סבון רצפות").
התאם שמות לעובדים ברשימה לפי id בלבד. אם השם לא ברור או לא קיים – אל תמציא id; הסבר ב-reply.
hours: שעות המחליף/ה, רק אם צוין במפורש, אחרת השמט.
client: רק אם צוין במפורש. אפשר להחזיר כמה פעולות. reply: משפט קצר בעברית שמסכם מה הבנת.`;

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
                type: { type: 'string', enum: ['add_notice', 'add_absence', 'add_supply', 'add_reminder'] },
                text: { type: 'string' },
                empId: { type: 'string' },
                date: { type: 'string' },
                time: { type: 'string' },
                replacementId: { type: 'string' },
                hours: { type: 'number' },
                client: { type: 'string' },
                note: { type: 'string' }
              },
              required: ['type']
            }
          }
        },
        required: ['reply', 'actions']
      }
    };

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5',
        max_tokens: 1024,
        system,
        tools: [tool],
        tool_choice: { type: 'tool', name: 'submit_actions' },
        messages: [{ role: 'user', content: text }]
      })
    });
    const data = await r.json();
    if (!r.ok) return res.status(502).json({ error: (data.error && data.error.message) || 'שגיאת AI' });
    const block = (data.content || []).find(b => b.type === 'tool_use');
    if (!block) return res.status(502).json({ error: 'תשובה לא צפויה' });
    res.json(block.input);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
      await col.updateOne(
        { id: String(r.id) },
        { $set: { text: String(r.text).slice(0, 500), date: r.date, time: /^\d{2}:\d{2}$/.test(r.time || '') ? r.time : '', done: !!r.done, wa: r.wa !== false },
          $setOnInsert: { waSent: false, createdAt: new Date() } },
        { upsert: true }
      );
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
    const { date, hm } = israelNow();
    const defHour = (process.env.REMINDER_DEFAULT_TIME || '08:00');
    const due = await db.collection('reminders').find({ done: false, waSent: false, wa: true, date: { $lte: date } }).toArray();
    let sent = 0, skipped = 0;
    for (const r of due) {
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
