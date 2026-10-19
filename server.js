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
      if (!prev || prev.date !== set.date || (prev.time || '') !== time) set.waSent = false;
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
    const { date, hm } = israelNow();
    const defHour = (process.env.REMINDER_DEFAULT_TIME || '08:00');
    const due = await db.collection('reminders').find({ done: false, wa: true, date: { $lte: date }, $or: [{ waSent: { $ne: true } }, { repeat: 'daily' }] }).toArray();
    let sent = 0, skipped = 0;
    for (const r of due) {
      // תזכורת יומית — מתגלגלת להיום גם אם האתר לא נפתח
      if (r.repeat === 'daily' && r.date < date) {
        await db.collection('reminders').updateOne({ id: r.id }, { $set: { date, waSent: false } });
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
