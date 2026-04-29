require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
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
    const resp = await fetch(`${GI_BASE}/clients?page=1&pageSize=100`, {
      headers: { Authorization: `Bearer ${token}` }
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

// ===== SPA Fallback =====
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));