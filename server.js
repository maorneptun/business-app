require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ dest: '/tmp/uploads/' });

const ID = process.env.GREEN_INVOICE_API_KEY_ID;
const SECRET = process.env.GREEN_INVOICE_API_KEY_SECRET;
const BASE = 'https://api.greeninvoice.co.il/api/v1';

let tok = null;
let exp = null;

// תנועות CSV בזיכרון
let csvTransactions = [];

async function getToken() {
  if (tok && exp > Date.now()) return tok;
  const r = await axios.post(BASE + '/account/token', { id: ID, secret: SECRET });
  tok = r.data.token;
  exp = Date.now() + 3500000;
  return tok;
}

// פרסר CSV של בנק הפועלים
function parsePoalimCSV(content) {
  // הסר BOM אם קיים
  content = content.replace(/^\uFEFF/, '');

  const lines = content.split('\n').filter(l => l.trim());
  const transactions = [];

  // שורה ראשונה = headers, דלג עליה
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',');
    if (cols.length < 8) continue;

    const date = (cols[0] || '').trim();
    const description = (cols[1] || '').trim();
    const details = (cols[2] || '').trim();
    const debit = parseFloat((cols[6] || '').trim()) || 0;
    const credit = parseFloat((cols[7] || '').trim()) || 0;
    const balance = parseFloat((cols[8] || '').trim()) || 0;

    if (!date || (!debit && !credit)) continue;

    // זיהוי שם לקוח — נסה מ"פרטים" קודם, אחרי כן מ"תיאור"
    let clientName = '';
    if (details) {
      // חלץ שם מ"עבור: XXX"
      const match = details.match(/עבור:\s*(.+?)(?:\s+מזהה|\s+מח-ן|$)/);
      if (match) clientName = match[1].trim();
    }
    if (!clientName) clientName = description;

    const isIncome = credit > 0;

    transactions.push({
      id: 'csv_' + date + '_' + i,
      date: date,
      description: description,
      details: details,
      clientName: clientName,
      amount: isIncome ? credit : debit,
      type: isIncome ? 'credit' : 'debit',
      balance: balance,
      canInvoice: isIncome,
      done: false,
      source: 'csv'
    });
  }

  return transactions;
}

// ===== ENDPOINTS =====

app.get('/api/health', async function(req, res) {
  try {
    await getToken();
    res.json({ status: 'ok', connected: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// העלאת CSV
app.post('/api/transactions/upload', upload.single('csv'), function(req, res) {
  try {
    if (!req.file) return res.status(400).json({ error: 'לא התקבל קובץ' });

    const content = fs.readFileSync(req.file.path, 'utf8');
    fs.unlinkSync(req.file.path); // מחק קובץ זמני

    const parsed = parsePoalimCSV(content);
    if (parsed.length === 0) {
      return res.status(400).json({ error: 'לא נמצאו תנועות בקובץ' });
    }

    csvTransactions = parsed;
    console.log('CSV imported:', parsed.length, 'transactions');

    res.json({
      success: true,
      count: parsed.length,
      transactions: parsed
    });
  } catch(e) {
    console.error('CSV parse error:', e);
    res.status(500).json({ error: e.message });
  }
});

// קבלת תנועות (CSV בלבד)
app.get('/api/transactions', function(req, res) {
  res.json({ transactions: csvTransactions, source: 'csv' });
});

// רשימת לקוחות ממורנינג
app.get('/api/clients', async function(req, res) {
  try {
    const t = await getToken();
    const r = await axios.post(BASE + '/documents/search', { page: 1, pageSize: 100, type: [320, 305, 300] }, { headers: { Authorization: 'Bearer ' + t } });
    const clients = [];
    const seen = {};
    (r.data.items || []).forEach(function(doc) {
      if (doc.client && doc.client.name && !seen[doc.client.name]) {
        seen[doc.client.name] = true;
        clients.push({ id: doc.client.id, name: doc.client.name });
      }
    });
    res.json({ items: clients });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/webhook', function(req, res) {
  console.log('Webhook:', JSON.stringify(req.body));
  res.json({ ok: true });
});

app.post('/api/invoice/create', async function(req, res) {
  try {
    const b = req.body;
    const t = await getToken();
    const r = await axios.post(BASE + '/documents', {
      type: 320, lang: 'he', currency: 'ILS', vatType: 0,
      client: { name: b.clientName, emails: b.clientEmail ? [b.clientEmail] : [], phone: b.clientPhone || '', add: true },
      income: [{ description: b.description || 'שירותים', price: b.amount, currency: 'ILS', vatType: 0 }],
      payment: [{ type: 1, price: b.amount, currency: 'ILS', date: new Date().toISOString().split('T')[0] }]
    }, { headers: { Authorization: 'Bearer ' + t } });
    res.json({ success: true, invoiceId: r.data.id, invoiceNumber: r.data.number });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(4000, function() {
  console.log('Server running on port 4000');
});
