const express = require('express');
const cors = require('cors');
const axios = require('axios');
const app = express();
app.use(cors());
app.use(express.json());

const ID = process.env.GREEN_INVOICE_API_KEY_ID;
const SECRET = process.env.GREEN_INVOICE_API_KEY_SECRET;
const BASE = 'https://api.greeninvoice.co.il/api/v1';

let tok = null;
let exp = null;

async function getToken() {
  if (tok && exp > Date.now()) return tok;
  const r = await axios.post(BASE + '/account/token', { id: ID, secret: SECRET });
  tok = r.data.token;
  exp = Date.now() + 3500000;
  return tok;
}

app.get('/api/clients', async function(req, res) {
  try {
    const t = await getToken();
    const r = await axios.post(BASE + '/documents/search', {
      page: 1,
      pageSize: 100,
      type: [320, 305, 300]
    }, {
      headers: { Authorization: 'Bearer ' + t }
    });
    const clients = [];
    const seen = {};
    (r.data.items || []).forEach(function(doc) {
      if (doc.client && doc.client.name && !seen[doc.client.name]) {
        seen[doc.client.name] = true;
        clients.push({ id: doc.client.id, name: doc.client.name, email: doc.client.emails ? doc.client.emails[0] : '' });
      }
    });
    res.json({ items: clients, total: clients.length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
  }
});

app.get('/api/clients', async function(req, res) {
  try {
    const t = await getToken();
    const r = await axios.post(BASE + '/clients/search', {
      page: 1,
      pageSize: 100
    }, {
      headers: { Authorization: 'Bearer ' + t }
    });
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
      type: 320,
      lang: 'he',
      currency: 'ILS',
      vatType: 0,
      client: {
        name: b.clientName,
        emails: b.clientEmail ? [b.clientEmail] : [],
        phone: b.clientPhone || '',
        add: true
      },
      income: [{ description: b.description || 'תשלום', price: b.amount, currency: 'ILS', vatType: 0 }],
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