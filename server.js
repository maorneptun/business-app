const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

const ID = '94814b61-b92e-4a3d-9dea-ec9ca53aa9c7';
const SECRET = process.env.GREEN_INVOICE_API_KEY_SECRET || '_7p5_[m[_1t4v?eIl=C!+XhTa9Ma!m=a';
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

app.get('/api/health', async function(req, res) {
  try {
    await getToken();
    res.json({ status: 'ok', connected: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/clients', async function(req, res) {
  try {
    var t = await getToken();
   var r = await axios.post(BASE + '/clients/search', {
  headers: { Authorization: 'Bearer ' + t },
  data: { page: 1, pageSize: 100 }
});
      headers: { Authorization: 'Bearer ' + t },
      params: { page: 1, pageSize: 100, active: true }
    });
    res.json(r.data);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/transactions', async function(req, res) {
  try {
    var t = await getToken();
  var r = await axios.get(BASE + '/clients', {
      headers: { Authorization: 'Bearer ' + t },
      params: { page: 1, pageSize: 50 }
    });
    res.json(r.data);
  } catch(e) {
    res.status(500).json({ error: e.message, transactions: [] });
  }
});

app.post('/api/webhook', function(req, res) {
  console.log('Webhook received:', JSON.stringify(req.body));
  res.json({ ok: true });
});

app.post('/api/invoice/create', async function(req, res) {
  try {
    var b = req.body;
    var t = await getToken();
    var r = await axios.post(BASE + '/documents', {
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
      income: [{
        description: b.description || 'תשלום',
        price: b.amount,
        currency: 'ILS',
        vatType: 0
      }],
      payment: [{
        type: 1,
        price: b.amount,
        currency: 'ILS',
        date: new Date().toISOString().split('T')[0]
      }]
    }, { headers: { Authorization: 'Bearer ' + t } });
    res.json({ success: true, invoiceId: r.data.id, invoiceNumber: r.data.number, invoiceUrl: r.data.url });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(4000, function() {
  console.log('Server running on port 4000');
});