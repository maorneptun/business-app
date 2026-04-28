require('dotenv').config();
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

app.get('/api/transactions', async function(req, res) {
  try {
    const t = await getToken();
    const today = new Date().toISOString().split('T')[0];
    const from = new Date();
    from.setMonth(from.getMonth() - 1);
    const fromDate = from.toISOString().split('T')[0];
    const r = await axios.get('https://apigw.greeninvoice.co.il/open-banking/v2/transactions', {
      headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' },
      params: { 'valueDate[from]': fromDate, 'valueDate[to]': today, from: 0, size: 50, bookingStatus: 'booked' }
    });
    const items = r.data.transactions || r.data.items || r.data || [];
    const seen = {};
    const txs = items.filter(function(tx) {
      const key = (tx.valueDate || tx.date) + '_' + Math.abs(tx.amount || (tx.transactionAmount && tx.transactionAmount.amount) || 0);
      if (seen[key]) return false;
      seen[key] = true;
      return true;
    }).map(function(tx) {
      const rawAmount = tx.transactionAmount ? tx.transactionAmount.amount : tx.amount;
      const amount = tx.creditDebitIndicator === 'DBIT' ? -Math.abs(rawAmount) : Math.abs(rawAmount);
      return {
        id: tx.transactionId || tx.id,
        amount: amount,
        description: tx.remittanceInformationUnstructured || tx.creditorName || tx.debtorName || tx.description || 'תנועה',
        date: (tx.valueDate || tx.bookingDate || tx.date || '').split('T')[0],
        canInvoice: amount > 0,
        done: false
      };
    });
    res.json({ transactions: txs });
  } catch(e) {
    res.status(500).json({ error: e.message, transactions: [] });
  }
});

app.get('/api/balance', async function(req, res) {
  try {
    const t = await getToken();
    const r = await axios.get(BASE + '/bank/accounts', {
      headers: { Authorization: 'Bearer ' + t }
    });
    const account = (r.data.items || r.data || [])[0];
    res.json({ balance: account ? account.balance : null, accountNumber: account ? account.accountNumber : null });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/transactions', async function(req, res) {
  try {
    const t = await getToken();
    const today = new Date().toISOString().split('T')[0];
    const from = new Date();
    from.setMonth(from.getMonth() - 3);
    const fromDate = from.toISOString().split('T')[0];
    const r = await axios.get(BASE + '/bank/transactions', {
      headers: { Authorization: 'Bearer ' + t },
      params: { dateFrom: fromDate, dateTo: today, page: 1, pageSize: 50 }
    });
    const items = r.data.items || r.data.transactions || r.data || [];
    const seen = {};
    const txs = items.filter(function(tx) {
      const key = (tx.date || tx.valueDate) + '_' + Math.abs(tx.amount || 0) + '_' + (tx.description || '');
      if (seen[key]) return false;
      seen[key] = true;
      return true;
    }).map(function(tx) {
      const amount = tx.creditDebitIndicator === 'DBIT' ? -Math.abs(tx.amount) : tx.amount;
      return {
        id: tx.id || tx.transactionId,
        amount: amount,
        description: tx.description || tx.name || tx.remittanceInformation || 'תנועה',
        date: (tx.date || tx.valueDate || '').split('T')[0],
        canInvoice: amount > 0,
        done: false
      };
    });
    res.json({ transactions: txs });
  } catch(e) {
    res.status(500).json({ error: e.message, transactions: [] });
  }
});

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
      type: 320,
      lang: 'he',
      currency: 'ILS',
      vatType: 0,
      client: { name: b.clientName, emails: b.clientEmail ? [b.clientEmail] : [], phone: b.clientPhone || '', add: true },
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