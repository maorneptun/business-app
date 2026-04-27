const express = require('express');
const cors = require('cors');
const axios = require('axios');
const app = express();
app.use(cors());
app.use(express.json());
const ID = '2888f895-fd92-4775-926e-3c778bda51d4';
const SECRET = '_7p5_[m[_1t4v?eIl=C!+XhTa9Ma!m=a';
const BASE = 'https://api.greeninvoice.co.il/api/v1';
let tok = null;
let exp = null;
async function getToken() {
  if (tok && exp > Date.now()) return tok;
  const r = await axios.post(BASE + '/account/token', {id: ID, secret: SECRET});
  tok = r.data.token;
  exp = Date.now() + 3500000;
  return tok;
}
app.get('/api/health', async function(req, res) {
  try {
    await getToken();
    res.json({status: 'ok', connected: true});
  } catch(e) {
    res.status(500).json({error: e.message});
  }
});

app.get('/api/bank/transactions', async function(req, res) {
  try {
    var t = await getToken();
    var response = await axios.get(BASE + '/bank/transactions', {
      headers: { Authorization: 'Bearer ' + t }
    });
    res.json(response.data);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/bank/accounts', async function(req, res) {
  try {
    var t = await getToken();
    var response = await axios.get(BASE + '/bank/accounts', {
      headers: { Authorization: 'Bearer ' + t }
    });
    res.json(response.data);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/webhook', function(req, res) {
  var data = req.body;
  console.log('Webhook received:', JSON.stringify(data));
  res.json({ ok: true });
});

app.listen(4000, async function() {
  console.log('Server running on port 4000');
  try {
    var { connectToCloudflare } = require('cloudflared');
    var result = await connectToCloudflare({ port: 4000 });
    console.log('Public URL: ' + result.url);
    console.log('Webhook URL: ' + result.url + '/api/webhook');
  } catch(e) {
    console.log('Tunnel error: ' + e.message);
  }
});