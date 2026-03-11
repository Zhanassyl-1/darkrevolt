const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();
app.use(cors());
app.use(express.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));

const CRYPTO_PAY_TOKEN = process.env.CRYPTO_PAY_TOKEN || '';
const FIREBASE_CONFIG_RAW = process.env.FIREBASE_CONFIG || '';
const CRYPTO_PAY_API_BASE = 'https://pay.crypt.bot/api';
// Client prices are RUB-based; with 1 RUB = 5.5 KZT and 1 USDT = 90 RUB => 495 KZT per USDT.
const USDT_RATE_KZT = 495;

const parseFirebaseConfig = () => {
  if (!FIREBASE_CONFIG_RAW) return null;
  try {
    return JSON.parse(FIREBASE_CONFIG_RAW);
  } catch (_) {
    return null;
  }
};

const initFirebase = () => {
  if (admin.apps.length) {
    return admin.app();
  }
  const config = parseFirebaseConfig();
  if (config && (config.private_key || config.privateKey)) {
    const normalized = {
      ...config,
      private_key: (config.private_key || config.privateKey || '').replace(/\\n/g, '\n')
    };
    admin.initializeApp({
      credential: admin.credential.cert(normalized)
    });
    return admin.app();
  }
  if (config && config.projectId) {
    admin.initializeApp({
      projectId: config.projectId,
      credential: admin.credential.applicationDefault()
    });
    return admin.app();
  }
  admin.initializeApp({
    credential: admin.credential.applicationDefault()
  });
  return admin.app();
};

const getDb = () => {
  initFirebase();
  return admin.firestore();
};

const requireToken = () => {
  if (!CRYPTO_PAY_TOKEN) {
    const error = new Error('CRYPTO_PAY_TOKEN is not set');
    error.status = 500;
    throw error;
  }
};

const createInvoice = async ({ nick, privilege, amount }) => {
  requireToken();
  const kztAmount = Number(amount) || 0;
  const usdtAmount = (kztAmount / USDT_RATE_KZT).toFixed(2);
  const payload = JSON.stringify({ nick, privilege, amount: kztAmount });

  const response = await axios.post(
    `${CRYPTO_PAY_API_BASE}/createInvoice`,
    {
      asset: 'USDT',
      amount: usdtAmount,
      description: `DarkRevolt: ${privilege} for ${nick}`,
      payload,
      webhook_url: 'https://darkrevolt-production.up.railway.app/crypto-webhook'
    },
    {
      headers: {
        'Crypto-Pay-API-Token': CRYPTO_PAY_TOKEN
      },
      timeout: 10000
    }
  );

  if (!response.data || !response.data.ok) {
    const error = new Error('Crypto Pay API error');
    error.status = 502;
    error.details = response.data;
    throw error;
  }

  return response.data.result;
};

const verifyWebhookSignature = (rawBody, signature) => {
  requireToken();
  if (!signature) return false;
  const secret = crypto.createHash('sha256').update(CRYPTO_PAY_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature));
  } catch (_) {
    return false;
  }
};

app.post('/create-invoice', async (req, res) => {
  try {
    const { nick, privilege, amount } = req.body || {};
    if (!nick || !privilege || !amount) {
      return res.status(400).json({ error: 'nick, privilege, amount are required' });
    }
    const invoice = await createInvoice({ nick, privilege, amount });
    const invoiceUrl = invoice.web_app_invoice_url || invoice.bot_invoice_url || invoice.mini_app_invoice_url || '';
    return res.json({ invoiceUrl, invoiceId: invoice.invoice_id });
  } catch (error) {
    const status = error.status || 500;
    return res.status(status).json({ error: error.message || 'Unknown error' });
  }
});

app.post('/crypto-webhook', async (req, res) => {
  const signature = req.headers['crypto-pay-api-signature'];
  const rawBody = req.rawBody || Buffer.from('');
  if (!verifyWebhookSignature(rawBody, signature)) {
    return res.status(400).send('Invalid signature');
  }

  const body = req.body || {};
  const updateType = body.update_type;
  const payload = body.payload || {};

  if (updateType !== 'invoice_paid' && payload.status !== 'paid') {
    return res.sendStatus(200);
  }

  let meta = {};
  try {
    meta = JSON.parse(payload.payload || '{}');
  } catch (_) {
    meta = {};
  }

  const nick = meta.nick || payload.payments?.[0]?.payer?.user_id || 'Unknown';
  const privilege = meta.privilege || payload.description || 'VIP';
  const amount = Number(meta.amount) || 0;
  const invoiceId = payload.invoice_id || payload.id || '';

  try {
    const db = getDb();
    const docId = invoiceId ? `crypto_${invoiceId}` : undefined;
    const docRef = docId ? db.collection('purchases').doc(docId) : db.collection('purchases').doc();
    await docRef.set({
      nick,
      privilege,
      amount,
      paymentMethod: 'USDT',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'paid',
      invoiceId
    }, { merge: true });
  } catch (_) {
    return res.sendStatus(500);
  }

  return res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DarkRevolt backend listening on port ${PORT}`);
});
