import express from 'express';
import fs from 'fs-extra';
import pino from 'pino';
import { makeWASocket, useMultiFileAuthState, delay } from '@whiskeysockets/baileys';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

let sock; // WhatsApp socket instance
let messages = [];
let haterName = "";
let delaySec = 15;
let targetNumbers = [];
let targetGroups = [];
let sendingLoop = false;

// Initialize WhatsApp connection
async function initWhatsApp() {
  const { state, saveCreds } = await useMultiFileAuthState('./auth_info');
  sock = makeWASocket({ logger: pino({ level: 'silent' }), auth: state });

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async (update) => {
    if (update.connection === 'open') {
      console.log('[√] WhatsApp Connected!');
      if (sendingLoop) sendMessages();
    }
    if (update.connection === 'close') {
      console.log('[!] WhatsApp Disconnected. Reconnecting in 5s...');
      setTimeout(initWhatsApp, 5000);
    }
  });
}

await initWhatsApp();

// Request pairing code
app.post('/request-pairing', async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    if (!phoneNumber) return res.status(400).json({ error: 'Phone number required' });

    const code = await sock.requestPairingCode(phoneNumber);
    res.json({ pairingCode: code });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start bot with config
app.post('/start-bot', async (req, res) => {
  try {
    const { targets, groups, messageFile, hater, delaySeconds } = req.body;

    if (!targets && !groups) return res.status(400).json({ error: 'Provide numbers or groups' });

    // Load messages
    if (messageFile && fs.existsSync(messageFile)) {
      messages = fs.readFileSync(messageFile, 'utf-8').split('\n').filter(Boolean);
    } else {
      messages = ['Test message'];
    }

    targetNumbers = targets || [];
    targetGroups = groups || [];
    haterName = hater || '';
    delaySec = delaySeconds || 15;
    sendingLoop = true;

    res.json({ status: 'Bot started and sending messages' });
    sendMessages();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Infinite send loop
async function sendMessages() {
  while (sendingLoop) {
    // Send to numbers
    for (const num of targetNumbers) {
      for (const msg of messages) {
        try {
          await sock.sendMessage(`${num}@c.us`, { text: `${haterName} ${msg}` });
          console.log(`[√] Sent to ${num}: ${msg}`);
          await delay(delaySec * 1000);
        } catch (err) {
          console.log(`[!] Error sending to ${num}: ${err.message}`);
        }
      }
    }

    // Send to groups
    for (const link of targetGroups) {
      try {
        const code = link.split('chat.whatsapp.com/')[1];
        const groupInfo = await sock.groupGetInviteInfo(code);
        for (const msg of messages) {
          await sock.sendMessage(groupInfo.id, { text: `${haterName} ${msg}` });
          console.log(`[√] Sent to group ${groupInfo.subject}: ${msg}`);
          await delay(delaySec * 1000);
        }
      } catch (err) {
        console.log(`[!] Error with group ${link}: ${err.message}`);
      }
    }
  }
}

// Stop bot endpoint (optional)
app.post('/stop-bot', (req, res) => {
  sendingLoop = false;
  res.json({ status: 'Bot stopped' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[√] Server running on port ${PORT}`));
