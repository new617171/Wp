import express from 'express';
import fs from 'fs-extra';
import pino from 'pino';
import { makeWASocket, useMultiFileAuthState, delay } from '@whiskeysockets/baileys';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import cookieParser from 'cookie-parser';

// ES module equivalents for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const SALT_ROUNDS = 10;

// File upload configuration
const upload = multer({ dest: 'uploads/' });

// Initialize Express
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// WhatsApp connection variables
let sock;
let messages = [];
let haterName = "";
let delaySec = 15;
let targetNumbers = [];
let targetGroups = [];
let sendingLoop = false;

// Simple user database (in production, use a real database)
let users = [];

// Initialize WhatsApp connection
async function initWhatsApp() {
  try {
    const { state, saveCreds } = await useMultiFileAuthState('./auth_info');
    sock = makeWASocket({ 
      logger: pino({ level: 'silent' }), 
      auth: state,
      printQRInTerminal: true
    });

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
  } catch (err) {
    console.error('WhatsApp initialization error:', err);
  }
}

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// API Endpoints

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const user = { username, password: hashedPassword };
    users.push(user);
    
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    res.json({ message: 'Logged in successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Protected endpoints
app.post('/api/request-pairing', authenticate, async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    if (!phoneNumber) return res.status(400).json({ error: 'Phone number required' });

    const code = await sock.requestPairingCode(phoneNumber);
    res.json({ pairingCode: code });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/start-bot', authenticate, upload.single('messageFile'), async (req, res) => {
  try {
    const { targets, groups, messages: msgList, hater, delaySeconds } = req.body;

    if (!targets?.length && !groups?.length) {
      return res.status(400).json({ error: 'Provide numbers or groups' });
    }

    // Get messages from file if uploaded
    if (req.file) {
      const filePath = req.file.path;
      messages = fs.readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
      fs.unlinkSync(filePath); // Clean up uploaded file
    } else if (msgList) {
      messages = msgList.split('\n').filter(Boolean);
    } else {
      messages = ['Test message'];
    }

    targetNumbers = targets ? targets.split('\n') : [];
    targetGroups = groups ? groups.split('\n') : [];
    haterName = hater || '';
    delaySec = delaySeconds || 15;
    sendingLoop = true;

    res.json({ status: 'Bot started and sending messages' });
    sendMessages();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/stop-bot', authenticate, (req, res) => {
  sendingLoop = false;
  res.json({ status: 'Bot stopped' });
});

// Message sending loop
async function sendMessages() {
  while (sendingLoop) {
    // Send to numbers
    for (const num of targetNumbers) {
      for (const msg of messages) {
        if (!sendingLoop) break;
        try {
          await sock.sendMessage(`${num}@s.whatsapp.net`, { text: `${haterName} ${msg}` });
          console.log(`[√] Sent to ${num}: ${msg}`);
          await delay(delaySec * 1000);
        } catch (err) {
          console.log(`[!] Error sending to ${num}: ${err.message}`);
        }
      }
    }

    // Send to groups
    for (const link of targetGroups) {
      if (!sendingLoop) break;
      try {
        const code = link.split('chat.whatsapp.com/')[1];
        const groupInfo = await sock.groupGetInviteInfo(code);
        for (const msg of messages) {
          if (!sendingLoop) break;
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

// Frontend routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize WhatsApp and start server
initWhatsApp().then(() => {
  app.listen(PORT, () => console.log(`[√] Server running on port ${PORT}`));
});

// Frontend HTML (served from public/index.html)
const frontendHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WhatsApp Message Sender</title>
    <style>
        :root {
            --primary: #25D366;
            --secondary: #128C7E;
            --danger: #dc3545;
            --light: #f8f9fa;
            --dark: #343a40;
            --gray: #6c757d;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background-color: #f5f5f5;
            color: #333;
            min-height: 100vh;
        }
        
        .container {
            max-width: 100%;
            padding: 1rem;
            margin: 0 auto;
        }
        
        @media (min-width: 768px) {
            .container {
                max-width: 800px;
                padding: 2rem;
            }
        }
        
        .card {
            background: white;
            border-radius: 0.5rem;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        h1, h2, h3 {
            color: var(--secondary);
            margin-bottom: 1rem;
        }
        
        .form-group {
            margin-bottom: 1.25rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: var(--dark);
        }
        
        input, textarea, select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 0.25rem;
            font-family: inherit;
            font-size: 1rem;
        }
        
        textarea {
            min-height: 120px;
            resize: vertical;
        }
        
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 0.25rem;
            background-color: var(--primary);
            color: white;
            font-weight: 600;
            text-align: center;
            cursor: pointer;
            text-decoration: none;
            transition: background-color 0.3s;
        }
        
        .btn:hover {
            background-color: var(--secondary);
        }
        
        .btn-danger {
            background-color: var(--danger);
        }
        
        .btn-secondary {
            background-color: var(--secondary);
        }
        
        .btn-group {
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
        }
        
        .btn-block {
            display: block;
            width: 100%;
        }
        
        .alert {
            padding: 1rem;
            border-radius: 0.25rem;
            margin-bottom: 1rem;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
        }
        
        .alert-info {
            background-color: #d1ecf1;
            color: #0c5460;
            border-left: 4px solid #17a2b8;
        }
        
        .nav-tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 1.5rem;
        }
        
        .nav-tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            border: 1px solid transparent;
            border-bottom: none;
            border-radius: 0.25rem 0.25rem 0 0;
            margin-right: 0.25rem;
        }
        
        .nav-tab.active {
            border-color: #ddd;
            border-bottom-color: white;
            background: white;
            font-weight: 600;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .log {
            background-color: var(--dark);
            color: white;
            padding: 1rem;
            border-radius: 0.25rem;
            font-family: monospace;
            max-height: 300px;
            overflow-y: auto;
            margin-top: 1.5rem;
        }
        
        .auth-container {
            max-width: 400px;
            margin: 2rem auto;
        }
        
        .hidden {
            display: none;
        }
        
        .file-upload {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }
        
        .file-upload input[type="file"] {
            display: none;
        }
        
        .file-upload-label {
            padding: 0.5rem 1rem;
            background-color: var(--light);
            border: 1px solid #ddd;
            border-radius: 0.25rem;
            cursor: pointer;
        }
        
        .file-name {
            font-size: 0.875rem;
            color: var(--gray);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Authentication Section -->
        <div id="auth-section" class="auth-container">
            <div class="card">
                <h2>Login</h2>
                <div id="login-alert" class="alert hidden"></div>
                <form id="login-form">
                    <div class="form-group">
                        <label for="login-username">Username</label>
                        <input type="text" id="login-username" required>
                    </div>
                    <div class="form-group">
                        <label for="login-password">Password</label>
                        <input type="password" id="login-password" required>
                    </div>
                    <button type="submit" class="btn btn-block">Login</button>
                </form>
                <p class="text-center" style="margin-top: 1rem;">Don't have an account? <a href="#" id="show-register">Register</a></p>
            </div>
            
            <div id="register-section" class="card hidden">
                <h2>Register</h2>
                <div id="register-alert" class="alert hidden"></div>
                <form id="register-form">
                    <div class="form-group">
                        <label for="register-username">Username</label>
                        <input type="text" id="register-username" required>
                    </div>
                    <div class="form-group">
                        <label for="register-password">Password</label>
                        <input type="password" id="register-password" required>
                    </div>
                    <div class="btn-group">
                        <button type="submit" class="btn">Register</button>
                        <button type="button" id="show-login" class="btn btn-secondary">Back to Login</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Main App Section -->
        <div id="app-section" class="hidden">
            <div class="card">
                <h1>WhatsApp Message Sender</h1>
                <div id="status" class="alert alert-info">Status: Ready</div>
                
                <div class="form-group">
                    <label for="phoneNumber">Your WhatsApp Number (with country code):</label>
                    <input type="text" id="phoneNumber" placeholder="e.g. 1234567890">
                    <button id="pairingBtn" class="btn" style="margin-top: 0.5rem;">Get Pairing Code</button>
                    <div id="pairingResult" style="margin-top: 0.5rem;"></div>
                </div>
                
                <div class="nav-tabs">
                    <div class="nav-tab active" data-tab="numbers">Send to Numbers</div>
                    <div class="nav-tab" data-tab="groups">Send to Groups</div>
                </div>
                
                <div id="numbers-tab" class="tab-content active">
                    <div class="form-group">
                        <label for="targetNumbers">Target Numbers (one per line, with country code):</label>
                        <textarea id="targetNumbers" placeholder="1234567890\n9876543210"></textarea>
                    </div>
                </div>
                
                <div id="groups-tab" class="tab-content">
                    <div class="form-group">
                        <label for="groupLinks">Group Links (one per line):</label>
                        <textarea id="groupLinks" placeholder="https://chat.whatsapp.com/ABC123\nhttps://chat.whatsapp.com/DEF456"></textarea>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="messages">Messages (one per line) OR upload a text file:</label>
                    <div class="file-upload">
                        <label for="messageFile" class="file-upload-label">Choose File</label>
                        <input type="file" id="messageFile" accept=".txt">
                        <span id="fileName" class="file-name">No file chosen</span>
                    </div>
                    <textarea id="messages" placeholder="Hello!\nHow are you?"></textarea>
                </div>
                
                <div class="form-group">
                    <label for="haterName">Message Prefix (optional):</label>
                    <input type="text" id="haterName" placeholder="e.g. Admin">
                </div>
                
                <div class="form-group">
                    <label for="delaySeconds">Delay Between Messages (seconds):</label>
                    <input type="number" id="delaySeconds" value="15" min="5">
                </div>
                
                <div class="btn-group">
                    <button id="startBtn" class="btn">Start Sending</button>
                    <button id="stopBtn" class="btn btn-danger" disabled>Stop Sending</button>
                </div>
                
                <div class="log" id="log">
                    <!-- Log messages will appear here -->
                </div>
                
                <button id="logoutBtn" class="btn btn-secondary" style="margin-top: 1.5rem;">Logout</button>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // DOM Elements
            const authSection = document.getElementById('auth-section');
            const appSection = document.getElementById('app-section');
            const loginForm = document.getElementById('login-form');
            const registerForm = document.getElementById('register-form');
            const showRegister = document.getElementById('show-register');
            const showLogin = document.getElementById('show-login');
            const loginAlert = document.getElementById('login-alert');
            const registerAlert = document.getElementById('register-alert');
            const logoutBtn = document.getElementById('logoutBtn');
            const startBtn = document.getElementById('startBtn');
            const stopBtn = document.getElementById('stopBtn');
            const pairingBtn = document.getElementById('pairingBtn');
            const statusDiv = document.getElementById('status');
            const logDiv = document.getElementById('log');
            const pairingResult = document.getElementById('pairingResult');
            const tabButtons = document.querySelectorAll('.nav-tab');
            const tabContents = document.querySelectorAll('.tab-content');
            const messageFileInput = document.getElementById('messageFile');
            const fileNameSpan = document.getElementById('fileName');
            
            // Check if user is already logged in
            checkAuth();
            
            // Event Listeners
            showRegister.addEventListener('click', (e) => {
                e.preventDefault();
                document.getElementById('register-section').classList.remove('hidden');
                document.getElementById('auth-section').querySelector('.card').classList.add('hidden');
            });
            
            showLogin.addEventListener('click', (e) => {
                e.preventDefault();
                document.getElementById('register-section').classList.add('hidden');
                document.getElementById('auth-section').querySelector('.card').classList.remove('hidden');
            });
            
            loginForm.addEventListener('submit', handleLogin);
            registerForm.addEventListener('submit', handleRegister);
            logoutBtn.addEventListener('click', handleLogout);
            messageFileInput.addEventListener('change', handleFileSelect);
            
            // Tab switching
            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    tabContents.forEach(content => content.classList.remove('active'));
                    
                    button.classList.add('active');
                    const tabId = button.getAttribute('data-tab') + '-tab';
                    document.getElementById(tabId).classList.add('active');
                });
            });
            
            // WhatsApp functionality
            pairingBtn.addEventListener('click', handlePairingRequest);
            startBtn.addEventListener('click', handleStartBot);
            stopBtn.addEventListener('click', handleStopBot);
            
            // Functions
            function checkAuth() {
                const token = getCookie('token');
                if (token) {
                    authSection.classList.add('hidden');
                    appSection.classList.remove('hidden');
                }
            }
            
            function getCookie(name) {
                const value = `; ${document.cookie}`;
                const parts = value.split(`; ${name}=`);
                if (parts.length === 2) return parts.pop().split(';').shift();
            }
            
            async function handleLogin(e) {
                e.preventDefault();
                const username = document.getElementById('login-username').value;
                const password = document.getElementById('login-password').value;
                
                try {
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showAlert(loginAlert, data.message, 'success');
                        setTimeout(() => {
                            authSection.classList.add('hidden');
                            appSection.classList.remove('hidden');
                        }, 1000);
                    } else {
                        throw new Error(data.error || 'Login failed');
                    }
                } catch (error) {
                    showAlert(loginAlert, error.message, 'danger');
                }
            }
            
            async function handleRegister(e) {
                e.preventDefault();
                const username = document.getElementById('register-username').value;
                const password = document.getElementById('register-password').value;
                
                try {
                    const response = await fetch('/api/register', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showAlert(registerAlert, data.message, 'success');
                        setTimeout(() => {
                            document.getElementById('register-section').classList.add('hidden');
                            document.getElementById('auth-section').querySelector('.card').classList.remove('hidden');
                        }, 1000);
                    } else {
                        throw new Error(data.error || 'Registration failed');
                    }
                } catch (error) {
                    showAlert(registerAlert, error.message, 'danger');
                }
            }
            
            function handleLogout() {
                document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                authSection.classList.remove('hidden');
                appSection.classList.add('hidden');
            }
            
            function showAlert(element, message, type) {
                element.textContent = message;
                element.classList.remove('hidden', 'alert-success', 'alert-danger');
                element.classList.add(`alert-${type}`);
            }
            
            function logMessage(message) {
                const timestamp = new Date().toLocaleTimeString();
                logDiv.innerHTML += `[${timestamp}] ${message}<br>`;
                logDiv.scrollTop = logDiv.scrollHeight;
            }
            
            function updateStatus(message, isError = false) {
                statusDiv.textContent = `Status: ${message}`;
                statusDiv.className = isError ? 'alert alert-danger' : 'alert alert-success';
            }
            
            function handleFileSelect(e) {
                const file = e.target.files[0];
                if (file) {
                    fileNameSpan.textContent = file.name;
                } else {
                    fileNameSpan.textContent = 'No file chosen';
                }
            }
            
            async function handlePairingRequest() {
                const phoneNumber = document.getElementById('phoneNumber').value.trim();
                if (!phoneNumber) {
                    updateStatus('Please enter your phone number', true);
                    return;
                }
                
                try {
                    pairingBtn.disabled = true;
                    pairingBtn.textContent = 'Requesting...';
                    
                    const response = await fetch('/api/request-pairing', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ phoneNumber })
                    });
                    
                    const data = await response.json();
                    
                    if (data.pairingCode) {
                        pairingResult.innerHTML = `
                            <div class="alert alert-success">
                                <strong>Pairing Code:</strong> ${data.pairingCode}<br>
                                <small>Enter this code in your WhatsApp linked devices section</small>
                            </div>
                        `;
                        updateStatus('Pairing code generated');
                        logMessage(`Pairing code requested for ${phoneNumber}`);
                    } else {
                        throw new Error(data.error || 'Unknown error');
                    }
                } catch (error) {
                    updateStatus(error.message, true);
                    logMessage(`Error: ${error.message}`);
                } finally {
                    pairingBtn.disabled = false;
                    pairingBtn.textContent = 'Get Pairing Code';
                }
            }
            
            async function handleStartBot() {
                const activeTab = document.querySelector('.nav-tab.active').getAttribute('data-tab');
                let targets = '';
                let groups = '';
                
                if (activeTab === 'numbers') {
                    targets = document.getElementById('targetNumbers').value.trim();
                    if (!targets) {
                        updateStatus('Please provide at least one target number', true);
                        return;
                    }
                } else {
                    groups = document.getElementById('groupLinks').value.trim();
                    if (!groups) {
                        updateStatus('Please provide at least one group link', true);
                        return;
                    }
                }
                
                const messages = document.getElementById('messages').value.trim();
                const fileInput = document.getElementById('messageFile');
                
                if (!messages && !fileInput.files[0]) {
                    updateStatus('Please provide messages or upload a file', true);
                    return;
                }
                
                try {
                    startBtn.disabled = true;
                    stopBtn.disabled = false;
                    
                    const formData = new FormData();
                    formData.append('targets', targets);
                    formData.append('groups', groups);
                    formData.append('messages', messages);
                    formData.append('hater', document.getElementById('haterName').value.trim());
                    formData.append('delaySeconds', document.getElementById('delaySeconds').value);
                    
                    if (fileInput.files[0]) {
                        formData.append('messageFile', fileInput.files[0]);
                    }
                    
                    const response = await fetch('/api/start-bot', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    if (data.status) {
                        updateStatus(data.status);
                        logMessage('Message sending started');
                        if (activeTab === 'numbers') {
                            logMessage(`Sending to ${targets.split('\n').length} numbers`);
                        } else {
                            logMessage(`Sending to ${groups.split('\n').length} groups`);
                        }
                        logMessage(`Delay: ${document.getElementById('delaySeconds').value} seconds`);
                    } else {
                        throw new Error(data.error || 'Unknown error');
                    }
                } catch (error) {
                    updateStatus(error.message, true);
                    logMessage(`Error: ${error.message}`);
                    startBtn.disabled = false;
                    stopBtn.disabled = true;
                }
            }
            
            async function handleStopBot() {
                try {
                    const response = await fetch('/api/stop-bot', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        }
                    });
                    
                    const data = await response.json();
                    
                    if (data.status) {
                        updateStatus(data.status);
                        logMessage('Message sending stopped');
                        startBtn.disabled = false;
                        stopBtn.disabled = true;
                    } else {
                        throw new Error(data.error || 'Unknown error');
                    }
                } catch (error) {
                    updateStatus(error.message, true);
                    logMessage(`Error: ${error.message}`);
                }
            }
            
            // Initial log message
            logMessage('System initialized');
        });
    </script>
</body>
</html>
`;

// Create public directory and index.html if it doesn't exist
if (!fs.existsSync(path.join(__dirname, 'public'))) {
  fs.mkdirSync(path.join(__dirname, 'public'));
}

if (!fs.existsSync(path.join(__dirname, 'public', 'index.html'))) {
  fs.writeFileSync(path.join(__dirname, 'public', 'index.html'), frontendHTML);
}
