const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cors());

const db = new sqlite3.Database(path.join(__dirname, 'phantom_fury.db'), (err) => {
    if (!err) console.log('Connected to SQLite database safely.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'player')`);
    db.run(`CREATE TABLE IF NOT EXISTS applications (id INTEGER PRIMARY KEY AUTOINCREMENT, nickname TEXT, uid TEXT, level TEXT, rank TEXT, reason TEXT)`);
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashed = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username.trim(), hashed], (err) => {
            if (err) return res.status(400).json({ error: "Username taken." });
            res.json({ success: true });
        });
    } catch(e) { res.status(500).end(); }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username.trim()], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            res.json({ success: true, username: user.username, role: user.role });
        } else { res.status(400).json({ error: "Invalid credentials." }); }
    });
});

app.post('/api/apply', (req, res) => {
    const { nickname, uid, level, rank, reason } = req.body;
    db.run(`INSERT INTO applications (nickname, uid, level, rank, reason) VALUES (?, ?, ?, ?, ?)`, [nickname, uid, level, rank, reason], () => {
        res.json({ success: true });
    });
});

app.get('/api/applications', (req, res) => {
    const user = req.headers['x-username'];
    db.get(`SELECT role FROM users WHERE username = ?`, [user], (err, row) => {
        if (row && row.role === 'admin') {
            db.all(`SELECT * FROM applications`, [], (err, rows) => { res.json({ success: true, applications: rows }); });
        } else { res.status(403).json({ error: "Denied." }); }
    });
});

// Render dynamically assigns a port via process.env.PORT
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Database operational on port ${port}`);
});

