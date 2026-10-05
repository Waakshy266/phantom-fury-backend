const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const Datastore = require('nedb-promises');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// Automatically initializes clean cloud text data stores inside Render
const usersDb = Datastore.create({ filename: path.join(__dirname, 'users.db'), autoload: true });
const appsDb = Datastore.create({ filename: path.join(__dirname, 'applications.db'), autoload: true });

// --- REGISTER ACCOUNT ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        if (await usersDb.findOne({ username: username.trim() })) {
            return res.status(400).json({ error: "Username taken." });
        }
        const hashed = await bcrypt.hash(password, 10);
        await usersDb.insert({ username: username.trim(), password: hashed, role: 'player' });
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: "Registration failed." }); }
});

// --- LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await usersDb.findOne({ username: username.trim() });
        if (user && await bcrypt.compare(password, user.password)) {
            res.json({ success: true, username: user.username, role: user.role });
        } else { res.status(400).json({ error: "Invalid credentials." }); }
    } catch(e) { res.status(500).json({ error: "Login failed." }); }
});

// --- SUBMIT APPLICATION ---
app.post('/api/apply', async (req, res) => {
    try {
        await appsDb.insert(req.body);
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: "Submission failed." }); }
});

// --- VIEW APPLICATIONS (ADMINS ONLY) ---
app.get('/api/applications', async (req, res) => {
    try {
        const user = await usersDb.findOne({ username: req.headers['x-username'] });
        if (user && user.role === 'admin') {
            res.json({ success: true, applications: await appsDb.find({}) });
        } else { res.status(403).json({ error: "Denied." }); }
    } catch(e) { res.status(500).json({ error: "Failed to read applications." }); }
});

app.listen(port, () => console.log(`Database operational on port ${port}`));
