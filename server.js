const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const Datastore = require('nedb-promises');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
// Replace app.use(cors()); with this explicit cloud permission block:
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-username");
    
    // Handle browser preflight pre-check signals instantly
    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }
    next();
});


const usersDb = Datastore.create({ filename: path.join(__dirname, 'users.db'), autoload: true });
const appsDb = Datastore.create({ filename: path.join(__dirname, 'applications.db'), autoload: true });

// --- REGISTER ACCOUNT ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const cleanUser = username.trim().toLowerCase();
        if (await usersDb.findOne({ username: cleanUser })) {
            return res.status(400).json({ error: "Username taken." });
        }
        const hashed = await bcrypt.hash(password, 10);
        await usersDb.insert({ username: cleanUser, password: hashed, role: 'player' });
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: "Registration failed." }); }
});

// --- LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const cleanUser = username.trim().toLowerCase();
        const user = await usersDb.findOne({ username: cleanUser });
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
// --- ADMIN PASSWORD RESET ENDPOINT ---
app.post('/api/admin/reset-password', async (req, res) => {
    const { adminUser, targetUser, newPassword } = req.body;
    try {
        // Verify that the person making the change is a verified admin
        const adminCheck = await usersDb.findOne({ username: adminUser.trim().toLowerCase() });
        if (!adminCheck || adminCheck.role !== 'admin') {
            return res.status(403).json({ error: "Access Denied. Admins only." });
        }

        // Target and hash the new password string
        const cleanTarget = targetUser.trim().toLowerCase();
        const hashedNew = await bcrypt.hash(newPassword, 10);

        // Update the document record in users.db
        const updated = await usersDb.update(
            { username: cleanTarget }, 
            { $set: { password: hashedNew } }
        );

        if (updated === 0) {
            return res.status(444).json({ error: "Target account not found." });
        }
        res.json({ success: true, message: "Password updated successfully!" });
    } catch(e) { res.status(500).json({ error: "Reset transmission failure." }); }
});

app.listen(port, () => console.log(`Database operational on port ${port}`));
