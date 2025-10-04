const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const pgSession = require('connect-pg-simple')(session); 

const app = express();

// 🛑 CRITICAL FIX: Trust the Railway proxy to handle HTTPS/secure cookies 🛑
app.set('trust proxy', 1); 

// Use Railway's dynamic PORT environment variable, fallback to 3000 for local testing
const port = process.env.PORT || 3000; 

// ==============================================
// 1. DATABASE CONFIGURATION
// ==============================================
const pool = new Pool({
    // Retrieve credentials from Railway's environment variables
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'shuttle.proxy.rlwy.net',
    database: process.env.DB_NAME || 'railway', 
    password: process.env.DB_PASSWORD || 'jmkmuBNOWoPDclysupNBDtLjLprCNJMM',
    port: process.env.DB_PORT || 52101,
    ssl: {
        rejectUnauthorized: false
    }
});

// ==============================================
// 2. MIDDLEWARE SETUP
// ==============================================

app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Session Middleware Configuration (Includes all security fixes)
app.use(session({
    store: new pgSession({
        pool: pool,          
        tableName: 'session' 
    }),
    secret: process.env.SESSION_SECRET || 'A_VERY_LONG_AND_RANDOM_SESSION_SECRET_KEY', 
    resave: false, 
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24 hours
        httpOnly: true, 
        
        // Final Security Settings: Must be true in production, paired with SameSite='None'
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'None' : false 
    }
}));


// ==============================================
// 3. ROUTE HANDLERS
// ==============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// B. THE LOGIN POST ROUTE - RETURNS JSON AND FORCES SESSION SAVE
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Missing username or password.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, username, password_hash, is_partner FROM users WHERE username = $1', 
            [username]
        );
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        req.session.userId = user.id;
        req.session.isPartner = user.is_partner;
        
        // Explicitly save the session
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ success: false, message: 'Server error: Could not establish session.' });
            }
            
            // Send the JSON redirect instruction for the frontend
            return res.json({ 
                success: true, 
                redirectUrl: '/partner/dashboard' 
            });
        });

    } catch (error) {
        console.error('Login database or bcrypt error:', error);
        return res.status(500).json({ success: false, message: 'An unexpected server error occurred.' });
    }
});


// C. PROTECTED DASHBOARD ROUTE
app.get('/partner/dashboard', (req, res) => {
    // This check should now succeed because the session is being retrieved via trusted proxy.
    if (req.session.userId && req.session.isPartner) {
        res.sendFile(path.join(__dirname, 'partner-dashboard.html'));
    } else {
        res.redirect('/');
    }
});


// D. LOGOUT POST ROUTE
app.post('/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).send('Could not log out.');
        }
        res.redirect('/');
    });
});


// ==============================================
// 4. START THE SERVER
// ==============================================
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log(`Node environment: ${process.env.NODE_ENV || 'development'}`);
});