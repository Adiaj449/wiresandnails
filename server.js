const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const pgSession = require('connect-pg-simple')(session); 

const app = express();

// CRITICAL FIX FOR RAILWAY/PROXY: Trust the proxy headers for secure cookies
app.set('trust proxy', 1); 

// 🛑 EJS CONFIGURATION 🛑
app.set('views', __dirname); // Look for view files in the current directory
app.set('view engine', 'ejs'); // Use EJS as the templating engine

const port = process.env.PORT || 3000; 

// ==============================================
// 1. DATABASE CONFIGURATION
// ==============================================
const pool = new Pool({
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
        maxAge: 1000 * 60 * 60 * 24, 
        httpOnly: true, 
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

// B. LOGIN ROUTE (Unchanged)
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
        
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ success: false, message: 'Server error: Could not establish session.' });
            }
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


// C. 🛑 PROTECTED DASHBOARD ROUTE (Uses EJS to inject username) 🛑
app.get('/partner/dashboard', async (req, res) => {
    if (req.session.userId && req.session.isPartner) {
        try {
            // Fetch the username from the database using the stored userId
            const userResult = await pool.query(
                'SELECT username FROM users WHERE id = $1', 
                [req.session.userId]
            );
            
            // Default to 'Partner' if username isn't found
            const username = userResult.rows[0] ? userResult.rows[0].username : 'Partner';

            // Use res.render() to load the EJS file and inject the username
            res.render('partner-dashboard', { 
                username: username // Passed to the EJS template
            });

        } catch (error) {
            console.error('Database fetch error on dashboard load:', error);
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});


// D. LOGOUT POST ROUTE (Unchanged)
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