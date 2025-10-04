const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const pgSession = require('connect-pg-simple')(session); // CRITICAL: PostgreSQL session store

const app = express();
// Use Railway's dynamic PORT environment variable, fallback to 3000 for local testing
const port = process.env.PORT || 3000; 

// ==============================================
// 1. DATABASE CONFIGURATION (Using Environment Variables)
// ==============================================
const pool = new Pool({
    // Retrieve credentials from Railway's environment variables
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'shuttle.proxy.rlwy.net',
    database: process.env.DB_NAME || 'railway', // Use your specific DB name
    password: process.env.DB_PASSWORD || 'jmkmuBNOWoPDclysupNBDtLjLprCNJMM',
    port: process.env.DB_PORT || 52101,
    
    // Required for external connections (Node.js container to Railway DB)
    ssl: {
        rejectUnauthorized: false
    }
});

// ==============================================
// 2. MIDDLEWARE SETUP
// ==============================================

// Serve static files (index.html, CSS, etc.) from the root directory
app.use(express.static(__dirname));

// Parse incoming URL-encoded form data
app.use(express.urlencoded({ extended: true }));

// Session Middleware Configuration (Using PostgreSQL for production safety)
app.use(session({
    // Use the PostgreSQL store instead of the unsafe MemoryStore
    store: new pgSession({
        pool: pool,          // Use the existing PostgreSQL connection pool
        tableName: 'session' // The table where session data will be stored
    }),
    // Load secret key from environment variable (MANDATORY for security)
    secret: process.env.SESSION_SECRET || 'A_VERY_LONG_AND_RANDOM_SESSION_SECRET_KEY', 
    resave: false, 
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24 hours
        httpOnly: true, // Prevents client-side JS access
        // Set 'secure: true' ONLY if deployed via HTTPS (i.e., on Railway with NODE_ENV=production)
        secure: process.env.NODE_ENV === 'production' 
    }
}));


// ==============================================
// 3. ROUTE HANDLERS
// ==============================================

// A. Home Page Route (Serves your index.html)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// B. THE LOGIN POST ROUTE - NOW RETURNS JSON FOR AJAX HANDLER
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Missing username or password.' });
    }

    try {
        // 1. Find User
        const result = await pool.query(
            'SELECT id, username, password_hash, is_partner FROM users WHERE username = $1', 
            [username]
        );

        const user = result.rows[0];

        // 2. User Not Found OR Password Mismatch
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            // FAILED: Send a 401 response with a JSON error message
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        // 3. SUCCESS: Create Session
        req.session.userId = user.id;
        req.session.isPartner = user.is_partner;
        
        // 4. SUCCESS: Send a 200 response with the redirection URL
        return res.json({ 
            success: true, 
            redirectUrl: '/partner/dashboard' 
        });

    } catch (error) {
        console.error('Login database or bcrypt error:', error);
        return res.status(500).json({ success: false, message: 'An unexpected server error occurred.' });
    }
});


// C. PROTECTED DASHBOARD ROUTE (The 302/redirect problem is fixed if session is persisted)
app.get('/partner/dashboard', (req, res) => {
    // Check if user has a valid session and the isPartner flag is true
    if (req.session.userId && req.session.isPartner) {
        // Serves the partner-dashboard.html file
        res.sendFile(path.join(__dirname, 'partner-dashboard.html'));
    } else {
        // If not logged in or not authorized, redirect to home
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
        // Redirect to the home page
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