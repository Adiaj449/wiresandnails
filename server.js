const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const pgSession = require('connect-pg-simple')(session); // NEW: PostgreSQL session store

const app = express();
// Railway requires listening on the PORT environment variable
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

// For serving static files (CSS, Images, Video) from the root directory
app.use(express.static(__dirname));

// To parse form data (the username and password)
app.use(express.urlencoded({ extended: true }));

// Session Middleware Configuration (Using PostgreSQL for production safety)
app.use(session({
    // CRITICAL FIX: Use the PostgreSQL store instead of MemoryStore
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

// B. THE LOGIN POST ROUTE
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.redirect('/?loginError=MissingFields'); 
    }

    try {
        // Find User
        const result = await pool.query(
            'SELECT id, username, password_hash, is_partner FROM users WHERE username = $1', 
            [username]
        );

        const user = result.rows[0];

        // 3. User Not Found OR 4. Verify Password
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            // FAILED: Redirect back to home with an error parameter
            return res.redirect('/?loginError=InvalidCredentials');
        }

        // 5. SUCCESS: Create Session
        req.session.userId = user.id;
        req.session.isPartner = user.is_partner;
        
        // 6. Redirect to Protected Area
        return res.redirect('/partner/dashboard');

    } catch (error) {
        console.error('Login database or bcrypt error:', error);
        return res.redirect('/?loginError=ServerError');
    }
});


// C. PROTECTED DASHBOARD ROUTE
app.get('/partner/dashboard', (req, res) => {
    // Check if user has a valid session and the isPartner flag is true
    if (req.session.userId && req.session.isPartner) {
        // Serves the actual HTML file you created in your project
        res.sendFile(path.join(__dirname, 'partner-dashboard.html'));
    } else {
        // If not logged in or not authorized
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
        // Redirect to the home page (login modal)
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