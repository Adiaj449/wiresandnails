const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = 3000;

// ==============================================
// 1. DATABASE CONFIGURATION
// ==============================================
const pool = new Pool({
    user: 'postgres',
    host: 'shuttle.proxy.rlwy.net',
    database: 'railway',
    password: 'jmkmuBNOWoPDclysupNBDtLjLprCNJMM',
    port: 52101,
});

// ==============================================
// 2. MIDDLEWARE SETUP
// ==============================================

// For serving static files (CSS, Images, Video)
app.use(express.static(__dirname));

// To parse form data (the username and password)
app.use(express.urlencoded({ extended: true }));

// Session Middleware Configuration
app.use(session({
    secret: 'A_VERY_LONG_AND_RANDOM_SESSION_SECRET_KEY', // <-- CHANGE THIS!
    resave: false, 
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // Session lasts 24 hours
        httpOnly: true, // Prevents client-side JS access to the cookie
        // secure: true // Uncomment this if you deploy with HTTPS
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

    // 1. Basic Validation
    if (!username || !password) {
        // In a real app, you would redirect with an error message. 
        return res.status(400).send('Please enter both username and password.');
    }

    try {
        // 2. Find User
        const result = await pool.query(
            'SELECT id, username, password_hash, is_partner FROM users WHERE username = $1', 
            [username]
        );

        const user = result.rows[0];

        // 3. User Not Found
        if (!user) {
            return res.status(401).send('Invalid credentials.'); // Generic error
        }

        // 4. Verify Password
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // 5. SUCCESS: Create Session
            req.session.userId = user.id;
            req.session.isPartner = user.is_partner;
            
            // 6. Redirect to Protected Area
            // NOTE: You will need to create a 'partner-dashboard.html' file next!
            return res.redirect('/partner/dashboard');
        } else {
            // 7. FAILED Password
            return res.status(401).send('Invalid credentials.'); // Generic error
        }

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).send('An unexpected server error occurred.');
    }
});


// C. PROTECTED DASHBOARD ROUTE
// This route is only accessible if the user has a valid session.
app.get('/partner/dashboard', (req, res) => {
    if (req.session.userId && req.session.isPartner) {
        // Send a simple response or serve a protected HTML file
        res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>Partner Dashboard</title></head>
            <body>
                <h1>Welcome Back, Partner ${req.session.userId}!</h1>
                <p>This is your secure dashboard content.</p>
                <form action="/auth/logout" method="POST">
                    <button type="submit">Logout</button>
                </form>
            </body>
            </html>
        `);
    } else {
        // User is not logged in or not authorized
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
    console.log(`Server is running at http://localhost:${port}`);
});
