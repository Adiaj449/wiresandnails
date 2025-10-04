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
app.set('views', __dirname); 
app.set('view engine', 'ejs'); 

const port = process.env.PORT || 3000; 

// ==============================================
// 1. DATABASE CONFIGURATION
// ==============================================
// Connects to the PostgreSQL database using environment variables
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'shuttle.proxy.rlwy.net',
    database: process.env.DB_NAME || 'railway',
    password: process.env.DB_PASSWORD || 'jmkmuBNOWoPDclysupNBDtLjLprCNJMM',
    port: process.env.DB_PORT || 52101,
    ssl: {
        rejectUnauthorized: false // Required for platforms like Railway with self-signed certs
    }
});

// ==============================================
// 2. MIDDLEWARE SETUP
// ==============================================

// Serve static files (like CSS, images, client-side JS)
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true })); // Handle form submissions
app.use(express.json()); // Handle JSON payloads for API routes

// Session Middleware Configuration
app.use(session({
    store: new pgSession({
        pool: pool,          
        tableName: 'session' // Must match the table created in your database
    }),
    secret: process.env.SESSION_SECRET || 'A_VERY_LONG_AND_RANDOM_SESSION_SECRET_KEY', 
    resave: false, 
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24 hours
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
        sameSite: process.env.NODE_ENV === 'production' ? 'None' : false // Required for cross-site access in production
    }
}));


// ==============================================
// 3. ROUTE HANDLERS
// ==============================================

// A. LANDING PAGE
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// B. LOGIN ROUTE (POST)
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
        
        // 1. Check if user exists and if password is correct
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ success: false, message: 'Invalid credentials. Please try again.' });
        }

        // 2. Set session variables
        req.session.userId = user.id;
        req.session.isPartner = user.is_partner;
        
        // 3. Save session and redirect
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
        return res.status(500).json({ success: false, message: 'An unexpected server error occurred during login.' });
    }
});


// C. PROTECTED DASHBOARD ROUTE (GET) - EJS RENDER
app.get('/partner/dashboard', async (req, res) => {
    // Check if user is logged in AND is a partner
    if (req.session.userId && req.session.isPartner) {
        try {
            // Fetch the username for display in the EJS template
            const userResult = await pool.query(
                'SELECT username FROM users WHERE id = $1', 
                [req.session.userId]
            );
            
            const username = userResult.rows[0] ? userResult.rows[0].username : 'Partner';

            // Render the EJS file and inject the username
            res.render('partner-dashboard', { 
                username: username 
            });

        } catch (error) {
            console.error('Database fetch error on dashboard load:', error);
            res.redirect('/');
        }
    } else {
        // Not authorized or not logged in
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

// E. API Route to FETCH ALL DEALERS for the logged-in partner (GET)
// Retrieves a list of dealers associated with the current partner's userId.
app.get('/api/dealers', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    try {
        const result = await pool.query(
            // NOTE: Using the 'dealer_network' table and selecting all records for this user
            'SELECT id, company_name, contact_person, phone_number, gstin_number, address FROM dealer_network WHERE user_id = $1 ORDER BY company_name',
            [req.session.userId]
        );
        
        // Return the full list (or an empty array)
        res.json({ success: true, dealers: result.rows });
        
    } catch (error) {
        console.error('Error fetching dealer list:', error);
        res.status(500).json({ success: false, message: 'Database error fetching dealer network.' });
    }
});

// F. API Route to CREATE or UPDATE a Dealer (POST)
app.post('/api/dealers', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    // dealerId is sent by the client if editing an existing dealer
    const { dealerId, companyName, contactPerson, phoneNumber, gstinNumber, address } = req.body;

    if (!companyName || !phoneNumber) {
        return res.status(400).json({ success: false, message: 'Company Name and Phone Number are required fields.' });
    }

    try {
        if (dealerId) {
            // EDIT MODE (UPDATE)
            const updateResult = await pool.query(
                `UPDATE dealer_network 
                 SET company_name = $1,
                     contact_person = $2,
                     phone_number = $3,
                     gstin_number = $4,
                     address = $5,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = $6 AND user_id = $7
                 RETURNING id;`,
                [companyName, contactPerson, phoneNumber, gstinNumber, address, dealerId, req.session.userId]
            );

            if (updateResult.rowCount === 0) {
                 return res.status(404).json({ success: false, message: 'Dealer not found or unauthorized to edit.' });
            }

            res.json({ success: true, message: 'Dealer updated successfully!' });

        } else {
            // CREATE MODE (INSERT)
            await pool.query(
                `INSERT INTO dealer_network (user_id, company_name, contact_person, phone_number, gstin_number, address) 
                 VALUES ($1, $2, $3, $4, $5, $6);`,
                [req.session.userId, companyName, contactPerson, phoneNumber, gstinNumber, address]
            );

            res.json({ success: true, message: 'New dealer created successfully!' });
        }
        
    } catch (error) {
        console.error('Error saving dealer:', error);
        res.status(500).json({ success: false, message: 'Database error saving dealer.' });
    }
});


// ==============================================
// 4. START THE SERVER
// ==============================================
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log(`Node environment: ${process.env.NODE_ENV || 'development'}`);
});