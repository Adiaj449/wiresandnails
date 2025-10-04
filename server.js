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
            // Fetches is_admin status
            'SELECT id, username, password_hash, is_partner, is_admin FROM users WHERE username = $1', 
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
        req.session.isAdmin = user.is_admin; // <-- Stores admin status
        
        // 3. Save session and redirect
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ success: false, message: 'Server error: Could not establish session.' });
            }
            // Admins can use the same dashboard link
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
    // Allows access if user is a partner OR an admin
    if (req.session.userId && (req.session.isPartner || req.session.isAdmin)) {
        try {
            const userResult = await pool.query(
                'SELECT username FROM users WHERE id = $1', 
                [req.session.userId]
            );
            
            const username = userResult.rows[0] ? userResult.rows[0].username : 'User';

            // Render the EJS file and inject the username and isAdmin status
            res.render('partner-dashboard', { 
                username: username,
                isAdmin: req.session.isAdmin || false
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

// E. API Route to FETCH ALL DEALERS (Admin-Only Access)
app.get('/api/admin/all-dealers', async (req, res) => {
    // CRITICAL: Check for Admin authorization 
    if (!req.session.userId || !req.session.isAdmin) {
        return res.status(403).json({ success: false, message: 'Forbidden: Admin access required.' });
    }
    
    try {
        // Fetch ALL records. Joins with 'users' to show which partner owns the dealer.
        const result = await pool.query(
            `SELECT
                dn.id AS dealer_id,
                u.username AS partner_username,
                dn.company_name,
                dn.contact_person,
                dn.phone_number,
                dn.gstin_number,
                dn.address,
                dn.updated_at
             FROM dealer_network dn
             JOIN users u ON dn.user_id = u.id
             ORDER BY u.username, dn.company_name;`
        );
        
        // Renames key to 'dealers' for seamless consumption by client JS
        res.json({ success: true, dealers: result.rows }); 
        
    } catch (error) {
        console.error('Error fetching all dealer data:', error);
        res.status(500).json({ success: false, message: 'Database error fetching all dealer data.' });
    }
});


// F. API Route to FETCH DEALERS for the logged-in partner (Standard Partner View)
app.get('/api/dealers', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    try {
        const result = await pool.query(
            // Only selects records tied to the current user (req.session.userId)
            'SELECT id, company_name, contact_person, phone_number, gstin_number, address FROM dealer_network WHERE user_id = $1 ORDER BY company_name',
            [req.session.userId]
        );
        
        res.json({ success: true, dealers: result.rows });
        
    } catch (error) {
        console.error('Error fetching dealer list:', error);
        res.status(500).json({ success: false, message: 'Database error fetching dealer network.' });
    }
});

// G. API Route to CREATE or UPDATE a Dealer (POST) - Used by both Admin and Partner
app.post('/api/dealers', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    const { dealerId, companyName, contactPerson, phoneNumber, gstinNumber, address } = req.body;

    if (!companyName || !phoneNumber) {
        return res.status(400).json({ success: false, message: 'Company Name and Phone Number are required fields.' });
    }

    try {
        if (dealerId) {
            // EDIT MODE (UPDATE) - CRUCIAL: Must check that the record belongs to the user
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
                 // Even if admin, if the UPDATE is run on this route, we only allow updating owned records
                 return res.status(404).json({ success: false, message: 'Dealer not found or unauthorized to edit.' });
            }

            res.json({ success: true, message: 'Dealer updated successfully!' });

        } else {
            // CREATE MODE (INSERT) - New dealer is always associated with the logged-in user
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