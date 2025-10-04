// FILE: server.js

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');

const app = express();
const port = 3000;

// Set EJS as the templating engine
app.set('view engine', 'ejs');

// --- DATABASE CONFIGURATION ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// --- MIDDLEWARE ---

// Serve static files from the 'public' directory
app.use(express.static('public')); 
app.use('/style', express.static('style'));
app.use('/Images', express.static('Images'));

// Parse URL-encoded bodies (for form submissions)
app.use(express.urlencoded({ extended: true }));
// Parse JSON bodies (for API calls)
app.use(express.json());

// Configure session management
const PgStore = connectPgSimple(session);
app.use(session({
    store: new PgStore({
        pool: pool,
        tableName: 'session' // A table named 'session' must be created in your DB
    }),
    secret: process.env.SESSION_SECRET || 'your_secret_key', // USE A STRONG SECRET IN .env
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        secure: process.env.NODE_ENV === 'production' // Use secure cookies in production
    }
}));

// --- SESSION/AUTHENTICATION MIDDLEWARE ---

/**
 * Middleware to ensure the user is logged in.
 */
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        // Redirect to the login page (which is the homepage here)
        res.redirect('/');
    }
};

/**
 * Middleware to ensure the user is an admin.
 */
const isAdmin = (req, res, next) => {
    if (req.session.isAdmin) {
        next();
    } else {
        // Logged in but not an admin (i.e., a regular partner)
        res.status(403).send('Access Denied: You must be an Administrator.');
    }
};

// --- ROUTES ---

// 1. Homepage / Login Page
app.get('/', (req, res) => {
    // If the user is already logged in, redirect them to the dashboard
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    // Render the public landing page (index.html is assumed to be the home page, 
    // or you can render an EJS file if you rename index.html to index.ejs)
    res.sendFile(__dirname + '/index.html'); 
});

// 2. Authentication Route
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT id, password_hash, is_admin FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (user && await bcrypt.compare(password, user.password_hash)) {
            // Success: Set session variables
            req.session.userId = user.id;
            req.session.username = username;
            req.session.isAdmin = user.is_admin; 
            
            // Send JSON response for the frontend JS to handle the redirect
            return res.json({ 
                success: true, 
                message: 'Login successful', 
                redirectUrl: '/dashboard' 
            });
        } else {
            // Failure: Invalid credentials
            return res.json({ 
                success: false, 
                message: 'Invalid Username or Password.' 
            });
        }
    } catch (err) {
        console.error('Login Error:', err);
        return res.json({ 
            success: false, 
            message: 'A server error occurred during login.' 
        });
    }
});

// 3. Logout Route
app.post('/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Session destruction error:', err);
            return res.status(500).send('Could not log out.');
        }
        res.redirect('/');
    });
});

// 4. Dashboard Route (Secured)
app.get('/dashboard', isAuthenticated, (req, res) => {
    // Render the dashboard with user-specific data
    res.render('partner-dashboard', {
        username: req.session.username,
        userId: req.session.userId,
        isAdmin: req.session.isAdmin
    });
});

// ----------------------------------------
// 5. DEALER NETWORK API ROUTES (CRUD)
// ----------------------------------------

// A. GET /api/dealers: Fetch all dealers (Admin) OR only own dealers (Partner)
app.get('/api/dealers', isAuthenticated, async (req, res) => {
    const isAdminUser = req.session.isAdmin;
    const partnerId = req.session.userId;

    let query;
    let params = [];

    if (isAdminUser) {
        // Admin sees ALL dealers
        query = `
            SELECT 
                d.id, d.company_name, d.contact_person, d.phone_number, d.gstin_number, d.address, d.created_at,
                u.username AS partner_username
            FROM dealer_network d
            JOIN users u ON d.partner_user_id = u.id
            ORDER BY d.id DESC;
        `;
    } else {
        // Partner sees only their own dealers
        query = `
            SELECT 
                id, company_name, contact_person, phone_number, gstin_number, address, created_at
            FROM dealer_network
            WHERE partner_user_id = $1
            ORDER BY id DESC;
        `;
        params.push(partnerId);
    }

    try {
        const result = await pool.query(query, params);
        res.json({ success: true, dealers: result.rows });
    } catch (err) {
        console.error('Error fetching dealer network:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve dealer network data.' });
    }
});


// B. POST /api/dealers: Create or Update (UPSERT) a dealer record
app.post('/api/dealers', isAuthenticated, async (req, res) => {
    const { id, companyName, contactPerson, phoneNumber, gstinNumber, address } = req.body;
    const partnerId = req.session.userId;
    const isAdminUser = req.session.isAdmin;
    let client;

    // Basic validation
    if (!companyName || !phoneNumber) {
        return res.status(400).json({ success: false, message: 'Company Name and Phone Number are required.' });
    }

    // Determine if this is a CREATE (id is null/0) or UPDATE (id is valid)
    const isUpdate = !!id && id !== 0; 
    
    // Check ownership for updates (Partners can only update their own)
    if (isUpdate && !isAdminUser) {
        try {
            const check = await pool.query('SELECT partner_user_id FROM dealer_network WHERE id = $1', [id]);
            if (check.rows.length === 0 || check.rows[0].partner_user_id !== partnerId) {
                return res.status(403).json({ success: false, message: 'Access Denied: You can only edit dealers you created.' });
            }
        } catch(err) {
            return res.status(500).json({ success: false, message: 'Error checking dealer ownership.' });
        }
    }
    
    // UPSERT Query
    // Note: We use COALESCE to safely treat a null/empty 'id' as a new record.
    const upsertQuery = `
        INSERT INTO dealer_network (id, partner_user_id, company_name, contact_person, phone_number, gstin_number, address)
        VALUES (COALESCE($1, nextval('dealer_network_id_seq')), $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO UPDATE
        SET 
            company_name = EXCLUDED.company_name,
            contact_person = EXCLUDED.contact_person,
            phone_number = EXCLUDED.phone_number,
            gstin_number = EXCLUDED.gstin_number,
            address = EXCLUDED.address,
            updated_at = NOW()
        RETURNING *; 
    `;

    try {
        const result = await pool.query(upsertQuery, [
            isUpdate ? id : null, // Pass ID for update, null for new insert
            partnerId,
            companyName,
            contactPerson,
            phoneNumber,
            gstinNumber,
            address
        ]);

        const dealerRecord = result.rows[0];
        const action = isUpdate ? 'updated' : 'added';

        res.json({ 
            success: true, 
            message: `Dealer ${dealerRecord.company_name} successfully ${action}.`,
            dealer: dealerRecord
        });

    } catch (err) {
        console.error('Error in dealer UPSERT:', err);
        res.status(500).json({ success: false, message: 'Failed to save dealer details due to a database error.' });
    }
});


// C. DELETE /api/dealers/:id: Delete a dealer record
app.delete('/api/dealers/:id', isAuthenticated, async (req, res) => {
    const dealerId = req.params.id;
    const partnerId = req.session.userId;
    const isAdminUser = req.session.isAdmin;
    let client;

    try {
        // Partners can only delete their own dealers. Admin can delete any.
        let query = 'DELETE FROM dealer_network WHERE id = $1';
        let params = [dealerId];

        if (!isAdminUser) {
            query += ' AND partner_user_id = $2';
            params.push(partnerId);
        }

        const result = await pool.query(query, params);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'Dealer not found or you do not have permission to delete it.' });
        }

        res.json({ success: true, message: 'Dealer deleted successfully.' });

    } catch (err) {
        console.error('Error deleting dealer:', err);
        res.status(500).json({ success: false, message: 'Failed to delete dealer due to a server error.' });
    }
});


// 6. Start Server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log(`Node.js environment: ${process.env.NODE_ENV}`);
});