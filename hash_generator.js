const bcrypt = require('bcryptjs'); // Must be 'bcryptjs' to match your server.js
const saltRounds = 10;
const password = 'test@123'; // or 'adminpass'

bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err) throw err;
    console.log(`Password: ${password}`);
    console.log(`Hash: ${hash}`);
    // COPY the generated hash and replace the PLACEHOLDER in the SQL script!
});