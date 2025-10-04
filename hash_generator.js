const bcrypt = require('bcryptjs');
const password = 'saket@999'; // Change this if you want a different password

bcrypt.hash(password, 10, (err, hash) => {
    if (err) throw err;
    console.log(`Password: ${password}`);
    console.log(`New Hash: ${hash}`);
});