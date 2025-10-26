// --- FILE: project1/server/config/db.js ---
const mongoose = require('mongoose');

// MongoDB connection string. We use 'secure_auth_db' as the database name.
const DB_URI = 'mongodb://localhost:27017/secure_auth_db';

const connectDB = async () => {
    try {
        // Mongoose automatically handles connection pooling
        const conn = await mongoose.connect(DB_URI);
        console.log(`✅ MongoDB successfully connected! Host: ${conn.connection.host}`);
    } catch (err) {
        console.error(`❌ MongoDB connection error: ${err.message}`);
        // Exit process with failure
        process.exit(1); 
    }
};

module.exports = connectDB;

