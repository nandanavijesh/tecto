// --- FILE: project1/server/server.js ---
// Main entry point for the Node.js/Express server.

const express = require('express');
const userController = require('./controllers/userController');
const { protectRoute, restrictTo } = require('./utils/authUtils');
const connectDB = require('./config/db'); // Database connection function
const path = require('path');

// --- DATABASE CONNECTION ---
connectDB(); // Execute the database connection function when the server starts

const app = express();
const PORT = process.env.PORT || 3000;

// --- CORE MIDDLEWARE ---
// 1. JSON Body Parser
app.use(express.json());

// 2. Simple Logging Middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    next();
});

// --- API ROUTES ---

// Public Auth Routes
app.post('/api/register', userController.register);
app.post('/api/login', userController.login);
app.post('/api/forgot-password', userController.forgotPassword);
app.patch('/api/reset-password/:token', userController.resetPassword);

// Protected Dashboard Route
app.get('/api/dashboard', protectRoute, (req, res) => {
    res.json({ 
        success: true, 
        message: 'Welcome to the protected dashboard!', 
        user: req.user 
    });
});

// Admin Route (RBAC enforced by restrictTo middleware)
app.get('/api/admin', protectRoute, restrictTo('admin'), (req, res) => {
    res.json({ 
        success: true,
        message: 'Top secret admin data access granted.', 
        logs: [`Admin accessed by ${req.user.email} at ${new Date().toLocaleTimeString()}`],
        user: req.user 
    });
});

// --- STATIC FILES (Frontend) ---
// Serves the HTML, CSS, and JS files from the public folder
app.use(express.static(path.join(__dirname, '../public'))); 

// Final fallback for client-side routing (sends index.html for any route not found)
app.use((req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});


// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`🚀 Server running securely on http://localhost:${PORT}`);
});

