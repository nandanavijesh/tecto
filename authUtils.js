// --- FILE: project1/server/utils/authUtils.js ---

const jwt = require('jsonwebtoken');
const { promisify } = require('util'); // Node built-in utility
const User = require('../models/User'); // Mongoose User Model

// NOTE: These should be secured environment variables in production!
const JWT_SECRET = 'YOUR_SUPER_SECRET_AND_LONG_KEY_HERE';
const JWT_EXPIRES_IN = '1h'; // Token valid for 1 hour

// ----------------------------------------------------
// 1. JWT TOKEN GENERATION
// ----------------------------------------------------

// Creates and signs a JWT token with user ID and role
const signToken = (user) => {
    return jwt.sign(
        { id: user._id, role: user.role }, 
        JWT_SECRET, 
        { expiresIn: JWT_EXPIRES_IN }
    );
};

// ----------------------------------------------------
// 2. MIDDLEWARE: PROTECT ROUTE (Auth Guard)
// ----------------------------------------------------

// Middleware to protect routes: ensures user is logged in and token is valid
const protectRoute = async (req, res, next) => {
    try {
        let token;
        
        // 1. Get token from the request header (expected format: 'Bearer TOKEN')
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        // 2. Check if token exists
        if (!token) {
            return res.status(401).json({
                status: 'fail',
                message: 'Access denied. You are not logged in. Please log in to get access.'
            });
        }

        // 3. Verify the token (checks signature and expiration)
        const decoded = await promisify(jwt.verify)(token, JWT_SECRET);

        // 4. Check if user still exists (e.g., deleted account)
        const currentUser = await User.findById(decoded.id).select('+password'); 
        if (!currentUser) {
            return res.status(401).json({
                status: 'fail',
                message: 'The user belonging to this token no longer exists.'
            });
        }

        // 5. Grant access to protected route
        req.user = currentUser; // Attach the user document to the request object
        next();

    } catch (err) {
        // Handle common errors like token expiry or invalid signature
        console.error('JWT Verification Error:', err.name, err.message);
        let message = 'Invalid token. Please log in again.';
        if (err.name === 'TokenExpiredError') {
             message = 'Token has expired. Please log in again.';
        }
        
        return res.status(401).json({
            status: 'fail',
            message: message
        });
    }
};

// ----------------------------------------------------
// 3. MIDDLEWARE: RESTRICT TO ROLE (RBAC)
// ----------------------------------------------------

// Middleware to restrict access based on user role (e.g., restrictTo('admin'))
const restrictTo = (...roles) => {
    return (req, res, next) => {
        // req.user is available because protectRoute middleware ran first
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({
                status: 'fail',
                message: 'You do not have permission to perform this action.'
            });
        }
        next();
    };
};


module.exports = {
    signToken,
    protectRoute,
    restrictTo
};

