// --- FILE: project1/server/controllers/userController.js ---

const { signToken } = require('../utils/authUtils');
const User = require('../models/User'); 
const bcrypt = require('bcrypt');
const crypto = require('crypto'); 

// Helper function to verify password for login (Using bcrypt directly)
const verifyPassword = (candidatePassword, hash) => bcrypt.compare(candidatePassword, hash);
// Helper function to hash password for registration/reset (Using bcrypt directly)
const hashPassword = (password) => bcrypt.hash(password, 12); 


// Helper function to remove sensitive fields from the user object before sending to the client
const sanitizeUser = (user) => {
    // Convert Mongoose document to a plain JavaScript object
    const userObj = user.toObject ? user.toObject() : { ...user };
    
    // Explicitly delete sensitive fields
    delete userObj.password;
    delete userObj.passwordResetToken;
    delete userObj.passwordResetExpires;
    delete userObj.__v; // Mongoose version key
    
    return userObj;
}


// --- 1. REGISTRATION LOGIC (/api/register) ---
exports.register = async (req, res) => {
    try {
        const { email, password, name } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Please provide email and password.' });
        
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(409).json({ success: false, message: 'User with this email already exists.' });
        
        const userCount = await User.countDocuments();
        const role = userCount === 0 ? 'admin' : 'user';
        
        const newUser = await User.create({ name, email, password, role });

        const token = signToken(newUser);
        const sanitizedUser = sanitizeUser(newUser); // <-- POLISH: Sanitize user data

        res.status(201).json({ 
            success: true, 
            message: 'Registration successful and logged in.',
            token,
            user: sanitizedUser // <-- Send sanitized data
        });

    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ success: false, message: 'Server error during registration.' });
    }
};

// --- 2. LOGIN LOGIC (/api/login) ---
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Please provide email and password.' });
        
        const user = await User.findOne({ email }).select('+password');
        
        if (!user || !(await verifyPassword(password, user.password))) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        const token = signToken(user);
        const sanitizedUser = sanitizeUser(user); // <-- POLISH: Sanitize user data

        res.status(200).json({
            success: true,
            message: 'Login successful.',
            token,
            user: sanitizedUser, // <-- Send sanitized data
        });

    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
};

// --- 3. FORGOT PASSWORD (/api/forgot-password) ---
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(200).json({ 
                success: true, 
                message: 'If the email exists, a password reset link has been sent.' 
            });
        }

        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false }); 

        const resetURL = `http://localhost:3000/#reset-password/${resetToken}`;
        
        console.log('\n----------------------------------------------------');
        console.log(`🔑 PASSWORD RESET TOKEN FOR ${user.email}:`);
        console.log(`Copy this URL to test: ${resetURL}`);
        console.log('----------------------------------------------------\n');
        
        res.status(200).json({ 
            success: true, 
            message: 'Password reset link sent to console/terminal.',
            dev_reset_url: resetURL 
        });

    } catch (error) {
        console.error('Forgot Password Error:', error);
        if (user) {
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save({ validateBeforeSave: false });
        }
        res.status(500).json({ success: false, message: 'Error processing password reset request.' });
    }
};


// --- 4. RESET PASSWORD (/api/reset-password/:token) ---
exports.resetPassword = async (req, res) => {
    try {
        const { password } = req.body;
        const { token } = req.params;

        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() } 
        }).select('+password');

        if (!user) {
            return res.status(400).json({ success: false, message: 'Token is invalid or has expired.' });
        }
        
        user.password = await hashPassword(password);
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save(); 

        const newToken = signToken(user);
        const sanitizedUser = sanitizeUser(user); // <-- POLISH: Sanitize user data

        res.status(200).json({
            success: true,
            message: 'Password reset successful and you are now logged in.',
            token: newToken,
            user: sanitizedUser, // <-- Send sanitized data
        });

    } catch (error) {
        console.error('Reset Password Error:', error);
        res.status(500).json({ success: false, message: 'Server error during password reset.' });
    }
};

