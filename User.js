// --- FILE: project1/server/models/User.js ---

const mongoose = require('mongoose');
const crypto = require('crypto'); // Built-in Node module for generating secure tokens
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    // User identification and credentials
    name: {
        type: String,
        trim: true,
        default: 'User'
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: 6,
        // The select: false option prevents the password hash from being sent 
        // in query results by default, enhancing security.
        select: false 
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    
    // Fields for the secure password reset flow
    passwordResetToken: String,
    passwordResetExpires: Date
});


// --- Mongoose Middleware (Pre-Save Hook) ---

// 1. Encrypt password before saving the document
userSchema.pre('save', async function(next) {
    // Only run this function if password was actually modified
    if (!this.isModified('password')) return next();
    
    // Hash the password with a cost of 12
    this.password = await bcrypt.hash(this.password, 12);
    
    next();
});


// --- Instance Methods (Methods available on a User document) ---

// 1. Compare candidate password with stored hash
userSchema.methods.correctPassword = async function(candidatePassword, userPasswordHash) {
    // Note: this.password cannot be used because select: false is set.
    return await bcrypt.compare(candidatePassword, userPasswordHash);
};

// 2. Generate a secure, temporary password reset token
userSchema.methods.createPasswordResetToken = function() {
    // Generate a random, cryptographically secure token (plain text)
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Store the ENCRYPTED version of the token in the database
    // This protects against database compromise (like JWT, we don't store the plain token)
    this.passwordResetToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');

    // Set token expiration to 1 hour (60 minutes)
    this.passwordResetExpires = Date.now() + 60 * 60 * 1000;

    // Return the PLAIN, unencrypted token to be sent to the user (via email/console)
    return resetToken;
};

// Create the Mongoose Model
const User = mongoose.model('User', userSchema);

module.exports = User;

