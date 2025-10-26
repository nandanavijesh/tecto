// --- FILE: project1/public/app.js ---

// --- GLOBAL STATE & DOM ELEMENTS ---
const elements = {
    appContainer: document.getElementById('app-container'),
    headerNav: document.getElementById('header-nav'),
    viewTitle: document.getElementById('view-title'),
    messageArea: document.getElementById('message-area'),
    
    // Forms
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    forgotForm: document.getElementById('forgot-password-form'),
    resetForm: document.getElementById('reset-password-form'),

    // Buttons/Nav
    logoutButton: document.getElementById('logout-button'),
    navDashboard: document.getElementById('nav-dashboard'),
    navAdmin: document.getElementById('nav-admin'),

    // Dashboard Info
    dashboardName: document.getElementById('dashboard-name'),
    dashboardEmail: document.getElementById('dashboard-email'),
    dashboardRole: document.getElementById('dashboard-role'),
    dashboardResponse: document.getElementById('dashboard-response'),
    adminResponse: document.getElementById('admin-response'),

    // Views
    loginView: document.getElementById('login-view'),
    registerView: document.getElementById('register-view'),
    dashboardView: document.getElementById('dashboard-view'),
    adminView: document.getElementById('admin-view'),
    forgotView: document.getElementById('forgot-password-view'),
    resetView: document.getElementById('reset-password-view'),
};

let currentToken = localStorage.getItem('jwt_token') || null;
let userRole = null; 
let resetToken = null; 

// --- HELPER FUNCTIONS ---

/**
 * Displays a message to the user (success or error).
 * @param {string} text - The message content.
 * @param {string} type - 'success' or 'error'.
 */
function displayMessage(text, type) {
    elements.messageArea.innerHTML = text; 
    elements.messageArea.classList.remove('hidden', 'bg-red-100', 'bg-green-100', 'text-red-800', 'text-green-800');
    
    if (type === 'success') {
        elements.messageArea.classList.add('bg-green-100', 'text-green-800');
    } else {
        elements.messageArea.classList.add('bg-red-100', 'text-red-800');
    }
}

/**
 * Hides all view elements.
 */
function hideAllViews() {
    document.querySelectorAll('.view').forEach(view => view.classList.add('hidden'));
    elements.messageArea.classList.add('hidden');
    elements.headerNav.classList.add('hidden');
}

/**
 * Clears all input fields in a given form element.
 * @param {HTMLElement} formElement - The form to clear.
 */
function clearForm(formElement) {
    if (formElement) {
        formElement.reset();
    }
}

/**
 * Sets the loading state for a form button.
 * @param {HTMLElement} form - The form element.
 * @param {boolean} isLoading - True to disable and change text, false to enable/revert.
 */
function setLoading(form, isLoading) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;

    if (isLoading) {
        button.disabled = true;
        button.textContent = 'Processing...';
    } else {
        button.disabled = false;
        // Revert text based on form ID
        if (form.id === 'login-form') button.textContent = 'Sign In';
        else if (form.id === 'register-form') button.textContent = 'Register Account';
        else if (form.id === 'forgot-password-form') button.textContent = 'Send Reset Link';
        else if (form.id === 'reset-password-form') button.textContent = 'Reset and Log In';
    }
}


/**
 * Makes an authenticated request to the backend.
 * @param {string} url - The API endpoint.
 * @param {string} method - HTTP method (GET, POST).
 * @returns {Promise<Object>} - JSON response data.
 */
async function makeAuthRequest(url, method = 'GET') {
    const token = localStorage.getItem('jwt_token');
    if (!token) {
        handleLogout(false);
        return null;
    }
    
    let response;
    try {
        response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Authentication required.');
        }
        return data;

    } catch (error) {
        console.error("Auth Request Error:", error);
        
        if (response && (response.status === 401 || response.status === 403)) {
            handleLogout(false); 
            displayMessage('Session expired or access denied. Please log in again.', 'error');
        } else {
            displayMessage(`API Error: ${error.message}`, 'error');
        }
        return null;
    }
}


// --- VIEW RENDERING AND ROUTING ---

/**
 * Updates the UI based on the hash route.
 * @param {string} viewName - The view to show (login, dashboard, etc.)
 */
function renderView(viewName) {
    hideAllViews();
    elements.viewTitle.textContent = viewName.toUpperCase().replace('-', ' ');

    const hash = window.location.hash.substring(1);
    resetToken = hash.startsWith('reset-password/') ? hash.split('/')[1] : null;

    currentToken = localStorage.getItem('jwt_token');
    
    if (currentToken) {
        // --- LOGGED IN VIEWS ---
        elements.headerNav.classList.remove('hidden');
        
        try {
            const payload = JSON.parse(atob(currentToken.split('.')[1]));
            userRole = payload.role;
            
            if (userRole === 'admin') {
                elements.navAdmin.classList.remove('hidden');
            } else {
                elements.navAdmin.classList.add('hidden');
            }

            if (viewName === 'dashboard') {
                elements.dashboardView.classList.remove('hidden');
                fetchDashboardData();
            } else if (viewName === 'admin') {
                elements.adminView.classList.remove('hidden');
                fetchAdminData();
            } else {
                window.location.hash = 'dashboard';
            }

        } catch(e) {
            console.error("Invalid token format, forcing logout:", e);
            handleLogout(false);
        }

    } else {
        // --- PUBLIC VIEWS ---
        if (viewName === 'register') {
            elements.registerView.classList.remove('hidden');
        } else if (viewName === 'forgot-password') {
            elements.forgotView.classList.remove('hidden');
        } else if (resetToken) {
            elements.resetView.classList.remove('hidden');
        } else {
            elements.loginView.classList.remove('hidden');
        }
    }
}

// --- API FETCHERS ---

async function fetchDashboardData() {
    const data = await makeAuthRequest('/api/dashboard');
    if (data && data.success) {
        elements.dashboardName.textContent = data.user.name || 'N/A';
        elements.dashboardEmail.textContent = data.user.email;
        elements.dashboardRole.textContent = data.user.role;
        // Clean up the JSON response by removing the password field 
        // to prevent false security warnings in the browser console.
        const cleanData = { ...data };
        if(cleanData.user && cleanData.user.password) {
            delete cleanData.user.password;
        }
        elements.dashboardResponse.textContent = JSON.stringify(cleanData, null, 2);
    } 
}

async function fetchAdminData() {
    const data = await makeAuthRequest('/api/admin');
    if (data && data.success) {
        elements.adminResponse.textContent = JSON.stringify(data, null, 2);
    } else if (data) {
        elements.adminResponse.textContent = `Error: ${data.message || 'Access denied.'}`;
    }
}


// --- FORM HANDLERS (with UX improvements) ---

async function handleRegister(e) {
    e.preventDefault();
    setLoading(elements.registerForm, true); // <--- UX Improvement: Start Loading
    
    const name = document.getElementById('register-name').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;

    if (password.length < 6) {
        displayMessage('Password must be at least 6 characters long.', 'error');
        setLoading(elements.registerForm, false);
        return;
    }

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password }),
        });

        const data = await response.json();
        if (data.success) {
            displayMessage(data.message + " Redirecting to dashboard...", 'success');
            clearForm(elements.registerForm); // <--- UX Improvement: Clear Form
            localStorage.setItem('jwt_token', data.token);
            window.location.hash = 'dashboard';
        } else {
            displayMessage(data.message || 'Registration failed.', 'error');
        }
    } catch (error) {
        displayMessage('Network error during registration.', 'error');
    } finally {
        setLoading(elements.registerForm, false); // <--- UX Improvement: End Loading
    }
}

async function handleLogin(e) {
    e.preventDefault();
    setLoading(elements.loginForm, true); // <--- UX Improvement: Start Loading
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();
        if (data.success && data.token) {
            localStorage.setItem('jwt_token', data.token);
            displayMessage('Login successful. Welcome!', 'success');
            clearForm(elements.loginForm); // <--- UX Improvement: Clear Form
            window.location.hash = 'dashboard';
        } else {
            displayMessage(data.message || 'Login failed: Invalid credentials.', 'error');
        }
    } catch (error) {
        displayMessage('Network error during login.', 'error');
    } finally {
        setLoading(elements.loginForm, false); // <--- UX Improvement: End Loading
    }
}

function handleLogout(redirect = true) {
    localStorage.removeItem('jwt_token');
    currentToken = null;
    userRole = null;
    elements.headerNav.classList.add('hidden');
    elements.navAdmin.classList.add('hidden');
    if (redirect) {
        displayMessage('You have been securely logged out.', 'success');
        window.location.hash = 'login';
    }
}

async function handleForgotPassword(e) {
    e.preventDefault();
    setLoading(elements.forgotForm, true); // <--- UX Improvement: Start Loading
    
    const email = document.getElementById('forgot-email').value;
    
    try {
        const response = await fetch('/api/forgot-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });

        const data = await response.json();
        if (data.success) {
            clearForm(elements.forgotForm); // <--- UX Improvement: Clear Form
            const devUrl = data.dev_reset_url ? `<br>Check server console for the reset link! (Only in dev)` : '';
            displayMessage(`Reset request successful. ${devUrl}`, 'success');
        } else {
            displayMessage(data.message || 'Failed to request password reset.', 'error');
        }
    } catch (error) {
        displayMessage('Network error during password reset request.', 'error');
    } finally {
        setLoading(elements.forgotForm, false); // <--- UX Improvement: End Loading
    }
}

async function handleResetPassword(e) {
    e.preventDefault();
    setLoading(elements.resetForm, true); // <--- UX Improvement: Start Loading
    
    const newPassword = document.getElementById('reset-password-new').value;
    const confirmPassword = document.getElementById('reset-password-confirm').value;

    if (newPassword !== confirmPassword || newPassword.length < 6 || !resetToken) {
        displayMessage(newPassword !== confirmPassword ? 'Passwords do not match.' : newPassword.length < 6 ? 'New password must be at least 6 characters long.' : 'Missing reset token in URL.', 'error');
        setLoading(elements.resetForm, false);
        return;
    }

    try {
        const response = await fetch(`/api/reset-password/${resetToken}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: newPassword }),
        });

        const data = await response.json();
        if (data.success && data.token) {
            localStorage.setItem('jwt_token', data.token);
            displayMessage('Password reset successful. Logging you in...', 'success');
            clearForm(elements.resetForm); // <--- UX Improvement: Clear Form
            window.location.hash = 'dashboard';
        } else {
            displayMessage(data.message || 'Password reset failed. Token may be invalid or expired.', 'error');
        }

    } catch (error) {
        displayMessage('Network error during password reset.', 'error');
    } finally {
        setLoading(elements.resetForm, false); // <--- UX Improvement: End Loading
    }
}


// --- EVENT LISTENERS & INITIALIZATION ---

window.addEventListener('hashchange', () => renderView(window.location.hash.substring(1)));
window.addEventListener('load', () => {
    const initialHash = window.location.hash.substring(1) || 'login';
    renderView(initialHash);

    // Attach form listeners
    if (elements.loginForm) elements.loginForm.addEventListener('submit', handleLogin);
    if (elements.registerForm) elements.registerForm.addEventListener('submit', handleRegister);
    if (elements.forgotForm) elements.forgotForm.addEventListener('submit', handleForgotPassword);
    if (elements.resetForm) elements.resetForm.addEventListener('submit', handleResetPassword);

    // Attach button listeners
    if (elements.logoutButton) elements.logoutButton.addEventListener('click', () => handleLogout(true));
    if (elements.navDashboard) elements.navDashboard.addEventListener('click', () => window.location.hash = 'dashboard');
    if (elements.navAdmin) elements.navAdmin.addEventListener('click', () => window.location.hash = 'admin');
});

