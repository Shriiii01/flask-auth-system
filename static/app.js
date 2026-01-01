const API_BASE_URL = window.location.origin;

// Check if we have tokens from OAuth redirect
window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const refreshToken = urlParams.get('refresh_token');
    
    if (token && refreshToken) {
        // Store tokens
        localStorage.setItem('access_token', token);
        localStorage.setItem('refresh_token', refreshToken);
        
        // Clean URL
        window.history.replaceState({}, document.title, '/');
        
        // Show success message
        showMessage('Login successful!', 'success');
        
        // Redirect to dashboard or home
        setTimeout(() => {
            window.location.href = '/dashboard';
        }, 1500);
    }
});

function showLogin() {
    document.getElementById('loginForm').parentElement.style.display = 'block';
    document.getElementById('signupCard').style.display = 'none';
}

function showSignup() {
    document.getElementById('loginForm').parentElement.style.display = 'none';
    document.getElementById('signupCard').style.display = 'block';
}

function showMessage(text, type) {
    const messageEl = document.getElementById('message');
    messageEl.textContent = text;
    messageEl.className = `message ${type}`;
    setTimeout(() => {
        messageEl.className = 'message';
    }, 5000);
}

// Login form handler
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('refresh_token', data.refresh_token);
            showMessage('Login successful!', 'success');
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1500);
        } else {
            showMessage(data.detail || 'Login failed', 'error');
        }
    } catch (error) {
        showMessage('Network error. Please try again.', 'error');
    }
});

// Signup form handler
document.getElementById('signupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('signupUsername').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showMessage('Account created successfully! Please sign in.', 'success');
            setTimeout(() => {
                showLogin();
            }, 2000);
        } else {
            showMessage(data.detail || 'Signup failed', 'error');
        }
    } catch (error) {
        showMessage('Network error. Please try again.', 'error');
    }
});

function loginWithGoogle() {
    window.location.href = `${API_BASE_URL}/auth/google`;
}

function loginWithGitHub() {
    window.location.href = `${API_BASE_URL}/auth/github`;
}

