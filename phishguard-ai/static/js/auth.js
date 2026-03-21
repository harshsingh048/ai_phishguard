/* PhishGuard AI - Auth JS */

const API_BASE = '/api';

document.addEventListener('DOMContentLoaded', () => {
  // If already logged in, redirect
  if (localStorage.getItem('phishguard_token')) {
    window.location.href = '/';
    return;
  }

  // Enter key support
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    if (!loginForm.classList.contains('hidden')) doLogin();
    else doRegister();
  });
});

function showLogin() {
  document.getElementById('loginForm').classList.remove('hidden');
  document.getElementById('registerForm').classList.add('hidden');
  document.getElementById('loginTab').classList.add('active');
  document.getElementById('registerTab').classList.remove('active');
  clearErrors();
}

function showRegister() {
  document.getElementById('loginForm').classList.add('hidden');
  document.getElementById('registerForm').classList.remove('hidden');
  document.getElementById('loginTab').classList.remove('active');
  document.getElementById('registerTab').classList.add('active');
  clearErrors();
}

function clearErrors() {
  document.getElementById('loginError').classList.add('hidden');
  document.getElementById('registerError').classList.add('hidden');
}

async function doLogin() {
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errorEl = document.getElementById('loginError');
  const btn = document.querySelector('#loginForm .auth-btn');
  const btnText = document.getElementById('loginBtnText');
  const spinner = document.getElementById('loginSpinner');

  if (!username || !password) {
    showError(errorEl, 'Please fill in all fields');
    return;
  }

  setLoading(btn, btnText, spinner, true);
  errorEl.classList.add('hidden');

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (data.success && data.token) {
      localStorage.setItem('phishguard_token', data.token);
      localStorage.setItem('phishguard_user', JSON.stringify(data.user));
      window.location.href = '/';
    } else {
      showError(errorEl, data.error || 'Login failed');
    }
  } catch (err) {
    showError(errorEl, 'Connection error. Is the server running?');
  } finally {
    setLoading(btn, btnText, spinner, false);
  }
}

async function doRegister() {
  const username = document.getElementById('regUsername').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPassword').value;
  const errorEl = document.getElementById('registerError');
  const btn = document.querySelector('#registerForm .auth-btn');
  const btnText = document.getElementById('registerBtnText');
  const spinner = document.getElementById('registerSpinner');

  if (!username || !email || !password) {
    showError(errorEl, 'Please fill in all fields');
    return;
  }

  setLoading(btn, btnText, spinner, true);
  errorEl.classList.add('hidden');

  try {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });

    const data = await res.json();

    if (data.success && data.token) {
      localStorage.setItem('phishguard_token', data.token);
      localStorage.setItem('phishguard_user', JSON.stringify(data.user));
      window.location.href = '/';
    } else {
      showError(errorEl, data.error || 'Registration failed');
    }
  } catch (err) {
    showError(errorEl, 'Connection error. Is the server running?');
  } finally {
    setLoading(btn, btnText, spinner, false);
  }
}

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

function setLoading(btn, textEl, spinnerEl, loading) {
  btn.disabled = loading;
  textEl.classList.toggle('hidden', loading);
  spinnerEl.classList.toggle('hidden', !loading);
}
