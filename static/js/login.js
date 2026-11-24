(() => {
  const form = document.getElementById('loginForm');
  const err = document.getElementById('loginError');
  const btn = document.getElementById('loginBtn');
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.hidden = true;
    const login = form.login.value.trim(), password = form.password.value;
    if (!login || !password) { err.textContent = 'Enter your username/email and password.'; err.hidden = false; return; }
    btn.disabled = true; btn.textContent = 'Signing in…';
    try {
      const res = await fetch('/api/auth/login', { method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify({ login, password }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Sign-in failed.');
      const next = new URLSearchParams(location.search).get('next');
      location.href = next && next.startsWith('/') && !next.startsWith('//') ? next : '/';
    } catch (ex) {
      err.textContent = ex.message; err.hidden = false;
      btn.disabled = false; btn.textContent = 'Sign in';
    }
  });
})();
