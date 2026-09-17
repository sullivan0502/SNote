function getToken() { return localStorage.getItem('token'); }

function requireAuth(expectedRole) {
  const token = getToken();
  const role = localStorage.getItem('role');
  if (!token || (expectedRole && role !== expectedRole)) {
    window.location.href = '/';
    return false;
  }
  return true;
}

function logout() {
  localStorage.clear();
  window.location.href = '/';
}

async function apiFetch(url, options = {}) {
  options.headers = options.headers || {};
  options.headers['Authorization'] = 'Bearer ' + getToken();
  const res = await fetch(url, options);
  if (res.status === 401) { logout(); return; }
  return res;
}

async function apiGet(url) {
  const res = await apiFetch(url);
  return res.json();
}

async function apiPostForm(url, formData) {
  const res = await apiFetch(url, { method: 'POST', body: formData });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || 'Erreur');
  return data;
}

async function apiDelete(url) {
  const res = await apiFetch(url, { method: 'DELETE' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || 'Erreur');
  return data;
}

function esc(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}
