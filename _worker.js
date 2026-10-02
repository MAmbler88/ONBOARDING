const PAGE_KEY_PATTERN = /^[a-zA-Z0-9_-]{1,100}$/;
const SESSION_COOKIE = "pi_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const PBKDF2_ITERATIONS = 100000;

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

function badRequest(message) {
  return jsonResponse({ error: message }, 400);
}

function getCookie(request, name) {
  const header = request.headers.get("cookie");
  if (!header) return undefined;
  for (const pair of header.split(";")) {
    const idx = pair.indexOf("=");
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (key === name) return value;
  }
  return undefined;
}

function setCookieHeader(name, value, maxAgeSeconds) {
  return `${name}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Strict`;
}

function clearCookieHeader(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

/* ---------- Password hashing (PBKDF2) ---------- */
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

async function hashPassword(password, existingSaltHex) {
  const salt = existingSaltHex ? hexToBytes(existingSaltHex) : crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash || !storedSalt) return false;
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
}

/* ---------- Users list (KV-backed) ---------- */
async function getUsers(env) {
  const raw = await env.PROCESS_INDEX_KV.get("auth:users");
  return raw ? JSON.parse(raw) : [];
}

async function saveUsers(env, users) {
  await env.PROCESS_INDEX_KV.put("auth:users", JSON.stringify(users));
}

function findUserByEmail(users, email) {
  const normalized = String(email || "").trim().toLowerCase();
  return users.find(u => u.email.toLowerCase() === normalized);
}

/* ---------- Sessions ---------- */
async function getSession(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const raw = await env.PROCESS_INDEX_KV.get(`auth:session:${token}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function requireRole(request, env, roles) {
  const session = await getSession(request, env);
  if (!session) return { ok: false, response: jsonResponse({ error: "Not signed in" }, 401) };
  if (roles && !roles.includes(session.role)) {
    return { ok: false, response: jsonResponse({ error: "Not allowed" }, 403) };
  }
  return { ok: true, session };
}

/* ---------- Login page ---------- */
function loginPageHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in</title>
<style>
  body{font-family:'Inter',system-ui,sans-serif;background:#F6F5F1;color:#33363A;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
  .box{background:#fff;border:1px solid #E1DED7;border-radius:10px;padding:36px 32px;max-width:340px;width:100%;box-sizing:border-box;}
  h1{font-size:18px;margin:0 0 18px;}
  input{width:100%;padding:10px 12px;border:1px solid #E1DED7;border-radius:6px;font-size:14px;margin-bottom:14px;box-sizing:border-box;font-family:inherit;}
  button{width:100%;padding:10px;border:none;border-radius:7px;background:#803A6C;color:#fff;font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;}
  button:hover{background:#6E325D;}
  button:disabled{opacity:.6;cursor:default;}
  .err{color:#A15048;font-size:13px;margin-bottom:14px;}
</style>
</head>
<body>
  <form class="box" id="loginForm">
    <h1>Sign in</h1>
    <div id="loginErr" class="err" style="display:none;"></div>
    <input type="email" id="emailInput" placeholder="you@company.com" autofocus autocomplete="email">
    <input type="password" id="passwordInput" placeholder="Password" autocomplete="current-password">
    <button type="submit" id="loginBtn">Sign in</button>
  </form>
  <script>
    const form = document.getElementById('loginForm');
    const emailInput = document.getElementById('emailInput');
    const passwordInput = document.getElementById('passwordInput');
    const loginErr = document.getElementById('loginErr');
    const loginBtn = document.getElementById('loginBtn');

    form.addEventListener('submit', async (e)=>{
      e.preventDefault();
      loginErr.style.display = 'none';
      const email = emailInput.value.trim();
      const password = passwordInput.value;
      if(!email || !password) return;
      loginBtn.disabled = true; loginBtn.textContent = 'Signing in…';
      try{
        const res = await fetch('/api/login', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ email, password })
        });
        if(res.ok){
          window.location.href = '/';
          return;
        }
        const data = await res.json().catch(()=>({}));
        loginErr.textContent = data.error || 'Incorrect email or password.';
        loginErr.style.display = 'block';
      }catch(err){
        loginErr.textContent = 'Something went wrong. Try again.';
        loginErr.style.display = 'block';
      }
      loginBtn.disabled = false; loginBtn.textContent = 'Sign in';
    });
  </script>
</body>
</html>`;
}

/* ---------- Email helper (used only for the welcome notice now) ---------- */
async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) return;
  try {
    const resendKey = typeof env.RESEND_API_KEY.get === "function"
      ? await env.RESEND_API_KEY.get()
      : env.RESEND_API_KEY;
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.RESEND_FROM || "onboarding@resend.dev",
        to,
        subject,
        html,
      }),
    });
  } catch (e) {
    // Swallow — don't leak email-sending failures to the client.
  }
}

/* ---------- Login endpoint ---------- */
async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!email || !password) return badRequest("Enter your email and password");

  const users = await getUsers(env);
  const user = findUserByEmail(users, email);

  let role = null;

  if (user && await verifyPassword(password, user.passwordHash, user.passwordSalt)) {
    role = user.role;
  }

  // Bootstrap admin fallback, in case they're not in the KV list yet.
  if (!role) {
    const initialAdmin = String(env.INITIAL_ADMIN_EMAIL || "").trim().toLowerCase();
    const initialAdminPassword = String(env.INITIAL_ADMIN_PASSWORD || "");
    if (initialAdmin && initialAdminPassword && email === initialAdmin && password === initialAdminPassword) {
      role = "admin";
    }
  }

  if (!role) {
    return jsonResponse({ error: "Incorrect email or password" }, 401);
  }

  const token = crypto.randomUUID();
  await env.PROCESS_INDEX_KV.put(`auth:session:${token}`, JSON.stringify({ email, role }), {
    expirationTtl: SESSION_TTL_SECONDS,
  });

  return jsonResponse({ ok: true }, 200, { "Set-Cookie": setCookieHeader(SESSION_COOKIE, token, SESSION_TTL_SECONDS) });
}

async function handleLogout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) await env.PROCESS_INDEX_KV.delete(`auth:session:${token}`);
  return jsonResponse({ ok: true }, 200, { "Set-Cookie": clearCookieHeader(SESSION_COOKIE) });
}

async function handleWhoami(request, env) {
  const session = await getSession(request, env);
  if (!session) return jsonResponse({ signedIn: false });
  return jsonResponse({ signedIn: true, email: session.email, role: session.role });
}

/* ---------- Users management (admin only) ---------- */
async function handleUsers(request, env) {
  const auth = await requireRole(request, env, ["admin"]);
  if (!auth.ok) return auth.response;

  if (request.method === "GET") {
    const users = await getUsers(env);
    // Never send password hashes/salts to the browser.
    const safe = users.map(u => ({ email: u.email, role: u.role }));
    return jsonResponse({ users: safe });
  }

  if (request.method === "POST") {
    let body;
    try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
    const email = String(body.email || "").trim().toLowerCase();
    const role = String(body.role || "").trim();
    const password = String(body.password || "");
    if (!email || !email.includes("@")) return badRequest("Enter a valid email");
    if (!["admin", "editor", "viewer"].includes(role)) return badRequest("Invalid role");

    const users = await getUsers(env);
    const existing = findUserByEmail(users, email);
    const isNewPerson = !existing;
    if (isNewPerson && !password) return badRequest("Set a password for this new person");

    if (existing) {
      existing.role = role;
      if (password) {
        const { hash, salt } = await hashPassword(password);
        existing.passwordHash = hash;
        existing.passwordSalt = salt;
      }
    } else {
      const { hash, salt } = await hashPassword(password);
      users.push({ email, role, passwordHash: hash, passwordSalt: salt });
    }
    await saveUsers(env, users);

    if (isNewPerson) {
      const siteUrl = new URL(request.url).origin;
      const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);
      await sendEmail(env, {
        to: email,
        subject: "You've been added to the Process Index",
        html: `<p>You've been given <strong>${roleLabel}</strong> access to the Process Index tool.</p>
<p>Visit <a href="${siteUrl}">${siteUrl}</a> and sign in with this email address — ask whoever added you for your password.</p>`,
      });
    }

    const safe = users.map(u => ({ email: u.email, role: u.role }));
    return jsonResponse({ ok: true, users: safe });
  }

  if (request.method === "DELETE") {
    let body;
    try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
    const email = String(body.email || "").trim().toLowerCase();
    const users = await getUsers(env);
    const next = users.filter(u => u.email.toLowerCase() !== email);
    await saveUsers(env, next);
    const safe = next.map(u => ({ email: u.email, role: u.role }));
    return jsonResponse({ ok: true, users: safe });
  }

  return new Response("Method not allowed", { status: 405 });
}

/* ---------- Page-data endpoint, role-gated ---------- */
async function handleData(request, env) {
  const url = new URL(request.url);
  const page = url.searchParams.get("page");
  if (!page || !PAGE_KEY_PATTERN.test(page)) return badRequest("Unknown or missing page");

  if (request.method === "GET") {
    const auth = await requireRole(request, env, ["admin", "editor", "viewer"]);
    if (!auth.ok) return auth.response;
    const raw = await env.PROCESS_INDEX_KV.get(page);
    return jsonResponse({ value: raw ? JSON.parse(raw) : null });
  }

  if (request.method === "POST") {
    const auth = await requireRole(request, env, ["admin", "editor"]);
    if (!auth.ok) return auth.response;
    let body;
    try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
    if (!Array.isArray(body.groups)) return badRequest("'groups' must be an array");
    await env.PROCESS_INDEX_KV.put(page, JSON.stringify(body.groups));
    return jsonResponse({ ok: true });
  }

  return new Response("Method not allowed", { status: 405 });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/data") return handleData(request, env);
    if (url.pathname === "/api/login" && request.method === "POST") return handleLogin(request, env);
    if (url.pathname === "/api/logout" && request.method === "POST") return handleLogout(request, env);
    if (url.pathname === "/api/whoami") return handleWhoami(request, env);
    if (url.pathname === "/api/users") return handleUsers(request, env);

    // Everything else (the app itself and its static assets) requires a valid session.
    const session = await getSession(request, env);
    if (!session) {
      return new Response(loginPageHtml(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    return env.ASSETS.fetch(request);
  },
};
