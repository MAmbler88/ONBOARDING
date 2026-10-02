const PAGE_KEY_PATTERN = /^[a-zA-Z0-9_-]{1,100}$/;
const SESSION_COOKIE = "pi_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const CODE_TTL_SECONDS = 60 * 10; // 10 minutes

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
  .box{background:#fff;border:1px solid #E1DED7;border-radius:10px;padding:36px 32px;max-width:360px;width:100%;box-sizing:border-box;}
  h1{font-size:18px;margin:0 0 8px;}
  p{font-size:13.5px;color:#767A75;margin:0 0 18px;}
  input{width:100%;padding:10px 12px;border:1px solid #E1DED7;border-radius:6px;font-size:14px;margin-bottom:14px;box-sizing:border-box;font-family:inherit;}
  button{width:100%;padding:10px;border:none;border-radius:7px;background:#803A6C;color:#fff;font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;}
  button:hover{background:#6E325D;}
  button:disabled{opacity:.6;cursor:default;}
  .err{color:#A15048;font-size:13px;margin-bottom:14px;}
  .msg{color:#4A7D67;font-size:13px;margin-bottom:18px;}
  .step{display:none;}
  .step.active{display:block;}
  a.back{font-size:13px;color:#767A75;text-decoration:underline;cursor:pointer;}
</style>
</head>
<body>
  <div class="box">
    <div class="step active" id="stepEmail">
      <h1>Sign in</h1>
      <p>Enter your email and we'll send you a one-time code.</p>
      <div id="emailErr" class="err" style="display:none;"></div>
      <input type="email" id="emailInput" placeholder="you@company.com" autofocus autocomplete="email">
      <button id="sendCodeBtn">Send code</button>
    </div>
    <div class="step" id="stepCode">
      <h1>Enter your code</h1>
      <p id="codeSentMsg" class="msg"></p>
      <div id="codeErr" class="err" style="display:none;"></div>
      <input type="text" id="codeInput" placeholder="6-digit code" inputmode="numeric" autocomplete="one-time-code" maxlength="6">
      <button id="verifyBtn">Sign in</button>
      <p style="margin-top:12px;"><a class="back" id="backLink">Use a different email</a></p>
    </div>
  </div>
  <script>
    let currentEmail = "";
    const stepEmail = document.getElementById('stepEmail');
    const stepCode = document.getElementById('stepCode');
    const emailInput = document.getElementById('emailInput');
    const emailErr = document.getElementById('emailErr');
    const codeInput = document.getElementById('codeInput');
    const codeErr = document.getElementById('codeErr');
    const codeSentMsg = document.getElementById('codeSentMsg');
    const sendBtn = document.getElementById('sendCodeBtn');
    const verifyBtn = document.getElementById('verifyBtn');

    sendBtn.addEventListener('click', async ()=>{
      emailErr.style.display = 'none';
      const email = emailInput.value.trim();
      if(!email) return;
      sendBtn.disabled = true; sendBtn.textContent = 'Sending…';
      try{
        await fetch('/api/request-code', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ email })
        });
        currentEmail = email;
        codeSentMsg.textContent = 'If ' + email + ' is approved, a code has been sent — check your inbox.';
        stepEmail.classList.remove('active');
        stepCode.classList.add('active');
        codeInput.focus();
      }catch(e){
        emailErr.textContent = 'Something went wrong. Try again.';
        emailErr.style.display = 'block';
      }
      sendBtn.disabled = false; sendBtn.textContent = 'Send code';
    });

    verifyBtn.addEventListener('click', async ()=>{
      codeErr.style.display = 'none';
      const code = codeInput.value.trim();
      if(!code) return;
      verifyBtn.disabled = true; verifyBtn.textContent = 'Checking…';
      try{
        const res = await fetch('/api/verify-code', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ email: currentEmail, code })
        });
        if(res.ok){
          window.location.href = '/';
          return;
        }
        const data = await res.json().catch(()=>({}));
        codeErr.textContent = data.error || 'Incorrect or expired code.';
        codeErr.style.display = 'block';
      }catch(e){
        codeErr.textContent = 'Something went wrong. Try again.';
        codeErr.style.display = 'block';
      }
      verifyBtn.disabled = false; verifyBtn.textContent = 'Sign in';
    });

    document.getElementById('backLink').addEventListener('click', ()=>{
      stepCode.classList.remove('active');
      stepEmail.classList.add('active');
      codeInput.value = '';
    });

    codeInput.addEventListener('keydown', e=>{ if(e.key === 'Enter') verifyBtn.click(); });
    emailInput.addEventListener('keydown', e=>{ if(e.key === 'Enter') sendBtn.click(); });
  </script>
</body>
</html>`;
}

/* ---------- Auth endpoints ---------- */
async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) return;
  try {
    // Secrets Store bindings expose the value via .get(), not as a plain string.
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

async function handleRequestCode(request, env) {
  let body;
  try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
  const email = String(body.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) return badRequest("Enter a valid email");

  const users = await getUsers(env);
  let user = findUserByEmail(users, email);

  // The configured initial admin is always allowed, even before appearing in the KV list.
  const initialAdmin = String(env.INITIAL_ADMIN_EMAIL || "").trim().toLowerCase();
  if (!user && initialAdmin && email === initialAdmin) {
    user = { email, role: "admin" };
  }

  if (!user) {
    // Don't reveal whether the email is approved.
    return jsonResponse({ ok: true });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  await env.PROCESS_INDEX_KV.put(`auth:code:${email}`, JSON.stringify({ code, role: user.role }), {
    expirationTtl: CODE_TTL_SECONDS,
  });

  await sendEmail(env, {
    to: email,
    subject: "Your sign-in code",
    html: `<p>Your sign-in code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p><p>This code expires in 10 minutes.</p>`,
  });

  return jsonResponse({ ok: true });
}

async function handleVerifyCode(request, env) {
  let body;
  try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || "").trim();
  if (!email || !code) return badRequest("Missing email or code");

  const raw = await env.PROCESS_INDEX_KV.get(`auth:code:${email}`);
  if (!raw) return jsonResponse({ error: "Incorrect or expired code" }, 401);

  let stored;
  try { stored = JSON.parse(raw); } catch { return jsonResponse({ error: "Incorrect or expired code" }, 401); }
  if (stored.code !== code) return jsonResponse({ error: "Incorrect or expired code" }, 401);

  await env.PROCESS_INDEX_KV.delete(`auth:code:${email}`);

  const token = crypto.randomUUID();
  await env.PROCESS_INDEX_KV.put(`auth:session:${token}`, JSON.stringify({ email, role: stored.role }), {
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
    return jsonResponse({ users: await getUsers(env) });
  }

  if (request.method === "POST") {
    let body;
    try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
    const email = String(body.email || "").trim().toLowerCase();
    const role = String(body.role || "").trim();
    if (!email || !email.includes("@")) return badRequest("Enter a valid email");
    if (!["admin", "editor", "viewer"].includes(role)) return badRequest("Invalid role");

    const users = await getUsers(env);
    const existing = findUserByEmail(users, email);
    const isNewPerson = !existing;
    if (existing) existing.role = role;
    else users.push({ email, role });
    await saveUsers(env, users);

    if (isNewPerson) {
      const siteUrl = new URL(request.url).origin;
      const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);
      await sendEmail(env, {
        to: email,
        subject: "You've been added to the Process Index",
        html: `<p>You've been given <strong>${roleLabel}</strong> access to the Process Index tool.</p>
<p>Visit <a href="${siteUrl}">${siteUrl}</a> and enter this email address to sign in — you'll get a one-time code by email each time you log in, no password needed.</p>`,
      });
    }

    return jsonResponse({ ok: true, users });
  }

  if (request.method === "DELETE") {
    let body;
    try { body = await request.json(); } catch { return badRequest("Invalid JSON body"); }
    const email = String(body.email || "").trim().toLowerCase();
    const users = await getUsers(env);
    const next = users.filter(u => u.email.toLowerCase() !== email);
    await saveUsers(env, next);
    return jsonResponse({ ok: true, users: next });
  }

  return new Response("Method not allowed", { status: 405 });
}

/* ---------- Page-data endpoint, now role-gated ---------- */
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
    if (url.pathname === "/api/request-code" && request.method === "POST") return handleRequestCode(request, env);
    if (url.pathname === "/api/verify-code" && request.method === "POST") return handleVerifyCode(request, env);
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
