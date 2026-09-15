const COOKIE_NAME = "pi_session";
const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 days, in seconds

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
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

function loginPage(showError) {
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
  .err{color:#A15048;font-size:13px;margin-bottom:14px;}
</style>
</head>
<body>
  <form class="box" method="POST" action="/__login">
    <h1>Sign in</h1>
    ${showError ? `<div class="err">Incorrect password. Try again.</div>` : ``}
    <input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`;
}

export default async (request, context) => {
  const url = new URL(request.url);
  const password = Deno.env.get("SITE_PASSWORD");

  // Never fail open — if the password hasn't been configured yet, block everything.
  if (!password) {
    return new Response(
      "This site is not yet configured. Set the SITE_PASSWORD environment variable in Netlify (Site configuration → Environment variables, scoped to Functions) to enable access.",
      { status: 503, headers: { "Content-Type": "text/plain" } }
    );
  }

  const expectedHash = await sha256Hex(password);

  if (url.pathname === "/__logout") {
    return new Response(null, {
      status: 302,
      headers: {
        "Location": "/",
        "Set-Cookie": `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
      },
    });
  }

  if (url.pathname === "/__login" && request.method === "POST") {
    let submitted = "";
    try {
      const form = await request.formData();
      submitted = String(form.get("password") || "");
    } catch {
      submitted = "";
    }
    const submittedHash = await sha256Hex(submitted);

    if (submittedHash === expectedHash) {
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "/",
          "Set-Cookie": `${COOKIE_NAME}=${expectedHash}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`,
        },
      });
    }

    return new Response(loginPage(true), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const sessionValue = getCookie(request, COOKIE_NAME);
  if (sessionValue === expectedHash) {
    return context.next();
  }

  return new Response(loginPage(false), {
    status: 401,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
};

export const config = { path: "/*" };
