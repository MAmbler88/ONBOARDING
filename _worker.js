const PAGE_KEY_PATTERN = /^[a-zA-Z0-9_-]{1,100}$/;

function badRequest(message) {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { "Content-Type": "application/json" },
  });
}

async function handleData(request, env) {
  const url = new URL(request.url);
  const page = url.searchParams.get("page");

  if (!page || !PAGE_KEY_PATTERN.test(page)) {
    return badRequest("Unknown or missing page");
  }

  if (request.method === "GET") {
    const raw = await env.PROCESS_INDEX_KV.get(page);
    const value = raw ? JSON.parse(raw) : null;
    return new Response(JSON.stringify({ value }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return badRequest("Invalid JSON body");
    }
    if (!Array.isArray(body.groups)) {
      return badRequest("'groups' must be an array");
    }
    await env.PROCESS_INDEX_KV.put(page, JSON.stringify(body.groups));
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response("Method not allowed", { status: 405 });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api/data") {
      return handleData(request, env);
    }
    return env.ASSETS.fetch(request);
  },
};
