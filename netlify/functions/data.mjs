import { getStore } from "@netlify/blobs";

const PAGE_KEY_PATTERN = /^[a-zA-Z0-9_-]{1,100}$/;

export default async (req) => {
  const url = new URL(req.url);
  const page = url.searchParams.get("page");

  if (!page || !PAGE_KEY_PATTERN.test(page)) {
    return new Response(JSON.stringify({ error: "Unknown or missing page" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const store = getStore({ name: "process-index", consistency: "strong" });

  if (req.method === "GET") {
    const value = await store.get(page, { type: "json" });
    return new Response(JSON.stringify({ value: value || null }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (req.method === "POST") {
    let body;
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (!Array.isArray(body.groups)) {
      return new Response(JSON.stringify({ error: "'groups' must be an array" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    await store.setJSON(page, body.groups);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response("Method not allowed", { status: 405 });
};
