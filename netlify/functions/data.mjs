import { getStore } from "@netlify/blobs";

const VALID_PAGES = ["onboarding", "offboarding", "campaign"];

export default async (req) => {
  const url = new URL(req.url);
  const page = url.searchParams.get("page");

  if (!page || !VALID_PAGES.includes(page)) {
    return new Response(JSON.stringify({ error: "Unknown or missing page" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const store = getStore("process-index");

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

export const config = {
  path: "/api/data",
};
