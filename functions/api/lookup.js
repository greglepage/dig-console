import { resolve, isValidHostname, RECORD_TYPES } from "../_lib/dns.js";

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();
  const typesParam = url.searchParams.get("types") || "ALL";

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }

  const types = typesParam === "ALL" ? RECORD_TYPES : typesParam.split(",").filter((t) => RECORD_TYPES.includes(t));
  if (types.length === 0) return json({ error: "No valid record types requested" }, 400);

  const results = await Promise.all(
    types.map(async (type) => {
      try {
        const { status, answers } = await resolve("cloudflare", domain, type);
        return { type, status, answers };
      } catch (err) {
        return { type, status: -1, answers: [], error: String(err.message || err) };
      }
    })
  );

  const records = results.flatMap((r) => r.answers);
  const errors = results.filter((r) => r.error).map((r) => `${r.type}: ${r.error}`);

  return json({ domain, records, queriedTypes: types, errors });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
