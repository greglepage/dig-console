import { resolve, isValidHostname, RESOLVERS, RECORD_TYPES } from "../_lib/dns.js";

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();
  const type = (url.searchParams.get("type") || "A").toUpperCase();

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }
  if (!RECORD_TYPES.includes(type)) {
    return json({ error: `Unsupported record type ${type}` }, 400);
  }

  const keys = Object.keys(RESOLVERS);
  const results = await Promise.all(
    keys.map(async (key) => {
      try {
        const { status, answers } = await resolve(key, domain, type);
        return { resolver: key, label: RESOLVERS[key].label, ip: RESOLVERS[key].ip, status, answers };
      } catch (err) {
        return { resolver: key, label: RESOLVERS[key].label, ip: RESOLVERS[key].ip, status: -1, answers: [], error: String(err.message || err) };
      }
    })
  );

  const ok = results.filter((r) => !r.error);
  const signatures = ok.map((r) => JSON.stringify(r.answers.map((a) => a.data).sort()));
  const inSync = ok.length > 0 && new Set(signatures).size === 1;
  const allReachable = ok.length === results.length;

  return json({ domain, type, resolvers: results, inSync, allReachable });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
