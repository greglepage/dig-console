import { resolve, isValidHostname, RECORD_TYPES, ALL_RECORD_TYPES, COMMON_DKIM_SELECTORS } from "../_lib/dns.js";

async function queryAt(name, type) {
  try {
    const { status, answers } = await resolve("cloudflare", name, type);
    return { type, status, answers };
  } catch (err) {
    return { type, status: -1, answers: [], error: String(err.message || err) };
  }
}

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();
  const typesParam = url.searchParams.get("types") || "COMMON";

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }

  const isAll = typesParam === "ALL";
  const types =
    typesParam === "COMMON" ? RECORD_TYPES :
    isAll ? ALL_RECORD_TYPES :
    typesParam.split(",").filter((t) => ALL_RECORD_TYPES.includes(t));
  if (types.length === 0) return json({ error: "No valid record types requested" }, 400);

  const queries = types.map((type) => queryAt(domain, type));

  // "Every record" also means the well-known names DNS tooling conventionally
  // checks even though they're not at the apex: DMARC policy, and DKIM public
  // keys under whichever selector the mail provider happens to use.
  if (isAll) {
    queries.push(queryAt(`_dmarc.${domain}`, "TXT"));
    for (const selector of COMMON_DKIM_SELECTORS) {
      const host = `${selector}._domainkey.${domain}`;
      queries.push(queryAt(host, "CNAME"));
      queries.push(queryAt(host, "TXT"));
    }
  }

  const results = await Promise.all(queries);
  const errors = results.filter((r) => r.error).map((r) => `${r.type}: ${r.error}`);

  // Querying both CNAME and TXT at a delegated DKIM name returns the same
  // CNAME hop twice (DNS follows the chain either way) - collapse duplicates.
  const seen = new Set();
  const records = results.flatMap((r) => r.answers).filter((rec) => {
    const key = `${rec.name}|${rec.type}|${rec.data}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return json({ domain, records, queriedTypes: types, errors });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
