import { isValidHostname } from "../_lib/dns.js";

// rdap.org resolves the correct authoritative RDAP server via IANA's bootstrap
// registry and redirects there. RDAP is the structured-JSON, HTTPS-native
// successor to WHOIS — a much better fit than raw port-43 sockets, which
// Cloudflare Pages Functions doesn't support (Workers-only feature).
function vcardField(vcardArray, field) {
  if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return null;
  const entry = vcardArray[1].find((e) => e[0] === field);
  return entry ? entry[3] : null;
}

function findRegistrar(entities) {
  if (!Array.isArray(entities)) return null;
  const registrar = entities.find((e) => Array.isArray(e.roles) && e.roles.includes("registrar"));
  return registrar ? vcardField(registrar.vcardArray, "fn") : null;
}

function findEvent(events, action) {
  if (!Array.isArray(events)) return null;
  return events.find((e) => e.eventAction === action)?.eventDate || null;
}

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }

  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: {
        accept: "application/rdap+json",
        "user-agent": "dig.greglepage.com (RDAP client; https://dig.greglepage.com)",
      },
    });

    if (res.status === 404) {
      return json({ domain, registered: false });
    }
    if (!res.ok) {
      return json({ error: `RDAP lookup returned HTTP ${res.status}` }, 502);
    }

    const data = await res.json();
    const registrar = findRegistrar(data.entities);
    const created = findEvent(data.events, "registration");
    const expires = findEvent(data.events, "expiration");
    const nameServers = (data.nameservers || []).map((ns) => ns.ldhName?.toLowerCase()).filter(Boolean);

    return json({
      domain,
      registered: true,
      registrar,
      created,
      expires,
      statuses: data.status || [],
      nameServers,
      dnssecSigned: !!data.secureDNS?.delegationSigned,
      raw: data,
    });
  } catch (err) {
    return json({ error: `WHOIS lookup failed: ${err.message || err}` }, 502);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
