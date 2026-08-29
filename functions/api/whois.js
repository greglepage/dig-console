import { connect } from "cloudflare:sockets";
import { isValidHostname } from "../_lib/dns.js";

async function whoisQueryWithRetry(server, query, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const text = await whoisQuery(server, query);
      if (text && text.trim().length > 0) return text;
      lastErr = new Error("empty response");
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

async function whoisQuery(server, query) {
  const socket = connect({ hostname: server, port: 43 });
  await socket.opened;
  const writer = socket.writable.getWriter();
  await writer.write(new TextEncoder().encode(query + "\r\n"));
  await writer.close();

  const reader = socket.readable.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  await socket.close().catch(() => {});

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { bytes.set(c, offset); offset += c.length; }
  return new TextDecoder().decode(bytes);
}

function parseField(text, labels) {
  for (const label of labels) {
    const re = new RegExp("^[ \\t]*" + label + ":\\s*(.+)$", "im");
    const match = re.exec(text);
    if (match) return match[1].trim();
  }
  return null;
}

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }

  try {
    const ianaText = await whoisQueryWithRetry("whois.iana.org", domain);
    const refer = /^refer:\s*(\S+)/im.exec(ianaText)?.[1];

    let text = ianaText;
    let server = "whois.iana.org";
    if (refer) {
      server = refer;
      text = await whoisQueryWithRetry(refer, domain);
      // Some registries (Verisign, etc.) return a thin record pointing at the registrar's own server.
      const registrarWhois = /^[ \t]*Registrar WHOIS Server:\s*(\S+)/im.exec(text)?.[1];
      if (registrarWhois && registrarWhois !== server) {
        try {
          const deeper = await whoisQueryWithRetry(registrarWhois, domain, 2);
          if (deeper && deeper.trim().length > 0) { text = deeper; server = registrarWhois; }
        } catch {
          // fall back to the registry-level record already in hand
        }
      }
    }

    const firstLine = text.trim().split(/\r?\n/, 1)[0] || "";
    if (/no match|not found|no data found|no entries found|status:\s*free|domain not found/i.test(firstLine)) {
      return json({ domain, registered: false, server, raw: text.trim() });
    }

    const registrar = parseField(text, ["Registrar", "Sponsoring Registrar"]);
    const created = parseField(text, ["Creation Date", "created", "Domain Registration Date", "created on"]);
    const expires = parseField(text, ["Registry Expiry Date", "Registrar Registration Expiration Date", "Expiration Date", "paid-till", "expire"]);
    const statuses = [...text.matchAll(/^[ \t]*Domain Status:\s*(.+)$/gim)].map((m) => m[1].trim());
    const nameServers = [...new Set([...text.matchAll(/^[ \t]*Name Server:\s*(.+)$/gim)].map((m) => m[1].trim().toLowerCase()))];

    return json({
      domain,
      registered: true,
      server,
      registrar,
      created,
      expires,
      statuses,
      nameServers,
      raw: text.trim(),
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
