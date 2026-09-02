import { resolve, isValidIPv4, reverseIPv4Name } from "../_lib/dns.js";

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const ip = (url.searchParams.get("ip") || "").trim();

  if (!ip || !isValidIPv4(ip)) {
    return json({ error: "Enter a valid IPv4 address, e.g. 172.67.150.249" }, 400);
  }

  try {
    const { status, answers } = await resolve("cloudflare", reverseIPv4Name(ip), "PTR");
    if (answers.length === 0) {
      return json({
        ip,
        found: false,
        summary: status === 3
          ? "NXDOMAIN — no reverse record configured for this IP."
          : "No PTR record returned for this IP.",
      });
    }
    return json({
      ip,
      found: true,
      hostnames: answers.map((a) => a.data),
      rawAnswers: answers.map((a) => ({ name: a.name, ttl: a.ttl, data: a.data })),
    });
  } catch (err) {
    return json({ error: `Reverse lookup failed: ${err.message || err}` }, 502);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
