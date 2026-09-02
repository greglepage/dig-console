import { resolve, isValidHostname } from "../_lib/dns.js";

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }

  try {
    const [dnskey, ds, apex] = await Promise.all([
      resolve("cloudflare", domain, "DNSKEY"),
      resolve("cloudflare", domain, "DS"),
      resolve("cloudflare", domain, "A"),
    ]);

    const signed = dnskey.answers.length > 0;
    const delegated = ds.answers.length > 0;
    const validating = apex.ad;

    let state, summary;
    if (!signed) {
      state = "warn";
      summary = "This zone isn't signed with DNSSEC. That's normal for most domains, but it means responses can be spoofed without detection.";
    } else if (!delegated) {
      state = "bad";
      summary = "The zone publishes DNSKEY records, but the parent zone has no matching DS record — the chain of trust is broken, so most validating resolvers will ignore the signing entirely.";
    } else if (!validating) {
      state = "bad";
      summary = "DNSKEY and DS records are both present, but a validating resolver could not confirm the signature — check for a key rollover in progress or a signature mismatch.";
    } else {
      state = "good";
      summary = "Signed, delegated, and validating cleanly end to end.";
    }

    return json({
      domain,
      state,
      summary,
      signed,
      delegated,
      validating,
      dnskeyCount: dnskey.answers.length,
      dsRecords: ds.answers.map((a) => a.data),
      dnskeyRecords: dnskey.answers.map((a) => ({ ttl: a.ttl, data: a.data })),
      dsRawRecords: ds.answers.map((a) => ({ ttl: a.ttl, data: a.data })),
      apexAd: apex.ad,
    });
  } catch (err) {
    return json({ error: `DNSSEC check failed: ${err.message || err}` }, 502);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
