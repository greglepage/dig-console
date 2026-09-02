import { isValidHostname } from "../_lib/dns.js";

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }

  try {
    const res = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=false&expand=dns_names`
    );
    if (!res.ok) {
      return json({ error: `Certificate transparency log lookup returned HTTP ${res.status}` }, 502);
    }
    const issuances = await res.json();
    if (!Array.isArray(issuances) || issuances.length === 0) {
      return json({ domain, found: false, summary: "No certificates found in public transparency logs for this domain." });
    }

    const now = Date.now();
    const active = issuances.filter((i) => new Date(i.not_before).getTime() <= now && new Date(i.not_after).getTime() >= now);
    const pool = active.length > 0 ? active : issuances;
    // Prefer the currently-valid cert with the most remaining runway; if none are
    // active right now, fall back to whichever expired most recently.
    pool.sort((a, b) => new Date(b.not_after) - new Date(a.not_after));
    const chosen = pool[0];

    const notAfter = new Date(chosen.not_after);
    const notBefore = new Date(chosen.not_before);
    const daysRemaining = Math.floor((notAfter.getTime() - now) / 86400000);
    const isActive = notBefore.getTime() <= now && notAfter.getTime() >= now;

    let state, summary;
    if (!isActive) {
      state = "bad";
      summary = `The most recent certificate found expired ${Math.abs(daysRemaining)} day${Math.abs(daysRemaining) === 1 ? "" : "s"} ago and no newer one has appeared in the logs yet.`;
    } else if (daysRemaining <= 14) {
      state = "bad";
      summary = `Certificate expires in ${daysRemaining} day${daysRemaining === 1 ? "" : "s"} — due for renewal now.`;
    } else if (daysRemaining <= 30) {
      state = "warn";
      summary = `Certificate expires in ${daysRemaining} days — worth scheduling a renewal.`;
    } else {
      state = "good";
      summary = `Certificate is valid for ${daysRemaining} more days.`;
    }

    return json({
      domain,
      found: true,
      state,
      summary,
      notBefore: chosen.not_before,
      notAfter: chosen.not_after,
      sans: chosen.dns_names || [],
      recentCertCount: issuances.length,
      raw: chosen,
    });
  } catch (err) {
    return json({ error: `SSL lookup failed: ${err.message || err}` }, 502);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
