import { resolve, isValidHostname, COMMON_DKIM_SELECTORS } from "../_lib/dns.js";

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain || !isValidHostname(domain)) {
    return json({ error: "Enter a valid domain name, e.g. example.com" }, 400);
  }

  const [spf, dmarc, mx, dkim] = await Promise.all([
    checkSpf(domain),
    checkDmarc(domain),
    checkMx(domain),
    checkDkim(domain),
  ]);

  return json({ domain, spf, dmarc, mx, dkim });
}

async function checkSpf(domain) {
  try {
    const { answers } = await resolve("cloudflare", domain, "TXT");
    const record = answers.find((a) => a.data.toLowerCase().startsWith("v=spf1"));
    if (!record) return { state: "warn", summary: "No SPF record found.", record: null };
    const endsAll = /[~\-?+]all\s*$/.test(record.data.trim());
    return {
      state: endsAll ? "good" : "warn",
      summary: endsAll ? "SPF record found and terminated correctly." : "SPF record found but doesn't end in an all mechanism — some senders may be missed.",
      record: record.data,
    };
  } catch (err) {
    return { state: "warn", summary: `SPF lookup failed: ${err.message || err}`, record: null };
  }
}

async function checkDmarc(domain) {
  try {
    const { answers } = await resolve("cloudflare", `_dmarc.${domain}`, "TXT");
    const record = answers.find((a) => a.data.toLowerCase().startsWith("v=dmarc1"));
    if (!record) return { state: "warn", summary: "No DMARC record found — SPF/DKIM failures aren't being enforced anywhere.", record: null };
    const policy = /p=(\w+)/i.exec(record.data)?.[1] || "none";
    const hasRua = /rua=/i.test(record.data);
    if (policy === "none") {
      return { state: "warn", summary: "DMARC is present but in monitor-only mode (p=none) — nothing is actually blocked yet.", record: record.data };
    }
    if (!hasRua) {
      return { state: "warn", summary: `Policy is enforcing (p=${policy}), but there's no rua= tag, so failures are never reported back to you.`, record: record.data };
    }
    return { state: "good", summary: `Enforcing (p=${policy}) with aggregate reporting configured.`, record: record.data };
  } catch (err) {
    return { state: "warn", summary: `DMARC lookup failed: ${err.message || err}`, record: null };
  }
}

async function checkMx(domain) {
  try {
    const { answers } = await resolve("cloudflare", domain, "MX");
    if (answers.length === 0) return { state: "warn", summary: "No MX records — this domain can't receive mail.", records: [] };
    return { state: "good", summary: `${answers.length} mail exchanger${answers.length > 1 ? "s" : ""} found.`, records: answers.map((a) => a.data) };
  } catch (err) {
    return { state: "warn", summary: `MX lookup failed: ${err.message || err}`, records: [] };
  }
}

async function checkDkim(domain) {
  const attempts = await Promise.all(
    COMMON_DKIM_SELECTORS.map(async (selector) => {
      const host = `${selector}._domainkey.${domain}`;
      for (const type of ["CNAME", "TXT"]) {
        try {
          const { answers } = await resolve("cloudflare", host, type);
          if (answers.length > 0) return { selector, type, target: answers[0].data };
        } catch {
          // try the next type / selector
        }
      }
      return null;
    })
  );
  const found = attempts.filter(Boolean);
  if (found.length === 0) {
    return {
      state: "warn",
      summary: "No DKIM selector found among common providers — this only means we didn't guess right, not that DKIM is missing. Ask the mail provider for their selector.",
      selectors: [],
    };
  }
  return {
    state: "good",
    summary: `${found.length} DKIM selector${found.length > 1 ? "s" : ""} found and delegated correctly.`,
    selectors: found,
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
