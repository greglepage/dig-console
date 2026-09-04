import { connect } from "cloudflare:sockets";

// The target is never user-supplied — it's always the caller's own
// CF-Connecting-IP, so this can't be pointed at anyone else's infrastructure.
// The port IS user-choosable (any 1-65535); that's safe precisely because the
// host isn't — the worst a caller can do is port-scan themselves.
//
// This map only supplies a friendly label + a sensible TLS default for ports
// people are likely to check; it's not an allowlist.
export const PORTS = {
  443: { label: "HTTPS / SSL-VPN portal", tls: true },
  4433: { label: "SonicWall SSL-VPN (common default)", tls: true },
  8041: { label: "ScreenConnect relay (common default)", tls: true },
  3389: { label: "RDP", tls: false },
  25: { label: "SMTP", tls: false },
  587: { label: "SMTP submission", tls: false },
  993: { label: "IMAPS", tls: true },
  995: { label: "POP3S", tls: true },
  465: { label: "SMTPS", tls: true },
  22: { label: "SSH", tls: false },
  21: { label: "FTP", tls: false },
  1194: { label: "OpenVPN (TCP mode only — most deployments use UDP)", tls: false },
};

const CONNECT_TIMEOUT_MS = 4000;
const BANNER_TIMEOUT_MS = 1500;

export async function onRequestGet({ request }) {
  const ip = request.headers.get("cf-connecting-ip");
  if (!ip) return json({ error: "Could not determine your public IP address from this request." }, 400);

  const url = new URL(request.url);
  const port = Number(url.searchParams.get("port"));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return json({ error: "Port must be a number between 1 and 65535." }, 400);
  }

  const known = PORTS[port];
  const tlsParam = url.searchParams.get("tls");
  const tls = tlsParam === null ? !!(known && known.tls) : tlsParam === "1";
  const label = (known && known.label) || "Custom port";

  // TODO before making this tab publicly linkable: add a Cloudflare dashboard
  // Rate Limiting rule on /api/portcheck* (this is stateless across edge
  // instances, so an in-code counter here wouldn't actually work) and gate
  // it behind Turnstile so it can't be scripted into a cost drain.

  const started = Date.now();
  let socket;
  try {
    socket = connect({ hostname: ip, port }, { secureTransport: tls ? "on" : "off" });
    await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, "connect timed out");
    const connectMs = Date.now() - started;

    // Try for a banner regardless of protocol — cheap, and plenty of
    // services (SSH, FTP, SMTP...) volunteer one without being asked.
    const banner = await readBannerLine(socket);
    await closeQuietly(socket);

    return json({
      ip,
      port,
      label,
      open: true,
      tls,
      connectMs,
      banner,
      summary: tls
        ? `Open — completed a TLS handshake in ${connectMs}ms.`
        : `Open — connected in ${connectMs}ms.` + (banner ? ` First line: ${banner}` : ""),
    });
  } catch (err) {
    await closeQuietly(socket);
    const msg = String((err && err.message) || err);
    const timedOut = /timed out/i.test(msg);
    return json({
      ip,
      port,
      label,
      open: false,
      tls,
      connectMs: Date.now() - started,
      error: msg,
      summary: timedOut
        ? "No response — the port is filtered/blocked rather than actively refusing connections."
        : "Closed — nothing is listening, or the connection was actively refused.",
    });
  }
}

function withTimeout(promise, ms, message) {
  return Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms))]);
}

async function readBannerLine(socket) {
  const reader = socket.readable.getReader();
  try {
    const { value } = await withTimeout(reader.read(), BANNER_TIMEOUT_MS, "banner read timed out");
    if (!value) return null;
    return new TextDecoder().decode(value).split(/\r?\n/)[0].slice(0, 200);
  } catch {
    return null;
  } finally {
    try { reader.releaseLock(); } catch {}
  }
}

async function closeQuietly(socket) {
  if (!socket) return;
  try { await socket.close(); } catch {}
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
