// Shared DNS-over-HTTPS client. Cloudflare and Google both speak a convenient
// JSON dialect; Quad9 only speaks raw RFC 8484 wire format, so this also carries
// a minimal DNS message encoder/decoder for that one resolver.

export const RESOLVERS = {
  cloudflare: { label: "Cloudflare", ip: "1.1.1.1", kind: "json", url: "https://cloudflare-dns.com/dns-query" },
  google: { label: "Google", ip: "8.8.8.8", kind: "json", url: "https://dns.google/resolve" },
  quad9: { label: "Quad9", ip: "9.9.9.9", kind: "wire", url: "https://dns.quad9.net/dns-query" },
};

const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257, PTR: 12 };
const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k]));

export const RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA"];

export function isValidHostname(name) {
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(name);
}

export function isValidIPv4(ip) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  return ip.split(".").every((o) => Number(o) >= 0 && Number(o) <= 255);
}

export function reverseIPv4Name(ip) {
  return ip.split(".").reverse().join(".") + ".in-addr.arpa";
}

async function queryJson(baseUrl, name, type) {
  const res = await fetch(`${baseUrl}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: "application/dns-json" },
  });
  if (!res.ok) throw new Error(`resolver returned HTTP ${res.status}`);
  const json = await res.json();
  return {
    status: json.Status,
    ad: !!json.AD,
    answers: (json.Answer || []).map((a) => ({
      name: a.name.replace(/\.$/, ""),
      type: TYPE_NAMES[a.type] || String(a.type),
      ttl: a.TTL,
      data: a.type === 16 ? stripTxtQuotes(a.data) : a.data.replace(/\.$/, ""),
    })),
  };
}

function stripTxtQuotes(data) {
  // Google/Cloudflare wrap each TXT character-string in quotes and space-join them.
  return data.replace(/^"|"$/g, "").replace(/" "/g, "");
}

// ---------- RFC 8484 wire format (Quad9) ----------

function encodeName(name) {
  const bytes = [];
  for (const part of name.replace(/\.$/, "").split(".")) {
    const buf = new TextEncoder().encode(part);
    bytes.push(buf.length, ...buf);
  }
  bytes.push(0);
  return bytes;
}

function buildQuery(name, type) {
  const id = Math.floor(Math.random() * 65535);
  const header = [id >> 8, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
  const qname = encodeName(name);
  const qtype = TYPES[type];
  return new Uint8Array([...header, ...qname, qtype >> 8, qtype & 0xff, 0x00, 0x01]);
}

function readName(bytes, offset) {
  const labels = [];
  let cursor = offset;
  let resumeAt = -1;
  let guard = 0;
  while (true) {
    if (++guard > 128) throw new Error("malformed name (compression loop)");
    const len = bytes[cursor];
    if (len === 0) { cursor += 1; break; }
    if ((len & 0xc0) === 0xc0) {
      const pointer = ((len & 0x3f) << 8) | bytes[cursor + 1];
      if (resumeAt === -1) resumeAt = cursor + 2;
      cursor = pointer;
      continue;
    }
    labels.push(new TextDecoder().decode(bytes.slice(cursor + 1, cursor + 1 + len)));
    cursor += 1 + len;
  }
  return { name: labels.join("."), next: resumeAt === -1 ? cursor : resumeAt };
}

function parseWireResponse(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const status = view.getUint16(2) & 0x000f;
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);
  let offset = 12;
  for (let i = 0; i < qdcount; i++) {
    offset = readName(bytes, offset).next + 4;
  }
  const answers = [];
  for (let i = 0; i < ancount; i++) {
    const owner = readName(bytes, offset);
    offset = owner.next;
    const type = view.getUint16(offset); offset += 2;
    offset += 2; // class
    const ttl = view.getUint32(offset); offset += 4;
    const rdlength = view.getUint16(offset); offset += 2;
    const start = offset;
    let data;
    switch (type) {
      case 1:
        data = Array.from(bytes.slice(start, start + 4)).join(".");
        break;
      case 28: {
        const groups = [];
        for (let j = 0; j < 16; j += 2) groups.push(view.getUint16(start + j).toString(16));
        data = groups.join(":");
        break;
      }
      case 2: case 5:
        data = readName(bytes, start).name;
        break;
      case 15: {
        const pref = view.getUint16(start);
        data = `${pref} ${readName(bytes, start + 2).name}`;
        break;
      }
      case 16: {
        let p = start, out = [];
        while (p < start + rdlength) {
          const len = bytes[p];
          out.push(new TextDecoder().decode(bytes.slice(p + 1, p + 1 + len)));
          p += 1 + len;
        }
        data = out.join("");
        break;
      }
      case 6: {
        const mname = readName(bytes, start);
        const rname = readName(bytes, mname.next);
        let p = rname.next;
        const nums = [];
        for (let j = 0; j < 5; j++) { nums.push(view.getUint32(p)); p += 4; }
        data = `${mname.name} ${rname.name} ${nums.join(" ")}`;
        break;
      }
      case 33: {
        const priority = view.getUint16(start);
        const weight = view.getUint16(start + 2);
        const port = view.getUint16(start + 4);
        data = `${priority} ${weight} ${port} ${readName(bytes, start + 6).name}`;
        break;
      }
      case 257: {
        const flag = bytes[start];
        const tagLen = bytes[start + 1];
        const tag = new TextDecoder().decode(bytes.slice(start + 2, start + 2 + tagLen));
        const value = new TextDecoder().decode(bytes.slice(start + 2 + tagLen, start + rdlength));
        data = `${flag} ${tag} "${value}"`;
        break;
      }
      case 12:
        data = readName(bytes, start).name;
        break;
      default:
        data = `[type ${type}]`;
    }
    answers.push({ name: owner.name, type: TYPE_NAMES[type] || String(type), ttl, data });
    offset = start + rdlength;
  }
  return { status, answers };
}

async function queryWire(url, name, type) {
  const body = buildQuery(name, type);
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
    body,
  });
  if (!res.ok) throw new Error(`resolver returned HTTP ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  return parseWireResponse(buf);
}

// resolverKey: "cloudflare" | "google" | "quad9"
export async function resolve(resolverKey, name, type) {
  const resolver = RESOLVERS[resolverKey];
  if (resolver.kind === "json") return queryJson(resolver.url, name, type);
  return queryWire(resolver.url, name, type);
}
