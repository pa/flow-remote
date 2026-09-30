// Phone side of the envelope format. Must stay byte-identical to
// internal/envelope/envelope.go; internal/envelope/interop_test.go runs this
// file under Node to prove it. WebCrypto only, no libraries.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const VERSION = 1;
const TAG = "flow-remote/v1";

const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const SIG = { name: "ECDSA", hash: "SHA-256" };

export function b64u(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}

// A device identity: one ECDSA key to sign, one ECDH key to receive.
// Private halves are non-extractable unless a test asks otherwise.
export async function generateIdentity(extractable = false) {
  const sign = await subtle.generateKey(ECDSA, extractable, ["sign", "verify"]);
  const box = await subtle.generateKey(ECDH, extractable, ["deriveBits"]);
  return { sign, box };
}

export async function exportPublic(identity) {
  return {
    sign_pub: b64u(await subtle.exportKey("raw", identity.sign.publicKey)),
    box_pub: b64u(await subtle.exportKey("raw", identity.box.publicKey)),
  };
}

export const importSignPub = (s) => subtle.importKey("raw", unb64u(s), ECDSA, true, ["verify"]);
export const importBoxPub = (s) => subtle.importKey("raw", unb64u(s), ECDH, true, []);

function header(e) {
  return `${TAG}\n${e.v}\n${e.id}\n${e.from}\n${e.to}\n${e.ts}`;
}

function signingInput(e) {
  return enc.encode(`${header(e)}\n${e.epk}\n${e.ct}`);
}

async function sealKey(priv, peer, epkRaw, recipRaw) {
  const shared = await subtle.deriveBits({ name: "ECDH", public: peer }, priv, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: concat(enc.encode(TAG), epkRaw, recipRaw) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// seal encrypts plaintext (a string) to the recipient's box key (base64url)
// and signs it with the sender's sign key. from and to are device or Mac
// ids, as in Go's envelope.Route.
export async function seal(plaintext, signKey, { from, to }, recipientBoxPub, ts = Date.now()) {
  const recipRaw = unb64u(recipientBoxPub);
  const recip = await importBoxPub(recipientBoxPub);
  const eph = await subtle.generateKey(ECDH, false, ["deriveBits"]);
  const epkRaw = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));

  const e = { v: VERSION, id: b64u(crypto.getRandomValues(new Uint8Array(16))), from, to, ts, epk: b64u(epkRaw) };
  const key = await sealKey(eph.privateKey, recip, epkRaw, recipRaw);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: enc.encode(header(e)) },
    key,
    enc.encode(plaintext),
  );
  e.ct = b64u(concat(nonce, new Uint8Array(ct)));
  e.sig = b64u(await subtle.sign(SIG, signKey, signingInput(e)));
  return e;
}

// verify throws unless the sender's sign key (base64url) signed e.
export async function verify(e, senderSignPub) {
  if (e.v !== VERSION) throw new Error("envelope: unsupported version");
  const ok = await subtle.verify(SIG, await importSignPub(senderSignPub), unb64u(e.sig), signingInput(e));
  if (!ok) throw new Error("envelope: bad signature");
}

// open decrypts a verified envelope with our box key pair; returns a string.
export async function open(e, boxKeyPair) {
  const epkRaw = unb64u(e.epk);
  const epk = await importBoxPub(e.epk);
  const recipRaw = new Uint8Array(await subtle.exportKey("raw", boxKeyPair.publicKey));
  const key = await sealKey(boxKeyPair.privateKey, epk, epkRaw, recipRaw);
  const ct = unb64u(e.ct);
  const pt = await subtle.decrypt(
    { name: "AES-GCM", iv: ct.slice(0, 12), additionalData: enc.encode(header(e)) },
    key,
    ct.slice(12),
  );
  return dec.decode(pt);
}

// fingerprint matches identity.Fingerprint in Go: the first 10 bytes of
// SHA-256(sign_pub || box_pub) as hex, in groups of four.
export async function fingerprint(signPub, boxPub) {
  const h = new Uint8Array(await subtle.digest("SHA-256", concat(unb64u(signPub), unb64u(boxPub))));
  const hex = Array.from(h.slice(0, 10), (b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g).join(" ");
}
