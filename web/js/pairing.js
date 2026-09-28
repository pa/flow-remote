// Phone side of pairing. Mirrors internal/pairing/pairing.go.
import { b64u, unb64u, seal, exportPublic } from "./envelope.js";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

// parseOffer reads the offer from a location hash like "#pair=...".
export function parseOffer(hash) {
  const m = /(?:^#|&)pair=([A-Za-z0-9_-]+)/.exec(hash);
  if (!m) return null;
  const offer = JSON.parse(new TextDecoder().decode(unb64u(m[1])));
  if (offer.v !== 1) throw new Error("pairing: unsupported offer version");
  return offer;
}

export function newDeviceId() {
  return "dev-" + b64u(crypto.getRandomValues(new Uint8Array(12)));
}

function macInput(e) {
  return enc.encode(`flow-remote/v1 enroll\n${e.pair_id}\n${e.device_id}\n${e.name}\n${e.sign_pub}\n${e.box_pub}`);
}

// enrollmentEnvelope seals the enrollment to the Mac, signed with the new
// device key. Throws if the offer has expired.
export async function enrollmentEnvelope(offer, identity, deviceId, name, now = Date.now()) {
  if (now > offer.exp) throw new Error("pairing: this code has expired, make a new one on the Mac");
  const pub = await exportPublic(identity);
  const en = { kind: "enroll", pair_id: offer.pair_id, device_id: deviceId, name, ...pub };
  const hkey = await subtle.importKey("raw", unb64u(offer.secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  en.mac = b64u(await subtle.sign("HMAC", hkey, macInput(en)));
  return seal(JSON.stringify(en), identity.sign.privateKey, deviceId, offer.mac_id, offer.mac_box_pub, now);
}
