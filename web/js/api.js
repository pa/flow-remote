// The phone's side of the mailbox API. Nobody signs in: after pairing,
// every request is signed with that pairing's device key, byte for byte the
// way internal/reqsig does it in Go. Pairing itself is the one unsigned
// call. The app and mailbox share an origin, so paths are relative.
//
// Each call takes its signer ({id, key}) explicitly. A phone paired with
// several Macs has one device key per Mac, and a shared "current signer"
// could sign one tenant's request with another's key when a poll and a
// send overlap.
import { b64u } from "./envelope.js";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function sha256hex(bytes) {
  const h = new Uint8Array(await subtle.digest("SHA-256", bytes));
  return Array.from(h, (b) => b.toString(16).padStart(2, "0")).join("");
}

// signHeaders returns the X-FR-* headers for one request. path includes
// the query string. Exported for the interop test.
export async function signHeaders(method, path, body, id, key, ts = Date.now()) {
  const input = `flow-remote/v1 req\n${method}\n${path}\n${ts}\n${await sha256hex(body)}`;
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(input));
  return { "X-FR-Key": id, "X-FR-TS": String(ts), "X-FR-Sig": b64u(sig) };
}

async function call(signer, method, path, body) {
  const raw = body ? enc.encode(JSON.stringify(body)) : new Uint8Array();
  const headers = body ? { "Content-Type": "application/json" } : {};
  if (signer) Object.assign(headers, await signHeaders(method, path, raw, signer.id, signer.key));
  const res = await fetch(path, { method, headers, body: body ? raw : undefined, cache: "no-store" });
  if (!res.ok) {
    let msg = `${res.status}`;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new ApiError(res.status, msg);
  }
  return res.status === 204 || res.status === 202 ? null : res.json();
}

export const signerFor = (pairing) => ({ id: pairing.device_id, key: pairing.keys.sign.privateKey });

export const postPair = (pairId, env) => call(null, "POST", `/v1/pair/${encodeURIComponent(pairId)}`, env);
export const postEnvelope = (signer, env) => call(signer, "POST", "/v1/envelopes", env);
export const listEnvelopes = (signer) => call(signer, "GET", "/v1/envelopes");
export const ack = (signer, ids) => call(signer, "POST", "/v1/ack", { ids });
export const status = (signer) => call(signer, "GET", "/v1/status");
