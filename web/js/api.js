// The phone's side of the mailbox API. Nobody signs in: after pairing,
// every request is signed with that pairing's device key, byte for byte the
// way internal/reqsig does it in Go. Pairing itself is the one unsigned
// call. A Mac's mailbox is usually the app's own origin (base ""); a Mac
// served from another address has its https base stored with the pairing.
// Only the path is signed, so the base doesn't change the signature.
//
// Each call takes its signer ({id, key}) explicitly. A phone paired with
// several Macs has one device key per Mac, and a shared "current signer"
// could sign one tenant's request with another's key when a poll and a
// send overlap.
import { b64u } from "./envelope.js";

const subtle = globalThis.crypto.subtle;
const TIMEOUT_MS = 10_000;
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

async function call(signer, method, path, body, base = signer?.base ?? "") {
  const raw = body ? enc.encode(JSON.stringify(body)) : new Uint8Array();
  const headers = body ? { "Content-Type": "application/json" } : {};
  if (signer) Object.assign(headers, await signHeaders(method, path, raw, signer.id, signer.key));
  // A Mac that's asleep or off the tailnet may not answer at all; give up
  // so the app can say it's unreachable instead of waiting.
  const res = await fetch(base + path, { method, headers, body: body ? raw : undefined, cache: "no-store", signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) {
    let msg = `${res.status}`;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new ApiError(res.status, msg);
  }
  return res.status === 204 || res.status === 202 ? null : res.json();
}

export const signerFor = (pairing) => ({ id: pairing.device_id, key: pairing.keys.sign.privateKey, base: pairing.mailbox || "" });

// mailboxBase checks an offer's mailbox address: "" (this origin) or https.
export function mailboxBase(offer) {
  const m = offer.mailbox || "";
  if (m === "") return "";
  const u = new URL(m);
  if (u.protocol !== "https:") throw new Error("pairing: the Mac's address must be https");
  return u.origin;
}

// offline says whether err means the Mac couldn't be reached at all, as
// opposed to answering with an error.
export const offline = (err) => !(err instanceof ApiError);

export const postPair = (base, pairId, env) => call(null, "POST", `/v1/pair/${encodeURIComponent(pairId)}`, env, base);
export const postEnvelope = (signer, env) => call(signer, "POST", "/v1/envelopes", env);
export const listEnvelopes = (signer) => call(signer, "GET", "/v1/envelopes");
export const ack = (signer, ids) => call(signer, "POST", "/v1/ack", { ids });
export const status = (signer) => call(signer, "GET", "/v1/status");
