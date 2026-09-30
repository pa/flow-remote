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
const QUICK_MS = 2_500; // under this, a failure never reached a computer
const enc = new TextEncoder();

// NetError is a request that got no answer at all. kind is a guess from
// how it failed: "unresolved" came back at once, which is what a name
// that can't be looked up does (a .ts.net address with Tailscale off);
// "timeout" waited and heard nothing (Tailscale on, computer down).
export class NetError extends Error {
  constructor(kind) {
    super(kind === "timeout" ? "no answer" : "can't reach the address");
    this.kind = kind;
  }
}

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

// call makes one API request, signed as signer unless it's null, and
// returns the decoded answer.
async function call(signer, method, path, body, base = signer?.base ?? "") {
  const raw = body ? enc.encode(JSON.stringify(body)) : new Uint8Array();
  const headers = body ? { "Content-Type": "application/json" } : {};
  if (signer) Object.assign(headers, await signHeaders(method, path, raw, signer.id, signer.key));
  const res = await fetchOrNetError(base + path, { method, headers, body: body ? raw : undefined, cache: "no-store" });
  if (!res.ok) throw new ApiError(res.status, await errorText(res));
  return res.status === 204 || res.status === 202 ? null : res.json();
}

// fetchOrNetError fetches url, turning a failure to connect into a
// NetError. A Mac that's asleep or off the tailnet may not answer at all;
// giving up lets the app say it's unreachable instead of waiting. A quick
// failure means the name didn't resolve (Tailscale off); a slow one, that
// nothing answered.
async function fetchOrNetError(url, init) {
  const started = performance.now();
  try {
    return await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    const quick = performance.now() - started < QUICK_MS;
    throw new NetError(e?.name !== "TimeoutError" && quick ? "unresolved" : "timeout");
  }
}

// errorText is the error an API response gives, or its status code when
// the body isn't the usual {"error": ...}.
async function errorText(res) {
  try {
    return (await res.json()).error || `${res.status}`;
  } catch {
    return `${res.status}`;
  }
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
export const netKind = (err) => (err instanceof NetError ? err.kind : "timeout");

export const postPair = (base, pairId, env) => call(null, "POST", `/v1/pair/${encodeURIComponent(pairId)}`, env, base);
export const postEnvelope = (signer, env) => call(signer, "POST", "/v1/envelopes", env);
export const listEnvelopes = (signer) => call(signer, "GET", "/v1/envelopes");
export const ack = (signer, ids) => call(signer, "POST", "/v1/ack", { ids });
export const status = (signer) => call(signer, "GET", "/v1/status");
