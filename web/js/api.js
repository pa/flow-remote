// The phone's side of the mailbox API. The app and mailbox share an origin
// (Firebase Hosting rewrites /v1/** to Cloud Run), so paths are relative.
import { bearer } from "./auth.js";

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function call(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${await bearer()}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (!res.ok) {
    let msg = `${res.status}`;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new ApiError(res.status, msg);
  }
  return res.status === 204 || res.status === 202 ? null : res.json();
}

export const postPair = (pairId, macId, macSignPub, env) =>
  call("POST", `/v1/pair/${encodeURIComponent(pairId)}`, { mac_id: macId, mac_sign_pub: macSignPub, env });
export const postEnvelope = (env) => call("POST", "/v1/envelopes", env);
export const listEnvelopes = (deviceId) => call("GET", `/v1/envelopes?to=${encodeURIComponent(deviceId)}`);
export const ack = (deviceId, ids) => call("POST", "/v1/ack", { to: deviceId, ids });
export const status = (macId) => call("GET", `/v1/status?mac=${encodeURIComponent(macId)}`);
