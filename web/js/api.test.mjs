// How a request that got no answer is classified. The app's message for an
// unreachable computer depends on it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { status, NetError, ApiError, netKind, offline } from "./api.js";

const signer = { id: "dev-test", key: (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])).privateKey, base: "https://flow-remote-x.tail0.ts.net" };

async function classify(fetchImpl) {
  globalThis.fetch = fetchImpl;
  try {
    await status(signer);
  } catch (e) {
    return e;
  }
  return null;
}

test("a name that can't be looked up fails at once: unresolved", async () => {
  const e = await classify(() => Promise.reject(new TypeError("Load failed")));
  assert.ok(e instanceof NetError && offline(e));
  assert.equal(netKind(e), "unresolved");
});

test("no answer until the timeout: timeout", async () => {
  const e = await classify(() => Promise.reject(new DOMException("timed out", "TimeoutError")));
  assert.equal(netKind(e), "timeout");
});

test("an answer with an error isn't offline", async () => {
  const e = await classify(async () => new Response(JSON.stringify({ error: "nope" }), { status: 401 }));
  assert.ok(e instanceof ApiError && !offline(e));
});
