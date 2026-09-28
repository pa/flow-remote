// Test driver for interop_test.go. Reads a JSON request on stdin, writes a
// JSON answer on stdout. Test-only: keys are extractable so they can cross
// the process boundary.
import * as env from "../../../web/js/envelope.js";

const subtle = globalThis.crypto.subtle;
const ECDH = { name: "ECDH", namedCurve: "P-256" };

let input = "";
for await (const chunk of process.stdin) input += chunk;
const req = JSON.parse(input);

let out;
switch (req.mode) {
  case "seal": {
    // Act as a phone: sign with a fresh device key, seal to the Mac.
    const id = await env.generateIdentity(true);
    const pub = await env.exportPublic(id);
    const e = await env.seal(req.plaintext, id.sign.privateKey, "dev-js", "mac", req.mac_box_pub, req.ts);
    out = { sign_pub: pub.sign_pub, env: e };
    break;
  }
  case "gen": {
    const id = await env.generateIdentity(true);
    const pub = await env.exportPublic(id);
    out = { ...pub, box_jwk: await subtle.exportKey("jwk", id.box.privateKey) };
    break;
  }
  case "open": {
    // Act as a phone receiving a reply: verify the Mac, then decrypt.
    await env.verify(req.env, req.mac_sign_pub);
    const pair = {
      privateKey: await subtle.importKey("jwk", req.box_jwk, ECDH, false, ["deriveBits"]),
      publicKey: await env.importBoxPub(req.box_pub),
    };
    out = { plaintext: await env.open(req.env, pair) };
    break;
  }
  default:
    throw new Error(`unknown mode ${req.mode}`);
}
process.stdout.write(JSON.stringify(out));
