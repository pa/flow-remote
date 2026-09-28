// flow-remote phone app. Screens: get started / pair, sessions, thread,
// settings. There's no sign-in: a device key authenticates every request.
//
// A phone can pair with several Macs. Each pairing has its own device key,
// threads and session list, so the Macs can't be linked through this
// phone's keys, and one Mac's tenant never sees another's.
//
// Every message body comes from a flow session or from the user, so the UI
// is built with DOM nodes and textContent, never innerHTML.
import * as api from "./api.js";
import * as db from "./db.js";
import { b64u, generateIdentity, exportPublic, fingerprint, seal, verify, open } from "./envelope.js";
import { parseOffer, newDeviceId, enrollmentEnvelope } from "./pairing.js";

const POLL_MS = 3000;
const STATUS_EVERY = 5; // polls between Mac status checks
const ONLINE_MS = 90_000; // a relay checks in at least once a minute
const SEEN_TTL = 8 * 24 * 3600_000;

const state = {
  // [{mac_id, mac_sign_pub, mac_box_pub, device_id, device_fp, mac_name,
  //   confirmed, rejected, keys: {sign, box}}]
  pairings: [],
  active: null, // mac_id of the pairing on screen
  sessions: {}, // mac_id -> [session]
  macSeen: {}, // mac_id -> Date | null
  view: "sessions",
  task: null,
  offer: null,
  error: "",
  replyTo: null,
};

const root = document.getElementById("app");
const current = () => state.pairings.find((p) => p.mac_id === state.active) || state.pairings[0] || null;
const macLabel = (p) => p.mac_name || p.mac_id;

// ---- tiny DOM helper ----

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function clock(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function go(view, extra = {}) {
  Object.assign(state, { view, error: "" }, extra);
  render();
}

async function savePairings() {
  // Keys are CryptoKeys; IndexedDB stores them without making them extractable.
  await db.set("pairings", state.pairings);
  await db.set("active", state.active);
}

// ---- screens ----

function render() {
  // Keep a half-typed message and its focus across re-renders.
  const ta = root.querySelector("textarea");
  const draft = ta ? { value: ta.value, focused: document.activeElement === ta, start: ta.selectionStart, end: ta.selectionEnd } : null;
  root.replaceChildren(screen());
  if (state.view === "thread") {
    const list = root.querySelector(".thread");
    if (list) list.scrollTop = list.scrollHeight;
    const next = root.querySelector("textarea");
    if (draft && next) {
      next.value = draft.value;
      if (draft.focused) {
        next.focus();
        next.setSelectionRange(draft.start, draft.end);
      }
    }
  }
}

// backgroundRender is for updates the user didn't ask for. It leaves the
// camera, the pairing form and the getting-started page alone.
function backgroundRender() {
  if (state.view === "scan" || state.view === "welcome" || state.offer) return;
  render();
}

function screen() {
  if (state.offer) return pairScreen();
  if (state.view === "scan") return scanScreen();
  const p = current();
  if (!p || state.view === "welcome") return welcomeScreen();
  if (!p.confirmed) return waitingScreen(p);
  if (state.view === "thread") return threadScreen(p);
  if (state.view === "settings") return settingsScreen();
  return sessionsScreen(p);
}

function bar(title, { back, sub } = {}) {
  return h("header", { class: "bar" },
    back ? h("button", { class: "back", "aria-label": "Back", onclick: back }, "‹") : null,
    h("div", { class: "titles" }, h("h1", {}, title), sub ?? null));
}

// cmd is a copyable command block.
function cmd(text) {
  const pre = h("pre", { class: "cmd" }, text);
  const btn = h("button", { class: "copy", type: "button" }, "Copy");
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Select and copy";
    }
    setTimeout(() => { btn.textContent = "Copy"; }, 1500);
  });
  return h("div", { class: "cmdbox" }, pre, btn);
}

// The getting-started guide: what to do on the Mac, then the ways to scan.
function welcomeScreen() {
  const origin = location.origin;
  const adding = state.pairings.length > 0;
  const note = h("p", { class: "muted" });
  return h("main", {},
    bar(adding ? "Pair another Mac" : "Get started", adding ? { back: () => go("settings") } : {}),
    h("section", { class: "card guide" },
      h("h2", {}, "On your Mac"),
      h("ol", {},
        h("li", {}, h("p", {}, "Install flow-remote from the repo (needs Go and flow):"),
          cmd("git clone https://github.com/pa/flow-remote && cd flow-remote && go install ./cmd/flow-remote")),
        h("li", {},
          h("p", {}, "Set up this Mac. The first Mac on a mailbox uses the mailbox's setup token:"),
          cmd(`FLOW_REMOTE_SETUP_TOKEN=<token> flow-remote setup --mailbox ${origin}`),
          h("p", { class: "muted" }, "Any other Mac, yours or someone else's, uses an invite. On an admin Mac run ",
            h("code", {}, "flow-remote invite"), ", then on the new Mac:"),
          cmd(`FLOW_REMOTE_INVITE=<code> flow-remote setup --mailbox ${origin}`)),
        h("li", {}, h("p", {}, "Start the relay. It runs in the background, starts at login, and restarts if it crashes:"),
          cmd("flow-remote start"),
          h("p", { class: "muted" }, "Stop it with ", h("code", {}, "flow-remote stop"), ", check it with ", h("code", {}, "flow-remote status"), ".")),
        h("li", {}, h("p", {}, "Show a pairing QR code. It's valid for 2 minutes:"),
          cmd("flow-remote pair")))),
    h("section", { class: "card guide" },
      h("h2", {}, "On this phone"),
      h("button", { class: "primary", onclick: () => go("scan") }, "Scan the QR code"),
      photoButton(note), note,
      pasteBox(),
      h("p", { class: "muted" }, "Then compare the fingerprints on both screens, and type ", h("code", {}, "y"), " on the Mac."),
      state.error ? h("p", { class: "error" }, state.error) : null));
}

function pasteBox() {
  const input = h("input", { type: "url", placeholder: "…or paste the pairing link", autocomplete: "off" });
  return h("form", {
    class: "paste",
    onsubmit: (ev) => {
      ev.preventDefault();
      takeOffer(input.value.trim());
    },
  }, input, h("button", { type: "submit" }, "Use link"));
}

function takeOffer(link) {
  try {
    const offer = parseOffer(new URL(link).hash);
    if (!offer) throw new Error("That isn't a pairing link.");
    if (state.pairings.some((p) => p.mac_id === offer.mac_id)) {
      throw new Error("This phone is already paired with that Mac. Unpair it in Settings first to pair again.");
    }
    go(state.view === "scan" ? "welcome" : state.view, { offer });
  } catch (e) {
    go(state.view === "scan" ? "welcome" : state.view, { error: e.message });
  }
}

let stopScan = null;

function scanScreen() {
  const video = h("video", { playsinline: true, muted: true });
  const note = h("p", { class: "muted" }, "Point the camera at the QR code from ", h("code", {}, "flow-remote pair"), ".");
  const view = h("main", {},
    bar("Scan", { back: () => { stopScan?.(); go("welcome"); } }),
    h("div", { class: "scan" }, video), note,
    h("div", { class: "pad" }, photoButton(note)));
  startScan(video, note);
  return view;
}

// photoButton decodes a QR code from a still photo. It goes through the
// ordinary camera picker, so it works where live camera access doesn't
// (some iOS home-screen apps, a denied camera permission).
function photoButton(note) {
  const input = h("input", { type: "file", accept: "image/*", capture: "environment", hidden: true });
  input.addEventListener("change", async () => {
    const file = input.files?.[0];
    if (!file) return;
    note.textContent = "Reading the photo…";
    try {
      const data = await decodeQRFromFile(file);
      if (!data?.includes("#pair=")) throw new Error("No pairing QR code found in that photo. Try again, closer and straight on.");
      stopScan?.();
      takeOffer(data);
    } catch (e) {
      note.textContent = e.message;
    }
  });
  return h("label", { class: "photo" }, input,
    h("span", { class: "button-like" }, "Take a photo of the QR code instead"));
}

async function decodeQRFromFile(file) {
  const bitmap = await createImageBitmap(file);
  // Scale big photos down: jsQR is slow on 12 MP images and doesn't need them.
  const scale = Math.min(1, 1200 / Math.max(bitmap.width, bitmap.height));
  const w = Math.round(bitmap.width * scale), hgt = Math.round(bitmap.height * scale);
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = hgt;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0, w, hgt);
  const img = ctx.getImageData(0, 0, w, hgt);
  const code = globalThis.jsQR?.(img.data, w, hgt, { inversionAttempts: "attemptBoth" });
  return code?.data;
}

async function startScan(video, note) {
  stopScan?.();
  let stream;
  try {
    if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("this browser gives web apps no live camera"), { name: "NotSupported" });
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch (e) {
    note.textContent = e.name === "NotAllowedError"
      ? "Camera access is blocked. Allow it in Settings, or take a photo instead."
      : `The live camera didn't start (${e.name}: ${e.message}). Take a photo instead.`;
    return;
  }
  let running = true;
  stopScan = () => {
    running = false;
    stream.getTracks().forEach((t) => t.stop());
    stopScan = null;
  };
  // iOS Safari plays a camera stream inline only with these set as
  // properties, not just attributes.
  video.muted = true;
  video.playsInline = true;
  video.setAttribute("autoplay", "");
  video.srcObject = stream;
  try {
    await video.play();
  } catch (e) {
    note.textContent = `The camera wouldn't start (${e.name}). Take a photo instead.`;
  }
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const frame = () => {
    if (!running) return;
    if (video.readyState >= 2 && video.videoWidth) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = globalThis.jsQR?.(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
      if (code?.data?.includes("#pair=")) {
        stopScan();
        takeOffer(code.data);
        return;
      }
    }
    requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

function pairScreen() {
  const o = state.offer;
  const macFp = h("code", { class: "fp" }, "…");
  fingerprint(o.mac_sign_pub, o.mac_box_pub).then((fp) => { macFp.textContent = fp; });
  const name = h("input", { type: "text", value: guessName(), maxlength: "40", "aria-label": "Name for this phone" });
  const btn = h("button", { class: "primary" }, "Pair");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await pair(o, name.value.trim() || "phone");
    } catch (e) {
      btn.disabled = false;
      go(state.view, { error: e.message });
    }
  });
  return h("main", {},
    bar("Pair with this Mac", { back: () => go("welcome", { offer: null }) }),
    h("section", { class: "card" },
      h("p", {}, "Check that your Mac shows this fingerprint:"), macFp,
      h("label", {}, "Name for this phone", name),
      btn,
      state.error ? h("p", { class: "error" }, state.error) : null));
}

function guessName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android phone";
  return "phone";
}

async function pair(offer, name) {
  // A fresh key per Mac, so pairings can't be linked by key.
  const keys = await generateIdentity(false);
  const deviceId = newDeviceId();
  const env = await enrollmentEnvelope(offer, keys, deviceId, name);
  await api.postPair(offer.pair_id, env);
  const pub = await exportPublic(keys);
  state.pairings.push({
    mac_id: offer.mac_id, mac_sign_pub: offer.mac_sign_pub, mac_box_pub: offer.mac_box_pub,
    device_id: deviceId, device_fp: await fingerprint(pub.sign_pub, pub.box_pub),
    confirmed: false, rejected: false, keys,
  });
  state.active = offer.mac_id;
  await savePairings();
  go("sessions", { offer: null });
  startPolling();
}

function waitingScreen(p) {
  return h("main", { class: "center" },
    h("h1", { class: "brand" }, "Confirm on your Mac"),
    h("p", {}, "The Mac asks you to confirm this phone. Check that it shows this fingerprint, then type y:"),
    h("code", { class: "fp" }, p.device_fp),
    h("p", { class: "muted" }, "Waiting for the Mac…"),
    h("button", { class: "link", onclick: () => unpair(p) }, "Cancel pairing"));
}

function macLine(p) {
  if (p.rejected) return h("span", { class: "status warn" }, "The mailbox no longer accepts this phone for this Mac. Unpair it in Settings and pair again.");
  const s = state.macSeen[p.mac_id];
  if (s === undefined) return h("span", { class: "status" }, "Checking the Mac…");
  if (s === null) return h("span", { class: "status warn" }, "The Mac hasn't checked in yet. Is `flow-remote start` running?");
  const t = s.getTime();
  if (Date.now() - t < ONLINE_MS) return h("span", { class: "status ok" }, `online · seen ${ago(t)}`);
  return h("span", { class: "status warn" }, `last seen ${ago(t)}. Messages wait until it's back.`);
}

let itemsCache = [];

function unreadCount(mac, task) {
  return itemsCache.filter((it) => it.mac === mac && it.dir === "in" && !it.read && (!task || it.task === task)).length;
}

function macSwitcher() {
  if (state.pairings.length < 2) return null;
  return h("nav", { class: "macs" }, state.pairings.map((p) => {
    const n = unreadCount(p.mac_id);
    return h("button", {
      class: `macchip ${p.mac_id === state.active ? "on" : ""}`,
      onclick: async () => {
        state.active = p.mac_id;
        await db.set("active", state.active);
        go("sessions");
      },
    }, macLabel(p), n ? h("span", { class: "badge" }, n) : null);
  }));
}

function sessionsScreen(p) {
  const mine = itemsCache.filter((it) => it.mac === p.mac_id);
  const tasksWithItems = new Set(mine.map((it) => it.task));
  const live = [...(state.sessions[p.mac_id] || [])].sort((a, b) =>
    (b.slug === "phone-dispatch") - (a.slug === "phone-dispatch") || (b.can_send - a.can_send));
  const liveSlugs = new Set(live.map((s) => s.slug));
  const earlier = [...tasksWithItems].filter((t) => !liveSlugs.has(t)).sort();

  const row = (slug, sub, chip, chipClass) => {
    const n = unreadCount(p.mac_id, slug);
    return h("button", { class: "row", onclick: () => openThread(slug) },
      h("div", { class: "top" },
        h("span", { class: "slug" }, slug),
        n ? h("span", { class: "badge" }, n) : null,
        h("span", { class: `chip ${chipClass}` }, chip)),
      sub ? h("span", { class: "sub" }, sub) : null);
  };

  return h("main", {},
    bar(macLabel(p), { sub: macLine(p) }),
    macSwitcher(),
    h("div", { class: "list" },
      live.length ? null : h("p", { class: "muted pad" }, "No live sessions reported yet."),
      live.map((s) => row(s.slug, s.waiting_on ? `waiting on ${s.waiting_on}` : s.name,
        s.can_send ? "live" : "read only", s.can_send ? "live" : "ro")),
      earlier.length ? h("h2", { class: "section" }, "Not running") : null,
      earlier.map((slug) => row(slug, "", "not running", "off"))),
    h("footer", { class: "foot" },
      h("button", { class: "link", onclick: () => { sendSync(p); go("settings"); } }, "Settings")));
}

async function openThread(task) {
  const p = current();
  const items = (await db.itemsFor(task)).filter((it) => it.mac === p.mac_id);
  for (const it of items) {
    if (it.dir === "in" && !it.read) {
      it.read = true;
      await db.putItem(it);
    }
  }
  itemsCache = await db.allItems();
  const pending = [...items].reverse().find((it) => it.dir === "in" && !it.replied && !it.broadcast);
  go("thread", { task, replyTo: pending ? { id: pending.flow_id, body: pending.body } : null });
}

function threadScreen(p) {
  const task = state.task;
  const session = (state.sessions[p.mac_id] || []).find((s) => s.slug === task);
  const items = itemsCache.filter((it) => it.mac === p.mac_id && it.task === task).sort((a, b) => a.ts - b.ts);
  const canSend = Boolean(session?.can_send);

  const bubble = (it) => {
    if (it.dir === "in") {
      return h("div", { class: "msg in" },
        h("div", { class: "bubble them" }, it.urgent ? h("span", { class: "chip urgent" }, "urgent") : null, it.body),
        h("span", { class: "meta" }, `${clock(it.ts)}${it.broadcast ? " · broadcast" : ""}`));
    }
    const label = { sending: "sending…", sent: "sent, waiting for the Mac", delivered: "delivered", refused: "refused", failed: "failed" }[it.state] || it.state;
    return h("div", { class: "msg out" },
      h("div", { class: "bubble me" }, it.body),
      h("span", { class: `meta ${it.state === "refused" || it.state === "failed" ? "bad" : ""}` },
        `${clock(it.ts)} · ${label}${it.reason ? ` · ${it.reason}` : ""}`));
  };

  const input = h("textarea", { rows: "2", placeholder: canSend ? "Message…" : "", maxlength: "4000", "aria-label": "Message" });
  const sendBtn = h("button", { class: "primary", type: "submit" }, "Send");
  const composer = canSend
    ? h("form", {
      class: "composer",
      onsubmit: async (ev) => {
        ev.preventDefault();
        const body = input.value.trim();
        if (!body) return;
        sendBtn.disabled = true;
        input.value = "";
        await send(p, task, body, state.replyTo?.id);
        state.replyTo = null;
        sendBtn.disabled = false;
      },
    },
    state.replyTo ? h("div", { class: "replying" },
      h("span", {}, "Replying to: ", state.replyTo.body.slice(0, 80)),
      h("button", { type: "button", class: "link", onclick: () => go("thread", { replyTo: null }) }, "✕")) : null,
    h("div", { class: "row2" }, input, sendBtn))
    : h("p", { class: "muted pad" }, session
      ? "Read only. Add this session to ~/.flow-remote/allow.txt on the Mac to message it."
      : "This session isn't running on the Mac.");

  return h("main", { class: "threadview" },
    bar(task, { back: () => go("sessions"), sub: h("span", { class: session ? "status ok" : "status" }, `${macLabel(p)} · ${session ? "live" : "not running"}`) }),
    h("div", { class: "thread" }, items.length ? items.map(bubble) : h("p", { class: "muted pad" }, "No messages yet.")),
    composer);
}

function settingsScreen() {
  return h("main", {},
    bar("Settings", { back: () => go("sessions") }),
    state.pairings.map((p) => h("section", { class: "card" },
      h("h2", {}, macLabel(p), p.mac_id === state.active ? h("span", { class: "chip live" }, "showing") : null),
      h("p", {}, "Mac id: ", h("code", {}, p.mac_id)),
      h("p", {}, "This phone, for this Mac: ", h("code", {}, p.device_id)),
      h("p", {}, "Fingerprint: ", h("code", { class: "fp" }, p.device_fp)),
      h("button", { class: "danger", onclick: () => unpair(p) }, "Unpair from this Mac"),
      h("p", { class: "muted" }, "Unpairing deletes this phone's key for that Mac. Also run ",
        h("code", {}, `flow-remote revoke ${p.device_id}`), " on it."))),
    h("div", { class: "pad" }, h("button", { class: "primary", onclick: () => go("welcome") }, "Pair another Mac")));
}

async function unpair(p) {
  state.pairings = state.pairings.filter((x) => x !== p);
  delete state.sessions[p.mac_id];
  if (state.pairings.length === 0) {
    stopPolling();
    await db.forget();
    Object.assign(state, { active: null, sessions: {}, macSeen: {} });
    itemsCache = [];
    go("welcome");
    return;
  }
  if (state.active === p.mac_id) state.active = state.pairings[0].mac_id;
  await savePairings();
  go("sessions");
}

// ---- messaging ----

function sealToMac(p, msg) {
  return seal(JSON.stringify(msg), p.keys.sign.privateKey, p.device_id, p.mac_id, p.mac_box_pub);
}

async function send(p, task, body, replyTo) {
  const clientId = b64u(crypto.getRandomValues(new Uint8Array(9)));
  const item = { id: `c:${clientId}`, mac: p.mac_id, task, dir: "out", body, ts: Date.now(), state: "sending", reply_to: replyTo || null };
  await db.putItem(item);
  itemsCache = await db.allItems();
  render();
  try {
    await api.postEnvelope(api.signerFor(p), await sealToMac(p, { kind: "send", client_id: clientId, task, body, reply_to: replyTo || undefined }));
    item.state = "sent";
  } catch (e) {
    item.state = "failed";
    item.reason = e.message;
  }
  await db.putItem(item);
  itemsCache = await db.allItems();
  render();
}

async function sendSync(p) {
  if (!p?.confirmed) return;
  try { await api.postEnvelope(api.signerFor(p), await sealToMac(p, { kind: "sync" })); } catch {}
}

// handle verifies and applies one envelope from p's Mac. It returns
// normally for junk too, so junk gets acked and doesn't come back.
async function handle(p, e) {
  if (e.from !== p.mac_id || e.to !== p.device_id) return;
  try {
    await verify(e, p.mac_sign_pub);
  } catch {
    return;
  }
  if (!(await db.firstSighting(e.id))) return;
  let m;
  try {
    m = JSON.parse(await open(e, p.keys.box));
  } catch {
    return;
  }
  const here = state.view === "thread" && state.active === p.mac_id;
  switch (m.kind) {
    case "paired":
      p.confirmed = true;
      p.mac_name = m.mac_name;
      await savePairings();
      sendSync(p);
      render();
      break;
    case "sessions":
      state.sessions[p.mac_id] = m.sessions || [];
      await db.set(`sessions:${p.mac_id}`, state.sessions[p.mac_id]);
      break;
    case "status": {
      const it = await db.getItem(`c:${m.client_id}`);
      if (!it) break;
      it.state = m.state;
      it.reason = m.reason || "";
      it.flow_id = m.flow_id || "";
      await db.putItem(it);
      if (m.state === "delivered" && it.reply_to) {
        const answered = await db.getItem(`m:${p.mac_id}:${it.reply_to}`);
        if (answered) {
          answered.replied = true;
          await db.putItem(answered);
        }
      }
      break;
    }
    case "mail": {
      const mail = m.mail;
      // flow message ids are only unique per Mac, so scope by Mac.
      const id = `m:${p.mac_id}:${mail.flow_id}`;
      if (await db.getItem(id)) break;
      await db.putItem({
        id, mac: p.mac_id, task: mail.task, dir: "in", body: mail.body, ts: mail.created_at, flow_id: mail.flow_id,
        urgent: Boolean(mail.urgent), broadcast: Boolean(mail.broadcast),
        read: here && state.task === mail.task, replied: false,
      });
      // In the open thread, offer to answer what just arrived.
      if (here && state.task === mail.task && !mail.broadcast && !state.replyTo) {
        state.replyTo = { id: mail.flow_id, body: mail.body };
      }
      break;
    }
  }
}

let polling = false;
let pollTimer = null;

async function pollPairing(p, withStatus) {
  const signer = api.signerFor(p);
  try {
    const res = await api.listEnvelopes(signer);
    const ids = [];
    for (const rec of res.envelopes || []) {
      await handle(p, rec.env);
      ids.push(rec.env.id);
    }
    if (ids.length) await api.ack(signer, ids);
    if (withStatus && p.confirmed) {
      const st = await api.status(signer);
      const seen = st.macs?.[p.mac_id]?.last_seen;
      state.macSeen[p.mac_id] = seen ? new Date(seen) : null;
    }
    p.rejected = false;
    return ids.length > 0;
  } catch (e) {
    // Before the Mac confirms pairing, the mailbox doesn't know this
    // device yet, so 401 is expected. After that it means revoked.
    if (e.status === 401 && p.confirmed) p.rejected = true;
    return false;
  }
}

function startPolling() {
  if (polling || state.pairings.length === 0) return;
  polling = true;
  let n = 0;
  const loop = async () => {
    if (!polling) return;
    const withStatus = n++ % STATUS_EVERY === 0;
    let changed = false;
    // Every pairing, so mail from any of your Macs shows up with a badge.
    for (const p of [...state.pairings]) changed = (await pollPairing(p, withStatus)) || changed;
    if (changed) itemsCache = await db.allItems();
    if (changed || withStatus) backgroundRender();
    pollTimer = setTimeout(loop, POLL_MS);
  };
  loop();
}

function stopPolling() {
  polling = false;
  clearTimeout(pollTimer);
}

// A pairing link opened while the app is already running only changes the
// fragment, so the page doesn't reload. Pick it up here.
window.addEventListener("hashchange", () => {
  let offer = null;
  try { offer = parseOffer(location.hash); } catch {}
  if (location.hash) history.replaceState(null, "", location.pathname);
  if (!offer) return;
  if (state.pairings.some((p) => p.mac_id === offer.mac_id)) {
    go(state.view, { error: "This phone is already paired with that Mac." });
    return;
  }
  go("welcome", { offer });
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) stopPolling();
  else startPolling();
});

// ---- boot ----

async function loadState() {
  let pairings = (await db.get("pairings")) || [];
  // Before multi-Mac support there was one pairing under "pairing"/"keys".
  const old = await db.get("pairing");
  const oldKeys = await db.get("keys");
  if (pairings.length === 0 && old && oldKeys) {
    pairings = [{ ...old, keys: oldKeys, rejected: false }];
    await db.set("pairings", pairings);
    await db.set("active", old.mac_id);
    await db.del("pairing");
    await db.del("keys");
  }
  state.pairings = pairings;
  state.active = (await db.get("active")) || pairings[0]?.mac_id || null;
  for (const p of pairings) state.sessions[p.mac_id] = (await db.get(`sessions:${p.mac_id}`)) || [];
  itemsCache = await db.allItems();
}

async function boot() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("./sw.js").catch(() => {});
  const offer = (() => {
    try { return parseOffer(location.hash); } catch { return null; }
  })();
  // The fragment holds the one-time secret; don't leave it in history.
  if (location.hash) history.replaceState(null, "", location.pathname);

  await loadState();
  if (offer && !state.pairings.some((p) => p.mac_id === offer.mac_id)) state.offer = offer;
  if (!current()) state.view = "welcome";
  db.pruneSeen(Date.now() - SEEN_TTL).catch(() => {});
  render();
  startPolling();
  for (const p of state.pairings) sendSync(p);
}

boot();
