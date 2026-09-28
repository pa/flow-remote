// flow-remote phone app. Screens: pair, sessions, thread, settings.
// There's no sign-in: the device key authenticates every request.
// Every message body comes from a flow session or from the user, so the
// UI is built with DOM nodes and textContent, never innerHTML.
import * as api from "./api.js";
import * as db from "./db.js";
import { b64u, generateIdentity, exportPublic, fingerprint, seal, verify, open } from "./envelope.js";
import { parseOffer, newDeviceId, enrollmentEnvelope } from "./pairing.js";

const POLL_MS = 3000;
const STATUS_EVERY = 5; // polls between Mac status checks
const ONLINE_MS = 90_000; // the relay checks in at least once a minute
const SEEN_TTL = 8 * 24 * 3600_000;

const state = {
  rejected: false, // the mailbox no longer accepts this device
  pairing: null, // {mac_id, mac_sign_pub, mac_box_pub, device_id, confirmed, mac_name}
  keys: null, // {sign, box} CryptoKeyPairs, non-extractable
  sessions: [],
  macSeen: undefined, // Date | null
  view: "sessions",
  task: null,
  offer: null,
  error: "",
  replyTo: null,
};

const root = document.getElementById("app");

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
// camera and the pairing form alone.
function backgroundRender() {
  if (state.view === "scan" || state.offer) return;
  render();
}

function screen() {
  if (state.offer) return pairScreen();
  if (!state.pairing) return welcomeScreen();
  if (!state.pairing.confirmed) return waitingScreen();
  if (state.view === "scan") return scanScreen();
  if (state.view === "thread") return threadScreen();
  if (state.view === "settings") return settingsScreen();
  return sessionsScreen();
}

function bar(title, { back, sub } = {}) {
  return h("header", { class: "bar" },
    back ? h("button", { class: "back", "aria-label": "Back", onclick: back }, "‹") : null,
    h("div", { class: "titles" }, h("h1", {}, title), sub ?? null));
}

function welcomeScreen() {
  return h("main", { class: "center" },
    h("h1", { class: "brand" }, "Pair with your Mac"),
    h("p", { class: "muted" }, "On the Mac, run ", h("code", {}, "relay pair"), ". Then scan the QR code it shows."),
    h("button", { class: "primary", onclick: () => go("scan") }, "Scan the QR code"),
    pasteBox(),
    state.error ? h("p", { class: "error" }, state.error) : null);
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
    go(state.view, { offer });
  } catch (e) {
    go(state.view, { error: e.message });
  }
}

let stopScan = null;

function scanScreen() {
  const video = h("video", { playsinline: true, muted: true });
  const note = h("p", { class: "muted" }, "Point the camera at the QR code on your Mac.");
  const view = h("main", {},
    bar("Scan", { back: () => { stopScan?.(); go("sessions"); } }),
    h("div", { class: "scan" }, video), note);
  startScan(video, note);
  return view;
}

async function startScan(video, note) {
  stopScan?.();
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch {
    note.textContent = "The camera isn't available. Paste the pairing link instead.";
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
    note.textContent = `The camera wouldn't start (${e.name}). Paste the pairing link instead.`;
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
    bar("Pair this phone", { back: () => go("sessions", { offer: null }) }),
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
  const keys = await generateIdentity(false);
  const deviceId = newDeviceId();
  const env = await enrollmentEnvelope(offer, keys, deviceId, name);
  await api.postPair(offer.pair_id, env);
  const pub = await exportPublic(keys);
  const pairing = {
    mac_id: offer.mac_id, mac_sign_pub: offer.mac_sign_pub, mac_box_pub: offer.mac_box_pub,
    device_id: deviceId, confirmed: false, device_fp: await fingerprint(pub.sign_pub, pub.box_pub),
  };
  await db.set("keys", keys);
  await db.set("pairing", pairing);
  api.setSigner(deviceId, keys.sign.privateKey);
  Object.assign(state, { keys, pairing, offer: null });
  render();
  startPolling();
}

function waitingScreen() {
  return h("main", { class: "center" },
    h("h1", { class: "brand" }, "Confirm on your Mac"),
    h("p", {}, "The Mac asks you to confirm this phone. Check that it shows this fingerprint, then type y:"),
    h("code", { class: "fp" }, state.pairing.device_fp),
    h("p", { class: "muted" }, "Waiting for the Mac…"),
    h("button", { class: "link", onclick: unpair }, "Cancel pairing"));
}

function macLine() {
  if (state.rejected) return h("span", { class: "status warn" }, "The mailbox no longer accepts this phone. Unpair it in Settings and pair again.");
  const s = state.macSeen;
  if (s === undefined) return h("span", { class: "status" }, "Checking the Mac…");
  if (s === null) return h("span", { class: "status warn" }, "The Mac hasn't checked in yet. Is the relay running?");
  const t = s.getTime();
  if (Date.now() - t < ONLINE_MS) return h("span", { class: "status ok" }, `Mac online · seen ${ago(t)}`);
  return h("span", { class: "status warn" }, `Mac last seen ${ago(t)}. Messages wait until it's back.`);
}

let itemsCache = [];

function sessionsScreen() {
  const unread = {};
  const tasksWithItems = new Set();
  for (const it of itemsCache) {
    tasksWithItems.add(it.task);
    if (it.dir === "in" && !it.read) unread[it.task] = (unread[it.task] || 0) + 1;
  }
  const live = [...state.sessions].sort((a, b) =>
    (b.slug === "phone-dispatch") - (a.slug === "phone-dispatch") || (b.can_send - a.can_send));
  const liveSlugs = new Set(live.map((s) => s.slug));
  const earlier = [...tasksWithItems].filter((t) => !liveSlugs.has(t)).sort();

  const row = (slug, sub, chip, chipClass) => h("button", { class: "row", onclick: () => openThread(slug) },
    h("div", { class: "top" },
      h("span", { class: "slug" }, slug),
      unread[slug] ? h("span", { class: "badge" }, unread[slug]) : null,
      h("span", { class: `chip ${chipClass}` }, chip)),
    sub ? h("span", { class: "sub" }, sub) : null);

  return h("main", {},
    bar("Sessions", { sub: macLine() }),
    h("div", { class: "list" },
      live.length ? null : h("p", { class: "muted pad" }, "No live sessions reported yet."),
      live.map((s) => row(s.slug, s.waiting_on ? `waiting on ${s.waiting_on}` : s.name,
        s.can_send ? "live" : "read only", s.can_send ? "live" : "ro")),
      earlier.length ? h("h2", { class: "section" }, "Not running") : null,
      earlier.map((slug) => row(slug, "", "not running", "off"))),
    h("footer", { class: "foot" },
      h("button", { class: "link", onclick: () => { sendSync(); go("settings"); } }, "Settings")));
}

async function openThread(task) {
  const items = await db.itemsFor(task);
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

function threadScreen() {
  const task = state.task;
  const session = state.sessions.find((s) => s.slug === task);
  const items = itemsCache.filter((it) => it.task === task).sort((a, b) => a.ts - b.ts);
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
        await send(task, body, state.replyTo?.id);
        state.replyTo = null;
        sendBtn.disabled = false;
      },
    },
    state.replyTo ? h("div", { class: "replying" },
      h("span", {}, "Replying to: ", state.replyTo.body.slice(0, 80)),
      h("button", { type: "button", class: "link", onclick: () => go("thread", { replyTo: null }) }, "✕")) : null,
    h("div", { class: "row2" }, input, sendBtn))
    : h("p", { class: "muted pad" }, session
      ? "Read only. Add this session to allow.txt on the Mac to message it."
      : "This session isn't running on the Mac.");

  return h("main", { class: "threadview" },
    bar(task, { back: () => go("sessions"), sub: session ? h("span", { class: "status ok" }, "live") : h("span", { class: "status" }, "not running") }),
    h("div", { class: "thread" }, items.length ? items.map(bubble) : h("p", { class: "muted pad" }, "No messages yet.")),
    composer);
}

function settingsScreen() {
  const p = state.pairing;
  return h("main", {},
    bar("Settings", { back: () => go("sessions") }),
    h("section", { class: "card" },
      h("p", {}, "Paired with ", h("b", {}, p.mac_name || p.mac_id)),
      h("p", {}, "This phone: ", h("code", {}, p.device_id)),
      h("p", {}, "Fingerprint: ", h("code", { class: "fp" }, p.device_fp)),
      h("button", { class: "danger", onclick: unpair }, "Unpair this phone"),
      h("p", { class: "muted" }, "Unpairing deletes this phone's keys. Also run ", h("code", {}, `relay revoke ${p.device_id}`), " on the Mac.")));
}

async function unpair() {
  stopPolling();
  await db.forget();
  api.setSigner(null, null);
  Object.assign(state, { pairing: null, keys: null, sessions: [], offer: null, rejected: false });
  itemsCache = [];
  go("sessions");
}

// ---- messaging ----

async function sealToMac(msg) {
  const p = state.pairing;
  return seal(JSON.stringify(msg), state.keys.sign.privateKey, p.device_id, p.mac_id, p.mac_box_pub);
}

async function send(task, body, replyTo) {
  const clientId = b64u(crypto.getRandomValues(new Uint8Array(9)));
  const item = { id: `c:${clientId}`, task, dir: "out", body, ts: Date.now(), state: "sending", reply_to: replyTo || null };
  await db.putItem(item);
  itemsCache = await db.allItems();
  render();
  try {
    await api.postEnvelope(await sealToMac({ kind: "send", client_id: clientId, task, body, reply_to: replyTo || undefined }));
    item.state = "sent";
  } catch (e) {
    item.state = "failed";
    item.reason = e.message;
  }
  await db.putItem(item);
  itemsCache = await db.allItems();
  render();
}

async function sendSync() {
  if (!state.pairing?.confirmed) return;
  try { await api.postEnvelope(await sealToMac({ kind: "sync" })); } catch {}
}

// handle verifies and applies one envelope from the Mac. It returns
// normally for junk too, so junk gets acked and doesn't come back.
async function handle(e) {
  const p = state.pairing;
  if (e.from !== p.mac_id || e.to !== p.device_id) return;
  try {
    await verify(e, p.mac_sign_pub);
  } catch {
    return;
  }
  if (!(await db.firstSighting(e.id))) return;
  let m;
  try {
    m = JSON.parse(await open(e, state.keys.box));
  } catch {
    return;
  }
  switch (m.kind) {
    case "paired":
      p.confirmed = true;
      p.mac_name = m.mac_name;
      await db.set("pairing", p);
      sendSync();
      break;
    case "sessions":
      state.sessions = m.sessions || [];
      await db.set("sessions", state.sessions);
      break;
    case "status": {
      const it = await db.getItem(`c:${m.client_id}`);
      if (!it) break;
      it.state = m.state;
      it.reason = m.reason || "";
      it.flow_id = m.flow_id || "";
      await db.putItem(it);
      if (m.state === "delivered" && it.reply_to) {
        const answered = await db.getItem(`m:${it.reply_to}`);
        if (answered) {
          answered.replied = true;
          await db.putItem(answered);
        }
      }
      break;
    }
    case "mail": {
      const mail = m.mail;
      const id = `m:${mail.flow_id}`;
      if (await db.getItem(id)) break;
      await db.putItem({
        id, task: mail.task, dir: "in", body: mail.body, ts: mail.created_at, flow_id: mail.flow_id,
        urgent: Boolean(mail.urgent), broadcast: Boolean(mail.broadcast),
        read: state.view === "thread" && state.task === mail.task, replied: false,
      });
      // In the open thread, offer to answer what just arrived.
      if (state.view === "thread" && state.task === mail.task && !mail.broadcast && !state.replyTo) {
        state.replyTo = { id: mail.flow_id, body: mail.body };
      }
      break;
    }
  }
}

let polling = false;
let pollTimer = null;

async function pollOnce(n) {
  const p = state.pairing;
  const res = await api.listEnvelopes();
  const ids = [];
  for (const rec of res.envelopes || []) {
    await handle(rec.env);
    ids.push(rec.env.id);
  }
  if (ids.length) {
    await api.ack(ids);
    itemsCache = await db.allItems();
  }
  if (n % STATUS_EVERY === 0) {
    const st = await api.status(p.mac_id);
    const seen = st.macs?.[p.mac_id]?.last_seen;
    state.macSeen = seen ? new Date(seen) : null;
  }
  if (ids.length || n % STATUS_EVERY === 0) backgroundRender();
}

function startPolling() {
  if (polling || !state.pairing) return;
  polling = true;
  let n = 0;
  const loop = async () => {
    if (!polling) return;
    try {
      await pollOnce(n++);
      state.rejected = false;
    } catch (e) {
      // Before the Mac confirms pairing, the mailbox doesn't know this
      // device yet, so 401 is expected. After that it means revoked.
      if (e.status === 401 && state.pairing?.confirmed && !state.rejected) {
        state.rejected = true;
        backgroundRender();
      }
    }
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
  if (state.pairing) {
    go(state.view, { error: "This phone is already paired. Unpair it in Settings first." });
    return;
  }
  go("sessions", { offer });
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) stopPolling();
  else startPolling();
});

// ---- boot ----

async function boot() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("./sw.js").catch(() => {});
  const offer = (() => {
    try { return parseOffer(location.hash); } catch { return null; }
  })();
  // The fragment holds the one-time secret; don't leave it in history.
  if (location.hash) history.replaceState(null, "", location.pathname);

  state.pairing = (await db.get("pairing")) || null;
  state.keys = (await db.get("keys")) || null;
  if (state.pairing && state.keys) api.setSigner(state.pairing.device_id, state.keys.sign.privateKey);
  state.sessions = (await db.get("sessions")) || [];
  if (offer && !state.pairing) state.offer = offer;
  itemsCache = await db.allItems();
  db.pruneSeen(Date.now() - SEEN_TTL).catch(() => {});
  render();
  if (state.pairing) {
    startPolling();
    sendSync();
  }
}

boot();
