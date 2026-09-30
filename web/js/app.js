// flow-remote phone app. Screens: get started / pair, sessions, thread,
// settings. There's no sign-in: a device key authenticates every request.
//
// A phone can pair with several computers. Each pairing has its own device
// key, threads and session list, so the computers can't be linked through
// this phone's keys.
//
// Every message body comes from a flow session or from the user, so the UI
// is built with DOM nodes and textContent, never innerHTML.
import * as api from "./api.js";
import { segments, matches as findInChat } from "./highlight.js";
import * as db from "./db.js";
import { b64u, generateIdentity, exportPublic, fingerprint, seal, verify, open } from "./envelope.js";
import { parseOffer, newDeviceId, enrollmentEnvelope } from "./pairing.js";
import qrcode from "../vendor/qrcode-generator-2.0.4/qrcode.mjs";
import { search } from "./fuzzy.js";

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
  unreachable: {}, // mac_id -> true while that Mac doesn't answer at all
  updates: {}, // mac_id -> a newer flow-remote release that Mac could install
  view: "sessions",
  task: null,
  offer: null,
  error: "",
  replyTo: null,
  tsearch: false, // the search row in a chat is open
  tquery: "",
  thit: 0, // which match is current
  query: "", // sessions-screen search
  toast: null, // {mac, task, body}: a reply that just arrived elsewhere
};

const root = document.getElementById("app");
const current = () => state.pairings.find((p) => p.mac_id === state.active) || state.pairings[0] || null;
const macLabel = (p) => p.mac_name || p.mac_id;

// ---- where are we running? ----

// detectEnv decides which getting-started path to show. On iOS an app added
// to the home screen keeps its own storage, apart from Safari, so a phone
// should install before pairing or its keys end up in the wrong place.
function detectEnv() {
  const ua = navigator.userAgent;
  const ios = /iPhone|iPod/.test(ua) || (/iPad|Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  const android = /Android/.test(ua);
  const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  const phone = ios || android;
  return {
    os: ios ? "ios" : android ? "android" : "desktop",
    kind: !phone ? "desktop" : standalone ? "phone-app" : "phone-browser",
    camera: Boolean(navigator.mediaDevices?.getUserMedia),
  };
}

const env = detectEnv();
let installPrompt = null; // Android Chrome's deferred install prompt
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  installPrompt = e;
  if (state.view === "welcome") render();
});
let continueInBrowser = false;

// qrSvg draws text as a QR code with DOM calls, not markup strings.
function qrSvg(text, size = 200) {
  const q = qrcode(0, "M");
  q.addData(text);
  q.make();
  const n = q.getModuleCount(), quiet = 4, total = n + quiet * 2;
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${total} ${total}`);
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("class", "qr");
  const bg = document.createElementNS(NS, "rect");
  bg.setAttribute("width", total);
  bg.setAttribute("height", total);
  bg.setAttribute("fill", "#fff");
  svg.append(bg);
  let d = "";
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (q.isDark(y, x)) d += `M${x + quiet} ${y + quiet}h1v1h-1z`;
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", d);
  path.setAttribute("fill", "#000");
  svg.append(path);
  return svg;
}

// ---- tiny DOM helper ----

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// svgIcon draws a stroked 24x24 icon from a path, as DOM nodes.
function svgIcon(d) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", d);
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "2.6");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");
  svg.append(path);
  return svg;
}

// hl renders text with the matched characters highlighted, as DOM nodes.
function hl(text, positions) {
  if (!positions?.length) return text;
  const set = new Set(positions);
  const out = [];
  let run = "", inMatch = false;
  const flush = () => {
    if (run) out.push(inMatch ? h("mark", {}, run) : run);
    run = "";
  };
  for (let i = 0; i < text.length; i++) {
    const m = set.has(i);
    if (m !== inMatch) { flush(); inMatch = m; }
    run += text[i];
  }
  flush();
  return out;
}

// snippet cuts a long message around its first match, keeping positions.
function snippet(text, positions, width = 90) {
  if (text.length <= width) return { text, positions };
  const first = positions[0] ?? 0;
  const start = Math.max(0, Math.min(first - 20, text.length - width));
  const cut = text.slice(start, start + width);
  return { text: (start > 0 ? "…" : "") + cut + "…", positions: positions.map((p) => p - start + (start > 0 ? 1 : 0)).filter((p) => p >= 0 && p < cut.length + 1) };
}

// listTime is when a session's latest message was, as chat lists show
// it: the time today, the weekday this week, else the date.
function listTime(ms, now = Date.now()) {
  const d = new Date(ms), today = new Date(now);
  if (d.toDateString() === today.toDateString()) return clock(ms);
  const days = (new Date(today.toDateString()) - new Date(d.toDateString())) / 86400000;
  if (days === 1) return "Yesterday";
  if (days < 7) return d.toLocaleDateString([], { weekday: "short" });
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// clock is a message's time the way chat apps show it: "8:21 PM" or "20:21".
function clock(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

// whenLabel is a divider's time: "10:42", "Yesterday 10:42", "Mon 10:42",
// or "12 Sep 10:42".
function whenLabel(ms) {
  const d = new Date(ms), now = new Date();
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((day(now) - day(d)) / 86_400_000);
  const date = days === 0 ? "" : days === 1 ? "Yesterday " : days < 7
    ? d.toLocaleDateString([], { weekday: "short" }) + " "
    : d.toLocaleDateString([], { day: "numeric", month: "short" }) + " ";
  return date + clock(ms);
}

// ---- navigation ----

// Screens past the sessions list get a history entry, so Android's back
// button (and gesture) steps back instead of leaving the app. An installed
// iOS app has no system back gesture, so it gets a left-edge swipe below.
const DEEP = new Set(["thread", "settings", "scan"]);
const isDeep = (view) => DEEP.has(view) || (view === "welcome" && state.pairings.length > 0);

function go(view, extra = {}, { fromHistory = false } = {}) {
  const wasDeep = isDeep(state.view);
  Object.assign(state, { view, error: "" }, extra);
  if (!fromHistory) {
    // The entry also says which thread, so a reload can come back to it.
    const entry = { fr: view, task: view === "thread" ? state.task : undefined, mac: state.active };
    if (isDeep(view) && !wasDeep) history.pushState(entry, "");
    else if (isDeep(view)) history.replaceState(entry, "");
  }
  render();
}

// restoreView reopens the screen a reload left: the browser keeps the
// history entry's state across a reload, not the app's memory. A fresh
// start from the home screen has none, so it opens the list as before.
function restoreView() {
  const saved = history.state;
  if (!saved?.fr) return;
  if (saved.mac && state.pairings.some((p) => p.mac_id === saved.mac)) state.active = saved.mac;
  if (saved.fr === "settings") state.view = "settings";
  else if (saved.fr === "thread" && saved.task) Object.assign(state, { view: "thread", task: saved.task });
  // Anything else (the camera, the pairing guide) starts over.
  else history.replaceState(null, "");
}

// goBack is what every back button does.
function goBack() {
  stopScan?.();
  if (history.state?.fr) history.back(); // popstate brings us to sessions
  else go(state.pairings.length ? "sessions" : "welcome");
}

window.addEventListener("popstate", () => {
  stopScan?.();
  if (!isDeep(state.view)) return;
  go(state.pairings.length ? "sessions" : "welcome", { offer: null }, { fromHistory: true });
});

// Left-edge swipe back, for installed iOS apps. It follows the finger and
// commits past a third of the width or on a quick flick, like native iOS.
// Swipe one of the session's messages to the right to answer it, as in
// Messages or WhatsApp. It's the same as tapping the message. Touches that
// start at the very left edge are left to the back gesture.
(function swipeToReply() {
  const EDGE = 24, TRIGGER = 56, MAX = 72;
  let s = null;
  document.addEventListener("touchstart", (e) => {
    const bubble = e.target.closest?.(".bubble.tappable");
    if (!bubble || e.touches.length !== 1 || e.touches[0].clientX <= EDGE) return;
    s = { bubble, msg: bubble.closest(".msg"), x: e.touches[0].clientX, y: e.touches[0].clientY, dx: 0, horizontal: null };
  }, { passive: true });
  document.addEventListener("touchmove", (e) => {
    if (!s) return;
    const dx = e.touches[0].clientX - s.x, dy = e.touches[0].clientY - s.y;
    if (s.horizontal === null && Math.abs(dx) + Math.abs(dy) > 8) s.horizontal = Math.abs(dx) > Math.abs(dy) && dx > 0;
    if (!s.horizontal) return;
    s.dx = Math.min(MAX, Math.max(0, dx));
    s.msg.style.transition = "none";
    s.msg.style.transform = `translateX(${s.dx}px)`;
    s.msg.classList.toggle("swipe-ready", s.dx >= TRIGGER);
  }, { passive: true });
  const end = () => {
    if (!s) return;
    const { bubble, msg, dx, horizontal } = s;
    s = null;
    msg.style.transition = "transform 0.18s ease-out";
    msg.style.transform = "";
    msg.classList.remove("swipe-ready");
    if (horizontal && dx >= TRIGGER) {
      navigator.vibrate?.(10);
      bubble.click(); // the tap handler sets "Replying to"
    }
  };
  document.addEventListener("touchend", end, { passive: true });
  document.addEventListener("touchcancel", end, { passive: true });
})();

(function edgeSwipe() {
  if (!(env.os === "ios" && env.kind === "phone-app")) return;
  let start = null;
  const page = () => root.querySelector("main");
  document.addEventListener("touchstart", (e) => {
    if (!isDeep(state.view) || e.touches.length !== 1 || e.touches[0].clientX > 24) return;
    start = { x: e.touches[0].clientX, y: e.touches[0].clientY, t: Date.now(), dx: 0, horizontal: null };
  }, { passive: true });
  document.addEventListener("touchmove", (e) => {
    if (!start) return;
    const dx = e.touches[0].clientX - start.x, dy = e.touches[0].clientY - start.y;
    if (start.horizontal === null && Math.abs(dx) + Math.abs(dy) > 8) start.horizontal = Math.abs(dx) > Math.abs(dy);
    if (!start.horizontal) return;
    start.dx = Math.max(0, dx);
    const m = page();
    if (m) { m.style.transition = "none"; m.style.transform = `translateX(${start.dx}px)`; }
  }, { passive: true });
  document.addEventListener("touchend", () => {
    if (!start) return;
    const { dx, t, horizontal } = start;
    start = null;
    const m = page();
    if (!m || !horizontal) return;
    const fast = dx > 40 && dx / Math.max(1, Date.now() - t) > 0.5;
    if (dx > innerWidth / 3 || fast) {
      m.style.transition = "transform 0.18s ease-out";
      m.style.transform = `translateX(${innerWidth}px)`;
      setTimeout(goBack, 170);
    } else {
      m.style.transition = "transform 0.18s ease-out";
      m.style.transform = "";
    }
  });
})();

async function savePairings() {
  // Keys are CryptoKeys; IndexedDB stores them without making them extractable.
  await db.set("pairings", state.pairings);
  await db.set("active", state.active);
}

// ---- screens ----

// ---- keyboard ----

// iOS doesn't shrink the page when the keyboard opens. It scrolls the whole
// page up to reveal the text box, taking the header with it. So the thread
// screen is pinned to the *visible* area, which visualViewport reports, and
// only the message list scrolls. Android Chrome gets the same result from
// interactive-widget=resizes-content in the viewport meta.
// BUILD must match CACHE in sw.js. Settings shows it, so it's clear which
// version a phone is running: an installed iOS app doesn't reload when a
// new one is deployed.
const BUILD = "v51";

// The keyboard is "up" exactly while the message box has focus. On a phone
// that's when iOS shows the keyboard. Guessing it from heights failed in
// the installed app and left the thread unpinned while typing.
let typing = false;

function fitViewport() {
  const vv = window.visualViewport;
  const html = document.documentElement;
  if (vv) {
    html.style.setProperty("--app-h", `${vv.height}px`);
    html.style.setProperty("--app-top", `${vv.offsetTop}px`);
  }
  html.classList.toggle("kb-open", typing && env.kind !== "desktop");
  // Keep the newest message in view as the keyboard moves, but only if
  // that's where you were: iOS fires these while you scroll, too.
  const list = root.querySelector(".thread");
  if (list && state.view === "thread" && threadPinned) list.scrollTop = list.scrollHeight;
}

// threadPinned is whether the open thread is scrolled to its newest
// message. The list's own scroll events keep it current.
let threadPinned = true;
const trackPin = (e) => {
  const l = e.currentTarget;
  threadPinned = l.scrollHeight - l.scrollTop - l.clientHeight < 48;
};

if (window.visualViewport) {
  visualViewport.addEventListener("resize", fitViewport);
  visualViewport.addEventListener("scroll", fitViewport);
}
document.addEventListener("focusin", (e) => {
  if (e.target.tagName !== "TEXTAREA") return;
  typing = true;
  // Undo iOS scrolling the page itself to reveal the box.
  requestAnimationFrame(() => { window.scrollTo(0, 0); fitViewport(); });
  setTimeout(fitViewport, 350); // after the keyboard animation settles
});
document.addEventListener("focusout", (e) => {
  if (e.target.tagName !== "TEXTAREA") return;
  typing = false;
  requestAnimationFrame(() => { window.scrollTo(0, 0); fitViewport(); });
});

// ---- reply indicators ----

let toastTimer = null;

function showToast(t) {
  state.toast = t;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { state.toast = null; backgroundRender(); }, 6000);
}

function toastView(t) {
  const p = state.pairings.find((x) => x.mac_id === t.mac);
  return h("button", {
    class: "toast",
    onclick: async () => {
      state.toast = null;
      if (t.mac !== state.active) {
        state.active = t.mac;
        await db.set("active", state.active);
      }
      openThread(t.task);
    },
  },
  h("span", { class: "slug" }, t.task, state.pairings.length > 1 && p ? ` · ${macLabel(p)}` : ""),
  h("span", { class: "preview" }, t.body));
}

// The home-screen icon badge, where the platform allows it.
function updateAppBadge() {
  const n = itemsCache.filter((it) => it.dir === "in" && !it.read).length;
  try {
    if (n > 0) navigator.setAppBadge?.(n)?.catch?.(() => {});
    else navigator.clearAppBadge?.()?.catch?.(() => {});
  } catch {
    // The badge is a nicety; a browser that refuses it changes nothing.
  }
}

// What the last render put on screen, to skip renders that change nothing.
let shownView = null;
let shownHTML = "";
let shownComposer = "";

// render redraws the current screen. It builds the screen fresh, but only
// swaps it in if it differs from what's showing, and keeps the scroll
// position: the app renders on every poll, and most polls change nothing.
// stickToBottom scrolls an open thread to its newest message even if you'd
// scrolled up, for a message you just sent or opened the thread for.
function render({ stickToBottom = false } = {}) {
  const next = screen();
  const toast = state.toast ? toastView(state.toast) : null;
  const html = next.outerHTML + (toast ? toast.outerHTML : "");
  const view = state.view === "thread" ? `thread:${state.active}:${state.task}` : state.view;
  const sameView = shownView === view;
  if (sameView && html === shownHTML) return;

  // In the same thread, keep the composer that's on screen unless it
  // changed: replacing it drops focus, and on a phone the keyboard then
  // hides and comes back, which makes the page jump.
  const slot = next.querySelector(".composer-slot");
  // The placeholder follows the computer's status; that alone isn't a
  // reason to replace the field someone may be typing in.
  const composerKey = slot ? slot.outerHTML.replace(/ placeholder="[^"]*"/, "") : "";
  const oldMain = root.querySelector("main.threadview");
  if (sameView && slot && oldMain && composerKey === shownComposer) {
    patchThread(oldMain, next, stickToBottom);
  } else {
    shownComposer = composerKey;
    swapScreen(next, sameView, stickToBottom);
    shownView = view;
  }
  root.querySelector(".toast")?.remove();
  if (toast) root.append(toast);
  shownHTML = html;
  updateAppBadge();
}

// caret is where the cursor is in el, if el has focus.
function caret(el) {
  return el && document.activeElement === el ? { start: el.selectionStart, end: el.selectionEnd } : null;
}

// putCaret gives el focus with the cursor where caret() found it.
function putCaret(el, at) {
  if (!el || !at) return;
  el.focus();
  el.setSelectionRange(at.start, at.end);
}

// patchThread updates an open thread in place: the header and the
// messages, but not the composer.
function patchThread(oldMain, next, stickToBottom) {
  const nextTa = next.querySelector(".composer-slot textarea"), liveTa = oldMain.querySelector(".composer-slot textarea");
  if (nextTa && liveTa) liveTa.placeholder = nextTa.placeholder;
  const list = oldMain.querySelector(".thread");
  const top = list.scrollTop;
  const nextList = next.querySelector(".thread");
  // The chat's search field is in the header: keep typing in it.
  const searching = caret(oldMain.querySelector("input.tsearch"));
  oldMain.replaceChild(next.querySelector("header"), oldMain.querySelector("header"));
  oldMain.replaceChild(nextList, list);
  putCaret(oldMain.querySelector("input.tsearch"), searching);
  nextList.scrollTop = stickToBottom || threadPinned ? nextList.scrollHeight : top;
}

// swapScreen replaces the whole screen, keeping a half-typed message, the
// search box's focus, and where you'd scrolled to.
function swapScreen(next, sameView, stickToBottom) {
  const ta = root.querySelector("textarea");
  const draft = ta ? { value: ta.value, at: caret(ta) } : null;
  const searchAt = caret(root.querySelector("input.search"));
  const scrollY = window.scrollY;
  const list = root.querySelector(".thread");
  const listTop = list ? list.scrollTop : 0;
  const atBottom = !list || threadPinned;

  root.replaceChildren(next);
  document.documentElement.classList.toggle("in-thread", state.view === "thread");
  fitViewport();
  putCaret(root.querySelector("input.search"), searchAt);
  if (sameView) window.scrollTo(0, scrollY);
  if (state.view !== "thread") return;
  const nextList = root.querySelector(".thread");
  // Follow new messages only if you were already at the newest one.
  if (!sameView) threadPinned = true; // a thread opens at its newest message
  if (nextList) nextList.scrollTop = !sameView || stickToBottom || atBottom ? nextList.scrollHeight : listTop;
  const nextTa = root.querySelector("textarea");
  if (draft && nextTa) {
    nextTa.value = draft.value;
    putCaret(nextTa, draft.at);
  }
}

// backgroundRender is for updates the user didn't ask for. It leaves the
// camera, the pairing form and the getting-started page alone.
function backgroundRender() {
  if (state.view === "scan" || state.view === "welcome" || state.offer) return;
  render();
}

function screen() {
  if (state.offer) {
    // On an iPhone, a home-screen app keeps its own storage apart from
    // Safari. A pairing made in a Safari tab leaves its keys in Safari, so
    // send people to the installed app first. (Android's installed app
    // shares the browser's storage, so pairing in the tab is fine there.)
    if (env.kind === "phone-browser" && env.os === "ios" && !continueInBrowser) return installScreen(true);
    return pairScreen();
  }
  if (state.view === "scan") return scanScreen();
  const p = current();
  if (!p || state.view === "welcome") return welcomeScreen();
  if (!p.confirmed) return waitingScreen(p);
  if (state.view === "thread") return threadScreen(p);
  if (state.view === "settings") return settingsScreen();
  return sessionsScreen(p);
}

// flow's wave, from flow-bar, at the top of the Settings page.
function brandMark() {
  return h("img", { class: "mark-wave", src: "flow-wave.svg", alt: "flow" });
}

function bar(title, { back, sub, backCount, action } = {}) {
  return h("header", { class: "bar" },
    back ? h("button", { class: "back", "aria-label": backCount ? `Back, ${backCount} unread` : "Back", onclick: back },
      "‹", backCount ? h("span", { class: "count" }, backCount) : null) : null,
    h("div", { class: "titles" }, h("h1", {}, title), sub ?? null),
    action ?? null);
}

// The gear in the top-right corner, so Settings is never below a long list.
// It carries a dot when that computer has an update to install.
function settingsButton(p) {
  const update = state.updates[p.mac_id];
  return h("button", {
    class: `icon-btn${update ? " has-update" : ""}`, "aria-label": update ? `Settings, ${update} available` : "Settings",
    onclick: () => { sendSync(p); go("settings"); },
  }, svgIcon("M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"));
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
  const adding = state.pairings.length > 0;
  if (!adding && env.kind === "phone-browser" && !continueInBrowser) return installScreen();
  return guideScreen(adding);
}

// installScreen is for a phone in a browser tab: install first. forPairing
// means a pairing link brought them here.
function installScreen(forPairing = false) {
  const steps = env.os === "ios"
    ? [
      h("li", {}, "Tap the ", h("b", {}, "Share"), " button in Safari's toolbar."),
      h("li", {}, "Choose ", h("b", {}, "Add to Home Screen"), ", then ", h("b", {}, "Add"), "."),
      forPairing
        ? h("li", {}, "Open ", h("b", {}, "flow-remote"), " from your home screen, tap ", h("b", {}, "Scan the QR code"),
          ", and scan the code on your computer again. If it has expired, run ", h("code", {}, "flow-remote pair"), " for a new one.")
        : h("li", {}, "Open ", h("b", {}, "flow-remote"), " from your home screen, and pair from there."),
    ]
    : [
      installPrompt
        ? h("li", {}, h("button", { class: "primary", onclick: async () => { installPrompt.prompt(); await installPrompt.userChoice; installPrompt = null; render(); } }, "Install flow-remote"))
        : h("li", {}, "Open Chrome's menu and choose ", h("b", {}, "Install app"), " (or ", h("b", {}, "Add to Home screen"), ")."),
      h("li", {}, "Open ", h("b", {}, "flow-remote"), " from your home screen, and pair from there."),
    ];
  return h("main", {},
    bar("Install first"),
    h("div", { class: "pad center-text" },
      h("img", { class: "logo", src: "icon.svg", alt: "" }),
      h("h1", { class: "brand" }, "flow-remote")),
    h("section", { class: "card guide" },
      h("h2", {}, env.os === "ios" ? (forPairing ? "Install the app, then pair from it" : "You're in Safari on an iPhone") : "You're in a browser on an Android phone"),
      h("p", { class: "muted" }, env.os === "ios"
        ? "An app on your home screen keeps its own storage, separate from Safari. Pair from the installed app, or its keys would stay behind in Safari."
        : "Installed, it opens full screen and keeps checking for replies while it's open."),
      h("ol", {}, steps)),
    h("div", { class: "pad" },
      h("button", { class: "link", onclick: () => { continueInBrowser = true; render(); } }, "Continue in the browser anyway")));
}

function guideScreen(adding) {
  const origin = location.origin;
  const note = h("p", { class: "muted" });
  const desktop = env.kind === "desktop";
  return h("main", {},
    bar(adding ? "Pair another computer" : "Get started", adding ? { back: goBack } : {}),
    adding ? null : h("div", { class: "pad center-text" },
      h("img", { class: "logo", src: "icon.svg", alt: "" }),
      h("h1", { class: "brand" }, "flow-remote"),
      h("p", { class: "muted" }, desktop ? "Message your flow sessions from your phone." : "Message your flow sessions from this phone.")),
    desktop ? h("section", { class: "card guide" },
      h("h2", {}, "Open it on your phone"),
      h("p", { class: "muted" }, "Point your phone's camera at this code to open flow-remote there, then install it and pair from the phone."),
      h("div", { class: "qrwrap" }, qrSvg(origin)),
      h("p", { class: "muted center-text" }, origin)) : null,
    h("section", { class: "card guide" },
      h("h2", {}, "On your computer"),
      h("ol", {},
        h("li", {}, h("p", {}, "Install flow-remote (it needs flow):"),
          cmd("curl -fsSL https://raw.githubusercontent.com/pa/flow-remote/main/install.sh | sh")),
        h("li", {},
          h("p", {}, "Set it up. It walks you through the Tailscale settings, then asks for an auth key:"),
          cmd('flow-remote setup --name "My laptop"')),
        h("li", {}, h("p", {}, "Start it. It runs in the background, starts at login, and restarts if it crashes:"),
          cmd("flow-remote start"),
          h("p", { class: "muted" }, "Stop it with ", h("code", {}, "flow-remote stop"), ", check it with ", h("code", {}, "flow-remote status"), ".")),
        h("li", {}, h("p", {}, "Show a pairing QR code. It's valid for 2 minutes:"),
          cmd("flow-remote pair")))),
    h("section", { class: "card guide" },
      h("h2", {}, desktop ? "Or pair this browser" : "On this phone"),
      desktop
        ? h("p", { class: "muted" }, "To use flow-remote at a desk, paste the link that ", h("code", {}, "flow-remote pair"), " prints.")
        : null,
      !desktop || env.camera ? h("button", { class: desktop ? "secondary" : "primary", onclick: () => go("scan") }, desktop ? "Scan with this computer's camera" : "Scan the QR code") : null,
      note,
      pasteBox(),
      h("p", { class: "muted" }, "Then compare the fingerprints on both screens, and type ", h("code", {}, "y"), " on the computer."),
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
    const existing = state.pairings.find((p) => p.mac_id === offer.mac_id);
    if (existing && !existing.rejected) {
      throw new Error("This phone is already paired with that computer. Unpair it in Settings first to pair again.");
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
  // The photo fallback appears only if the live camera fails or finds
  // nothing for a while; most of the time scanning just works.
  const fallback = h("div", { class: "pad", hidden: true }, photoButton(note));
  const view = h("main", {},
    bar("Scan", { back: goBack }),
    h("div", { class: "scan" }, video), note, fallback);
  startScan(video, note, () => { fallback.hidden = false; });
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

async function startScan(video, note, showFallback) {
  stopScan?.();
  let stream;
  try {
    if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("this browser gives web apps no live camera"), { name: "NotSupported" });
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch (e) {
    note.textContent = e.name === "NotAllowedError"
      ? "Camera access is blocked. Allow it in Settings, or take a photo instead."
      : `The live camera didn't start (${e.name}: ${e.message}). Take a photo instead.`;
    showFallback();
    return;
  }
  const slow = setTimeout(showFallback, 10_000);
  let running = true;
  stopScan = () => {
    running = false;
    clearTimeout(slow);
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
    showFallback();
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
    bar("Pair with this computer", { back: () => go("welcome", { offer: null }) }),
    h("section", { class: "card" },
      h("p", {}, "Check that your computer shows this fingerprint:"), macFp,
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
  const mailbox = api.mailboxBase(offer);
  await api.postPair(mailbox, offer.pair_id, env);
  const pub = await exportPublic(keys);
  // Pairing again after a revocation replaces the dead pairing. Threads are
  // stored by Mac, so the history comes back with the new key.
  state.pairings = state.pairings.filter((x) => x.mac_id !== offer.mac_id);
  state.pairings.push({
    mac_id: offer.mac_id, mac_sign_pub: offer.mac_sign_pub, mac_box_pub: offer.mac_box_pub,
    device_id: deviceId, device_fp: await fingerprint(pub.sign_pub, pub.box_pub),
    confirmed: false, rejected: false, keys, mailbox,
  });
  state.active = offer.mac_id;
  await savePairings();
  go("sessions", { offer: null });
  startPolling();
}

function waitingScreen(p) {
  return h("main", { class: "center" },
    h("h1", { class: "brand" }, "Confirm on your computer"),
    h("p", {}, "The computer asks you to confirm this phone. Check that it shows this fingerprint, then type y:"),
    h("code", { class: "fp" }, p.device_fp),
    h("p", { class: "muted" }, "Waiting for the computer…"),
    h("button", { class: "link", onclick: () => unpair(p) }, "Cancel pairing"));
}

// macOffline: the Mac hasn't checked in for a while, so the session list
// is only the last one it sent, and "live" can't be trusted.
function macOffline(p) {
  if (state.unreachable[p.mac_id]) return true;
  const seen = state.macSeen[p.mac_id];
  if (seen === undefined) return false; // not checked yet
  return seen === null || Date.now() - seen.getTime() > ONLINE_MS;
}

// unreachableLine says why a computer can't be reached, as far as the
// phone can tell from how the request failed.
// answeredTest says, for one thread's items, whether a message of yours
// has had its answer: a reply that names it with --reply-to, or, for a
// session that doesn't say what it's answering, any unlinked reply after it.
function answeredTest(items) {
  const linked = new Set(items.filter((it) => it.dir === "in" && it.reply_to).map((it) => it.reply_to));
  const lastLoose = Math.max(0, ...items.filter((it) => it.dir === "in" && !it.reply_to).map((it) => it.ts));
  return (it) => Boolean(it.flow_id && linked.has(it.flow_id)) || it.ts < lastLoose;
}

function unreachableLine(p) {
  const host = new URL(p.mailbox || location.origin).hostname;
  const wait = " Messages wait here and go when it's back.";
  switch (state.unreachable[p.mac_id]) {
    case "phone-offline":
      return "This phone is offline." + wait;
    case "unresolved":
      return host.endsWith(".ts.net")
        ? "Can't find this computer. Is Tailscale on? Open the Tailscale app and connect." + wait
        : "Can't reach this computer's address. Check the tunnel, or that flow-remote is running." + wait;
    default:
      return "This computer isn't answering. It may be asleep, or flow-remote isn't running." + wait;
  }
}

function macLine(p) {
  if (p.rejected) {
    return h("span", { class: "status warn" }, "This computer revoked this phone. ",
      h("button", { class: "inline", onclick: () => go("welcome") }, "Pair again"),
      " to reconnect with a new key; your messages stay.");
  }
  if (state.unreachable[p.mac_id]) return h("span", { class: "status warn" }, unreachableLine(p));
  const s = state.macSeen[p.mac_id];
  if (s === undefined) return h("span", { class: "status" }, "Checking the computer…");
  if (s === null) return h("span", { class: "status warn" }, "The computer hasn't checked in yet. Is `flow-remote start` running?");
  const t = s.getTime();
  if (Date.now() - t < ONLINE_MS) return h("span", { class: "status ok" }, `online · seen ${ago(t)}`);
  return h("span", { class: "status warn" }, `last seen ${ago(t)}. Messages wait until it's back.`);
}

let itemsCache = [];

// Unread counts, worked out once per change of itemsCache rather than once
// per row on every render.
let unreadFor = null;
let unreadFrom = null;
function unreadCount(mac, task) {
  if (unreadFrom !== itemsCache) {
    unreadFor = new Map();
    for (const it of itemsCache) {
      if (it.dir !== "in" || it.read) continue;
      for (const k of [it.mac, `${it.mac}\n${it.task}`]) unreadFor.set(k, (unreadFor.get(k) || 0) + 1);
    }
    unreadFrom = itemsCache;
  }
  return unreadFor.get(task ? `${mac}\n${task}` : mac) || 0;
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

// The main screen: this computer's sessions, grouped by what needs you,
// or search results while there's a query.
function sessionsScreen(p) {
  const home = homeContext(p);
  const q = state.query.trim();
  return h("main", {},
    bar(macLabel(p), { sub: macLine(p), action: settingsButton(p) }),
    macSwitcher(),
    homeSearchBar(),
    h("div", { class: `list ${home.offline ? "dim" : ""}` }, q ? searchResults(home, q) : homeSections(home)));
}

// A message whose last attempt went wrong.
const BAD = ["refused", "failed", "stale"];
// How long the main screen keeps showing where your last message is.
const WAIT_MS = 12 * 3600_000;

// homeContext gathers what the main screen's rows need: this computer's
// messages, its live sessions (phone-dispatch first, then the ones you
// can message), the sessions that have only history, and helpers for
// which of your messages are still unanswered.
function homeContext(p) {
  const mine = itemsCache.filter((it) => it.mac === p.mac_id);
  const live = [...(state.sessions[p.mac_id] || [])].sort((a, b) =>
    (b.slug === "phone-dispatch") - (a.slug === "phone-dispatch") || (b.can_send - a.can_send));
  const liveSlugs = new Set(live.map((s) => s.slug));
  const earlier = [...new Set(mine.map((it) => it.task))].filter((t) => !liveSlugs.has(t)).sort();
  const lastOut = {}, lastAt = {};
  for (const it of mine) {
    if (it.dir === "out" && (!lastOut[it.task] || it.ts > lastOut[it.task].ts)) lastOut[it.task] = it;
    lastAt[it.task] = Math.max(lastAt[it.task] || 0, it.ts);
  }
  const tests = new Map();
  const answeredIn = (slug) => {
    if (!tests.has(slug)) tests.set(slug, answeredTest(mine.filter((it) => it.task === slug)));
    return tests.get(slug);
  };
  const home = { p, mine, live, earlier, lastOut, lastAt, answeredIn, offline: macOffline(p) };
  // How many of your delivered messages to slug haven't had their answer.
  home.waitingCount = (slug) =>
    mine.filter((it) => it.task === slug && it.dir === "out" && it.state === "delivered" && !answeredIn(slug)(it)).length;
  home.awaiting = (slug) => awaiting(home, slug);
  return home;
}

// awaiting is your latest message to slug while it's unanswered, so the
// session's row can say where it is. flow can't say yet whether the
// session has read it, so "waiting for a reply" is as far as it goes.
function awaiting(home, slug) {
  const o = home.lastOut[slug];
  if (!o || o.state === "resent" || Date.now() - o.ts > WAIT_MS) return null;
  if (o.state === "delivered" && home.waitingCount(slug) === 0) return null;
  if (o.state !== "delivered" && home.answeredIn(slug)(o)) return null;
  return o;
}

// sessionRow is one session in the list. A dot says whether you can
// message the session; a word says why not.
function sessionRow(home, slug, { sub = "", chip, cls, marks = {}, where = "" }) {
  const n = unreadCount(home.p.mac_id, slug);
  const o = home.awaiting(slug);
  const busy = o && !BAD.includes(o.state) ? " busy" : "";
  return h("button", { class: "row", onclick: () => openThread(slug) },
    h("div", { class: "top" },
      h("span", { class: `dot ${cls}${busy}`, title: chip, "aria-label": chip }),
      h("span", { class: "slug" }, hl(slug, marks.slug)),
      n ? h("span", { class: "badge" }, n) : null,
      cls === "live" ? null : h("span", { class: "state" }, chip),
      home.lastAt[slug] ? h("span", { class: "meta" }, listTime(home.lastAt[slug])) : null),
    sub ? h("span", { class: "sub" }, hl(sub, marks.sub)) : null,
    where ? h("span", { class: "where" }, hl(where, marks.where)) : null,
    o ? pendingLine(home, o) : null);
}

// liveRow is sessionRow for a running session, with its details.
function liveRow(home, s, marks) {
  const [chip, cls] = home.offline ? ["offline", "off"] : s.can_send ? ["live", "live"] : ["read only", "ro"];
  return sessionRow(home, s.slug, { sub: sessionSub(s), chip, cls, marks, where: whereOf(s) });
}

// A session that's no longer running, with only its history.
function endedRow(home, slug, marks) {
  return sessionRow(home, slug, { chip: "not running", cls: "off", marks });
}

// The line under a session's name: who it's waiting on, or its name.
const sessionSub = (s) => s.waiting_on ? `waiting on ${s.waiting_on}` : s.name;

// project · #tag #tag, the task's place in flow.
const whereOf = (s) => [s.project, (s.tags || []).map((t) => "#" + t).join(" ")].filter(Boolean).join(" · ");

// pendingLine says where your unanswered message to a session is.
function pendingLine(home, o) {
  const n = home.waitingCount(o.task);
  return h("span", { class: `pending${BAD.includes(o.state) ? " bad" : ""}` }, {
    sending: "Sending…", queued: "Waiting for the computer to be reachable", sent: "Sent, waiting for the computer",
    delivered: n > 1 ? `${n} messages waiting in the session's inbox` : "In the session's inbox · waiting for a reply",
  }[o.state] || "Not delivered · open to see why");
}

// group puts rows in one card under a heading; nothing if there are none.
function group(title, rows, kind = "") {
  return rows.length ? [
    title ? h("h2", { class: `section ${kind}` }, title) : null,
    h("div", { class: "group" }, rows),
  ] : null;
}

// homeSearchBar is the main search field, with a clear button while
// there's a query.
function homeSearchBar() {
  const searchBox = h("input", {
    class: "search", type: "search", placeholder: "Search sessions and messages", value: state.query,
    autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "Search",
  });
  searchBox.addEventListener("input", () => { state.query = searchBox.value; render(); });
  const clearSearch = state.query ? h("button", {
    class: "clear", type: "button", "aria-label": "Clear search",
    onclick: () => { state.query = ""; render(); root.querySelector("input.search")?.focus(); },
  }, "✕") : null;
  return h("div", { class: "searchbar" }, searchBox, clearSearch);
}

// searchResults matches q against sessions (live ones with their details,
// plus threads no longer running) and against messages.
function searchResults(home, q) {
  const pool = [
    ...home.live.map((s) => ({ ...s, sub: sessionSub(s), where: whereOf(s), live: true })),
    ...home.earlier.map((slug) => ({ slug, sub: "", live: false })),
  ];
  const hits = search(q, pool, { slug: 3, sub: 1.5, where: 1 });
  const msgHits = search(q, home.mine, { body: 1 }).slice(0, 20);
  return [
    group("Sessions", hits.map(({ item, field, positions }) => {
      const marks = { [field]: positions };
      return item.live ? liveRow(home, item, marks) : endedRow(home, item.slug, marks);
    })),
    group("Messages", msgHits.map(({ item, positions }) => messageHit(item, positions))),
    hits.length || msgHits.length ? null : h("p", { class: "muted pad" }, `Nothing matches "${q}".`),
  ];
}

// messageHit is a message that matched the search, with the match shown.
function messageHit(item, positions) {
  const sn = snippet(item.body, positions);
  return h("button", { class: "row", onclick: () => openThread(item.task) },
    h("div", { class: "top" },
      h("span", { class: "dot ro", "aria-hidden": "true" }),
      h("span", { class: "slug" }, item.task),
      h("span", { class: "state" }, item.dir === "in" ? "from session" : "you")),
    h("span", { class: "sub wrap" }, hl(sn.text, sn.positions)));
}

// byRecent orders sessions like a chat app: the latest message first.
// Sessions with no messages keep their order, after the rest.
function byRecent(home, slugOf = (s) => s.slug) {
  return (a, b) => (home.lastAt[slugOf(b)] || 0) - (home.lastAt[slugOf(a)] || 0);
}

// homeSections lists the sessions with no query: new replies first, then
// those waiting for a reply, then the rest, then the ones no longer
// running. Each section has the latest message on top.
function homeSections(home) {
  const latestUnread = {};
  for (const it of home.mine) {
    if (it.dir === "in" && !it.read && (!latestUnread[it.task] || it.ts > latestUnread[it.task].ts)) latestUnread[it.task] = it;
  }
  const replied = Object.values(latestUnread).sort((a, b) => b.ts - a.ts);
  const repliedSet = new Set(replied.map((it) => it.task));
  const liveBySlug = new Map(home.live.map((s) => [s.slug, s]));
  const rest = home.live.filter((s) => !repliedSet.has(s.slug)).sort(byRecent(home));
  const waiting = rest.filter((s) => home.awaiting(s.slug));
  return [
    group("New replies", replied.map((it) => repliedRow(home, it, liveBySlug.get(it.task))), "new"),
    home.live.length ? null : h("p", { class: "muted pad" }, "No live sessions reported yet."),
    group("Waiting for a reply", waiting.map((s) => liveRow(home, s)), "wait"),
    group(replied.length || home.live.some((s) => home.awaiting(s.slug)) ? "Sessions" : "",
      rest.filter((s) => !home.awaiting(s.slug)).map((s) => liveRow(home, s))),
    group("Not running", home.earlier.filter((t) => !repliedSet.has(t)).sort(byRecent(home, (t) => t)).map((slug) => endedRow(home, slug))),
  ];
}

// repliedRow is a session with unread replies, previewing the newest.
// s is the live session, if it's still running.
function repliedRow(home, it, s) {
  const n = unreadCount(home.p.mac_id, it.task);
  const where = s ? whereOf(s) : "";
  return h("button", { class: "row", onclick: () => openThread(it.task) },
    h("div", { class: "top" },
      h("span", { class: "dot new", "aria-hidden": "true" }),
      h("span", { class: "slug" }, it.task),
      h("span", { class: "badge" }, n),
      h("span", { class: "meta" }, ago(it.ts))),
    h("span", { class: "preview" }, it.body),
    s ? (where ? h("span", { class: "where" }, where) : null) : h("span", { class: "sub" }, "not running"));
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
  // A new message isn't a reply unless you pick one: tap or swipe it.
  go("thread", { task, replyTo: null, tsearch: false, tquery: "" });
}

// threadScreen is one chat: its messages, and the field to send more.
function threadScreen(p) {
  const task = state.task;
  const session = (state.sessions[p.mac_id] || []).find((s) => s.slug === task);
  const items = itemsCache.filter((it) => it.mac === p.mac_id && it.task === task).sort((a, b) => a.ts - b.ts);
  // Your delivered messages without an answer are still in the session's
  // queue, as far as anyone can tell: flow doesn't say when a session reads
  // its inbox (Facets-cloud/flow#100), but an answer means it did.
  const answered = answeredTest(items);
  const hits = state.tsearch ? findInChat(items, state.tquery) : [];
  const chat = {
    p, task, items, answered,
    canSend: Boolean(session?.can_send),
    waiting: items.filter((it) => it.dir === "out" && it.state === "delivered" && !answered(it)),
    byFlow: new Map(items.filter((it) => it.flow_id).map((it) => [it.flow_id, it])),
    current: hits[Math.min(Math.max(state.thit, 0), hits.length - 1)],
  };
  const header = chatHeader(p, task, session, hits, chat.current);
  return h("main", { class: "threadview" },
    header,
    h("div", { class: "thread", onscroll: trackPin },
      items.length ? items.map((it, i) => chatBubble(chat, it, i)) : h("p", { class: "muted pad" }, "No messages yet.")),
    // render() keeps this slot's element across renders while its markup
    // is unchanged, so the field keeps focus and the keyboard stays up.
    h("div", { class: "composer-slot" }, chatComposer(p, task, session, chat.canSend)));
}

// Messages from one side within a few minutes form a run: tight spacing,
// and a tail only on the last one. A gap of an hour or more gets a divider.
const RUN_MS = 5 * 60_000;
const GAP_MS = 60 * 60_000;
const sameRun = (a, b) => a && b && a.dir === b.dir && Math.abs(b.ts - a.ts) < RUN_MS;
const failed = (it) => it.state === "refused" || it.state === "failed" || it.state === "stale";

// chatBubble draws one message of a chat, with the divider above it if
// it starts a new stretch of time.
function chatBubble(chat, it, i) {
  const prev = chat.items[i - 1], next = chat.items[i + 1];
  const run = `${sameRun(prev, it) ? " cont" : ""}${sameRun(it, next) ? " more" : ""}${it === chat.current ? " found" : ""}`;
  const divider = !prev || it.ts - prev.ts >= GAP_MS ? h("div", { class: "divider" }, whenLabel(it.ts)) : null;
  const q = replyQuote(chat, it);
  return [divider, it.dir === "in" ? inBubble(chat, it, run, q) : outBubble(chat, it, run, q)];
}

// inBubble is a message from the session. Tap or swipe it to reply.
function inBubble(chat, it, run, q) {
  const tappable = chat.canSend && it.flow_id && !it.broadcast;
  const chosen = state.replyTo?.id === it.flow_id ? " chosen" : "";
  return h("div", { class: `msg in${run}${chosen}`, "data-id": it.id },
    h("div", {
      class: `bubble them${q ? " hasq" : ""}${tappable ? " tappable" : ""}`,
      onclick: tappable ? () => replyTo(it) : null, title: tappable ? "Tap or swipe to reply" : null,
    },
    q,
    h("span", { class: "body" },
      it.urgent ? h("span", { class: "chip urgent" }, "urgent") : null, searchMarks(it, chat.current),
      h("span", { class: "stamp" }, clock(it.ts), it.broadcast ? " · all" : null))));
}

// outBubble is a message you sent, with its ticks and, under it, where it
// is if that needs saying.
function outBubble(chat, it, run, q) {
  const note = outNote(it, chat.waiting);
  return h("div", { class: `msg out${run}${note.queued ? " queued" : ""}`, "data-id": it.id },
    h("div", { class: `bubble me${q ? " hasq" : ""}` },
      q,
      h("span", { class: "body" }, searchMarks(it, chat.current), h("span", { class: "stamp" }, clock(it.ts), " ", ticks(it, chat.answered)))),
    note.text ? h("span", { class: `note${failed(it) ? " bad" : ""}` }, note.text) : null,
    sendAgain(chat, it));
}

// sendAgain offers to resend a message that went stale. The relay won't
// act on a message that waited too long in the mailbox; sending it again
// is a deliberate, fresh decision.
function sendAgain(chat, it) {
  if (it.state !== "stale" || !chat.canSend) return null;
  return h("button", {
    class: "inline", onclick: async () => {
      it.state = "resent";
      await db.putItem(it);
      await send(chat.p, chat.task, it.body, it.reply_to);
    },
  }, "Send again");
}

// replyQuote is the quote a reply opens with, WhatsApp style: who said the
// message it answers and the start of it. Tap it to go there.
function replyQuote(chat, it) {
  const target = it.reply_to && chat.byFlow.get(it.reply_to);
  if (!target) return null;
  return h("button", {
    class: "rq", type: "button", "aria-label": "Show the message this answers",
    onclick: (e) => { e.stopPropagation(); showMessage(target.id); },
  }, h("span", {}, h("b", {}, target.dir === "out" ? "You" : macLabel(chat.p)), h("i", {}, target.body)));
}

// replyTo makes the next message an answer to it, after a tap or a swipe.
function replyTo(it) {
  state.replyTo = { id: it.flow_id, body: it.body };
  render();
  root.querySelector(".composer textarea")?.focus();
}

// searchMarks is a message's text with the chat search's matches marked.
function searchMarks(it, current) {
  if (!state.tsearch || !state.tquery.trim()) return it.body;
  return segments(it.body, state.tquery).map((s) =>
    s.hit ? h("mark", { class: it === current ? "hit now" : "hit" }, s.text) : s.text);
}

// ticks, as in WhatsApp, for what we know: ✓ reached the computer, grey ✓✓
// in the session's inbox, teal ✓✓ answered. A clock while it's still on its
// way; ! if it didn't make it.
function ticks(it, answered) {
  if (failed(it)) return h("span", { class: "ticks bad", title: it.state }, "!");
  if (it.state === "sending" || it.state === "queued") return h("span", { class: "ticks wait", title: it.state }, "◷");
  if (it.state === "sent") return h("span", { class: "ticks", title: "reached the computer" }, "✓");
  return answered(it)
    ? h("span", { class: "ticks read", title: "answered" }, "✓✓")
    : h("span", { class: "ticks", title: "in the session's inbox" }, "✓✓");
}

// outNote is the line under one of your messages, when it needs one: why it
// failed, that it's waiting for the computer, or how many wait in the queue
// (on the last of them).
function outNote(it, waiting) {
  if (failed(it)) {
    const what = { refused: "refused", failed: "failed", stale: "not delivered" }[it.state];
    return { text: it.reason ? `${what} · ${it.reason}` : what };
  }
  if (it.state === "queued") return { text: "waiting for the computer to be reachable" };
  if (it.state === "resent") return { text: "sent again below" };
  if (waiting.length && it === waiting[waiting.length - 1]) {
    return { queued: true, text: waiting.length > 1 ? `${waiting.length} waiting in the session's inbox` : "waiting in the session's inbox" };
  }
  return {};
}

// chatHeader is a chat's bar: back, the session, where it runs, and the
// search button, with the search row under it while it's open.
function chatHeader(p, task, session, hits, current) {
  const offline = macOffline(p);
  const header = bar(task, {
    back: goBack, action: chatSearchButton(),
    backCount: itemsCache.filter((it) => it.dir === "in" && !it.read && !(it.mac === p.mac_id && it.task === task)).length,
    sub: h("span", { class: offline ? "status warn" : session ? "status ok" : "status" },
      [macLabel(p), offline ? "offline" : session ? "live" : "not running", session?.project].filter(Boolean).join(" · ")),
  });
  if (state.tsearch) header.append(chatSearchRow(hits.length, hits.indexOf(current)));
  return header;
}

// chatComposer is one rounded panel with the send button inside it, like
// Messages: the round up-arrow appears only once there's something to send,
// the field grows with the text up to a few lines, and a reply's quote sits
// at the top of the same panel.
function chatComposer(p, task, session, canSend) {
  if (!canSend) {
    return h("p", { class: "muted pad" }, session
      ? "Read only: this computer's flow-remote is too old to take messages for it."
      : "This session isn't running on the computer.");
  }
  const input = h("textarea", { rows: "1", placeholder: macOffline(p) ? "The computer is offline; this waits until it's back" : "Message", maxlength: "4000", "aria-label": "Message", enterkeyhint: "enter" });
  const sendBtn = h("button", { class: "send", type: "submit", "aria-label": "Send", hidden: true },
    svgIcon("M12 19V5M5 12l7-7 7 7"));
  const grow = () => {
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 132)}px`;
    sendBtn.hidden = input.value.trim() === "";
  };
  input.addEventListener("input", grow);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && env.kind === "desktop") {
      e.preventDefault();
      input.form?.requestSubmit();
    }
  });
  requestAnimationFrame(grow); // a restored draft needs sizing too
  const onsubmit = async (ev) => {
    ev.preventDefault();
    const body = input.value.trim();
    if (!body) return;
    input.value = "";
    grow();
    input.focus(); // keep the keyboard up, as Messages does
    // Take the reply target before sending: a second message sent while
    // the first is still going out must not answer the same message.
    const replyTo = state.replyTo?.id;
    state.replyTo = null;
    await send(p, task, body, replyTo);
  };
  return h("form", { class: "composer", onsubmit },
    h("div", { class: "field" },
      state.replyTo ? h("div", { class: "replying" },
        h("div", {}, h("b", {}, macLabel(p)), h("span", {}, state.replyTo.body)),
        h("button", { type: "button", "aria-label": "Don't reply to this message", onclick: () => go("thread", { replyTo: null }) }, "✕")) : null,
      h("div", { class: "pill" }, input, sendBtn)));
}
// showMessage scrolls a thread to one message and lights it up briefly.
function showMessage(id) {
  const el = root.querySelector(`[data-id="${CSS.escape(id)}"]`);
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.classList.remove("flash");
  void el.offsetWidth; // restart the animation
  el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1200);
}

// chatSearchButton opens and closes the search row in a chat's header.
function chatSearchButton() {
  return h("button", {
    class: `icon-btn${state.tsearch ? " on" : ""}`, "aria-label": "Search this chat",
    onclick: () => {
      state.tsearch = !state.tsearch;
      state.tquery = "";
      render();
      if (state.tsearch) root.querySelector("input.tsearch")?.focus();
    },
  }, svgIcon("M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-4.35-4.35"));
}

// The search row under a chat's header: the field, "2 of 5", older and
// newer, and close. The newest match is the first one shown.
function chatSearchRow(count, at) {
  const jump = (step) => {
    if (!count) return;
    state.thit = (at + step + count) % count;
    render();
    scrollToHit();
  };
  const close = () => { state.tsearch = false; state.tquery = ""; render(); };
  const field = h("input", {
    class: "tsearch", type: "search", placeholder: "Search this chat", value: state.tquery,
    autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "Search this chat",
    enterkeyhint: "search",
  });
  field.addEventListener("input", () => {
    state.tquery = field.value;
    state.thit = Number.MAX_SAFE_INTEGER; // the newest match
    render();
    scrollToHit();
  });
  field.addEventListener("keydown", (e) => {
    if (e.key === "Escape") close();
    if (e.key === "Enter") { e.preventDefault(); jump(e.shiftKey ? 1 : -1); }
  });
  return h("div", { class: "chatsearch" },
    field,
    h("span", { class: "count" }, state.tquery.trim() ? (count ? `${at + 1} of ${count}` : "No matches") : ""),
    h("button", { class: "icon-btn", "aria-label": "Older match", disabled: count < 2 ? true : null, onclick: () => jump(-1) }, svgIcon("M6 15l6-6 6 6")),
    h("button", { class: "icon-btn", "aria-label": "Newer match", disabled: count < 2 ? true : null, onclick: () => jump(1) }, svgIcon("M6 9l6 6 6-6")),
    h("button", { class: "clear", type: "button", "aria-label": "Close search", onclick: close }, "✕"));
}

// scrollToHit brings the current search match into view.
function scrollToHit() {
  const el = root.querySelector(".msg.found");
  if (el) el.scrollIntoView({ block: "center" });
}

function envLabel() {
  const where = { ios: "iPhone or iPad", android: "Android", desktop: "computer" }[env.os];
  const how = { "phone-app": "installed app", "phone-browser": "browser tab", desktop: "browser" }[env.kind];
  return `${where}, ${how}`;
}

function settingsScreen() {
  return h("main", {},
    bar("Settings", { back: goBack }),
    state.pairings.map((p) => h("section", { class: "card" },
      h("h2", {}, macLabel(p), p.mac_id === state.active ? h("span", { class: "chip live" }, "showing") : null),
      h("p", {}, "Computer id: ", h("code", {}, p.mac_id)),
      h("p", {}, "This phone, for this computer: ", h("code", {}, p.device_id)),
      h("p", {}, "Fingerprint: ", h("code", { class: "fp" }, p.device_fp)),
      updateNote(p),
      h("button", { class: "danger", onclick: () => unpair(p) }, "Unpair from this computer"),
      h("p", { class: "muted" }, "Unpairing deletes this phone's key for that computer and keeps its messages. Also run ",
        h("code", {}, `flow-remote revoke ${p.device_id}`), " on it."))),
    h("div", { class: "pad stack" },
      h("button", { class: "primary", onclick: () => go("welcome") }, "Pair another computer"),
      h("button", { class: "link", onclick: forgetEverything }, "Delete everything on this phone"),
      storageLine()),
    aboutSection());
}

// updateNote tells you to upgrade flow-remote on a computer that has a
// newer release waiting. The phone's app follows on its own afterwards.
function updateNote(p) {
  const update = state.updates[p.mac_id];
  if (!update) return null;
  return h("div", { class: "update-note" },
    h("p", {}, h("b", {}, `flow-remote ${update} is out.`), " On this computer, run:"),
    cmd("flow-remote upgrade"));
}

const kb = (n) => (n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

// storageLine says how much this app keeps on the phone: its cached files
// and its messages (the rest of what the browser counts is keys and
// bookkeeping). It fills in once measured.
function storageLine() {
  const el = h("p", { class: "muted storage" }, "Measuring storage…");
  (async () => {
    let cached = 0;
    for (const name of await caches.keys()) {
      const cache = await caches.open(name);
      for (const req of await cache.keys()) {
        const res = await cache.match(req);
        if (res) cached += (await res.clone().blob()).size;
      }
    }
    const used = (await navigator.storage?.estimate?.())?.usage;
    const n = itemsCache.length;
    el.textContent = `${used ? `This app uses ${kb(used)} on this phone: ` : "On this phone: "}` +
      `the app ${kb(cached)}, and ${n} message${n === 1 ? "" : "s"}.`;
  })().catch(() => { el.textContent = ""; });
  return el;
}

const REPO = "https://github.com/pa/flow-remote";

// A link that leaves the app, without telling the other site where from.
const outLink = (href, text) => h("a", { href, target: "_blank", rel: "noopener noreferrer" }, text);

function aboutSection() {
  return h("section", { class: "about" },
    brandMark(),
    h("h2", {}, "flow-remote"),
    h("p", { class: "muted" }, `Build ${BUILD} · running on `, envLabel()),
    h("p", { class: "muted" }, "Message your ", outLink("https://github.com/Facets-cloud/flow", "flow"), " sessions from your phone. End-to-end encrypted, MIT licensed."),
    h("div", { class: "about-links" },
      outLink(REPO, "Source on GitHub"),
      outLink(REPO, "★ Star it on GitHub"),
      outLink(`${REPO}/issues/new`, "Report a problem")));
}

// unpair forgets this phone's key for a Mac but keeps its threads, so
// pairing with that Mac again brings the history back.
async function unpair(p) {
  state.pairings = state.pairings.filter((x) => x !== p);
  delete state.sessions[p.mac_id];
  delete state.updates[p.mac_id];
  if (state.active === p.mac_id) state.active = state.pairings[0]?.mac_id || null;
  await savePairings();
  if (state.pairings.length === 0) {
    stopPolling();
    go("welcome");
    return;
  }
  go("sessions");
}

// forgetEverything wipes all keys and history from this phone.
async function forgetEverything() {
  if (!confirm("Delete every pairing and all message history from this phone?")) return;
  stopPolling();
  await db.forget();
  Object.assign(state, { pairings: [], active: null, sessions: {}, macSeen: {}, unreachable: {}, updates: {} });
  itemsCache = [];
  go("welcome");
}

// ---- messaging ----

function sealToMac(p, msg) {
  return seal(JSON.stringify(msg), p.keys.sign.privateKey, { from: p.device_id, to: p.mac_id }, p.mac_box_pub);
}

async function send(p, task, body, replyTo) {
  const clientId = b64u(crypto.getRandomValues(new Uint8Array(9)));
  const item = { id: `c:${clientId}`, mac: p.mac_id, task, dir: "out", body, ts: Date.now(), state: "sending", reply_to: replyTo || null };
  await db.putItem(item);
  itemsCache = await db.allItems();
  render({ stickToBottom: true });
  await post(p, item);
}

// A message waits on the phone this long for an unreachable Mac, then
// needs "Send again": the same rule the Mac applies to one that waited in
// a mailbox, so an old "yes, go ahead" isn't delivered by surprise.
const QUEUE_MS = 10 * 60_000;

// post seals and sends one outgoing item. If the Mac can't be reached (it's
// asleep, or the phone is offline) the item stays queued and goes out on
// the next successful poll.
async function post(p, item) {
  const clientId = item.id.slice(2);
  try {
    await api.postEnvelope(api.signerFor(p), await sealToMac(p, { kind: "send", client_id: clientId, task: item.task, body: item.body, reply_to: item.reply_to || undefined }));
    item.state = "sent";
    delete item.reason;
  } catch (e) {
    if (api.offline(e)) {
      item.state = "queued";
    } else {
      item.state = "failed";
      item.reason = e.message;
    }
  }
  await db.putItem(item);
  itemsCache = await db.allItems();
  render();
}

// flushQueued sends what waited for p's Mac, once it answers again.
async function flushQueued(p) {
  for (const it of itemsCache.filter((x) => x.mac === p.mac_id && x.state === "queued")) {
    if (Date.now() - it.ts > QUEUE_MS) {
      it.state = "stale";
      it.reason = "it waited too long for the computer";
      await db.putItem(it);
      continue;
    }
    await post(p, it);
  }
}

async function sendSync(p) {
  if (!p?.confirmed) return;
  try {
    await api.postEnvelope(api.signerFor(p), await sealToMac(p, { kind: "sync" }));
  } catch {
    // Unreachable now: the next poll and the relay's own updates catch up.
  }
}

// handle verifies and applies one envelope from p's Mac. It returns
// normally for junk too, so junk gets acked and doesn't come back.
async function handle(p, e) {
  const m = await openFromMac(p, e);
  if (m && Object.hasOwn(onMessage, m.kind)) await onMessage[m.kind](p, m);
}

// openFromMac returns what's inside e, or null unless e is addressed from
// p's Mac to this phone, carries the Mac's signature, is seen for the
// first time, and decrypts. Verifying comes before anything else looks
// at the envelope.
async function openFromMac(p, e) {
  if (e.from !== p.mac_id || e.to !== p.device_id) return null;
  try {
    await verify(e, p.mac_sign_pub);
  } catch {
    return null;
  }
  if (!(await db.firstSighting(e.id))) return null;
  try {
    return JSON.parse(await open(e, p.keys.box));
  } catch {
    return null;
  }
}

// onMessage applies each kind of message from the Mac.
const onMessage = {
  // The Mac enrolled this phone.
  async paired(p, m) {
    p.confirmed = true;
    p.mac_name = m.mac_name;
    await savePairings();
    sendSync(p);
    render();
  },
  // The sessions running there now, and a newer flow-remote release if
  // the computer's last check found one.
  async sessions(p, m) {
    state.sessions[p.mac_id] = m.sessions || [];
    state.updates[p.mac_id] = m.update || "";
    await db.set(`sessions:${p.mac_id}`, state.sessions[p.mac_id]);
    await db.set(`update:${p.mac_id}`, state.updates[p.mac_id]);
  },
  // How far one of your messages got. A delivered reply marks the message
  // it answers as replied.
  async status(p, m) {
    const it = await db.getItem(`c:${m.client_id}`);
    if (!it) return;
    it.state = m.state;
    it.reason = m.reason || "";
    it.flow_id = m.flow_id || "";
    await db.putItem(it);
    if (m.state !== "delivered" || !it.reply_to) return;
    const answered = await db.getItem(`m:${p.mac_id}:${it.reply_to}`);
    if (answered) {
      answered.replied = true;
      await db.putItem(answered);
    }
  },
  // A message from a session.
  async mail(p, m) {
    const mail = m.mail;
    // flow message ids are only unique per Mac, so scope by Mac.
    const id = `m:${p.mac_id}:${mail.flow_id}`;
    if (await db.getItem(id)) return;
    const inThread = state.view === "thread" && state.active === p.mac_id && state.task === mail.task;
    await db.putItem({
      id, mac: p.mac_id, task: mail.task, dir: "in", body: mail.body, ts: mail.created_at, flow_id: mail.flow_id,
      urgent: Boolean(mail.urgent), broadcast: Boolean(mail.broadcast), reply_to: mail.reply_to || null,
      read: inThread, replied: false,
    });
    // Outside the open thread, say it arrived.
    if (!inThread && !mail.broadcast && Date.now() - mail.created_at < 10 * 60_000) {
      showToast({ mac: p.mac_id, task: mail.task, body: mail.body });
    }
  },
};

let polling = false;
let pollTimer = null;

// pollPairing fetches, applies and acks p's new mail, and on status
// rounds asks when the Mac was last seen. It returns whether the screen
// needs redrawing.
async function pollPairing(p, withStatus) {
  try {
    const got = await takeMail(p);
    if (withStatus && p.confirmed) await checkMacSeen(p);
    p.rejected = false;
    const back = Boolean(state.unreachable[p.mac_id]);
    state.unreachable[p.mac_id] = false;
    // The Mac serves the app too, so a build published while it was
    // unreachable can only be fetched now.
    if (back) checkForUpdate();
    if (p.confirmed) await flushQueued(p);
    return got || back; // redraw when it comes back, too
  } catch (e) {
    return pollFailed(p, e);
  }
}

// takeMail applies each envelope waiting for this phone, then acks them
// all, junk included, so none comes back. It says whether there were any.
async function takeMail(p) {
  const signer = api.signerFor(p);
  const res = await api.listEnvelopes(signer);
  const ids = [];
  for (const rec of res.envelopes || []) {
    await handle(p, rec.env);
    ids.push(rec.env.id);
  }
  if (ids.length) await api.ack(signer, ids);
  return ids.length > 0;
}

// checkMacSeen records when p's Mac last checked its mailbox.
async function checkMacSeen(p) {
  const st = await api.status(api.signerFor(p));
  const seen = st.macs?.[p.mac_id]?.last_seen;
  state.macSeen[p.mac_id] = seen ? new Date(seen) : null;
}

// pollFailed notes why a poll of p failed, and returns whether that
// changes what the screen says.
function pollFailed(p, e) {
  if (!p.confirmed) return false;
  // Before the Mac confirms pairing, the mailbox doesn't know this device
  // yet, so 401 is expected. After that it means revoked.
  if (e.status === 401) p.rejected = true;
  // A Mac that serves the phone itself can't be reached while it's
  // asleep: show it offline straight away.
  if (!api.offline(e)) return false;
  // Why, as best the phone can tell: see unreachableLine.
  const why = navigator.onLine === false ? "phone-offline" : api.netKind(e);
  if (state.unreachable[p.mac_id] === why) return false;
  state.unreachable[p.mac_id] = why;
  return true; // redraw now, not on the next status check
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
  try {
    offer = parseOffer(location.hash);
  } catch {
    // Not a pairing link (or a broken one): open the app as usual.
  }
  if (location.hash) history.replaceState(null, "", location.pathname);
  if (!offer) return;
  if (state.pairings.some((p) => p.mac_id === offer.mac_id && !p.rejected)) {
    go(state.view, { error: "This phone is already paired with that computer." });
    return;
  }
  go("welcome", { offer });
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) stopPolling();
  else startPolling();
});

// When the phone's own connection comes or goes, look again straight away
// rather than on the next poll.
window.addEventListener("online", () => { stopPolling(); startPolling(); });
window.addEventListener("offline", () => {
  for (const p of state.pairings) if (p.confirmed) state.unreachable[p.mac_id] = "phone-offline";
  backgroundRender();
});

// ---- updates ----

// An installed app keeps running the code it loaded, possibly for days, so
// check for a new version each time it comes to the front, and reload onto
// it as soon as it takes over. Not while typing: that would lose a draft.
let checkForUpdate = () => {};

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  const hadController = Boolean(navigator.serviceWorker.controller);
  // If the app opened while the Mac was unreachable, registering fails
  // too; checkForUpdate tries again, and runs whenever the Mac is back.
  const register = () => navigator.serviceWorker.register("./sw.js").then((reg) => {
    checkForUpdate = () => reg.update().catch(() => {});
  }).catch(() => {});
  checkForUpdate = register;
  register();
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) checkForUpdate();
  });
  // An app left open on screen never comes "to the front" again, so also
  // look every few minutes. It's one small request for sw.js.
  setInterval(() => { if (!document.hidden) checkForUpdate(); }, 5 * 60_000);
  let reloading = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (!hadController || reloading) return; // first install: nothing to replace
    const reload = () => { reloading = true; location.reload(); };
    if (typing) document.addEventListener("focusout", reload, { once: true });
    else reload();
  });
}

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
  for (const p of pairings) {
    state.sessions[p.mac_id] = (await db.get(`sessions:${p.mac_id}`)) || [];
    state.updates[p.mac_id] = (await db.get(`update:${p.mac_id}`)) || "";
  }
  itemsCache = await db.allItems();
}

async function boot() {
  registerServiceWorker();
  // Ask the browser to keep the app's storage (keys and history) when the
  // device runs low on space. iOS keeps an installed app's storage anyway.
  navigator.storage?.persist?.().catch(() => {});
  const offer = (() => {
    try { return parseOffer(location.hash); } catch { return null; }
  })();
  // The fragment holds the one-time secret; don't leave it in history.
  if (location.hash) history.replaceState(null, "", location.pathname);

  await loadState();
  if (offer && !state.pairings.some((p) => p.mac_id === offer.mac_id && !p.rejected)) state.offer = offer;
  if (!current()) state.view = "welcome";
  else if (!state.offer) restoreView();
  db.pruneSeen(Date.now() - SEEN_TTL).catch(() => {});
  render();
  startPolling();
  for (const p of state.pairings) sendSync(p);
}

boot();
