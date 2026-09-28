// Sign-in. On GCP this is Google through Identity Platform; locally,
// config.devEmail skips it and the mailbox (with MAILBOX_DEV_AUTH=1)
// trusts "Bearer dev:<email>".
import config from "../config.js";

let auth;
let fb;

async function firebase() {
  if (!fb) {
    const app = await import("../vendor/firebase-12.19.0/firebase-app.js");
    const a = await import("../vendor/firebase-12.19.0/firebase-auth.js");
    auth = a.initializeAuth(app.initializeApp(config.firebase), {
      persistence: [a.indexedDBLocalPersistence, a.browserLocalPersistence],
      popupRedirectResolver: a.browserPopupRedirectResolver,
    });
    if (config.tenantId) auth.tenantId = config.tenantId;
    fb = a;
  }
  return fb;
}

export const isDev = () => Boolean(config.devEmail);

// user resolves to {email} or null once the sign-in state is known.
export async function user() {
  if (isDev()) return { email: config.devEmail };
  const a = await firebase();
  await a.getRedirectResult(auth).catch(() => {});
  await auth.authStateReady();
  return auth.currentUser ? { email: auth.currentUser.email } : null;
}

// signIn uses a redirect, which works in an installed iOS web app where
// popups don't.
export async function signIn() {
  const a = await firebase();
  const p = new a.GoogleAuthProvider();
  p.setCustomParameters({ prompt: "select_account" });
  await a.signInWithRedirect(auth, p);
}

export async function signOut() {
  if (isDev()) return;
  const a = await firebase();
  await a.signOut(auth);
}

export async function bearer() {
  if (isDev()) return `dev:${config.devEmail}`;
  await firebase();
  if (!auth.currentUser) throw new Error("signed out");
  return auth.currentUser.getIdToken();
}
