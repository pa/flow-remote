// IndexedDB storage. CryptoKeys are stored as-is: structured clone keeps
// them non-extractable, so the private halves never exist as bytes.

const NAME = "flow-remote";
const VERSION = 1;

let dbp;

function open() {
  dbp ??= new Promise((resolve, reject) => {
    const req = indexedDB.open(NAME, VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore("kv");
      const items = db.createObjectStore("items", { keyPath: "id" });
      items.createIndex("task", "task");
      db.createObjectStore("seen");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbp;
}

async function tx(store, mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const s = t.objectStore(store);
    let out;
    Promise.resolve(fn(s)).then((v) => { out = v; });
    t.oncomplete = () => resolve(out);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

const req = (r) => new Promise((resolve, reject) => {
  r.onsuccess = () => resolve(r.result);
  r.onerror = () => reject(r.error);
});

export const get = (key) => tx("kv", "readonly", (s) => req(s.get(key)));
export const set = (key, value) => tx("kv", "readwrite", (s) => { s.put(value, key); });
export const del = (key) => tx("kv", "readwrite", (s) => { s.delete(key); });

// Thread items: messages we sent and mail sessions sent us.
export const putItem = (item) => tx("items", "readwrite", (s) => { s.put(item); });
export const getItem = (id) => tx("items", "readonly", (s) => req(s.get(id)));
export const allItems = () => tx("items", "readonly", (s) => req(s.getAll()));
export const itemsFor = (task) =>
  tx("items", "readonly", (s) => req(s.index("task").getAll(task)))
    .then((items) => items.sort((a, b) => a.ts - b.ts));

// seen remembers envelope ids so a replayed one is dropped.
// Callback style on purpose: the put must be queued inside the get's
// success handler, or the transaction may commit in between.
export async function firstSighting(id, now = Date.now()) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction("seen", "readwrite");
    const s = t.objectStore("seen");
    let first = false;
    const g = s.get(id);
    g.onsuccess = () => {
      if (g.result === undefined) {
        first = true;
        s.put(now, id);
      }
    };
    t.oncomplete = () => resolve(first);
    t.onerror = () => reject(t.error);
  });
}

export async function pruneSeen(olderThan) {
  return tx("seen", "readwrite", (s) => {
    const c = s.openCursor();
    c.onsuccess = () => {
      const cur = c.result;
      if (!cur) return;
      if (cur.value < olderThan) cur.delete();
      cur.continue();
    };
  });
}

// forget wipes everything, for "unpair this phone".
export async function forget() {
  const db = await open();
  db.close();
  dbp = undefined;
  await req(indexedDB.deleteDatabase(NAME));
}
