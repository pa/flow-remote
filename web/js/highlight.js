// Search within one chat: which messages match, and where in each.
// Matching is plain, case-insensitive substring search, which is what
// people expect from a chat's search box (the session list uses fuzzy
// matching instead).

// segments splits text into runs, marking the ones that match query.
// [{text: "the ", hit: false}, {text: "Build", hit: true}, ...]
export function segments(text, query) {
  const q = query.trim().toLowerCase();
  if (!q) return [{ text, hit: false }];
  const lower = text.toLowerCase();
  const out = [];
  let at = 0;
  for (let i = lower.indexOf(q); i !== -1; i = lower.indexOf(q, i + q.length)) {
    if (i > at) out.push({ text: text.slice(at, i), hit: false });
    out.push({ text: text.slice(i, i + q.length), hit: true });
    at = i + q.length;
  }
  if (at < text.length) out.push({ text: text.slice(at), hit: false });
  return out;
}

// matches returns the items whose body contains query, oldest first.
export function matches(items, query) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return items.filter((it) => (it.body || "").toLowerCase().includes(q));
}
