// Fuzzy matching in the spirit of fzf: the query's characters must appear
// in order, not necessarily adjacent. Matches score higher when characters
// are consecutive or start a word, and lower when they're spread out.
// Spaces in the query split it into terms that must all match, anywhere.

const WORD_START = /[\s\-_/.:#]/;

// A term of n letters must fit within this many characters of the text.
const maxSpan = (n) => n * 3 + 2;

// match returns {score, positions} for one term against text, or null.
// It tries every starting point and keeps the best, which matters for
// strings like "fragile-flow-remote" where the first "f" isn't the best.
function matchTerm(term, text) {
  const t = text.toLowerCase();
  const q = term.toLowerCase();
  if (!q) return { score: 0, positions: [] };
  let best = null;
  for (let start = t.indexOf(q[0]); start !== -1; start = t.indexOf(q[0], start + 1)) {
    const positions = [];
    let ti = start;
    for (const ch of q) {
      ti = t.indexOf(ch, ti);
      if (ti === -1) break;
      positions.push(ti++);
    }
    if (positions.length !== q.length) break; // later starts can't do better
    // Letters scattered across a long sentence aren't a match anyone meant.
    if (positions[positions.length - 1] - positions[0] + 1 > maxSpan(q.length)) continue;
    const score = scorePositions(positions, t);
    if (!best || score > best.score) best = { score, positions };
  }
  return best;
}

function scorePositions(pos, t) {
  let score = 0;
  for (let i = 0; i < pos.length; i++) {
    const p = pos[i];
    score += 1;
    if (p === 0 || WORD_START.test(t[p - 1])) score += 3; // start of a word
    if (i > 0 && pos[i - 1] === p - 1) score += 4; // consecutive
    if (i > 0) score -= Math.min(3, p - pos[i - 1] - 1) * 0.2; // gap
  }
  score -= pos[0] * 0.05; // earlier is slightly better
  return score;
}

// fuzzyMatch matches a whole query (space-separated terms) against text.
export function fuzzyMatch(query, text) {
  const terms = query.trim().split(/\s+/).filter(Boolean);
  if (terms.length === 0 || !text) return null;
  let score = 0;
  const positions = new Set();
  for (const term of terms) {
    const m = matchTerm(term, text);
    if (!m) return null;
    score += m.score;
    m.positions.forEach((p) => positions.add(p));
  }
  return { score, positions: [...positions].sort((a, b) => a - b) };
}

// search ranks items by their best-matching field. fields maps a field name
// to a weight; the slug of a session should outrank a word in its notes.
export function search(query, items, fields) {
  const out = [];
  for (const item of items) {
    let best = null;
    for (const [field, weight] of Object.entries(fields)) {
      const value = item[field];
      const text = Array.isArray(value) ? value.join(" ") : value;
      const m = typeof text === "string" ? fuzzyMatch(query, text) : null;
      if (m && (!best || m.score * weight > best.score)) best = { item, field, score: m.score * weight, positions: m.positions };
    }
    if (best) out.push(best);
  }
  return out.sort((a, b) => b.score - a.score);
}
