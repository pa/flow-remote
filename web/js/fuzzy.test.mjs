// node --test web/js/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { fuzzyMatch, search } from "./fuzzy.js";

test("characters in order, gaps allowed", () => {
  assert.ok(fuzzyMatch("feol", "fragile-eol-packages"));
  assert.equal(fuzzyMatch("pef", "fragile-eol-packages"), null);
});

test("case-insensitive, and every term must match", () => {
  assert.ok(fuzzyMatch("EOL fragile", "fragile-eol-packages"));
  assert.equal(fuzzyMatch("eol globex", "fragile-eol-packages"), null);
});

test("word starts and consecutive runs rank higher", () => {
  const slugs = ["flow-remote", "fragile-flow-migration", "floci-local-apply"].map((slug) => ({ slug }));
  assert.equal(search("flre", slugs, { slug: 1 })[0].item.slug, "flow-remote");
  assert.equal(search("floci", slugs, { slug: 1 })[0].item.slug, "floci-local-apply");
});

test("the best start wins, not the first", () => {
  // The first "r" is in "fragile"; the best "re" is in "remote".
  const m = fuzzyMatch("remote", "fragile-flow-remote");
  assert.deepEqual(m.positions, [13, 14, 15, 16, 17, 18]);
});

test("weights make a slug hit beat a notes hit", () => {
  const items = [
    { slug: "phone-dispatch", name: "answers messages" },
    { slug: "globex-governance", name: "waiting on the phone team" },
  ];
  const r = search("phone", items, { slug: 3, name: 1 });
  assert.equal(r[0].item.slug, "phone-dispatch");
  assert.equal(r.length, 2);
});

test("empty query matches nothing", () => {
  assert.equal(fuzzyMatch("   ", "anything"), null);
});

test("letters scattered across a sentence don't match", () => {
  assert.equal(fuzzyMatch("eol", "waiting on Intepark approval on the Harborknot self-host proposal"), null);
  assert.ok(fuzzyMatch("eol", "EOL components"));
  assert.equal(fuzzyMatch("fep", "fragile-eol-packages"), null); // f…e…p spans 13 > 11
  assert.ok(fuzzyMatch("fra eol", "fragile-eol-packages"));
});
