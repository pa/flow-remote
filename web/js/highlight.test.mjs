import { test } from "node:test";
import assert from "node:assert/strict";
import { segments, matches } from "./highlight.js";

test("marks every match, whatever the case", () => {
  assert.deepEqual(segments("Build ok, rebuild later", "build"), [
    { text: "Build", hit: true },
    { text: " ok, re", hit: false },
    { text: "build", hit: true },
    { text: " later", hit: false },
  ]);
});

test("an empty query marks nothing", () => {
  assert.deepEqual(segments("hello", "  "), [{ text: "hello", hit: false }]);
});

test("a match at either end leaves no empty runs", () => {
  assert.deepEqual(segments("okok", "ok"), [{ text: "ok", hit: true }, { text: "ok", hit: true }]);
});

test("finds the messages that contain the query, in order", () => {
  const items = [{ body: "Check the build" }, { body: "Stats?" }, { body: "build is green" }, {}];
  assert.deepEqual(matches(items, "BUILD").map((it) => it.body), ["Check the build", "build is green"]);
  assert.deepEqual(matches(items, ""), []);
});
