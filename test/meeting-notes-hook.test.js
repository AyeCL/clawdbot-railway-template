import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("server exposes authenticated async meeting notes hook", () => {
  const src = fs.readFileSync(new URL("../src/server.js", import.meta.url), "utf8");

  assert.match(src, /app\.post\("\/youanai\/meeting-notes"/);
  assert.match(src, /OPENCLAW_MEETING_NOTES_WEBHOOK_SECRET/);
  assert.match(src, /"--deliver"/);
  assert.match(src, /"--reply-channel"/);
  assert.match(src, /"--reply-to"/);
  assert.match(src, /"wx"/);
});
