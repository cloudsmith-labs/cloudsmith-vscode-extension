// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");

function count(source, expression) {
  return (source.match(expression) || []).length;
}

function assertWebviewDocument(html, options = {}) {
  const { interactive = false, scripted = false, tables = false } = options;
  assert.strictEqual(typeof html, "string");
  assert.match(html, /<!DOCTYPE html>/i);
  assert.match(html, /<html\s+lang="en">/i);
  assert.match(html, /<meta\s+charset="UTF-8"\s*\/?>/i);
  assert.match(html, /<meta\s+name="viewport"\s+content="width=device-width,\s*initial-scale=1\.0"\s*\/?>/i);
  assert.match(html, /<title>[^<]+<\/title>/i);
  assert.strictEqual(count(html, /<main(?:\s|>)/gi), 1, "one main landmark is required");
  assert.strictEqual(count(html, /<h1(?:\s|>)/gi), 1, "one h1 is required");
  const csp = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i.exec(html)?.[1] || "";
  for (const directive of ["default-src 'none'", "base-uri 'none'", "form-action 'none'", "img-src 'none'"]) {
    assert.ok(csp.includes(directive), `CSP must contain ${directive}`);
  }
  if (scripted) {
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    assert.ok(nonce, "scripted documents require a CSP nonce");
    assert.match(html, new RegExp(`<script nonce="${nonce.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}">`));
  } else {
    assert.doesNotMatch(html, /<script\b/i);
  }
  if (interactive) {
    assert.match(html, /:focus-visible/);
    for (const button of html.match(/<button\b[^>]*>/gi) || []) {
      assert.match(button, /\btype="button"/i);
    }
  }
  if (tables) {
    const tableCount = count(html, /<table(?:\s|>)/gi);
    assert.ok(tableCount > 0, "expected at least one table");
    assert.strictEqual(count(html, /<caption(?:\s|>)/gi), tableCount, "every table requires a caption");
    for (const header of html.match(/<th\b[^>]*>/gi) || []) {
      assert.match(header, /\bscope="col"/i);
    }
  }
  assert.doesNotMatch(html, /<h[1-6][^>]+title="[^"]+"/i);
}

module.exports = { assertWebviewDocument };
