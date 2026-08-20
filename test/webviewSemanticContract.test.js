// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const { assertWebviewDocument } = require("./helpers/webviewSemanticContract");

const VALID = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-good'; base-uri 'none'; form-action 'none';"><title>Fixture</title><style>button:focus-visible{outline:1px solid}</style></head><body><main><h1>Fixture</h1><table><caption>Values</caption><thead><tr><th scope="col">Value</th></tr></thead></table><button type="button">Retry</button></main><script nonce="good">void 0;</script></body></html>`;

suite("WebView semantic contract", () => {
  test("accepts one complete synthetic document", () => {
    assert.doesNotThrow(() => assertWebviewDocument(VALID, { interactive: true, scripted: true, tables: true }));
  });

  test("fails independently for missing document, CSP, table, focus, and nonce semantics", () => {
    const cases = [
      VALID.replace(' lang="en"', ""),
      VALID.replace("base-uri 'none'; ", ""),
      VALID.replace("<main>", "<div>").replace("</main>", "</div>"),
      VALID.replace("<title>Fixture</title>", ""),
      VALID.replace(' scope="col"', ""),
      VALID.replace('nonce="good"', 'nonce="wrong"'),
      VALID.replace(":focus-visible", ":hover"),
    ];
    for (const invalid of cases) {
      assert.throws(() => assertWebviewDocument(invalid, { interactive: true, scripted: true, tables: true }));
    }
  });
});
