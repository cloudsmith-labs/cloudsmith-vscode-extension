const assert = require("assert");
const {
  buildExactPackageQuery,
  packageMatchesExactIdentity,
} = require("../util/packageQuery");

suite("Cloudsmith exact package query", () => {
  test("escapes query operators, quotes, and backslashes without widening identity", () => {
    const query = buildExactPackageQuery(
      'widget" OR status:quarantined',
      "1.0\\beta && *",
      "npm"
    );

    assert.strictEqual(
      query,
      'name:"widget\\" OR status\\:quarantined" AND version:"1.0\\\\beta \\&\\& \\*" AND format:"npm"'
    );
    assert.strictEqual(
      packageMatchesExactIdentity(
        { name: 'widget" OR status:quarantined', version: "1.0\\beta && *", format: "npm" },
        { name: 'widget" OR status:quarantined', version: "1.0\\beta && *", format: "npm" }
      ),
      true
    );
    assert.strictEqual(
      packageMatchesExactIdentity(
        { name: "unrelated", version: "1.0\\beta && *", format: "npm" },
        { name: 'widget" OR status:quarantined', version: "1.0\\beta && *", format: "npm" }
      ),
      false
    );
  });

  test("rejects controls and incomplete identities", () => {
    for (const value of ["", "bad\nvalue", "bad\u0000value"]) {
      assert.throws(() => buildExactPackageQuery(value, "1.0.0", "npm"), /invalid/i);
    }
    assert.throws(() => buildExactPackageQuery("widget", {}, "npm"), /invalid/i);
  });
});
