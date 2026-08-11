const assert = require("assert");
const {
  DEFAULT_WEBVIEW_STRING_LIMIT,
  parseWebviewMessage,
} = require("../util/webviewMessage");

suite("Webview Message Contract Test Suite", () => {
  const requiredStringContract = Object.freeze({
    openExternal: Object.freeze(["url"]),
  });

  test("uses the finite default when limits are omitted, empty, or partial", () => {
    const atDefault = "x".repeat(DEFAULT_WEBVIEW_STRING_LIMIT);
    const message = { command: "openExternal", url: atDefault };

    assert.deepStrictEqual(parseWebviewMessage(message, requiredStringContract), message);
    assert.deepStrictEqual(
      parseWebviewMessage(message, requiredStringContract, undefined),
      message
    );
    assert.deepStrictEqual(parseWebviewMessage(message, requiredStringContract, {}), message);
    assert.deepStrictEqual(
      parseWebviewMessage(message, requiredStringContract, { other: 1 }),
      message
    );
    assert.strictEqual(
      parseWebviewMessage(
        { command: "openExternal", url: `${atDefault}x` },
        requiredStringContract
      ),
      null
    );
  });

  test("respects exact explicit limits, including a trusted larger override", () => {
    assert.ok(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      { url: 1 }
    ));
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "xx" },
      requiredStringContract,
      { url: 1 }
    ), null);

    const explicitLimit = DEFAULT_WEBVIEW_STRING_LIMIT + 1;
    assert.ok(parseWebviewMessage(
      { command: "openExternal", url: "x".repeat(explicitLimit) },
      requiredStringContract,
      { url: explicitLimit }
    ));
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x".repeat(explicitLimit + 1) },
      requiredStringContract,
      { url: explicitLimit }
    ), null);
  });

  test("rejects every explicitly invalid selected-field limit", () => {
    const invalidLimits = [
      0,
      -1,
      NaN,
      Infinity,
      Number.MAX_SAFE_INTEGER + 1,
      "12",
      null,
      {},
      [],
      undefined,
    ];
    for (const invalidLimit of invalidLimits) {
      assert.strictEqual(
        parseWebviewMessage(
          { command: "openExternal", url: "x" },
          requiredStringContract,
          { url: invalidLimit }
        ),
        null,
        `expected ${String(invalidLimit)} to be rejected`
      );
    }
  });

  test("rejects malformed limits maps and ignores unrelated own keys without reading them", () => {
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      null
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      []
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      Object.create({ url: 1 })
    ), null);

    const nullPrototypeLimits = Object.assign(Object.create(null), { url: 1 });
    assert.ok(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      nullPrototypeLimits
    ));

    let reads = 0;
    const limits = { [Symbol("ignored")]: 0 };
    Object.defineProperty(limits, "ignored", {
      get() { reads += 1; return 0; },
    });
    assert.ok(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      limits
    ));
    assert.strictEqual(reads, 0);
  });

  test("rejects a selected limit accessor without invoking it", () => {
    let reads = 0;
    const limits = {};
    Object.defineProperty(limits, "url", {
      get() { reads += 1; return DEFAULT_WEBVIEW_STRING_LIMIT; },
    });
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      limits
    ), null);
    assert.strictEqual(reads, 0);
  });

  test("rejects empty, non-string, missing, oversized, and controlled required fields", () => {
    const invalidValues = [
      "",
      1,
      null,
      `safe\u0000unsafe`,
      `safe\u001funsafe`,
      `safe\u007funsafe`,
      `safe\u0080unsafe`,
      `safe\u009funsafe`,
    ];
    for (const value of invalidValues) {
      assert.strictEqual(
        parseWebviewMessage({ command: "openExternal", url: value }, requiredStringContract),
        null
      );
    }
    assert.strictEqual(
      parseWebviewMessage({ command: "openExternal" }, requiredStringContract),
      null
    );
  });

  test("enforces exact command boundaries and control-character rejection", () => {
    const commandAtLimit = "c".repeat(64);
    const contracts = { [commandAtLimit]: [] };
    assert.ok(parseWebviewMessage({ command: commandAtLimit }, contracts));
    assert.strictEqual(parseWebviewMessage(
      { command: "c".repeat(65) },
      { ["c".repeat(65)]: [] }
    ), null);
    for (const command of ["bad\u0000command", "bad\u007fcommand", "bad\u0080command"]) {
      assert.strictEqual(parseWebviewMessage({ command }, { [command]: [] }), null);
    }
  });

  test("accepts null-prototype messages and returns an immutable copy", () => {
    const message = Object.assign(Object.create(null), {
      command: "openExternal",
      url: "https://nvd.nist.gov/",
    });
    const parsed = parseWebviewMessage(message, requiredStringContract);
    assert.deepStrictEqual(parsed, {
      command: "openExternal",
      url: "https://nvd.nist.gov/",
    });
    assert.strictEqual(Object.isFrozen(parsed), true);
    assert.notStrictEqual(parsed, message);
  });

  test("rejects message accessors, inherited data, extra keys, and symbol keys", () => {
    let commandReads = 0;
    const commandAccessor = {};
    Object.defineProperty(commandAccessor, "command", {
      enumerable: true,
      get() { commandReads += 1; return "openExternal"; },
    });
    Object.defineProperty(commandAccessor, "url", { enumerable: true, value: "x" });

    let fieldReads = 0;
    const fieldAccessor = { command: "openExternal" };
    Object.defineProperty(fieldAccessor, "url", {
      enumerable: true,
      get() { fieldReads += 1; return "x"; },
    });

    assert.strictEqual(parseWebviewMessage(commandAccessor, requiredStringContract), null);
    assert.strictEqual(parseWebviewMessage(fieldAccessor, requiredStringContract), null);
    assert.strictEqual(commandReads, 0);
    assert.strictEqual(fieldReads, 0);
    assert.strictEqual(parseWebviewMessage(
      Object.create({ command: "openExternal", url: "x" }),
      requiredStringContract
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x", extra: true },
      requiredStringContract
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x", [Symbol("extra")]: true },
      requiredStringContract
    ), null);
  });

  test("fails closed for malformed contract tables without invoking accessors", () => {
    let contractReads = 0;
    const contractAccessor = {};
    Object.defineProperty(contractAccessor, "openExternal", {
      get() { contractReads += 1; return ["url"]; },
    });
    const inheritedContract = Object.create({ openExternal: ["url"] });

    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      contractAccessor
    ), null);
    assert.strictEqual(contractReads, 0);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      inheritedContract
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      null
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      { openExternal: ["url", "other"] }
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      { openExternal: ["command"] }
    ), null);
  });

  test("rejects contract holes and field accessors without invoking them", () => {
    const fieldsWithHole = new Array(1);
    let fieldReads = 0;
    const fieldsWithAccessor = [];
    Object.defineProperty(fieldsWithAccessor, "0", {
      configurable: true,
      get() { fieldReads += 1; return "url"; },
    });
    fieldsWithAccessor.length = 1;

    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      { openExternal: fieldsWithHole }
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      { openExternal: fieldsWithAccessor }
    ), null);
    assert.strictEqual(fieldReads, 0);
  });

  test("enforces field-name bounds, controls, and reserved-name rejection", () => {
    const fieldAtLimit = "f".repeat(64);
    assert.ok(parseWebviewMessage(
      { command: "bounded", [fieldAtLimit]: "x" },
      { bounded: [fieldAtLimit] }
    ));

    const invalidFields = [
      "f".repeat(65),
      "bad\u0000field",
      "bad\u007ffield",
      "bad\u0080field",
      "__proto__",
      "command",
      "constructor",
      "prototype",
    ];
    for (const field of invalidFields) {
      assert.strictEqual(parseWebviewMessage(
        { command: "bounded", [field]: "x" },
        { bounded: [field] }
      ), null);
    }
  });

  test("returns null when message, contract, or limit reflection throws", () => {
    const throwing = new Proxy({}, {
      getPrototypeOf() { throw new Error("blocked"); },
    });
    assert.strictEqual(parseWebviewMessage(throwing, requiredStringContract), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      throwing
    ), null);
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      throwing
    ), null);

    const ownKeysThrowingMessage = new Proxy({}, {
      ownKeys() { throw new Error("blocked"); },
    });
    assert.strictEqual(parseWebviewMessage(ownKeysThrowingMessage, requiredStringContract), null);

    const descriptorThrowingMessage = new Proxy({}, {
      ownKeys() { return ["command"]; },
      getOwnPropertyDescriptor() { throw new Error("blocked"); },
    });
    assert.strictEqual(parseWebviewMessage(descriptorThrowingMessage, requiredStringContract), null);

    const descriptorThrowingContract = new Proxy({}, {
      getOwnPropertyDescriptor() { throw new Error("blocked"); },
    });
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      descriptorThrowingContract
    ), null);

    const descriptorThrowingLimits = new Proxy({}, {
      getOwnPropertyDescriptor() { throw new Error("blocked"); },
    });
    assert.strictEqual(parseWebviewMessage(
      { command: "openExternal", url: "x" },
      requiredStringContract,
      descriptorThrowingLimits
    ), null);
  });
});
