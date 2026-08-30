// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const {
  PACKAGE_ACTION_CONTEXT_FAMILIES,
  PACKAGE_ACTION_SURFACES,
  PACKAGE_ACTIONS,
  derivePackageActionCapabilities,
  encodePackageActionContext,
  hasPackageAction,
} = require("../domain/packageActionCapabilities");

suite("Package action capabilities", () => {
  test("seven orthogonal evidence states grant and block every action by surface", () => {
    const rows = [
      ["vulnerable", { vulnerable: true }],
      ["quarantined", { quarantined: true }],
      ["vulnerable and quarantined", { vulnerable: true, quarantined: true }],
      ["vulnerable and policy-violating", { vulnerable: true, policyViolation: true }],
      ["vulnerable and restrictive", { vulnerable: true, restrictiveLicense: true }],
      ["quarantined and policy-violating", { quarantined: true, policyViolation: true }],
      ["clean", {}],
    ];
    const allActions = Object.values(PACKAGE_ACTIONS);

    for (const [name, evidence] of rows) {
      for (const surface of Object.values(PACKAGE_ACTION_SURFACES)) {
        const capabilities = derivePackageActionCapabilities({
          surface,
          found: true,
          exact: true,
          copyable: true,
          installGuidance: true,
          ...evidence,
        });
        const packageSurface = surface === PACKAGE_ACTION_SURFACES.PACKAGE;
        const vulnerable = evidence.vulnerable === true;
        const quarantined = evidence.quarantined === true;
        const expected = new Set([
          PACKAGE_ACTIONS.INSPECT,
          PACKAGE_ACTIONS.OPEN,
          ...(packageSurface || vulnerable
            ? [PACKAGE_ACTIONS.FIND_SAFE_VERSION, PACKAGE_ACTIONS.SHOW_VULNERABILITIES]
            : []),
          ...(quarantined ? [PACKAGE_ACTIONS.EXPLAIN_QUARANTINE] : []),
          ...(!quarantined ? [PACKAGE_ACTIONS.INSTALL] : []),
          ...(packageSurface && !quarantined ? [PACKAGE_ACTIONS.PROMOTE] : []),
          ...(packageSurface ? [PACKAGE_ACTIONS.SHOW_PROMOTION_STATUS] : []),
        ]);

        for (const action of allActions) {
          assert.strictEqual(
            hasPackageAction(capabilities, action),
            expected.has(action),
            `${name} on ${surface}: ${action}`
          );
        }
      }
    }
  });

  test("combined vulnerability and quarantine evidence retains safe actions and blocks install", () => {
    const capabilities = derivePackageActionCapabilities({
      surface: PACKAGE_ACTION_SURFACES.DEPENDENCY_HEALTH,
      found: true,
      exact: true,
      copyable: true,
      installGuidance: true,
      vulnerable: true,
      quarantined: true,
      policyViolation: true,
      restrictiveLicense: true,
    });

    for (const action of [
      PACKAGE_ACTIONS.INSPECT,
      PACKAGE_ACTIONS.OPEN,
      PACKAGE_ACTIONS.FIND_SAFE_VERSION,
      PACKAGE_ACTIONS.SHOW_VULNERABILITIES,
      PACKAGE_ACTIONS.EXPLAIN_QUARANTINE,
    ]) {
      assert.strictEqual(hasPackageAction(capabilities, action), true, action);
    }
    assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.INSTALL), false);
    assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.PROMOTE), false);
    assert.deepStrictEqual(capabilities.evidence, {
      copyable: true,
      exact: true,
      found: true,
      installGuidance: true,
      policyViolation: true,
      quarantined: true,
      restrictiveLicense: true,
      vulnerable: true,
    });
    assert.strictEqual(
      encodePackageActionContext(PACKAGE_ACTION_CONTEXT_FAMILIES.DEPENDENCY_HEALTH, capabilities),
      "dependencyHealthActions.inspect.open.findSafeVersion.showVulnerabilities.explainQuarantine"
    );
  });

  test("workspace and search package actions compose without mutually exclusive states", () => {
    const capabilities = derivePackageActionCapabilities({
      surface: PACKAGE_ACTION_SURFACES.PACKAGE,
      found: true,
      exact: true,
      copyable: true,
      installGuidance: true,
      vulnerable: true,
      quarantined: false,
    });
    for (const action of [
      PACKAGE_ACTIONS.INSPECT,
      PACKAGE_ACTIONS.OPEN,
      PACKAGE_ACTIONS.FIND_SAFE_VERSION,
      PACKAGE_ACTIONS.SHOW_VULNERABILITIES,
      PACKAGE_ACTIONS.INSTALL,
      PACKAGE_ACTIONS.PROMOTE,
      PACKAGE_ACTIONS.SHOW_PROMOTION_STATUS,
    ]) {
      assert.strictEqual(hasPackageAction(capabilities, action), true, action);
    }
    assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.EXPLAIN_QUARANTINE), false);
    const encoded = encodePackageActionContext(
      PACKAGE_ACTION_CONTEXT_FAMILIES.PACKAGE,
      capabilities
    );
    assert.strictEqual(
      encoded,
      "packageActions.inspect.open.findSafeVersion.showVulnerabilities.install.promote.showPromotionStatus"
    );
    assert.ok(encoded.length <= 256);
  });

  test("copyability cannot advertise Install without buildable guidance or disable independent promotion", () => {
    const capabilities = derivePackageActionCapabilities({
      surface: PACKAGE_ACTION_SURFACES.PACKAGE,
      found: true,
      exact: true,
      copyable: true,
      installGuidance: false,
      quarantined: false,
    });

    assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.INSTALL), false);
    assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.PROMOTE), true);
    assert.strictEqual(
      encodePackageActionContext(PACKAGE_ACTION_CONTEXT_FAMILIES.PACKAGE, capabilities),
      "packageActions.inspect.open.findSafeVersion.showVulnerabilities.promote.showPromotionStatus"
    );
  });

  test("missing and malformed evidence grants no action", () => {
    for (const input of [undefined, null, {}, {
      surface: PACKAGE_ACTION_SURFACES.PACKAGE,
      found: "true",
      exact: true,
      copyable: true,
    }]) {
      const capabilities = derivePackageActionCapabilities(input);
      assert.ok(Object.isFrozen(capabilities));
      assert.ok(Object.isFrozen(capabilities.actions));
      assert.strictEqual(
        Object.values(capabilities.actions).some(value => value === true),
        false
      );
    }
    assert.strictEqual(
      hasPackageAction({ actions: { install: "true" } }, PACKAGE_ACTIONS.INSTALL),
      false
    );
    assert.strictEqual(
      encodePackageActionContext("hostile", derivePackageActionCapabilities()),
      null
    );
  });

  test("invalid derivation returns the exact frozen deny-all action contract", () => {
    const expectedActions = Object.fromEntries(
      Object.values(PACKAGE_ACTIONS).map(action => [action, false])
    );

    for (const input of [undefined, null, {}, { surface: "unknown" }]) {
      const capabilities = derivePackageActionCapabilities(input);
      assert.deepStrictEqual(capabilities.actions, expectedActions);
      assert.strictEqual(Object.isFrozen(capabilities.actions), true);
    }
  });

  test("action lookup dispatches each known action independently", () => {
    const allActions = Object.values(PACKAGE_ACTIONS);

    for (const enabledAction of allActions) {
      const actions = Object.fromEntries(
        allActions.map(action => [action, action === enabledAction])
      );

      for (const requestedAction of allActions) {
        assert.strictEqual(
          hasPackageAction({ actions }, requestedAction),
          requestedAction === enabledAction,
          `${requestedAction} must not alias ${enabledAction}`
        );
      }
    }
  });

  test("unknown package actions are always denied without coercion", () => {
    const actions = Object.fromEntries(
      Object.values(PACKAGE_ACTIONS).map(action => [action, true])
    );
    const unknownActions = [
      undefined,
      null,
      "",
      "unknown",
      "__proto__",
      {},
      [],
      Symbol("unknown"),
    ];

    for (const action of unknownActions) {
      assert.doesNotThrow(() => hasPackageAction({ actions }, action));
      assert.strictEqual(hasPackageAction({ actions }, action), false);
    }
  });

  test("own data evidence on callable values remains supported", () => {
    const input = function packageEvidence() {};
    Object.assign(input, {
      surface: PACKAGE_ACTION_SURFACES.PACKAGE,
      found: true,
      exact: true,
      copyable: true,
      installGuidance: true,
    });

    const capabilities = derivePackageActionCapabilities(input);
    assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.INSPECT), true);
    assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.INSTALL), true);
  });

  test("hostile and inherited capability data cannot throw or grant actions", () => {
    const hostileInput = {};
    Object.defineProperty(hostileInput, "found", {
      get() { throw new Error("must not invoke evidence accessors"); },
    });
    const inherited = Object.create({
      surface: PACKAGE_ACTION_SURFACES.PACKAGE,
      found: true,
      exact: true,
      copyable: true,
    });
    const hostileProxy = new Proxy({}, {
      getOwnPropertyDescriptor() { throw new Error("hostile descriptor trap"); },
      get() { throw new Error("hostile read trap"); },
    });
    for (const input of [hostileInput, inherited, hostileProxy, Symbol("hostile")]) {
      let capabilities;
      assert.doesNotThrow(() => {
        capabilities = derivePackageActionCapabilities(input);
      });
      assert.strictEqual(Object.values(capabilities.actions).some(Boolean), false);
    }

    const hostileCapabilities = {};
    Object.defineProperty(hostileCapabilities, "actions", {
      get() { throw new Error("must not invoke capability accessors"); },
    });
    const hostileActions = {
      actions: new Proxy({}, {
        getOwnPropertyDescriptor() { throw new Error("hostile action descriptor"); },
        get() { throw new Error("hostile action read"); },
      }),
    };
    for (const capabilities of [
      hostileCapabilities,
      hostileActions,
      hostileProxy,
      Symbol("hostile"),
    ]) {
      assert.doesNotThrow(() => hasPackageAction(capabilities, PACKAGE_ACTIONS.INSTALL));
      assert.strictEqual(hasPackageAction(capabilities, PACKAGE_ACTIONS.INSTALL), false);
      assert.doesNotThrow(() => encodePackageActionContext(
        PACKAGE_ACTION_CONTEXT_FAMILIES.PACKAGE,
        capabilities
      ));
      assert.strictEqual(
        encodePackageActionContext(PACKAGE_ACTION_CONTEXT_FAMILIES.PACKAGE, capabilities),
        PACKAGE_ACTION_CONTEXT_FAMILIES.PACKAGE
      );
    }
  });
});
