const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const vscode = require("vscode");
const { CloudsmithAPI } = require("../../util/cloudsmithAPI");
const {
  ConnectionManager,
  bindConnectionManager,
} = require("../../util/connectionManager");
const { SSOAuthManager } = require("../../util/ssoAuthManager");
const { FakeSecretStorage } = require("../helpers/fakeSecretStorage");

suite("Live isolated Cloudsmith SSO acceptance", function liveSSOSuite() {
  this.timeout(10 * 60 * 1000);

  test("browser login, bearer API, forced refresh, reload, and local clear", async () => {
    assert.strictEqual(process.env.CLOUDSMITH_SSO_LIVE_TESTS, "1");
    const workspace = process.env.CLOUDSMITH_SSO_TEST_WORKSPACE;
    assert.match(workspace || "", /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cloudsmith-sso-live-"));
    const secrets = new FakeSecretStorage();
    const context = {
      secrets,
      globalStorageUri: vscode.Uri.file(directory),
    };
    let manager = new ConnectionManager(context, { activationId: "sso-live-one" });
    let binding = bindConnectionManager(context, manager);
    try {
      await manager.initialize();
      const sso = new SSOAuthManager(context, { connectionManager: manager });
      const login = await sso.loginViaBrowser(workspace);
      assert.strictEqual(login.ok, true, login.error && login.error.message);
      assert.strictEqual(manager.getCredentialKind(), "sso");

      const self = await new CloudsmithAPI(context).get("user/self", {
        responseType: "object",
        retry: "never",
      });
      assert.strictEqual(self.ok, true);
      assert.strictEqual(self.data.authenticated, true);

      const refreshed = await manager.refreshSSO({ force: true });
      assert.strictEqual(refreshed.ok, true);

      binding.dispose();
      await manager.dispose();
      manager = new ConnectionManager(context, { activationId: "sso-live-two" });
      binding = bindConnectionManager(context, manager);
      const reloaded = await manager.initialize();
      assert.strictEqual(reloaded.ok, true);
      assert.strictEqual(manager.getCredentialKind(), "sso");

      const cleared = await manager.disconnect();
      assert.strictEqual(cleared.ok, true);
      assert.strictEqual(await secrets.get("cloudsmith-vsc.authToken"), undefined);
    } finally {
      try { await manager.disconnect(); } catch { /* best-effort local cleanup */ }
      binding.dispose();
      await manager.dispose();
      await fs.promises.rm(directory, { recursive: true, force: true });
    }
  });
});
