// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const RepositoryNode = require("../../models/repositoryNode");
const UpstreamIndicatorNode = require("../../models/upstreamIndicatorNode");
const { liveFixture } = require("./setup");

suite("Live integration: upstream inventory production path", function () {
  this.timeout(60_000);

  test("settles the RepositoryNode inventory with canonical safe outcomes", async () => {
    const repository = process.env.CLOUDSMITH_TEST_UPSTREAM_REPOSITORY
      || liveFixture.repository;
    const context = {
      secrets: {
        async get() { return liveFixture.apiKey; },
      },
      globalState: {
        get() { return undefined; },
        async update() {},
      },
    };
    const connectionManager = {
      activationId: "live-upstream-contract",
      getState() {
        return {
          activationId: this.activationId,
          accountEpoch: 1,
          sessionConnected: true,
          status: "connected",
        };
      },
    };
    const node = new RepositoryNode(
      { slug: repository, slug_perm: repository, name: repository },
      liveFixture.workspace,
      context,
      { connectionManager }
    );
    node.getPackages = async () => [{ format: "python" }];
    node._packageState = { ...node._packageState, pageCount: 1 };

    const children = await node.getChildren();
    const indicator = children.find(child => child instanceof UpstreamIndicatorNode);

    assert.ok(indicator, "Production path did not publish a settled upstream summary");
    assert.ok(["boolean"].includes(typeof indicator.complete));
    assert.strictEqual(new Set(indicator.upstreams.map(upstream => (
      `${upstream.format}\0${upstream.slug_perm || upstream.name}`
    ))).size, indicator.upstreams.length);
    const serialized = JSON.stringify(indicator.upstreams);
    for (const forbidden of ["auth_secret", "extra_value_1", "extra_value_2", "Authorization"]) {
      assert.strictEqual(serialized.includes(forbidden), false);
    }
  });
});
