// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const InfoNode = require("./infoNode");
const { CONNECTION_PRESENTATIONS } = require("../util/connectionPresentation");

function createConnectionStatusNode(presentation) {
  switch (presentation) {
    case CONNECTION_PRESENTATIONS.CONNECTING:
      return new InfoNode(
        "Connecting to Cloudsmith...",
        "",
        "Connecting to Cloudsmith...",
        "loading~spin"
      );
    case CONNECTION_PRESENTATIONS.ABSENT:
      return new InfoNode(
        "Connect to Cloudsmith",
        "Set up authentication to get started.",
        "Set up an API key, import Cloudsmith CLI credentials, or sign in with SSO.",
        "plug",
        undefined,
        { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
      );
    case CONNECTION_PRESENTATIONS.FAILED:
      return new InfoNode(
        "Connection failed",
        "Check Cloudsmith authentication and retry.",
        "Connection failed. Check Cloudsmith authentication and retry.",
        "warning",
        undefined,
        { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
      );
    case CONNECTION_PRESENTATIONS.UNAVAILABLE:
      return new InfoNode(
        "Could not check the connection",
        "Retry.",
        "Could not check the Cloudsmith connection. Retry.",
        "warning",
        undefined,
        { command: "cloudsmith-vsc.connectCloudsmith", title: "Retry connection" }
      );
    default:
      return null;
  }
}

module.exports = { createConnectionStatusNode };
