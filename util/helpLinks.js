// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const HELP_LINKS = Object.freeze([
  Object.freeze({
    id: "extensionDocs",
    label: "Read extension documentation",
    url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/blob/main/README.md",
    icon: "external",
  }),
  Object.freeze({
    id: "gettingStarted",
    label: "Get started with Cloudsmith",
    url: "https://docs.cloudsmith.com/",
    icon: "cloudsmith",
  }),
  Object.freeze({
    id: "viewIssues",
    label: "View issues",
    url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues",
    icon: "github",
  }),
  Object.freeze({
    id: "reportIssue",
    label: "Report an issue",
    url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues/new/choose",
    icon: "github",
  }),
]);

module.exports = { HELP_LINKS };
