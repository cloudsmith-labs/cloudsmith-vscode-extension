// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./shared");
const { parsePomManifest } = require("./manifestHelpers");

const TREE_FILE_CANDIDATES = [
  "dependency-tree.txt",
  path.join("target", "dependency-tree.txt"),
  path.join(".mvn", "dependency-tree.txt"),
];

const mavenParser = {
  name: "mavenParser",
  ecosystem: "maven",

  async canResolve(workspaceFolder) {
    return await pathExists(path.join(getWorkspacePath(workspaceFolder), "pom.xml"), workspaceFolder);
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const pomPath = path.join(rootPath, "pom.xml");
    if (!(await pathExists(pomPath, workspaceFolder))) {
      return [];
    }

    let lockfilePath = null;
    for (const candidate of TREE_FILE_CANDIDATES) {
      const candidatePath = path.join(rootPath, candidate);
      if (await pathExists(candidatePath, workspaceFolder)) {
        lockfilePath = candidatePath;
        break;
      }
    }

    return [{
      resolverName: this.name,
      ecosystem: this.ecosystem,
      lockfilePath,
      manifestPath: pomPath,
      sourceFile: "pom.xml",
    }];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder }) {
    const directDependencies = parsePomManifest(await readUtf8(manifestPath, workspaceFolder))
      .map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "maven",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile: getSourceFileName(manifestPath),
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      }));

    if (!lockfilePath) {
      return buildTree("maven", getSourceFileName(manifestPath), directDependencies);
    }

    const treeRoots = parseDependencyTree(await readUtf8(lockfilePath, workspaceFolder));
    const hydratedDirectDependencies = directDependencies.map((dependency) => {
      const matchingTreeNode = treeRoots.find((node) => (
        node.name === dependency.name
        && (!dependency.version || node.version === dependency.version || !node.version)
      )) || treeRoots.find((node) => node.name === dependency.name);

      if (!matchingTreeNode) {
        return dependency;
      }

      return {
        ...dependency,
        version: dependency.version || matchingTreeNode.version,
        transitives: matchingTreeNode.children.map((child) => toMavenDependency(child, [dependency.name], getSourceFileName(manifestPath))),
      };
    });

    let dependencies = deduplicateDeps(flattenDependencies(hydratedDirectDependencies));
    for (const rootNode of treeRoots) {
      appendTreeNodeIfMissing(rootNode, dependencies, getSourceFileName(manifestPath));
    }

    return buildTree("maven", getSourceFileName(manifestPath), dependencies);
  },
};

function parseDependencyTree(content) {
  const roots = [];
  const stack = [];

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const body = rawLine.replace(/^\[INFO\]\s*/, "");
    if (!body.trim()) {
      continue;
    }

    const markerIndex = body.search(/[+\\]-/);
    if (markerIndex === -1) {
      continue;
    }

    const depth = Math.floor(markerIndex / 3);
    const coordinates = body.slice(markerIndex + 2).trim().replace(/\s+\(\*\)$/, "");
    const node = parseMavenCoordinate(coordinates);
    if (!node) {
      continue;
    }

    while (stack.length > depth) {
      stack.pop();
    }

    if (stack.length === 0) {
      roots.push(node);
    } else {
      stack[stack.length - 1].children.push(node);
    }
    stack.push(node);
  }

  return roots;
}

function parseMavenCoordinate(coordinates) {
  const withoutScopeHint = coordinates.split(" -> ")[0].trim();
  const parts = withoutScopeHint.split(":");
  if (parts.length < 4) {
    return null;
  }

  const resolvedVersion = coordinates.includes(" -> ")
    ? coordinates.split(" -> ")[1].trim().split(" ")[0]
    : parts[3];

  return {
    name: `${parts[0]}:${parts[1]}`,
    version: resolvedVersion || "",
    children: [],
  };
}

function toMavenDependency(node, parentChain, sourceFile) {
  return createDependency({
    name: node.name,
    version: node.version,
    ecosystem: "maven",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(node.children.map((child) => toMavenDependency(child, parentChain.concat(node.name), sourceFile))),
    sourceFile,
    isDevelopmentDependency: false,
  });
}

function appendTreeNodeIfMissing(node, dependencies, sourceFile) {
  const key = `${node.name.toLowerCase()}@${node.version.toLowerCase()}`;
  const exists = dependencies.some((dependency) => (
    `${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}` === key
  ));
  if (!exists) {
    dependencies.push(toMavenDependency(node, [], sourceFile));
  }
  for (const child of node.children) {
    appendTreeNodeIfMissing(child, dependencies, sourceFile);
  }
}

module.exports = mavenParser;
