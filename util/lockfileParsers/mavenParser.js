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

const TREE_FILE_CANDIDATES = [
  "dependency-tree.txt",
  path.join("target", "dependency-tree.txt"),
  path.join(".mvn", "dependency-tree.txt"),
];
const MAX_PROPERTY_RESOLUTION_DEPTH = 20;
const MAX_PROPERTY_VALUE_LENGTH = 4096;
const MAX_TREE_DEPTH = 128;
const MAX_TREE_NODES = 50000;
const VERSION_STATES = Object.freeze({
  EXACT_DECLARATION: "exact-declaration",
  RANGE: "range",
  RESOLVED: "resolved",
  UNRESOLVED: "unresolved",
});

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
    const sourceFile = getSourceFileName(manifestPath);
    const manifestResult = parsePomManifest(await readUtf8(manifestPath, workspaceFolder));
    const directDependencies = manifestResult.dependencies.map((dependency) => createMavenDependency({
      ...dependency,
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
    }));

    if (!lockfilePath) {
      return buildTree(
        "maven",
        sourceFile,
        directDependencies,
        manifestResult.warnings.concat(buildUnresolvedVersionWarnings(directDependencies))
      );
    }

    const treeContent = await readUtf8(lockfilePath, workspaceFolder);
    const treeRoots = parseDependencyTree(treeContent);
    const warnings = manifestResult.warnings.slice();
    if (treeRoots.length === 0) {
      warnings.push(
        "Maven dependency tree output contained no parseable dependency coordinates; "
        + "manifest dependency versions were not treated as package-manager resolutions."
      );
      warnings.push(...buildUnresolvedVersionWarnings(directDependencies));
      return buildTree("maven", sourceFile, directDependencies, warnings);
    }

    const availableRoots = treeRoots.slice();
    const hydratedDirectDependencies = directDependencies.map((dependency) => {
      const matchingTreeNode = takeMatchingTreeRoot(dependency, availableRoots);
      if (!matchingTreeNode) {
        return dependency;
      }

      return {
        ...dependency,
        version: matchingTreeNode.version,
        resolvedVersion: matchingTreeNode.version,
        versionState: VERSION_STATES.RESOLVED,
        hasResolutionEvidence: true,
        transitives: matchingTreeNode.children.map((child) => (
          toMavenDependency(child, [dependency.name], sourceFile)
        )),
      };
    });

    const matchedRoots = new Set(treeRoots.filter((root) => !availableRoots.includes(root)));
    const dependencies = deduplicateDeps(flattenDependencies(hydratedDirectDependencies));
    warnings.push(...buildUnresolvedVersionWarnings(hydratedDirectDependencies));
    for (const rootNode of treeRoots) {
      appendTreeNodeIfMissing(rootNode, dependencies, sourceFile, matchedRoots.has(rootNode));
    }

    return buildTree("maven", sourceFile, dependencies, warnings);
  },
};

function parsePomManifest(content) {
  const structuralXml = prepareXmlForStructuralParsing(content);
  const projectMatch = structuralXml.match(/<project\b[^>]*>([\s\S]*?)<\/project\s*>/i);
  if (!projectMatch) {
    throw new Error("Invalid Maven POM: expected a complete <project> element.");
  }

  const projectElements = parseDirectXmlChildren(projectMatch[1], "Maven project");
  const properties = buildProjectPropertyMap(projectElements);
  const dependencyManagement = parseDependencyManagement(projectElements, properties);
  const warnings = [];
  const dependencies = [];

  for (const dependenciesElement of findElements(projectElements, "dependencies")) {
    for (const dependencyElement of findElements(
      parseDirectXmlChildren(dependenciesElement.content, "Maven dependencies"),
      "dependency"
    )) {
      const parsed = parseManifestDependency(dependencyElement, properties, dependencyManagement);
      if (!parsed) {
        warnings.push("Skipped a Maven dependency whose groupId or artifactId could not be resolved locally.");
        continue;
      }
      dependencies.push(parsed);
    }
  }

  return {
    dependencies: deduplicateManifestDependencies(dependencies),
    warnings,
  };
}

function prepareXmlForStructuralParsing(content) {
  const value = String(content || "");
  if (value.length === 0) {
    return value;
  }

  const prepared = value.replace(/<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?]]>/g, (match) => (
    match.replace(/[^\r\n]/g, " ")
  ));
  if (prepared.includes("<!--") || prepared.includes("<![CDATA[")) {
    throw new Error("Invalid Maven POM: unterminated XML comment or CDATA section.");
  }
  return prepared;
}

function parseDirectXmlChildren(content, contextLabel) {
  const elements = [];
  const stack = [];
  const tokenPattern = /<(\/)?([A-Za-z_][A-Za-z0-9_.:-]*)(?:\s[^<>]*?)?(\/?)>/g;
  let match;

  while ((match = tokenPattern.exec(content)) !== null) {
    const closing = Boolean(match[1]);
    const rawName = match[2];
    const localName = getXmlLocalName(rawName);
    const selfClosing = Boolean(match[3]);

    if (closing) {
      const opened = stack.pop();
      if (!opened || opened.localName !== localName) {
        throw new Error(`Invalid ${contextLabel}: mismatched <${rawName}> element.`);
      }
      if (stack.length === 0) {
        elements.push({
          name: opened.localName,
          rawName: opened.rawName,
          content: content.slice(opened.contentStart, match.index),
        });
      }
      continue;
    }

    if (selfClosing) {
      if (stack.length === 0) {
        elements.push({ name: localName, rawName, content: "" });
      }
      continue;
    }

    stack.push({
      localName,
      rawName,
      contentStart: tokenPattern.lastIndex,
    });
  }

  if (stack.length > 0) {
    throw new Error(`Invalid ${contextLabel}: unclosed <${stack[stack.length - 1].rawName}> element.`);
  }

  return elements;
}

function getXmlLocalName(rawName) {
  return String(rawName || "").split(":").pop();
}

function findElements(elements, name) {
  const normalizedName = String(name || "");
  return elements.filter((element) => element.name === normalizedName);
}

function findElementText(elements, name) {
  const element = findElements(elements, name)[0];
  return element ? decodeXmlText(element.content) : "";
}

function decodeXmlText(value) {
  return String(value || "")
    .trim()
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function buildProjectPropertyMap(projectElements) {
  const values = new Map();
  for (const propertiesElement of findElements(projectElements, "properties")) {
    const propertyElements = parseDirectXmlChildren(propertiesElement.content, "Maven properties");
    for (const propertyElement of propertyElements) {
      values.set(propertyElement.rawName, decodeXmlText(propertyElement.content));
    }
  }

  const parentElement = findElements(projectElements, "parent")[0];
  const parentElements = parentElement
    ? parseDirectXmlChildren(parentElement.content, "Maven parent")
    : [];
  const parentGroupId = findElementText(parentElements, "groupId");
  const parentArtifactId = findElementText(parentElements, "artifactId");
  const parentVersion = findElementText(parentElements, "version");
  const projectGroupId = findElementText(projectElements, "groupId") || parentGroupId;
  const projectArtifactId = findElementText(projectElements, "artifactId");
  const projectVersion = findElementText(projectElements, "version") || parentVersion;

  setPropertyAliases(values, ["project.groupId", "pom.groupId"], projectGroupId);
  setPropertyAliases(values, ["project.artifactId", "pom.artifactId"], projectArtifactId);
  setPropertyAliases(values, ["project.version", "pom.version"], projectVersion);
  setPropertyAliases(values, ["project.parent.groupId", "parent.groupId"], parentGroupId);
  setPropertyAliases(values, ["project.parent.artifactId", "parent.artifactId"], parentArtifactId);
  setPropertyAliases(values, ["project.parent.version", "parent.version"], parentVersion);
  return values;
}

function setPropertyAliases(properties, names, value) {
  if (!value) {
    return;
  }
  for (const name of names) {
    properties.set(name, value);
  }
}

function parseDependencyManagement(projectElements, properties) {
  const managedDependencies = new Map();
  for (const managementElement of findElements(projectElements, "dependencyManagement")) {
    const managementChildren = parseDirectXmlChildren(
      managementElement.content,
      "Maven dependencyManagement"
    );
    for (const dependenciesElement of findElements(managementChildren, "dependencies")) {
      const dependencyElements = parseDirectXmlChildren(
        dependenciesElement.content,
        "Maven dependencyManagement dependencies"
      );
      for (const dependencyElement of findElements(dependencyElements, "dependency")) {
        const fields = parseDependencyFields(dependencyElement, properties);
        if (!fields || !fields.declaredConstraint) {
          continue;
        }
        managedDependencies.set(fields.identity, fields);
      }
    }
  }
  return managedDependencies;
}

function parseManifestDependency(dependencyElement, properties, dependencyManagement) {
  const fields = parseDependencyFields(dependencyElement, properties);
  if (!fields) {
    return null;
  }

  const managed = fields.declaredConstraint ? null : dependencyManagement.get(fields.identity);
  const declaredConstraint = fields.declaredConstraint || managed && managed.declaredConstraint || null;
  const versionResolution = resolveManifestVersion(declaredConstraint, properties);

  return {
    name: fields.name,
    version: versionResolution.version,
    declaredConstraint,
    versionState: versionResolution.versionState,
    versionOrigin: fields.declaredConstraint ? "dependency" : managed ? "dependency-management" : null,
    mavenType: fields.type,
    mavenClassifier: fields.classifier,
    mavenIdentity: fields.identity,
    isDevelopmentDependency: fields.scope === "test",
  };
}

function parseDependencyFields(dependencyElement, properties) {
  const elements = parseDirectXmlChildren(dependencyElement.content, "Maven dependency");
  const rawGroupId = findElementText(elements, "groupId");
  const rawArtifactId = findElementText(elements, "artifactId");
  const rawType = findElementText(elements, "type") || "jar";
  const rawClassifier = findElementText(elements, "classifier");
  const rawScope = findElementText(elements, "scope") || "compile";
  const groupId = resolveMavenValue(rawGroupId, properties);
  const artifactId = resolveMavenValue(rawArtifactId, properties);
  const type = resolveMavenValue(rawType, properties);
  const classifier = resolveMavenValue(rawClassifier, properties);
  const scope = resolveMavenValue(rawScope, properties);

  if (
    !groupId.complete
    || !artifactId.complete
    || !isSafeMavenCoordinatePart(groupId.value)
    || !isSafeMavenCoordinatePart(artifactId.value)
  ) {
    return null;
  }

  const resolvedType = type.complete && type.value ? type.value : "jar";
  const resolvedClassifier = classifier.complete ? classifier.value : "";
  return {
    name: `${groupId.value}:${artifactId.value}`,
    declaredConstraint: findElementText(elements, "version") || null,
    type: resolvedType,
    classifier: resolvedClassifier,
    scope: scope.complete && scope.value ? scope.value : "compile",
    identity: createMavenIdentity(groupId.value, artifactId.value, resolvedType, resolvedClassifier),
  };
}

function resolveManifestVersion(declaredConstraint, properties) {
  if (!declaredConstraint) {
    return { version: "", versionState: VERSION_STATES.UNRESOLVED };
  }

  const resolved = resolveMavenValue(declaredConstraint, properties);
  if (!resolved.complete || !resolved.value) {
    return { version: "", versionState: VERSION_STATES.UNRESOLVED };
  }

  const singletonRange = resolved.value.match(/^\[\s*([^,[\]()]+)\s*]$/);
  if (singletonRange) {
    return {
      version: singletonRange[1].trim(),
      versionState: VERSION_STATES.EXACT_DECLARATION,
    };
  }
  if (/[\[\]()]/.test(resolved.value) || /^(?:LATEST|RELEASE)$/i.test(resolved.value)) {
    return { version: "", versionState: VERSION_STATES.RANGE };
  }
  if (/[\s<>]/.test(resolved.value)) {
    return { version: "", versionState: VERSION_STATES.UNRESOLVED };
  }

  return {
    version: resolved.value,
    versionState: VERSION_STATES.EXACT_DECLARATION,
  };
}

function resolveMavenValue(rawValue, properties, activeProperties = new Set(), depth = 0) {
  const value = String(rawValue || "").trim();
  if (!value) {
    return { value: "", complete: true };
  }
  if (value.length > MAX_PROPERTY_VALUE_LENGTH || depth > MAX_PROPERTY_RESOLUTION_DEPTH) {
    return { value, complete: false };
  }

  let complete = true;
  let resolvedValue = "";
  let cursor = 0;
  const expressionPattern = /\$\{([^}]+)}/g;
  let match;
  while ((match = expressionPattern.exec(value)) !== null) {
    resolvedValue += value.slice(cursor, match.index);
    const placeholder = match[0];
    const normalizedName = match[1].trim();
    if (!normalizedName || activeProperties.has(normalizedName) || !properties.has(normalizedName)) {
      complete = false;
      resolvedValue += placeholder;
    } else {
      const nextActiveProperties = new Set(activeProperties);
      nextActiveProperties.add(normalizedName);
      const resolvedProperty = resolveMavenValue(
        properties.get(normalizedName),
        properties,
        nextActiveProperties,
        depth + 1
      );
      if (!resolvedProperty.complete) {
        complete = false;
      }
      resolvedValue += resolvedProperty.value;
    }
    if (resolvedValue.length > MAX_PROPERTY_VALUE_LENGTH) {
      return { value, complete: false };
    }
    cursor = expressionPattern.lastIndex;
  }
  resolvedValue += value.slice(cursor);
  if (resolvedValue.length > MAX_PROPERTY_VALUE_LENGTH) {
    return { value, complete: false };
  }

  return {
    value: resolvedValue.trim(),
    complete: complete && !resolvedValue.includes("${"),
  };
}

function createMavenDependency(values) {
  return {
    ...createDependency({
      name: values.name,
      version: values.version,
      ecosystem: "maven",
      isDirect: values.isDirect,
      parent: values.parent,
      parentChain: values.parentChain,
      transitives: values.transitives,
      sourceFile: values.sourceFile,
      isDevelopmentDependency: values.isDevelopmentDependency,
    }),
    declaredConstraint: values.declaredConstraint || null,
    resolvedVersion: values.resolvedVersion || null,
    versionState: values.versionState || VERSION_STATES.UNRESOLVED,
    versionOrigin: values.versionOrigin || null,
    mavenType: values.mavenType || "jar",
    mavenClassifier: values.mavenClassifier || "",
    mavenIdentity: values.mavenIdentity || createMavenIdentityFromName(
      values.name,
      values.mavenType,
      values.mavenClassifier
    ),
    hasResolutionEvidence: Boolean(values.hasResolutionEvidence),
  };
}

function parseDependencyTree(content) {
  const roots = [];
  const stack = [];
  let nodeCount = 0;

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const body = rawLine.replace(/^\[INFO]\s*/, "");
    if (!body.trim() || /\(omitted for (?:conflict|duplicate)/i.test(body)) {
      continue;
    }

    const markerIndex = body.search(/[+\\]-/);
    if (markerIndex === -1) {
      continue;
    }

    const depth = Math.floor(markerIndex / 3);
    if (depth > MAX_TREE_DEPTH) {
      throw new Error(`Maven dependency tree exceeds depth ${MAX_TREE_DEPTH}`);
    }
    const coordinates = body.slice(markerIndex + 2).trim().replace(/\s+\(\*\)$/, "");
    const node = parseMavenCoordinate(coordinates);
    if (!node) {
      continue;
    }
    nodeCount += 1;
    if (nodeCount > MAX_TREE_NODES) {
      throw new Error(`Maven dependency tree exceeds ${MAX_TREE_NODES} nodes`);
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
  const arrowParts = String(coordinates || "").split(/\s+->\s+/, 2);
  const coordinateToken = arrowParts[0].trim().split(/\s+\(/, 1)[0];
  const parts = coordinateToken.split(":");
  if (parts.length < 4 || !parts[0] || !parts[1]) {
    return null;
  }

  const hasScope = parts.length >= 5;
  const versionIndex = hasScope ? parts.length - 2 : parts.length - 1;
  const type = parts[2] || "jar";
  const classifier = parts.length >= 6 ? parts.slice(3, versionIndex).join(":") : "";
  const scope = hasScope ? parts[parts.length - 1] : "compile";
  const redirectedVersion = arrowParts.length > 1
    ? arrowParts[1].trim().split(/\s+/, 1)[0]
    : "";
  const version = redirectedVersion || parts[versionIndex];
  if (!version) {
    return null;
  }

  return {
    name: `${parts[0]}:${parts[1]}`,
    version,
    type,
    classifier,
    scope,
    identity: createMavenIdentity(parts[0], parts[1], type, classifier),
    children: [],
  };
}

function takeMatchingTreeRoot(dependency, availableRoots) {
  const identityIndex = availableRoots.findIndex((node) => node.identity === dependency.mavenIdentity);
  if (identityIndex === -1) {
    return null;
  }
  return availableRoots.splice(identityIndex, 1)[0];
}

function toMavenDependency(node, parentChain, sourceFile) {
  return createMavenDependency({
    name: node.name,
    version: node.version,
    declaredConstraint: null,
    resolvedVersion: node.version,
    versionState: VERSION_STATES.RESOLVED,
    ecosystem: "maven",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(node.children.map((child) => (
      toMavenDependency(child, parentChain.concat(node.name), sourceFile)
    ))),
    sourceFile,
    isDevelopmentDependency: node.scope === "test",
    mavenType: node.type,
    mavenClassifier: node.classifier,
    mavenIdentity: node.identity,
    hasResolutionEvidence: true,
  });
}

function appendTreeNodeIfMissing(node, dependencies, sourceFile, rootMatchedManifest) {
  const key = `${node.identity}@${node.version}`;
  const exists = dependencies.some((dependency) => (
    `${dependency.mavenIdentity}@${dependency.version}` === key
  ));
  if (!exists) {
    dependencies.push(toMavenDependency(node, rootMatchedManifest ? [node.name] : [], sourceFile));
  }
  for (const child of node.children) {
    appendTreeNodeIfMissing(child, dependencies, sourceFile, true);
  }
}

function createMavenIdentity(groupId, artifactId, type = "jar", classifier = "") {
  return [groupId, artifactId, type || "jar", classifier || ""]
    .map((value) => String(value || "").trim())
    .join(":");
}

function isSafeMavenCoordinatePart(value) {
  return Boolean(value) && !/[\s:/\\<>${}]/.test(String(value));
}

function createMavenIdentityFromName(name, type, classifier) {
  const parts = String(name || "").split(":", 2);
  return createMavenIdentity(parts[0], parts[1], type, classifier);
}

function deduplicateManifestDependencies(dependencies) {
  const unique = [];
  const seen = new Set();
  for (const dependency of dependencies) {
    const key = [
      dependency.mavenIdentity,
      dependency.declaredConstraint || "",
      dependency.isDevelopmentDependency ? "test" : "runtime",
    ].join(":");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(dependency);
  }
  return unique;
}

function buildUnresolvedVersionWarnings(dependencies) {
  return dependencies
    .filter((dependency) => dependency.versionState === VERSION_STATES.UNRESOLVED)
    .map((dependency) => {
      const declaration = dependency.declaredConstraint ? ` (${dependency.declaredConstraint})` : "";
      return `Maven dependency ${dependency.name} has no locally resolvable version${declaration}.`;
    });
}

module.exports = mavenParser;
