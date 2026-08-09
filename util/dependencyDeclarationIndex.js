// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const {
  canonicalFormat,
  normalizePackageName,
} = require("./packageNameNormalizer");
const { parseRequirementSpec } = require("./lockfileParsers/manifestHelpers");

const MAX_INDEXED_DECLARATIONS = 10000;
const MAX_STRUCTURE_DEPTH = 128;
const CANCELLATION_CHECK_INTERVAL = 4096;
const MAX_DECLARATION_FIELD_LENGTH = 8192;
const EXACT_SOURCE_ECOSYSTEMS = new Map([
  ["package.json", "npm"],
  ["composer.json", "composer"],
  ["pyproject.toml", "python"],
  ["pom.xml", "maven"],
  ["go.mod", "go"],
]);

class DependencyDeclarationIndexError extends Error {
  constructor(message, code = "ERR_DEPENDENCY_DECLARATION_INDEX") {
    super(message);
    this.code = code;
  }
}

class DependencyDeclarationIndexCancelledError extends DependencyDeclarationIndexError {
  constructor() {
    super("Dependency declaration indexing was cancelled.", "ERR_DEPENDENCY_DECLARATION_INDEX_CANCELLED");
  }
}

/**
 * Build a bounded, source-local declaration index. The caller owns the source
 * text and must discard both values after preparing the scan snapshot.
 */
function buildDependencyDeclarationIndex({
  content,
  sourceType,
  ecosystem,
  wantedNames,
  shouldCancel,
  maxDeclarations = MAX_INDEXED_DECLARATIONS,
}) {
  const text = String(content || "");
  const contract = validateDependencyDeclarationSourceContract(sourceType, ecosystem);
  const format = contract.format;
  const normalizedType = contract.sourceType;
  const wantedKeys = new Set();
  for (const name of Array.isArray(wantedNames) ? wantedNames : []) {
    const key = declarationKey(name, format);
    if (key) {
      wantedKeys.add(key);
    }
  }

  const state = {
    byName: new Map(),
    byNameAndDevelopment: new Map(),
    bySelector: new Map(),
    count: 0,
    maxDeclarations: Math.min(
      Number.isInteger(maxDeclarations) && maxDeclarations > 0
        ? maxDeclarations
        : MAX_INDEXED_DECLARATIONS,
      MAX_INDEXED_DECLARATIONS
    ),
    truncated: false,
    wantedKeys,
    format,
    shouldCancel: typeof shouldCancel === "function" ? shouldCancel : () => false,
  };

  let precision = "file";
  if (normalizedType === "package.json") {
    precision = "exact";
    indexJsonDependencySections(text, state, new Map([
      ["dependencies", false],
      ["devDependencies", true],
      ["optionalDependencies", false],
      ["peerDependencies", false],
    ]));
  } else if (normalizedType === "composer.json") {
    precision = "exact";
    indexJsonDependencySections(text, state, new Map([
      ["require", false],
      ["require-dev", true],
    ]));
  } else if (normalizedType === "pyproject.toml") {
    precision = "exact";
    indexPyproject(text, state);
  } else if (format === "python") {
    precision = "exact";
    indexRequirements(text, state);
  } else if (normalizedType === "pom.xml") {
    precision = "exact";
    indexMavenPom(text, state);
  } else if (normalizedType === "go.mod") {
    precision = "exact";
    indexGoMod(text, state);
  }

  return Object.freeze({
    precision,
    byName: state.byName,
    byNameAndDevelopment: state.byNameAndDevelopment,
    bySelector: state.bySelector,
    truncated: state.truncated,
    declarationCount: state.count,
  });
}

/** Validate source/ecosystem compatibility without parsing the source text. */
function validateDependencyDeclarationSourceContract(sourceType, ecosystem) {
  const normalizedType = String(sourceType || "").trim().toLowerCase();
  const normalizedEcosystem = String(ecosystem || "").trim().toLowerCase();
  const format = canonicalFormat(normalizedEcosystem);
  const requiredEcosystem = EXACT_SOURCE_ECOSYSTEMS.get(normalizedType);
  if (requiredEcosystem && normalizedEcosystem !== requiredEcosystem) {
    throw new DependencyDeclarationIndexError(
      `Dependency source type ${normalizedType} is incompatible with ecosystem ${normalizedEcosystem || "<missing>"}.`,
      "ERR_DEPENDENCY_DECLARATION_SOURCE_CONTRACT"
    );
  }
  return Object.freeze({
    sourceType: normalizedType,
    ecosystem: normalizedEcosystem,
    format,
  });
}

function findDependencyDeclarationOffsets(index, occurrence) {
  if (
    !index
    || index.precision !== "exact"
    || index.truncated === true
    || !(index.byName instanceof Map)
  ) {
    return [];
  }

  const format = canonicalFormat(occurrence && (occurrence.format || occurrence.ecosystem));
  const declaredName = occurrence && (occurrence.declarationName || occurrence.name);
  const key = declarationKey(declaredName, format);
  const candidates = key ? index.byName.get(key) || [] : [];
  if (candidates.length === 0) {
    return [];
  }

  const isDevelopmentDependency = Boolean(occurrence && occurrence.isDevelopmentDependency);
  const developmentKey = selectorKey([key, isDevelopmentDependency ? "development" : "runtime"]);
  const sectionPool = index.byNameAndDevelopment.get(developmentKey) || [];
  if (sectionPool.length === 0) {
    return [];
  }
  const declaredConstraint = optionalString(occurrence && occurrence.declaredConstraint);
  const environmentMarker = optionalString(occurrence && occurrence.environmentMarker);
  const exactSelector = selectorKey([
    key,
    isDevelopmentDependency ? "development" : "runtime",
    declaredConstraint || "",
    environmentMarker || "",
  ]);
  const exactMatches = index.bySelector.get(exactSelector) || [];
  if (exactMatches.length === 1) {
    return [exactMatches[0].offsetRange];
  }
  if (exactMatches.length > 1 || sectionPool.length !== 1) {
    return [];
  }
  return [sectionPool[0].offsetRange];
}

/** Convert bounded absolute JS offsets into VS Code UTF-16 line/character ranges. */
function offsetRangesToSourceRanges(content, offsetRanges, shouldCancel) {
  const text = String(content || "");
  const ranges = Array.isArray(offsetRanges) ? offsetRanges.slice() : [];
  const offsets = new Set();
  for (const range of ranges) {
    if (
      !range
      || !Number.isInteger(range.start)
      || !Number.isInteger(range.end)
      || range.start < 0
      || range.end < range.start
      || range.end > text.length
    ) {
      throw new DependencyDeclarationIndexError("Dependency declaration offsets are invalid.");
    }
    offsets.add(range.start);
    offsets.add(range.end);
  }

  const sortedOffsets = [...offsets].sort((left, right) => left - right);
  const positions = new Map();
  let line = 0;
  let lineStart = 0;
  let cursor = 0;
  for (const offset of sortedOffsets) {
    while (cursor < offset) {
      const code = text.charCodeAt(cursor);
      if (code === 13) {
        line += 1;
        lineStart = cursor + 1;
      } else if (code === 10) {
        if (cursor === 0 || text.charCodeAt(cursor - 1) !== 13) {
          line += 1;
        }
        lineStart = cursor + 1;
      }
      cursor += 1;
      checkCancellation(cursor, shouldCancel);
    }
    positions.set(offset, Object.freeze({ line, character: offset - lineStart }));
  }

  return ranges.map((range) => Object.freeze({
    start: positions.get(range.start),
    end: positions.get(range.end),
  }));
}

/** Validate already-provided canonical ranges without materializing all lines. */
function validateSourceRanges(content, ranges, shouldCancel) {
  const text = String(content || "");
  const values = Array.isArray(ranges) ? ranges : [];
  const requiredLineLengths = new Map();
  for (const range of values) {
    validatePositionRangeShape(range);
    for (const position of [range.start, range.end]) {
      const current = requiredLineLengths.get(position.line) || 0;
      requiredLineLengths.set(position.line, Math.max(current, position.character));
    }
  }

  const unresolvedLines = new Set(requiredLineLengths.keys());
  let line = 0;
  let lineStart = 0;
  let cursor = 0;
  while (cursor <= text.length) {
    const atEnd = cursor === text.length;
    const lineBreakLength = atEnd ? 0 : lineBreakLengthAt(text, cursor);
    if (!atEnd && lineBreakLength === 0) {
      checkCancellation(cursor, shouldCancel);
      cursor += 1;
      continue;
    }

    if (requiredLineLengths.has(line)) {
      if (requiredLineLengths.get(line) > cursor - lineStart) {
        throw new DependencyDeclarationIndexError("Dependency source range exceeds its source file.");
      }
      unresolvedLines.delete(line);
    }
    if (atEnd) {
      break;
    }
    line += 1;
    cursor += lineBreakLength;
    lineStart = cursor;
    checkCancellation(cursor, shouldCancel);
  }

  if (unresolvedLines.size > 0) {
    throw new DependencyDeclarationIndexError("Dependency source range exceeds its source file.");
  }
}

function indexJsonDependencySections(content, state, sections) {
  let braceDepth = 0;
  let bracketDepth = 0;
  let pendingTopLevelKey = null;
  let expectingTopLevelValue = false;
  let activeSection = null;
  let activeSectionDepth = 0;
  let pendingDependencyKey = null;
  let expectingDependencyValue = false;
  const latestDeclarations = new Map();
  const ambiguousDeclarations = new Set();

  for (let cursor = 0; cursor < content.length;) {
    checkCancellation(cursor, state.shouldCancel);
    const character = content[cursor];
    if (isWhitespace(character)) {
      cursor += 1;
      continue;
    }

    if (character === '"') {
      const token = readJsonString(content, cursor);
      const next = skipWhitespace(content, token.end);
      const isKey = content[next] === ":";
      if (braceDepth === 1 && bracketDepth === 0 && isKey) {
        pendingTopLevelKey = token.value;
        expectingTopLevelValue = false;
      } else if (
        activeSection
        && braceDepth === activeSectionDepth
        && bracketDepth === 0
      ) {
        if (isKey) {
          pendingDependencyKey = token;
          expectingDependencyValue = false;
        } else if (expectingDependencyValue && pendingDependencyKey) {
          const key = declarationKey(pendingDependencyKey.value, state.format);
          if (state.wantedKeys.has(key)) {
            const declarationIdentity = `${activeSection}\u0000${key}`;
            if (latestDeclarations.has(declarationIdentity)) {
              ambiguousDeclarations.add(declarationIdentity);
            }
            latestDeclarations.set(declarationIdentity, {
              name: pendingDependencyKey.value,
              declaredConstraint: token.value,
              isDevelopmentDependency: sections.get(activeSection),
              qualifier: activeSection,
              offsetRange: Object.freeze({
                start: pendingDependencyKey.start + 1,
                end: pendingDependencyKey.end - 1,
              }),
            });
          }
          pendingDependencyKey = null;
          expectingDependencyValue = false;
        }
      }
      cursor = token.end;
      continue;
    }

    if (character === ":") {
      if (braceDepth === 1 && pendingTopLevelKey != null) {
        expectingTopLevelValue = true;
      } else if (activeSection && braceDepth === activeSectionDepth && pendingDependencyKey) {
        expectingDependencyValue = true;
      }
      cursor += 1;
      continue;
    }

    if (character === "{") {
      if (braceDepth + 1 > MAX_STRUCTURE_DEPTH) {
        throw new DependencyDeclarationIndexError("Dependency JSON nesting exceeds the indexing limit.");
      }
      if (
        braceDepth === 1
        && expectingTopLevelValue
        && sections.has(pendingTopLevelKey)
      ) {
        activeSection = pendingTopLevelKey;
        activeSectionDepth = braceDepth + 1;
      } else if (expectingDependencyValue) {
        pendingDependencyKey = null;
        expectingDependencyValue = false;
      }
      braceDepth += 1;
      pendingTopLevelKey = null;
      expectingTopLevelValue = false;
      cursor += 1;
      continue;
    }

    if (character === "}") {
      if (activeSection && braceDepth === activeSectionDepth) {
        activeSection = null;
        activeSectionDepth = 0;
      }
      braceDepth -= 1;
      if (braceDepth < 0) {
        throw new DependencyDeclarationIndexError("Dependency JSON structure is invalid.");
      }
      pendingDependencyKey = null;
      expectingDependencyValue = false;
      cursor += 1;
      continue;
    }

    if (character === "[") {
      bracketDepth += 1;
      if (braceDepth + bracketDepth > MAX_STRUCTURE_DEPTH) {
        throw new DependencyDeclarationIndexError("Dependency JSON nesting exceeds the indexing limit.");
      }
    } else if (character === "]") {
      bracketDepth -= 1;
      if (bracketDepth < 0) {
        throw new DependencyDeclarationIndexError("Dependency JSON structure is invalid.");
      }
    } else if (character === ",") {
      if (braceDepth === 1) {
        pendingTopLevelKey = null;
        expectingTopLevelValue = false;
      }
      if (activeSection && braceDepth === activeSectionDepth && bracketDepth === 0) {
        pendingDependencyKey = null;
        expectingDependencyValue = false;
      }
    } else if (expectingDependencyValue) {
      pendingDependencyKey = null;
      expectingDependencyValue = false;
    }
    cursor += 1;
  }

  if (braceDepth !== 0 || bracketDepth !== 0) {
    throw new DependencyDeclarationIndexError("Dependency JSON structure is invalid.");
  }
  try {
    JSON.parse(content);
  } catch {
    throw new DependencyDeclarationIndexError("Dependency JSON source is malformed.");
  }
  for (const [identity, declaration] of latestDeclarations) {
    if (!ambiguousDeclarations.has(identity)) {
      addDeclaration(state, declaration);
    }
  }
}

function indexRequirements(content, state) {
  forEachLine(content, (rawLine, lineStart) => {
    const start = firstNonWhitespaceOffset(rawLine);
    if (start === -1 || rawLine[start] === "#" || rawLine[start] === "-") {
      return;
    }
    const uncommented = stripRequirementComment(rawLine.slice(start));
    if (!uncommented || uncommented.trimEnd().endsWith("\\")) {
      return;
    }
    const withoutOptions = stripRequirementOptions(uncommented);
    const parsed = parseRequirementSpec(withoutOptions);
    if (!parsed) {
      return;
    }
    addDeclaration(state, {
      name: parsed.name,
      declaredConstraint: parsed.declaredConstraint,
      environmentMarker: parsed.environmentMarker,
      isDevelopmentDependency: false,
      qualifier: "requirements",
      offsetRange: Object.freeze({
        start: lineStart + start,
        end: lineStart + start + parsed.name.length,
      }),
    });
  }, state.shouldCancel);
}

function indexPyproject(content, state) {
  let section = "";
  let collectingProjectDependencies = false;

  forEachLine(content, (rawLine, lineStart) => {
    const commentOffset = findTomlCommentOffset(rawLine);
    const visibleLine = rawLine.slice(0, commentOffset).trimEnd();
    const leading = firstNonWhitespaceOffset(visibleLine);
    if (leading === -1) {
      return;
    }
    const trimmed = visibleLine.slice(leading);
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      section = trimmed;
      collectingProjectDependencies = false;
      return;
    }

    if (collectingProjectDependencies) {
      const scan = indexProjectDependencyStrings(
        visibleLine,
        lineStart,
        state,
        0
      );
      if (scan.closed) {
        collectingProjectDependencies = false;
      }
      return;
    }

    const separator = findUnquotedCharacter(trimmed, "=");
    if (separator < 0) {
      return;
    }
    const rawKey = trimmed.slice(0, separator).trim();
    const key = unquote(rawKey);
    const value = trimmed.slice(separator + 1).trim();
    if (section === "[project]" && key === "dependencies" && value.startsWith("[")) {
      const valueOffset = visibleLine.indexOf(value, leading + separator + 1);
      const scan = indexProjectDependencyStrings(
        value,
        lineStart,
        state,
        valueOffset
      );
      collectingProjectDependencies = !scan.closed;
      return;
    }

    const isPoetryDependency = section === "[tool.poetry.dependencies]"
      || section === "[tool.poetry.dev-dependencies]"
      || isPoetryGroupDependencySection(section);
    if (!isPoetryDependency || !key || key.toLowerCase() === "python") {
      return;
    }

    const keyStartInTrimmed = trimmed.indexOf(rawKey)
      + (rawKey.startsWith("\"") || rawKey.startsWith("'") ? 1 : 0);
    const declaredConstraint = value.startsWith("{")
      ? findInlineStringAssignment(value, "version")
      : unquote(value);
    const environmentMarker = value.startsWith("{")
      ? findInlineStringAssignment(value, "markers")
      : null;
    addDeclaration(state, {
      name: key,
      declaredConstraint: declaredConstraint === "*" ? null : declaredConstraint,
      environmentMarker,
      isDevelopmentDependency: section !== "[tool.poetry.dependencies]",
      qualifier: section,
      offsetRange: Object.freeze({
        start: lineStart + leading + keyStartInTrimmed,
        end: lineStart + leading + keyStartInTrimmed + key.length,
      }),
    });
  }, state.shouldCancel);

  if (collectingProjectDependencies) {
    throw new DependencyDeclarationIndexError("Dependency pyproject source has an unterminated dependencies array.");
  }
}

function indexProjectDependencyStrings(text, lineStart, state, baseOffset) {
  let closed = false;
  for (let cursor = 0; cursor < text.length;) {
    const character = text[cursor];
    if (character === "#") {
      break;
    }
    if (character === "]") {
      closed = true;
      break;
    }
    if (character !== '"' && character !== "'") {
      cursor += 1;
      continue;
    }

    const token = readQuotedString(text, cursor, character);
    const parsed = parseRequirementSpec(token.value);
    if (parsed) {
      const nameOffset = token.value.indexOf(parsed.name);
      if (nameOffset >= 0) {
        addDeclaration(state, {
          name: parsed.name,
          declaredConstraint: parsed.declaredConstraint,
          environmentMarker: parsed.environmentMarker,
          isDevelopmentDependency: false,
          qualifier: "[project].dependencies",
          offsetRange: Object.freeze({
            start: lineStart + baseOffset + token.start + 1 + nameOffset,
            end: lineStart + baseOffset + token.start + 1 + nameOffset + parsed.name.length,
          }),
        });
      }
    }
    cursor = token.end;
  }
  return { closed };
}

function indexMavenPom(content, state) {
  const stack = [];
  for (let cursor = 0; cursor < content.length;) {
    checkCancellation(cursor, state.shouldCancel);
    const opening = content.indexOf("<", cursor);
    if (opening < 0) {
      break;
    }
    if (content.startsWith("<!--", opening)) {
      const end = content.indexOf("-->", opening + 4);
      if (end < 0) {
        throw new DependencyDeclarationIndexError("Dependency POM contains an unterminated comment.");
      }
      cursor = end + 3;
      continue;
    }
    if (content.startsWith("<![CDATA[", opening)) {
      const end = content.indexOf("]]>", opening + 9);
      if (end < 0) {
        throw new DependencyDeclarationIndexError("Dependency POM contains unterminated CDATA.");
      }
      cursor = end + 3;
      continue;
    }
    if (content.startsWith("<?", opening)) {
      const end = content.indexOf("?>", opening + 2);
      if (end < 0) {
        throw new DependencyDeclarationIndexError("Dependency POM contains an unterminated processing instruction.");
      }
      cursor = end + 2;
      continue;
    }
    if (content.startsWith("<!", opening)) {
      throw new DependencyDeclarationIndexError("Dependency POM contains unsupported XML markup.");
    }

    const tag = readXmlTag(content, opening);
    if (tag.closing) {
      const frame = stack.pop();
      if (!frame || frame.name !== tag.name) {
        throw new DependencyDeclarationIndexError("Dependency POM contains mismatched XML elements.");
      }
      if (frame.field && frame.dependency) {
        const textRange = trimOffsetRange(content, frame.contentStart, opening);
        if (textRange && !content.slice(textRange.start, textRange.end).includes("<")) {
          frame.dependency[frame.field] = {
            value: content.slice(textRange.start, textRange.end),
            range: textRange,
          };
        }
      }
      if (frame.dependencyRoot) {
        const values = frame.dependencyRoot;
        if (values.groupId && values.artifactId) {
          addDeclaration(state, {
            name: `${values.groupId.value}:${values.artifactId.value}`,
            declaredConstraint: values.version ? values.version.value : null,
            isDevelopmentDependency: Boolean(values.scope && values.scope.value === "test"),
            qualifier: `${values.type && values.type.value || ""}:${values.classifier && values.classifier.value || ""}`,
            offsetRange: values.artifactId.range,
          });
        }
      }
      cursor = tag.end;
      continue;
    }

    if (stack.length + 1 > MAX_STRUCTURE_DEPTH) {
      throw new DependencyDeclarationIndexError("Dependency POM nesting exceeds the indexing limit.");
    }
    const parentNames = stack.map((frame) => frame.name);
    const isDirectDependency = tag.name === "dependency"
      && parentNames.length === 2
      && parentNames[0] === "project"
      && parentNames[1] === "dependencies";
    const parentDependency = stack.length > 0
      ? stack[stack.length - 1].dependencyRoot || stack[stack.length - 1].dependency
      : null;
    const field = parentDependency && [
      "groupId",
      "artifactId",
      "version",
      "scope",
      "type",
      "classifier",
    ].includes(tag.name) ? tag.name : null;
    const frame = {
      name: tag.name,
      contentStart: tag.end,
      dependencyRoot: isDirectDependency ? {} : null,
      dependency: parentDependency,
      field,
    };
    if (frame.dependencyRoot) {
      frame.dependency = frame.dependencyRoot;
    }
    if (!tag.selfClosing) {
      stack.push(frame);
    }
    cursor = tag.end;
  }

  if (stack.length > 0) {
    throw new DependencyDeclarationIndexError("Dependency POM contains unclosed XML elements.");
  }
}

function indexGoMod(content, state) {
  let inRequireBlock = false;
  forEachLine(content, (rawLine, lineStart) => {
    const comment = rawLine.indexOf("//");
    const visible = (comment >= 0 ? rawLine.slice(0, comment) : rawLine).trim();
    if (!visible) {
      return;
    }
    if (visible === "require (") {
      inRequireBlock = true;
      return;
    }
    if (visible === ")" && inRequireBlock) {
      inRequireBlock = false;
      return;
    }
    const declaration = visible.startsWith("require ")
      ? visible.slice("require ".length)
      : inRequireBlock ? visible : "";
    if (!declaration) {
      return;
    }
    const tokens = firstWhitespaceTokens(declaration, 2);
    if (tokens.length < 2) {
      return;
    }
    const declarationOffset = rawLine.indexOf(declaration);
    addDeclaration(state, {
      name: tokens[0].value,
      declaredConstraint: tokens[1].value,
      isDevelopmentDependency: false,
      qualifier: "require",
      offsetRange: Object.freeze({
        start: lineStart + declarationOffset + tokens[0].start,
        end: lineStart + declarationOffset + tokens[0].end,
      }),
    });
  }, state.shouldCancel);
}

function addDeclaration(state, declaration) {
  for (const field of [
    declaration.name,
    declaration.declaredConstraint,
    declaration.environmentMarker,
    declaration.qualifier,
  ]) {
    if (field != null && String(field).length > MAX_DECLARATION_FIELD_LENGTH) {
      throw new DependencyDeclarationIndexError("Dependency declaration fields exceed the indexing limit.");
    }
  }
  const key = declarationKey(declaration.name, state.format);
  if (!key || !state.wantedKeys.has(key)) {
    return;
  }
  if (state.count >= state.maxDeclarations) {
    state.truncated = true;
    return;
  }
  const frozenDeclaration = Object.freeze({ ...declaration });
  if (!state.byName.has(key)) {
    state.byName.set(key, []);
  }
  state.byName.get(key).push(frozenDeclaration);
  const developmentKey = selectorKey([
    key,
    declaration.isDevelopmentDependency ? "development" : "runtime",
  ]);
  if (!state.byNameAndDevelopment.has(developmentKey)) {
    state.byNameAndDevelopment.set(developmentKey, []);
  }
  state.byNameAndDevelopment.get(developmentKey).push(frozenDeclaration);
  const exactSelector = selectorKey([
    key,
    declaration.isDevelopmentDependency ? "development" : "runtime",
    optionalString(declaration.declaredConstraint) || "",
    optionalString(declaration.environmentMarker) || "",
  ]);
  if (!state.bySelector.has(exactSelector)) {
    state.bySelector.set(exactSelector, []);
  }
  state.bySelector.get(exactSelector).push(frozenDeclaration);
  state.count += 1;
}

function selectorKey(parts) {
  return JSON.stringify(parts);
}

function declarationKey(name, format) {
  return normalizePackageName(String(name || ""), canonicalFormat(format));
}

function readJsonString(content, start) {
  let escaped = false;
  for (let cursor = start + 1; cursor < content.length; cursor += 1) {
    const character = content[cursor];
    if (character === '"' && !escaped) {
      const end = cursor + 1;
      try {
        return {
          start,
          end,
          value: JSON.parse(content.slice(start, end)),
        };
      } catch {
        throw new DependencyDeclarationIndexError("Dependency JSON string is invalid.");
      }
    }
    if (character === "\\" && !escaped) {
      escaped = true;
    } else {
      escaped = false;
    }
  }
  throw new DependencyDeclarationIndexError("Dependency JSON contains an unterminated string.");
}

function readQuotedString(content, start, quote) {
  let escaped = false;
  for (let cursor = start + 1; cursor < content.length; cursor += 1) {
    const character = content[cursor];
    if (character === quote && !escaped) {
      const end = cursor + 1;
      const raw = content.slice(start + 1, cursor);
      if (quote === '"') {
        try {
          return { start, end, value: JSON.parse(`${quote}${raw}${quote}`) };
        } catch {
          throw new DependencyDeclarationIndexError("Dependency TOML string is invalid.");
        }
      }
      return { start, end, value: raw };
    }
    if (character === "\\" && quote === '"' && !escaped) {
      escaped = true;
    } else {
      escaped = false;
    }
  }
  throw new DependencyDeclarationIndexError("Dependency TOML contains an unterminated string.");
}

function readXmlTag(content, start) {
  let quote = "";
  for (let cursor = start + 1; cursor < content.length; cursor += 1) {
    const character = content[cursor];
    if (quote) {
      if (character === quote) {
        quote = "";
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character !== ">") {
      continue;
    }

    let body = content.slice(start + 1, cursor).trim();
    if (!body || body.startsWith("!")) {
      throw new DependencyDeclarationIndexError("Dependency POM contains invalid XML markup.");
    }
    const closing = body.startsWith("/");
    const selfClosing = body.endsWith("/");
    if (closing) {
      body = body.slice(1).trimStart();
    }
    if (selfClosing) {
      body = body.slice(0, -1).trimEnd();
    }
    const nameEnd = findXmlNameEnd(body);
    const rawName = body.slice(0, nameEnd);
    if (!rawName) {
      throw new DependencyDeclarationIndexError("Dependency POM contains an invalid XML element.");
    }
    return {
      name: rawName.split(":").pop(),
      closing,
      selfClosing,
      end: cursor + 1,
    };
  }
  throw new DependencyDeclarationIndexError("Dependency POM contains an unterminated XML tag.");
}

function findXmlNameEnd(value) {
  let cursor = 0;
  while (cursor < value.length) {
    const code = value.charCodeAt(cursor);
    const allowed = (code >= 65 && code <= 90)
      || (code >= 97 && code <= 122)
      || (code >= 48 && code <= 57)
      || value[cursor] === "_"
      || value[cursor] === "."
      || value[cursor] === ":"
      || value[cursor] === "-";
    if (!allowed) {
      break;
    }
    cursor += 1;
  }
  return cursor;
}

function forEachLine(content, callback, shouldCancel) {
  let lineStart = 0;
  let cursor = 0;
  while (cursor <= content.length) {
    const atEnd = cursor === content.length;
    const lineBreakLength = atEnd ? 0 : lineBreakLengthAt(content, cursor);
    if (!atEnd && lineBreakLength === 0) {
      checkCancellation(cursor, shouldCancel);
      cursor += 1;
      continue;
    }
    callback(content.slice(lineStart, cursor), lineStart);
    if (atEnd) {
      break;
    }
    cursor += lineBreakLength;
    lineStart = cursor;
    checkCancellation(cursor, shouldCancel);
  }
}

function firstWhitespaceTokens(value, limit) {
  const tokens = [];
  let cursor = 0;
  while (cursor < value.length && tokens.length < limit) {
    while (cursor < value.length && isWhitespace(value[cursor])) {
      cursor += 1;
    }
    if (cursor >= value.length) {
      break;
    }
    const start = cursor;
    while (cursor < value.length && !isWhitespace(value[cursor])) {
      cursor += 1;
    }
    tokens.push({ start, end: cursor, value: value.slice(start, cursor) });
  }
  return tokens;
}

function findInlineStringAssignment(value, key) {
  let cursor = 0;
  while (cursor < value.length) {
    while (cursor < value.length && (isWhitespace(value[cursor]) || value[cursor] === "{" || value[cursor] === ",")) {
      cursor += 1;
    }
    const keyStart = cursor;
    while (cursor < value.length && /[A-Za-z0-9_-]/.test(value[cursor])) {
      cursor += 1;
    }
    const candidate = value.slice(keyStart, cursor);
    while (cursor < value.length && isWhitespace(value[cursor])) {
      cursor += 1;
    }
    if (value[cursor] !== "=") {
      cursor += 1;
      continue;
    }
    cursor += 1;
    while (cursor < value.length && isWhitespace(value[cursor])) {
      cursor += 1;
    }
    if (candidate !== key || (value[cursor] !== '"' && value[cursor] !== "'")) {
      cursor += 1;
      continue;
    }
    return readQuotedString(value, cursor, value[cursor]).value;
  }
  return null;
}

function isPoetryGroupDependencySection(section) {
  const prefix = "[tool.poetry.group.";
  const suffix = ".dependencies]";
  if (!section.startsWith(prefix) || !section.endsWith(suffix)) {
    return false;
  }
  const groupName = section.slice(prefix.length, -suffix.length);
  return Boolean(groupName) && !groupName.includes(".");
}

function stripRequirementComment(line) {
  for (let cursor = 0; cursor < line.length; cursor += 1) {
    if (line[cursor] === "#" && (cursor === 0 || isWhitespace(line[cursor - 1]))) {
      return line.slice(0, cursor).trimEnd();
    }
  }
  return line;
}

function stripRequirementOptions(line) {
  const options = ["--hash", "--config-settings", "--global-option", "--install-option"];
  for (let cursor = 0; cursor < line.length;) {
    if (!isWhitespace(line[cursor])) {
      cursor += 1;
      continue;
    }
    const whitespaceStart = cursor;
    while (cursor < line.length && isWhitespace(line[cursor])) {
      cursor += 1;
    }
    if (options.some((option) => (
      line.startsWith(`${option}=`, cursor) || line.startsWith(`${option} `, cursor)
    ))) {
      return line.slice(0, whitespaceStart).trimEnd();
    }
  }
  return line.trim();
}

function findTomlCommentOffset(line) {
  let quote = "";
  let escaped = false;
  for (let cursor = 0; cursor < line.length; cursor += 1) {
    const character = line[cursor];
    if (quote) {
      if (quote === '"' && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = "";
      }
      escaped = false;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === "#") {
      return cursor;
    }
  }
  return line.length;
}

function findUnquotedCharacter(value, target) {
  let quote = "";
  let escaped = false;
  for (let cursor = 0; cursor < value.length; cursor += 1) {
    const character = value[cursor];
    if (quote) {
      if (quote === '"' && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = "";
      }
      escaped = false;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === target) {
      return cursor;
    }
  }
  return -1;
}

function trimOffsetRange(content, start, end) {
  while (start < end && isWhitespace(content[start])) {
    start += 1;
  }
  while (end > start && isWhitespace(content[end - 1])) {
    end -= 1;
  }
  return start < end ? Object.freeze({ start, end }) : null;
}

function validatePositionRangeShape(range) {
  if (!range || typeof range !== "object") {
    throw new DependencyDeclarationIndexError("Dependency source range is invalid.");
  }
  for (const position of [range.start, range.end]) {
    if (
      !position
      || !Number.isInteger(position.line)
      || position.line < 0
      || !Number.isInteger(position.character)
      || position.character < 0
    ) {
      throw new DependencyDeclarationIndexError("Dependency source range is invalid.");
    }
  }
  if (
    range.end.line < range.start.line
    || (range.end.line === range.start.line && range.end.character < range.start.character)
  ) {
    throw new DependencyDeclarationIndexError("Dependency source range is invalid.");
  }
}

function checkCancellation(cursor, shouldCancel) {
  if (
    cursor % CANCELLATION_CHECK_INTERVAL === 0
    && typeof shouldCancel === "function"
    && shouldCancel()
  ) {
    throw new DependencyDeclarationIndexCancelledError();
  }
}

function firstNonWhitespaceOffset(value) {
  for (let cursor = 0; cursor < value.length; cursor += 1) {
    if (!isWhitespace(value[cursor])) {
      return cursor;
    }
  }
  return -1;
}

function skipWhitespace(value, start) {
  let cursor = start;
  while (cursor < value.length && isWhitespace(value[cursor])) {
    cursor += 1;
  }
  return cursor;
}

function isWhitespace(character) {
  return character === " " || character === "\t" || character === "\r" || character === "\n";
}

function lineBreakLengthAt(value, offset) {
  const code = value.charCodeAt(offset);
  if (code === 10) {
    return 1;
  }
  if (code === 13) {
    return value.charCodeAt(offset + 1) === 10 ? 2 : 1;
  }
  return 0;
}

function unquote(value) {
  const text = String(value || "").trim();
  if (
    text.length >= 2
    && ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'")))
  ) {
    return text.slice(1, -1);
  }
  return text;
}

function optionalString(value) {
  const normalized = String(value == null ? "" : value).trim();
  return normalized || null;
}

module.exports = {
  MAX_INDEXED_DECLARATIONS,
  DependencyDeclarationIndexCancelledError,
  DependencyDeclarationIndexError,
  buildDependencyDeclarationIndex,
  findDependencyDeclarationOffsets,
  offsetRangesToSourceRanges,
  validateDependencyDeclarationSourceContract,
  validateSourceRanges,
};
