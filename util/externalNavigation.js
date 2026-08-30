// Copyright 2026 Cloudsmith Ltd. All rights reserved.

/**
 * Open an external target and turn a refused or rejected platform open into a
 * truthful visible outcome. Callers own target validation and freshness.
 *
 * @param {{
 *   target: unknown,
 *   openExternal: (target: unknown) => Promise<boolean>|boolean,
 *   showWarningMessage: (message: string) => Promise<unknown>|unknown,
 *   failureMessage: string,
 *   isCurrent?: () => boolean,
 * }} options
 * @returns {Promise<boolean>}
 */
async function openExternalWithFeedback(options) {
  const {
    target,
    openExternal,
    showWarningMessage,
    failureMessage,
    isCurrent = () => true,
  } = options || {};
  if (
    typeof openExternal !== "function"
    || typeof showWarningMessage !== "function"
    || typeof failureMessage !== "string"
    || failureMessage.length === 0
    || typeof isCurrent !== "function"
  ) {
    throw new TypeError("External navigation requires an opener, warning sink, and failure copy.");
  }
  if (isCurrent() !== true) return false;

  let opened = false;
  try {
    opened = await openExternal(target) === true;
  } catch {
    opened = false;
  }
  if (isCurrent() !== true) return false;
  if (!opened) await showWarningMessage(failureMessage);
  return opened;
}

module.exports = { openExternalWithFeedback };
