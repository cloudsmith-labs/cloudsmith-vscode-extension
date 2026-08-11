function createWebviewPanelHarness() {
  const panelCalls = [];
  const htmlWrites = [];
  const messageListeners = new Set();
  const disposeListeners = new Set();
  const allMessageListeners = [];
  const stats = {
    messageDisposals: 0,
    disposeDisposals: 0,
    panelDisposals: 0,
  };
  let panelDisposed = false;

  function subscription(listeners, listener, disposalKey) {
    let disposed = false;
    listeners.add(listener);
    return {
      dispose() {
        if (disposed) return;
        disposed = true;
        listeners.delete(listener);
        stats[disposalKey] += 1;
      },
    };
  }

  const webview = {
    set html(value) { htmlWrites.push(value); },
    get html() { return htmlWrites[htmlWrites.length - 1]; },
    onDidReceiveMessage(listener) {
      allMessageListeners.push(listener);
      return subscription(messageListeners, listener, "messageDisposals");
    },
  };
  const panel = {
    webview,
    onDidDispose(listener) {
      return subscription(disposeListeners, listener, "disposeDisposals");
    },
    dispose() {
      if (panelDisposed) return;
      panelDisposed = true;
      stats.panelDisposals += 1;
      for (const listener of [...disposeListeners]) listener();
    },
  };

  return {
    panel,
    panelCalls,
    htmlWrites,
    stats,
    createWebviewPanel(...args) {
      panelCalls.push(args);
      return panel;
    },
    async send(message) {
      await Promise.all([...messageListeners].map(listener => listener(message)));
    },
    async sendToStaleListener(message, index = 0) {
      const listener = allMessageListeners[index];
      if (listener) await listener(message);
    },
    activeMessageListenerCount() {
      return messageListeners.size;
    },
    activeDisposeListenerCount() {
      return disposeListeners.size;
    },
  };
}

module.exports = { createWebviewPanelHarness };
