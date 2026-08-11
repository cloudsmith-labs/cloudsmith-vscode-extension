class FakeSecretStorage {
  constructor(initial = {}, options = {}) {
    this._primaryKey = options.primaryKey || null;
    this._values = new Map(initial instanceof Map ? initial : Object.entries(initial));
    this._listeners = new Set();
    this._failures = { delete: 0, get: 0, store: 0 };
    this._operations = [];
    this.deletedKeys = [];
    this.storeHook = null;
    this.deleteHook = null;
    this.getHook = null;
  }

  get value() {
    return this._primaryKey ? (this._values.get(this._primaryKey) ?? null) : undefined;
  }

  set value(next) {
    if (!this._primaryKey) throw new Error("FakeSecretStorage has no primary key");
    if (next === null || next === undefined) this._values.delete(this._primaryKey);
    else this._values.set(this._primaryKey, next);
  }

  get listeners() {
    return this._listeners;
  }

  onDidChange(listener) {
    if (typeof listener !== "function") throw new TypeError("Secret listener must be a function");
    this._listeners.add(listener);
    return Object.freeze({ dispose: () => this._listeners.delete(listener) });
  }

  async get(key) {
    this._record("get", key);
    this._maybeFail("get");
    if (this.getHook) return this.getHook(key, this);
    return this._values.get(key);
  }

  async store(key, value) {
    this._record("store", key);
    this._maybeFail("store");
    if (this.storeHook) return this.storeHook(key, value, this);
    this._values.set(key, value);
    this._emit(key);
  }

  async delete(key) {
    this._record("delete", key);
    this.deletedKeys.push(key);
    this._maybeFail("delete");
    if (this.deleteHook) return this.deleteHook(key, this);
    this._values.delete(key);
    this._emit(key);
  }

  externalSet(key, value) {
    if (arguments.length === 1) {
      if (!this._primaryKey) throw new Error("FakeSecretStorage has no primary key");
      value = key;
      key = this._primaryKey;
    }
    if (value === undefined) this._values.delete(key);
    else if (value === null) this._values.delete(key);
    else this._values.set(key, value);
    this._emit(key);
  }

  emit(key) {
    this._emit(key);
  }

  failNext(operation, count = 1) {
    if (!Object.prototype.hasOwnProperty.call(this._failures, operation)) {
      throw new TypeError("Unsupported SecretStorage operation");
    }
    if (!Number.isInteger(count) || count < 1) throw new TypeError("Failure count must be positive");
    this._failures[operation] += count;
  }

  peek(key) {
    return this._values.get(key);
  }

  listenerCount() {
    return this._listeners.size;
  }

  get operations() {
    return Object.freeze(this._operations.slice());
  }

  _record(operation, key) {
    this._operations.push(Object.freeze({ operation, key }));
  }

  _maybeFail(operation) {
    if (this._failures[operation] === 0) return;
    this._failures[operation] -= 1;
    throw new Error(`Injected SecretStorage ${operation} failure`);
  }

  _emit(key) {
    const event = Object.freeze({ key });
    for (const listener of [...this._listeners]) listener(event);
  }
}

module.exports = { FakeSecretStorage };
