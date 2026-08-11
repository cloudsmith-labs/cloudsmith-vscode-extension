class FakeMemento {
  constructor(initial = {}) {
    this._values = new Map(initial instanceof Map ? initial : Object.entries(initial));
    this._updates = [];
    this._failures = 0;
  }

  get(key, defaultValue) {
    return this._values.has(key) ? this._values.get(key) : defaultValue;
  }

  keys() {
    return [...this._values.keys()];
  }

  async update(key, value) {
    this._updates.push(Object.freeze({ key, deleted: value === undefined }));
    if (this._failures > 0) {
      this._failures -= 1;
      throw new Error("Injected Memento update failure");
    }
    if (value === undefined) this._values.delete(key);
    else this._values.set(key, value);
  }

  failNextUpdate(count = 1) {
    if (!Number.isInteger(count) || count < 1) throw new TypeError("Failure count must be positive");
    this._failures += count;
  }

  get updates() {
    return Object.freeze(this._updates.slice());
  }
}

module.exports = { FakeMemento };
