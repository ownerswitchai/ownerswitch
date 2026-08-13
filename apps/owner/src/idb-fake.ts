/**
 * TEST-ONLY in-memory IndexedDB fake — exactly the API surface
 * owner-runtime.mjs touches (open/upgrade, transaction, objectStore
 * get/put/add, close), with the two semantics the custody tests exist to
 * exercise: state SHARED across opens (a "reload" sees what was written)
 * and `add` refusing an existing key with ConstraintError (the atomic
 * create-if-absent the key race depends on).
 */

class FakeConstraintError extends Error {
  override name = "ConstraintError";
}

type Store = Map<string, unknown>;
const databases = new Map<string, Map<string, Store>>();

/** wipe all fake databases — call between tests */
export function resetFakeIndexedDb(): void {
  databases.clear();
}

class FakeRequest {
  onsuccess: ((event: unknown) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onupgradeneeded: ((event: unknown) => void) | null = null;
  result: unknown;
  error: Error | null = null;
}

class FakeTransaction {
  oncomplete: (() => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onabort: (() => void) | null = null;
  error: Error | null = null;
  #stores: Map<string, Store>;
  #failed = false;

  constructor(stores: Map<string, Store>) {
    this.#stores = stores;
    queueMicrotask(() => queueMicrotask(() => {
      if (!this.#failed) this.oncomplete?.();
    }));
  }

  objectStore(name: string) {
    const store = this.#stores.get(name);
    if (store === undefined) throw new Error(`no object store ${name}`);
    const fail = (error: Error) => {
      this.#failed = true;
      this.error = error;
      queueMicrotask(() => {
        this.onerror?.({ target: { error } });
        this.onabort?.();
      });
    };
    return {
      get: (key: string) => {
        const request = new FakeRequest();
        queueMicrotask(() => {
          request.result = store.get(key);
          request.onsuccess?.({ target: request });
        });
        return request;
      },
      put: (value: unknown, key: string) => {
        const request = new FakeRequest();
        queueMicrotask(() => {
          if (!this.#failed) {
            store.set(key, value);
            request.onsuccess?.({ target: request });
          }
        });
        return request;
      },
      add: (value: unknown, key: string) => {
        const request = new FakeRequest();
        queueMicrotask(() => {
          if (this.#failed) return;
          if (store.has(key)) {
            const error = new FakeConstraintError(`key ${key} exists`);
            request.error = error;
            request.onerror?.({ target: request });
            fail(error);
            return;
          }
          store.set(key, value);
          request.onsuccess?.({ target: request });
        });
        return request;
      },
    };
  }
}

class FakeDatabase {
  #stores: Map<string, Store>;
  constructor(stores: Map<string, Store>) {
    this.#stores = stores;
  }
  createObjectStore(name: string) {
    if (!this.#stores.has(name)) this.#stores.set(name, new Map());
  }
  transaction(name: string, _mode?: string) {
    return new FakeTransaction(this.#stores);
  }
  close() {
    /* state lives in the module map — a reopen sees it, as on disk */
  }
}

export const fakeIndexedDb = {
  open(name: string, _version?: number) {
    const request = new FakeRequest();
    queueMicrotask(() => {
      let stores = databases.get(name);
      const isNew = stores === undefined;
      if (stores === undefined) {
        stores = new Map();
        databases.set(name, stores);
      }
      const db = new FakeDatabase(stores);
      request.result = db;
      if (isNew) request.onupgradeneeded?.({ target: request });
      request.onsuccess?.({ target: request });
    });
    return request;
  },
};

/** install on globalThis for modules that read the `indexedDB` global */
export function installFakeIndexedDb(): void {
  (globalThis as Record<string, unknown>).indexedDB = fakeIndexedDb;
  // navigator.storage.persist is best-effort in the runtime; give it a stub
  const nav = (globalThis as Record<string, unknown>).navigator as Record<string, unknown> | undefined;
  if (nav === undefined) {
    (globalThis as Record<string, unknown>).navigator = { storage: { persist: async () => true } };
  } else if (nav.storage === undefined) {
    try {
      Object.defineProperty(nav, "storage", { value: { persist: async () => true }, configurable: true });
    } catch {
      /* a read-only platform navigator without storage — the runtime treats it as best-effort */
    }
  }
}
