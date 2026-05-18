import { beforeEach } from 'vitest';
import '@testing-library/jest-dom/vitest';

const removeStorageItem = (storage: Storage | undefined, key: string): void => {
  if (typeof storage?.removeItem === 'function') {
    storage.removeItem(key);
  }
};

// Reset storage between tests
beforeEach(() => {
  removeStorageItem(globalThis.window?.sessionStorage ?? globalThis.sessionStorage, 'gitnexus-llm-settings');
  removeStorageItem(
    globalThis.window?.localStorage ?? globalThis.localStorage,
    'gitnexus-llm-settings',
  ); // legacy key (migration)
});
