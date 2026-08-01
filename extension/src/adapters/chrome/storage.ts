import type { ExtensionStorageAdapter } from '../../shared/types';

export class ChromeStorageAdapter implements ExtensionStorageAdapter {
  async get<T>(key: string): Promise<T | undefined> {
    const values = await chrome.storage.local.get(key);
    return values[key] as T | undefined;
  }

  async set<T>(key: string, value: T): Promise<void> {
    await chrome.storage.local.set({ [key]: value });
  }

  async remove(key: string): Promise<void> {
    await chrome.storage.local.remove(key);
  }
}
