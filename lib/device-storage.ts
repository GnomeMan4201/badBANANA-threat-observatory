export interface DeviceStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export type DeviceStorageFactory = () => DeviceStorage | null | undefined;

export function readDeviceStorage(factory: DeviceStorageFactory, key: string): string | null {
  try {
    return factory()?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export function writeDeviceStorage(factory: DeviceStorageFactory, key: string, value: string): boolean {
  try {
    const storage = factory();
    if (!storage) return false;
    storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}
