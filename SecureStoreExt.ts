import * as SecureStore from "./SecureStore.js";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";

declare module "./SecureStore.js" {
	// Add static KeySource method to load key from file
	namespace KeySource {
		/**
		 * Derive decryption keys from the specified file path
		 */
		export function fromKeyFile(path: string): Promise<KeySource>;
	}

	// Add static SecretsManager methods to load vault from file
	namespace SecretsManager {
		/**
		 * Load SecureStore vault from the specified file path, decrypting with the provided password.
		 */
		export function fromPathWithPassword(vaultPath: string, password: string): Promise<SecretsManager>;
		/**
		 * Load SecureStore vault from the specified file path, decrypting with the provided decryption key.
		 */
		export function fromPathWithKey(vaultPath: string, key: Uint8Array | string): Promise<SecretsManager>;
		/**
		 * Load SecureStore vault from the specified file path, decrypting with the decryption key at the specified path.
		 */
		export function fromPathWithKeyFile(vaultPath: string, keyPath: string): Promise<SecretsManager>;
	}
}

SecureStore.KeySource.fromKeyFile = async (path: string) => {
	if (!existsSync(path)) {
		throw new Error(`SecureStore key file not found at ${path}`);
	}

	let keyData: string;
	try {
		keyData = await readFile(path, "utf8");
	} catch (err) {
		throw new Error(`Unable to load SecureStore key from path ${path}`, { cause: err });
	}
	return SecureStore.KeySource.fromKey(keyData);
};

const loadVault = async (path: string) => {
	if (!existsSync(path)) {
		throw new Error(`SecureStore vault not found at ${path}`);
	}

	try {
		return await readFile(path, "utf-8");
	} catch (err) {
		throw new Error(`Error loading SecureStore vault from path ${path}`, { cause: err });
	}
};

SecureStore.SecretsManager.fromPathWithPassword = async (vaultPath, password) => {
	const vaultData = await loadVault(vaultPath);
	return SecureStore.SecretsManager.loadWithPassword(vaultData, password);
};

SecureStore.SecretsManager.fromPathWithKey = async (vaultPath, key) => {
	const vaultData = await loadVault(vaultPath);
	return SecureStore.SecretsManager.loadWithKey(vaultData, key);
};

SecureStore.SecretsManager.fromPathWithKeyFile = async (vaultPath, keyPath) => {
	const vaultData = await loadVault(vaultPath);
	const vaultKey = await SecureStore.KeySource.fromKeyFile(keyPath);
	return SecureStore.SecretsManager.load(vaultData, vaultKey);
};

// Re-export everything exported by SecureStore.js, but use patched versions
// from above where applicable.
export * from "./SecureStore.js";
