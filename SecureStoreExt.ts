import * as SecureStore from "./SecureStore.js";
import { SecretsManager, KeySource } from "./SecureStore.js";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";

declare module "./SecureStore.js" {
	// Make the type deductions "just work" based off of browser vs Node/Bun:
	interface EnvTypes {
		hasFs: true,
	}

	// Add static KeySource method to load key from file
	namespace KeySource {
		/**
		 * Derive decryption keys from the specified file path
		 */
		export function fromKeyFile(path: string): Promise<KeySource>;
	}

	// Add new fromFile() entrypoint and extend the others with AuthOptionsExt variants
	namespace SecretsManager {
		/**
		 * Load a SecureStore vault with the decoded contents of the (JSON) SecureStore container.
		 */
		export function fromFile(vaultPath: string, auth: AuthOptions): Promise<SecretsManager>;
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

SecretsManager.fromFile = async (path, auth) => {
	if (!existsSync(path)) {
		throw new Error(`SecureStore vault not found at ${path}`);
	}

	let vaultJson: string;
	try {
		vaultJson = await readFile(path, "utf-8");
	} catch (err) {
		throw new Error(`Error loading SecureStore vault from path ${path}`, { cause: err });
	}
	return SecureStore.SecretsManager.fromJSON(vaultJson, auth);
};

// @ts-expect-error forcibly access private member to patch
const baseAuthResolve = SecretsManager.resolveAuthOptions;
// @ts-expect-error forcibly access private member to patch
SecretsManager.resolveAuthOptions = async (auth: SecureStore.AuthOptions) => {
	let keySource: KeySource;
	if (auth.keyFile) {
		keySource = await KeySource.fromKeyFile(auth.keyFile);
	} else {
		keySource = await baseAuthResolve(auth);
	}
	return keySource;
};

// Re-export everything exported by SecureStore.js, but use patched versions
// from above where applicable.
export * from "./SecureStore.js";
