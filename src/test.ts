import * as SecureStore from "./SecureStore.js";
import fs from "node:fs/promises";
import { existsSync } from "node:fs";

declare module "./SecureStore.js" {
	namespace KeySource {
		/**
		 * Derive decryption keys from the specified file path
		 */
		export function fromKeyFile(path: string): Promise<KeySource>;
	}
}

SecureStore.KeySource.fromKeyFile = async (path: string) => {
	if (!existsSync(path)) {
		throw new Error(`SecureStore key file not found at ${path}`);
	}
	try {
		const key = await fs.readFile(path, "utf8");
		return SecureStore.KeySource.fromKey(key);
	} catch (err) {
		throw new Error(`Unable to load SecureStore key from path ${path}`, { cause: err });
	}
}

// Re-export everything exported by SecureStore.js, but use patched versions
// from above where applicable.
export * from "./SecureStore.js";
