const MASTER_KEY_LEN = 16 * 2;

/**
 * An encrypted entry in the SecureStore JSON vault
 */
export interface VaultEntry {
    readonly iv: string;
    readonly hmac: string;
    readonly payload: string;
}

/**
 * SecureStore secrets vault schema
 */
export interface VaultData {
    readonly version: number;
    readonly iv: string;
    readonly sentinel: VaultEntry;
    readonly secrets: Record<string, VaultEntry>;
}
type SafeVaultData = {
  [K in keyof VaultData]: VaultData[K] | null;
};

/**
 * An abstraction over SecureStore password- or key-based decryption
 */
export class KeySource {
    public static readonly TYPE_PASSWORD = 'password';
    public static readonly TYPE_KEY = 'key';

    public readonly type: typeof KeySource.TYPE_PASSWORD | typeof KeySource.TYPE_KEY;
    public readonly value: Uint8Array;

    private constructor(type: typeof KeySource.TYPE_PASSWORD | typeof KeySource.TYPE_KEY, value: Uint8Array) {
        this.type = type;
        this.value = value;
    }

    /**
     * Derive decryption keys from the provided password
     */
    public static fromPassword(password: string): KeySource {
        return new KeySource(this.TYPE_PASSWORD, new TextEncoder().encode(password));
    }

    /**
     * Load decryption key from a decryption key.
     * Handles raw binary (Uint8Array), Arrays, and ASCII-armored keys.
     */
    public static fromKey(key: Uint8Array | number[] | string): KeySource {
        let buffer: Uint8Array;

        if (Array.isArray(key)) {
            buffer = new Uint8Array(key);
        } else if (typeof key === 'string') {
            if (key.includes('--BEGIN')) {
                const match = key.match(/--+BEGIN.*?KEY--+([\s\S]*?)--+END.*?KEY--+/);
                const base64Content = match?.[1]?.replace(/\s/g, '');
                if (base64Content) {
                    const binaryString = atob(base64Content);
                    buffer = Uint8Array.from(binaryString, c => c.charCodeAt(0));
                } else {
                    throw new Error("Invalid ASCII-armored vault decryption key");
                }
            } else {
                buffer = new TextEncoder().encode(key);
            }
        } else {
            buffer = key;
        }

        if (buffer.length === MASTER_KEY_LEN) {
            return new KeySource(this.TYPE_KEY, buffer);
        }

        throw new Error("Invalid SecureStore decryption key provided");
    }
}

// Used to control node/bun type injection, overridden in `SecureStoreExt.ts`
export interface EnvTypes {}

type KeyFileOption = EnvTypes extends { hasFs: true }
    ? { keyFile: string; password?: never; key?: never; keySource?: never }
    : never;

export type AuthOptions =
    | { password: string; key?: never; keySource?: never; keyFile?: never }
    | { key: Uint8Array; password?: never; keySource?: never; keyFile?: never }
    | { keySource: KeySource; password?: never; key?: never; keyFile?: never }
    | KeyFileOption; // `never` in the browser

/**
 * SecretsManager instances are used to load and decrypt secrets from SecureStore vaults.
 */
export class SecretsManager {
    private static readonly PBKDF2_ROUNDS = 256000;

    private readonly aesKey: CryptoKey;
    private readonly hmacKey: CryptoKey;
    private readonly secrets: Record<string, VaultEntry>;

    private constructor(aesKey: CryptoKey, hmacKey: CryptoKey, secrets: Record<string, VaultEntry>) {
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.secrets = secrets;
    }

    /**
     * Load a SecureStore vault with the contents of the (JSON) SecureStore container.
     */
    public static async fromJSON(vaultJson: string, auth: AuthOptions): Promise<SecretsManager> {
        let vaultData: VaultData;
        try {
            vaultData = JSON.parse(vaultJson);
        } catch {
            throw new Error("Invalid SecureStore vault JSON provided!");
        }
        return await SecretsManager.load(vaultData, auth);
    }

    /**
     * Load a SecureStore vault with the decoded contents of the (JSON) SecureStore container.
     */
    public static async fromObject(vaultData: VaultData, auth: AuthOptions): Promise<SecretsManager> {
        return await SecretsManager.load(vaultData, auth);
    }

    /**
     * Extract a `KeySource` from the provided `AuthOptions`
     */
    private static async resolveAuthOptions(auth: AuthOptions): Promise<KeySource> {
        let keySource: KeySource;
        if (auth.password) {
            keySource = KeySource.fromPassword(auth.password);
        } else if (auth.key) {
            keySource = KeySource.fromKey(auth.key);
        } else if (auth.keySource) {
            keySource = auth.keySource;
        } else {
            throw new Error("Invalid, missing, or unrecognized SecureStore decryption method!");
        }
        return keySource;
    }

    private static async load(vaultData: VaultData, auth: AuthOptions): Promise<SecretsManager> {
        const vault: SafeVaultData = vaultData;

        if ((vault.version ?? 0) !== 3) {
            throw new Error("Unsupported SecureStore version. This library supports v3.");
        }

        // Derive or load the 32-byte master key
        const keySource = await SecretsManager.resolveAuthOptions(auth);
        const masterKeyBytes = await this.resolveMasterKey(keySource, vault.iv ?? null);

        if (masterKeyBytes.byteLength < MASTER_KEY_LEN) {
            throw new Error(`Invalid key length. Expected at least ${MASTER_KEY_LEN} bytes.`);
        }

        // Split master key (16-byte AES-128 key, 16-byte HMAC-SHA1 key)
        const aesRaw = masterKeyBytes.slice(0, 16) as BufferSource;
        const hmacRaw = masterKeyBytes.slice(16, 32) as BufferSource;

        // Import keys into Web Crypto format (compatible with browser, node, bun, and deno)
        const aesKey = await crypto.subtle.importKey("raw", aesRaw, "AES-CBC", false, ["decrypt"]);
        const hmacKey = await crypto.subtle.importKey("raw", hmacRaw, { name: "HMAC", hash: "SHA-1" }, false, ["verify", "sign"]);

        // Verify the correct password was provided via the (optional) sentinel
        if (vault.sentinel) {
            try {
                await this.decryptEntry(vault.sentinel, aesKey, hmacKey);
            } catch {
                throw new Error("SecureStore load failure: invalid key or password.");
            }
        }

        return new SecretsManager(aesKey, hmacKey, vault.secrets ?? {});
    }

    /**
     * Retrieve and decrypt a single named secret from the vault.
     * Returns `null` if no such secret exists in the vault.
     */
    public async get(name: string): Promise<string | null> {
        const entry = this.secrets[name];
        if (!entry) {
            return null;
        }
        return await SecretsManager.decryptEntry(entry, this.aesKey, this.hmacKey);
    }

    /**
     * Retrieve a list of all keys in the vault.
     */
    public keys(): string[] {
        return Object.keys(this.secrets);
    }

    private static async decryptEntry(entry: VaultEntry, aesKey: CryptoKey, hmacKey: CryptoKey): Promise<string> {
        const iv = this.base64ToBytes(entry.iv);
        const mac = this.base64ToBytes(entry.hmac);
        const ciphertext = this.base64ToBytes(entry.payload);

        const combined = new Uint8Array(iv.length + ciphertext.length);
        combined.set(iv);
        combined.set(ciphertext, iv.length);

        const isValid = await crypto.subtle.verify("HMAC", hmacKey, mac as BufferSource, combined as BufferSource);

        if (!isValid) {
            throw new Error("Integrity check failed (HMAC mismatch).");
        }

        // Decrypt: AES-128-CBC with PKCS#7 padding
        try {
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-CBC", iv: iv as BufferSource },
                aesKey,
                ciphertext as BufferSource
            );
            return new TextDecoder().decode(decrypted);
        } catch (e) {
            const msg = e instanceof Error ? e.message : "Unknown error";
            throw new Error(`Secret decryption failed: ${msg}`);
        }
    }

    private static async resolveMasterKey(source: KeySource, base64Salt: string | null): Promise<Uint8Array> {
        if (source.type === KeySource.TYPE_KEY) {
            return source.value;
        }

        if (!base64Salt) {
            throw new Error("Vault missing vault property 'iv' required for password decryption.");
        }

        const salt = this.base64ToBytes(base64Salt);
        const baseKey = await crypto.subtle.importKey(
            "raw",
            source.value as BufferSource,
            "PBKDF2",
            false,
            ["deriveBits"]
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: salt as BufferSource,
                iterations: this.PBKDF2_ROUNDS,
                hash: "SHA-1"
            },
            baseKey,
            MASTER_KEY_LEN * 8
        );

        return new Uint8Array(derivedBits);
    }

    private static base64ToBytes(base64: string): Uint8Array {
        const binaryString = atob(base64);
        return Uint8Array.from(binaryString, c => c.charCodeAt(0));
    }
}
