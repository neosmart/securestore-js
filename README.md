# SecureStore JS library

This repository/package houses a TypeScript/JavaScript implementation of the cross-platform, language-agnostic [SecureStore secrets specification](https://neosmart.net/SecureStore). In particular, this library may be used for interacting with [SecureStore](https://github.com/neosmart/securestore-rs) secrets containers, providing an easy-to-use and idiomatic interface for loading SecureStore containers and decrypting/retrieving secrets from within your existing JavaScript codebase, and is compatible with both frontend (à la browser) and backend (à la node/bun) code (though you're most likely to use it on the backend).

## Usage

_This JS library is largely intended to be used alongside one of the SecureStore cli companion apps, used to create SecureStore values and manage (add/remove/update) the secrets stored therein. In this example, we'll be using the [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient) cli utility to create a new store._

### Creating a secrets vault

Typical SecureStore usage begins by creating a new SecureStore "vault" (an encrypted secrets container) that will store the credentials (usually both usernames/access keys and passwords/api keys) that your app will need for one or more services. Begin by compiling or downloading and installing a copy of [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient), the SecureStore companion cli.

While you can compile it yourself or manually download [pre-built binaries for your platform](https://github.com/neosmart/securestore-rs/releases), you might find it easiest to just install it with `npm`:

```bash
~> npm install --global @neosmart/ssclient
```

after which you can proceed with the following steps:

```bash
~> mkdir secure/
~> cd secure/
~> ssclient create --export-key secrets.key
Password: ************
Confirm Password: ************

# Now you can use `ssclient -p` with your password or
# `ssclient -k secrets.key` to get or set additional
# secrets with the same keys.
```

### Adding secrets

Secrets may be added with your password or the equivalent encryption key file, and may be specified in-line as arguments to `ssclient` or more securely at a prompt by omitting the value when calling `ssclient create`:

```bash
# ssclient defaults to password-based decryption:
~> ssclient set aws:s3:accessId AKIAV4EXAMPLE7QWERT
Password: *********
```

similarly:

```bash
# Use `-k secrets.key` to load the encryption key and
# skip the prompt for the vault password:
~> ssclient -k secrets.key set aws:s3:accessKey
Value: v1Lp9X7mN2B5vR8zQ4tW1eY6uI0oP3aS5dF7gH9j
```

### Retrieving secrets

Secrets can be retrieved [at the commandline with `ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient) or programmatically with a SecureStore library [for your development language or framework of choice](https://neosmart.net/SecureStore).

This library contains the js/ts implementation of the SecureStore protocol. The SecureStore protocol was intentionally designed to maximize security and compatibility, as such, this library has no external dependencies and can be used either from source or by adding it via the npmjs registry:

```sh
npm install --save @neosmart/securestore
```

after which you can use the library as follows:

```typescript
import { SecretsManager } from "@neosmart/securestore";

const sman = await SecretsManager.fromFile("secure/secrets.json",
                      { keyFile: "secure/secrets.key" });

// Retrieve and decrypt a specific secret
const s3AccessId  = sman.get("aws:s3:accessId");
const s3AccessKey = sman.get("aws:s3:accessKey");

// List all available keys in the vault
for (const key of sman.keys()) {
  console.debug(`* ${key}`);
}
```

#### Notes on browser use

The `SecretsManager.fromFile()`, `KeySource.fromKeyFile()`, and `{ keyFile: string }` `AuthOptions` variants are only available in the backend (when using with node or bun). If using this library from the web or in another environment, you'll need to manually load the store contents and then use `SecretsManager.fromJSON()` instead:

```typescript
import { SecretsManager } from "@neosmart/securestore";

const vaultJson = "..."; // the contents of secure/secrets.json
const vaultKey = "..."; // the contents of secure/secrets.key
const sman = await SecretsManager.fromJSON(vaultJson,
                      { key: "..." });
```

Or, to decrypt with a password interactively:

```typescript
import { SecretsManager } from "@neosmart/securestore";

const vaultJson = "..."; // the contents of secure/secrets.json
const sman = await SecretsManager.fromJSON(vaultJson,
                      { password: "..." });
```

While it is **strongly recommended** to only load secrets programmatically with the encryption key with the `{ keyFile: "path/to/secrets.key" }` or `{ key: Uint8Array }` (where `key` has been securely preloaded) so as to avoid hard-coding any secrets in your code by specifying the path to the encryption key created by `ssclient` via the `--export-key` flag or top-level `ssclient export-key` command, the alternative `KeySource.fromPassword()` and `SecretsManager.fromXxx(..., { password: string })` interfaces are also available – this can be handy if you're developing an interactive tool using SecureStore, for example.

## API overview

The `SecureStore` library provides a high-level interface for decrypting and accessing secrets stored in SecureStore v3 vaults.

### `SecretsManager`
The primary interface for interacting with an encrypted vault.

*   **`fromJSON(json, auth)`** — `Universal`
    Initializes the manager from a raw JSON string (the contents of the SecureStore `secrets.json`).
*   **`fromObject(data, auth)`** — `Universal`
    Initializes the manager from the pre-parsed `VaultData` contents of `secrets.json`.
*   **`fromFile(path, auth)`** — **Backend Only**
    Asynchronously reads and decrypts a vault file from the disk.
*   **`get(name)`** — `Universal`
    Retrieves and decrypts a specific secret by its key. Returns `null` if not found.
*   **`keys()`** — `Universal`
    Returns an array with the names/keys of all secrets stored within the vault.

### `KeySource`
An abstraction for the credentials used to unlock a vault.

*   **`fromPassword(password)`** — `Universal`
    Derives decryption keys from the provided password. Primarily for interactive use.
*   **`fromKey(key)`** — `Universal`
    Loads a "raw" master key, loaded from the SecureStore encryption key into a `Uint8Array` or ASCII-armored string.
*   **`fromKeyFile(path)`** — **Backend Only**
    Reads a master key from the filesystem directly.

### `AuthOptions`
The configuration object used during initialization to specify how vault decryption will take place:

| Property | Type | Env | Description |
| :--- | :--- | :--- | :--- |
| `password` | `string` | `Universal` | Decrypt using a password string. |
| `key` | `Uint8Array` | `Universal` | Decrypt using a raw binary key. |
| `keySource` | `KeySource` | `Universal` | Decrypt using a pre-constructed `KeySource` instance. |
| `keyFile` | `string` | **Backend** | Path to a file containing the decryption key. |
