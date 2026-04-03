import { SecretsManager } from './SecureStoreExt';
import { execSync } from 'node:child_process';
import { rmSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert';
import { test, describe, before, after } from 'node:test';

describe('SecureStore Node.js Integration', () => {
    const TEST_PASSWORD = 'correct-horse-battery-staple';
    const TEST_KEY = 'test-label';
    const TEST_SECRET = 'this-is-a-very-secure-payload';
    const NEW_LABEL = 'app-api-key';
    const NEW_SECRET = 'sk_live_51Mabc123';

    let tempDir: string;
    let storePath: string;
    let keyPath: string;

    // Helper to run ssclient CLI commands
    const runCli = (args: string): string => {
        try {
            // We use toString().trim() to handle the output consistently
            return execSync(`ssclient ${args}`, { encoding: 'utf-8' }).trim();
        } catch (e: any) {
            throw new Error(`CLI execution failed: ${e.stderr || e.message}`);
        }
    };

    before(() => {
        // Create a temporary workspace for test files
        tempDir = mkdtempSync(join(tmpdir(), 'securestore-test-'));
        storePath = join(tempDir, 'test.ss');
        keyPath = join(tempDir, 'test.key');
    });

    after(() => {
        // Cleanup temporary files
        try {
            rmSync(tempDir, { recursive: true, force: true });
        } catch (err) {
            console.error('Cleanup failed', err);
        }
    });

    test('Compatibility: Read store created by ssclient CLI with password', async () => {
        runCli(`create -s "${storePath}" -p "${TEST_PASSWORD}" --no-vcs`);
        runCli(`set -s "${storePath}" -p "${TEST_PASSWORD}" "${TEST_KEY}" "${TEST_SECRET}"`);

        const store: SecretsManager = await SecretsManager.fromFile(storePath, { password: TEST_PASSWORD });

        const decrypted = await store.get(TEST_KEY);
        assert.strictEqual(decrypted, TEST_SECRET, 'Library should decrypt CLI-created secret correctly');
    });

    test('Compatibility: Read store created by ssclient CLI with password', async () => {
        runCli(`create -s "${storePath}" -p "${TEST_PASSWORD}" --export-key "${keyPath}" --no-vcs`);
        runCli(`set -s "${storePath}" -p "${TEST_PASSWORD}" "${TEST_KEY}" "${TEST_SECRET}"`);

        const store: SecretsManager = await SecretsManager.fromFile(storePath, { keyFile: keyPath });

        const decrypted = await store.get(TEST_KEY);
        assert.strictEqual(decrypted, TEST_SECRET, 'Library should decrypt CLI-created secret correctly');
    });

    test('Security: Incorrect password throws error', async () => {
        const wrongPassword = 'this-is-not-the-password';

        // SecureStore should reject the load due to MAC failure
        await assert.rejects(
            async () => {
                await SecretsManager.fromFile(storePath, { password: wrongPassword });
            },
            { name: 'Error' },
            'Should throw error when using an incorrect password'
        );
    });

    test('Functionality: Multiple keys retrieval', async () => {
        runCli(`create -s "${storePath}" -p "${TEST_PASSWORD}"`);
        runCli(`set -s "${storePath}" -p "${TEST_PASSWORD}" "${TEST_KEY}" "${TEST_SECRET}"`);
        runCli(`set -s "${storePath}" -p "${TEST_PASSWORD}" "${NEW_LABEL}" "${NEW_SECRET}"`);

        const store: SecretsManager = await SecretsManager.fromFile(storePath, { password: TEST_PASSWORD });

        const keys = store.keys();
        if (keys instanceof Array) {
            assert.ok(keys.includes(TEST_KEY));
            assert.ok(keys.includes(NEW_LABEL));
        }

        assert.strictEqual(await store.get(TEST_KEY), TEST_SECRET);
        assert.strictEqual(await store.get(NEW_LABEL), NEW_SECRET);
    });
});
