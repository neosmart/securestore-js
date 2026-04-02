import { SecretsManager, KeySource } from './SecureStore.js';
import fs from 'node:fs';

const vaultJson = fs.readFileSync('vault.json', 'utf8');
{
	let manager = await SecretsManager.load(vaultJson, KeySource.fromPassword('password123'));

	let apiKey = await manager.get('foo');
	console.log(apiKey);
}

{
	const vaultKey = fs.readFileSync('../secrets.key', 'utf8');
	let manager = await SecretsManager.load(vaultJson, KeySource.fromKey(vaultKey));

	let apiKey = await manager.get('foo');
	console.log(apiKey);
}
