import { env, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import constant from '../src/const/constant';
import publicTokenUtils from '../src/utils/public-token';

async function storePublicToken(scopes, expiresAt = Date.now() + 60_000) {
	const token = `public-test-${crypto.randomUUID()}`;
	const key = await publicTokenUtils.publicTokenStorageKey(token);
	await env.kv.put(key, JSON.stringify({ scopes, expiresAt }), { expirationTtl: 60 });
	return { token, key };
}

async function postPublic(path, token, body) {
	return SELF.fetch(`http://example.com/api/public/${path}`, {
		method: 'POST',
		headers: {
			[constant.TOKEN_HEADER]: token,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(body)
	});
}

describe('attachment routes', () => {
	it.each([
		'/oss/attachments/private-file.bin',
		'/attachments/private-file.bin',
		'/api/oss/attachments/private-file.bin',
	])('rejects unauthenticated downloads from %s', async path => {
		const response = await SELF.fetch(`http://example.com${path}`);
		expect(response.status).toBe(404);
	});
});

describe('public API token scopes', () => {
	it('allows user:create only on the user creation endpoint', async () => {
		const createUserToken = await storePublicToken(['user:create']);
		const allowed = await postPublic('addUser', createUserToken.token, { list: [] });
		expect((await allowed.json()).code).toBe(200);

		const emailReadToken = await storePublicToken(['email:read']);
		const denied = await postPublic('addUser', emailReadToken.token, { list: [] });
		expect((await denied.json()).code).toBe(403);
	});

	it('rejects and deletes expired public tokens', async () => {
		const expired = await storePublicToken(['user:create'], Date.now() - 1);
		const response = await postPublic('addUser', expired.token, { list: [] });

		expect((await response.json()).code).toBe(401);
		expect(await env.kv.get(expired.key)).toBeNull();
	});
});
