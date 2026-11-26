import { env } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';
import attService from '../src/service/att-service';
import jwtUtils from '../src/utils/jwt-utils';

const jwtSecret = 'test-only-signing-secret-at-least-32-bytes';
const context = {
	env: {
		jwt_secret: jwtSecret,
		db: env.db,
		kv: env.kv,
		domain: ['example.com'],
		project_link: false
	}
};

beforeAll(async () => {
	await env.db.prepare(`
		CREATE TABLE IF NOT EXISTS attachments (
			att_id INTEGER PRIMARY KEY,
			user_id INTEGER NOT NULL,
			key TEXT NOT NULL
		)
	`).run();
	await env.kv.put('setting:', JSON.stringify({
		bucket: '',
		endpoint: '',
		s3AccessKey: '',
		s3SecretKey: '',
		emailPrefixFilter: '',
		autoRefresh: 2
	}));
});

async function createAttachment({ key, userId = 42 } = {}) {
	const attachmentId = Math.floor(Math.random() * 1_000_000_000) + 1;
	const objectKey = key || `attachments/test-${crypto.randomUUID()}.bin`;
	await env.db.prepare('INSERT INTO attachments (att_id, user_id, key) VALUES (?, ?, ?)')
		.bind(attachmentId, userId, objectKey)
		.run();
	await env.kv.put(objectKey, 'authorized attachment body', {
		metadata: { contentType: 'application/octet-stream', contentDisposition: 'attachment' }
	});
	return { attachmentId, objectKey, userId };
}

async function createToken(payload, expiresInSeconds = 3600) {
	return jwtUtils.generateToken(context, payload, expiresInSeconds);
}

describe('signed attachment access', () => {
	it('serves an existing attachment only for its matching signed token and disables caching', async () => {
		const attachment = await createAttachment();
		const token = await createToken({
			purpose: 'attachment-download',
			attId: attachment.attachmentId,
			userId: attachment.userId,
			key: attachment.objectKey
		});

		const response = await attService.toAuthorizedObjResp(context, attachment.objectKey, token);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe('authorized attachment body');
		expect(response.headers.get('Cache-Control')).toBe('private, no-store');
		expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
	});

	it('rejects wrong-purpose, mismatched-key, mismatched-record and expired tokens', async () => {
		const attachment = await createAttachment();
		const base = {
			attId: attachment.attachmentId,
			userId: attachment.userId,
			key: attachment.objectKey
		};
		const wrongPurpose = await createToken({ ...base, purpose: 'telegram-email' });
		const wrongKey = await createToken({ ...base, purpose: 'attachment-download', key: 'attachments/other.bin' });
		const wrongRecord = await createToken({ ...base, purpose: 'attachment-download', attId: attachment.attachmentId + 1 });
		const expired = await createToken({ ...base, purpose: 'attachment-download' }, 1);
		await new Promise(resolve => setTimeout(resolve, 1_100));

		expect(await attService.toAuthorizedObjResp(context, attachment.objectKey, wrongPurpose)).toBeNull();
		expect(await attService.toAuthorizedObjResp(context, attachment.objectKey, wrongKey)).toBeNull();
		expect(await attService.toAuthorizedObjResp(context, attachment.objectKey, wrongRecord)).toBeNull();
		expect(await attService.toAuthorizedObjResp(context, attachment.objectKey, expired)).toBeNull();
	});
});
