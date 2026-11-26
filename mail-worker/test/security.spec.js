import { describe, expect, it } from 'vitest';
import cryptoUtils from '../src/utils/crypto-utils';
import jwtUtils from '../src/utils/jwt-utils';
import publicTokenUtils from '../src/utils/public-token';
import attService from '../src/service/att-service';

const validContext = { env: { jwt_secret: 'test-only-signing-secret-at-least-32-bytes' } };

describe('security primitives', () => {
	it('stores new passwords as PBKDF2-SHA-256 and verifies them', async () => {
		const password = 'correct horse battery staple';
		const { salt, hash } = await cryptoUtils.hashPassword(password);

		expect(hash).toMatch(/^pbkdf2-sha256\$600000\$/);
		expect(await cryptoUtils.verifyPassword(password, salt, hash)).toBe(true);
		expect(await cryptoUtils.verifyPassword('incorrect password', salt, hash)).toBe(false);
		expect(cryptoUtils.needsRehash(hash)).toBe(false);
	});

	it('still verifies legacy SHA-256 records so login can migrate them', async () => {
		const salt = cryptoUtils.generateSalt();
		const hash = await cryptoUtils.genHashPassword('legacy-password', salt);

		expect(await cryptoUtils.verifyPassword('legacy-password', salt, hash)).toBe(true);
		expect(await cryptoUtils.verifyPassword('wrong-password', salt, hash)).toBe(false);
		expect(cryptoUtils.needsRehash(hash)).toBe(true);
	});

	it('rejects JWT signing secrets shorter than 32 bytes', async () => {
		await expect(jwtUtils.generateToken({ env: { jwt_secret: 'short' } }, { sub: 'test' }))
			.rejects.toThrow('at least 32 bytes');
	});

	it('verifies purpose-marked JWTs and rejects them after expiry', async () => {
		const token = await jwtUtils.generateToken(validContext, {
			purpose: 'telegram-email',
			emailId: 42
		}, 1);

		expect((await jwtUtils.verifyToken(validContext, token))?.purpose).toBe('telegram-email');
		await new Promise(resolve => setTimeout(resolve, 1_100));
		expect(await jwtUtils.verifyToken(validContext, token)).toBeNull();
	});

	it('stores only a one-way fingerprint as the public token KV key', async () => {
		const token = 'a'.repeat(43);
		const key = await publicTokenUtils.publicTokenStorageKey(token);

		expect(key).toMatch(/^public_token:/);
		expect(key).not.toContain(token);
		expect(await publicTokenUtils.publicTokenStorageKey('short')).toBeNull();
	});

	it('signs ordinary and inline attachment URLs and rewrites full email content', async () => {
		const context = {
			...validContext,
			req: { url: 'https://mail.example/api/star/list?full=1' }
		};
		const emailRows = [{
			emailId: 7,
			userId: 42,
			content: '<img src="{{domain}}attachments/inline image.png"><a href="{{domain}}attachments/report.pdf">report</a>'
		}];
		const attachments = [
			{ attId: 11, emailId: 7, userId: 42, key: 'attachments/inline image.png', filename: 'inline image.png', type: 1 },
			{ attId: 12, emailId: 7, userId: 42, key: 'attachments/report.pdf', filename: 'report.pdf', type: 0 }
		];

		await attService.addEmailDownloadUrls(context, emailRows, attachments);

		expect(emailRows[0].attList).toHaveLength(1);
		expect(emailRows[0].attList[0].filename).toBe('report.pdf');
		expect(emailRows[0].content).not.toContain('{{domain}}');
		for (const attachment of attachments) {
			const url = new URL(attachment.downloadUrl);
			const token = await jwtUtils.verifyToken(context, url.searchParams.get('token'));
			expect(url.origin).toBe('https://mail.example');
			expect(url.pathname).toBe(`/oss/${attachment.key.split('/').map(encodeURIComponent).join('/')}`);
			expect(token).toMatchObject({
				purpose: 'attachment-download',
				attId: attachment.attId,
				userId: attachment.userId,
				key: attachment.key
			});
			expect(token.exp - token.iat).toBe(60 * 60);
			expect(emailRows[0].content).toContain(attachment.downloadUrl);
		}
	});
});
