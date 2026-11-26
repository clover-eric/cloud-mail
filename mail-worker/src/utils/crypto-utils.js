const encoder = new TextEncoder();
const PASSWORD_SCHEME = 'pbkdf2-sha256';
// Cloudflare Workers production Web Crypto rejects PBKDF2 counts above 100,000.
const PBKDF2_ITERATIONS = 100_000;
const MAX_VERIFY_ITERATIONS = 100_000;

function toBase64(bytes) {
	return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function constantTimeEqual(left, right) {
	if (typeof left !== 'string' || typeof right !== 'string') return false;
	let diff = left.length ^ right.length;
	const length = Math.max(left.length, right.length);
	for (let i = 0; i < length; i++) {
		diff |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
	}
	return diff === 0;
}

async function derivePbkdf2(password, salt, iterations) {
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(password),
		'PBKDF2',
		false,
		['deriveBits']
	);
	return new Uint8Array(await crypto.subtle.deriveBits({
		name: 'PBKDF2',
		hash: 'SHA-256',
		salt: encoder.encode(salt),
		iterations
	}, key, 256));
}

const saltHashUtils = {

	generateSalt(length = 16) {
		const array = new Uint8Array(length);
		crypto.getRandomValues(array);
		return toBase64(array);
	},

	async hashPassword(password) {
		const salt = this.generateSalt();
		const derived = await derivePbkdf2(String(password), salt, PBKDF2_ITERATIONS);
		return { salt, hash: `${PASSWORD_SCHEME}$${PBKDF2_ITERATIONS}$${toBase64(derived)}` };
	},

	// Kept only to verify and migrate existing SHA-256 password records.
	async genHashPassword(password, salt) {
		const data = encoder.encode(String(salt) + String(password));
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		return toBase64(hashBuffer);
	},

	async verifyPassword(inputPassword, salt, storedHash) {
		if (typeof storedHash !== 'string' || typeof salt !== 'string') return false;

		if (storedHash.startsWith(`${PASSWORD_SCHEME}$`)) {
			const [, iterationText, expectedHash, ...extra] = storedHash.split('$');
			const iterations = Number(iterationText);
			if (extra.length || !Number.isInteger(iterations) || iterations < 100_000 || iterations > MAX_VERIFY_ITERATIONS || !expectedHash) {
				return false;
			}
			const actualHash = toBase64(await derivePbkdf2(String(inputPassword), salt, iterations));
			return constantTimeEqual(actualHash, expectedHash);
		}

		const legacyHash = await this.genHashPassword(inputPassword, salt);
		return constantTimeEqual(legacyHash, storedHash);
	},

	needsRehash(storedHash) {
		if (typeof storedHash !== 'string') return true;
		const [scheme, iterationText] = storedHash.split('$');
		if (scheme !== PASSWORD_SCHEME) return true;
		const iterations = Number(iterationText);
		return !Number.isInteger(iterations) || iterations < PBKDF2_ITERATIONS || iterations > MAX_VERIFY_ITERATIONS;
	},

	genRandomPwd(length = 8) {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const maxByte = 256 - (256 % chars.length);
		let result = '';
		while (result.length < length) {
			const bytes = new Uint8Array(Math.max(16, (length - result.length) * 2));
			crypto.getRandomValues(bytes);
			for (const byte of bytes) {
				if (byte < maxByte) result += chars[byte % chars.length];
				if (result.length === length) break;
			}
		}
		return result;
	}
};

export default saltHashUtils;
