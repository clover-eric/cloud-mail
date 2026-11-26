const encoder = new TextEncoder();
const decoder = new TextDecoder();

const base64url = (input) => {
	const str = btoa(String.fromCharCode(...new Uint8Array(input)));
	return str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

const base64urlDecode = (str) => {
	str = str.replace(/-/g, '+').replace(/_/g, '/');
	while (str.length % 4) str += '=';
	return Uint8Array.from(atob(str), c => c.charCodeAt(0));
};

function signingSecret(c) {
	const secret = c?.env?.jwt_secret;
	const secretBytes = typeof secret === 'string' ? encoder.encode(secret) : new Uint8Array();
	if (secretBytes.byteLength < 32) {
		throw new Error('JWT_SECRET must be configured with at least 32 bytes of entropy');
	}
	return secretBytes;
}

const jwtUtils = {
	async generateToken(c, payload, expiresInSeconds) {
		if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
			throw new TypeError('JWT payload must be an object');
		}
		if (expiresInSeconds !== undefined && (!Number.isSafeInteger(expiresInSeconds) || expiresInSeconds <= 0)) {
			throw new TypeError('JWT expiry must be a positive integer');
		}

		const header = { alg: 'HS256', typ: 'JWT' };
		const now = Math.floor(Date.now() / 1000);
		const fullPayload = {
			...payload,
			iat: now,
			...(expiresInSeconds !== undefined ? { exp: now + expiresInSeconds } : {})
		};

		const headerStr = base64url(encoder.encode(JSON.stringify(header)));
		const payloadStr = base64url(encoder.encode(JSON.stringify(fullPayload)));
		const data = `${headerStr}.${payloadStr}`;
		const key = await crypto.subtle.importKey(
			'raw',
			signingSecret(c),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);
		const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
		return `${data}.${base64url(signature)}`;
	},

	async verifyToken(c, token) {
		try {
			if (typeof token !== 'string') return null;
			const parts = token.split('.');
			if (parts.length !== 3 || parts.some(part => !part)) return null;
			const [headerB64, payloadB64, signatureB64] = parts;
			const header = JSON.parse(decoder.decode(base64urlDecode(headerB64)));
			if (header?.alg !== 'HS256' || header?.typ !== 'JWT') return null;

			const data = `${headerB64}.${payloadB64}`;
			const key = await crypto.subtle.importKey(
				'raw',
				signingSecret(c),
				{ name: 'HMAC', hash: 'SHA-256' },
				false,
				['verify']
			);
			const valid = await crypto.subtle.verify(
				'HMAC',
				key,
				base64urlDecode(signatureB64),
				encoder.encode(data)
			);
			if (!valid) return null;

			const payload = JSON.parse(decoder.decode(base64urlDecode(payloadB64)));
			if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
			const now = Math.floor(Date.now() / 1000);
			if (payload.exp !== undefined && (!Number.isSafeInteger(payload.exp) || payload.exp <= now)) return null;
			if (payload.nbf !== undefined && (!Number.isSafeInteger(payload.nbf) || payload.nbf > now)) return null;
			return payload;
		} catch {
			return null;
		}
	}
};

export default jwtUtils;
