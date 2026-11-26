import KvConst from '../const/kv-const';

const encoder = new TextEncoder();

async function publicTokenStorageKey(token) {
	if (typeof token !== 'string' || token.length < 32 || token.length > 512) {
		return null;
	}
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(token)));
	const encoded = btoa(String.fromCharCode(...digest))
		.replace(/=/g, '')
		.replace(/\+/g, '-')
		.replace(/\//g, '_');
	return `${KvConst.PUBLIC_TOKEN_PREFIX}${encoded}`;
}

export default { publicTokenStorageKey };
