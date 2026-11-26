import { SELF } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { dbInit } from '../src/init/init';

const testSecret = 'test-only-init-secret-with-at-least-32-bytes';

function createContext(secret = testSecret) {
	return {
		env: { jwt_secret: secret },
		text(body, status = 200) {
			return new Response(body, { status });
		},
		json(body, status = 200) {
			return new Response(JSON.stringify(body), {
				status,
				headers: { 'Content-Type': 'application/json' }
			});
		}
	};
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe('initialization diagnostics', () => {
	it('logs only the failed stage identifier when a stage throws', async () => {
		const sensitiveError = 'private@example.com and secret-value';
		const intDb = vi.spyOn(dbInit, 'intDB').mockRejectedValue(new Error(sensitiveError));
		const info = vi.spyOn(console, 'info').mockImplementation(() => {});
		const error = vi.spyOn(console, 'error').mockImplementation(() => {});

		await expect(dbInit.init(createContext(), testSecret)).rejects.toThrow(sensitiveError);

		expect(info).toHaveBeenCalledWith('[init] stage=intDB status=started');
		expect(error).toHaveBeenCalledWith('[init] stage=intDB status=failed');
		const logOutput = JSON.stringify([...info.mock.calls, ...error.mock.calls]);
		expect(logOutput).not.toContain('private@example.com');
		expect(logOutput).not.toContain('secret-value');
		expect(intDb).toHaveBeenCalledTimes(1);
	});

	it('returns a real HTTP 500 and a generic body for an unexpected init failure', async () => {
		const sensitiveError = 'private@example.com and secret-value';
		const init = vi.spyOn(dbInit, 'init').mockRejectedValue(new Error(sensitiveError));
		const error = vi.spyOn(console, 'error').mockImplementation(() => {});

		const response = await SELF.fetch('http://example.com/api/init', {
			method: 'POST',
			headers: { 'X-Init-Secret': testSecret }
		});

		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ code: 500, message: 'Initialization failed' });
		expect(error).toHaveBeenCalledWith('[init] stage=handler status=failed');
		const logOutput = JSON.stringify(error.mock.calls);
		expect(logOutput).not.toContain('private@example.com');
		expect(logOutput).not.toContain('secret-value');
		expect(logOutput).not.toContain(testSecret);
		expect(init).toHaveBeenCalledTimes(1);
	});
});
