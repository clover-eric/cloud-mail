import assert from 'node:assert/strict';
import test from 'node:test';

import {
  InitAuthorizationError,
  PRODUCTION_INIT_URL,
  REQUIRED_CONFIRMATION,
  postInitOnce,
} from './initialize-production-once.mjs';

const testEnv = {
  RUN_INIT_ONCE: 'true',
  CONFIRM_INIT_ONCE: REQUIRED_CONFIRMATION,
  CONFIRM_PRODUCTION_DEPLOY: 'false',
  JWT_SECRET: 'test-only-not-a-production-secret',
};

test('does not send a request unless the boolean input is explicitly true', async () => {
  let calls = 0;
  await assert.rejects(
    postInitOnce({
      env: { ...testEnv, RUN_INIT_ONCE: 'false' },
      fetchImpl: async () => { calls += 1; return { status: 200 }; },
    }),
    InitAuthorizationError,
  );
  assert.equal(calls, 0);
});

test('does not send a request unless the confirmation matches exactly', async () => {
  let calls = 0;
  await assert.rejects(
    postInitOnce({
      env: { ...testEnv, CONFIRM_INIT_ONCE: `${REQUIRED_CONFIRMATION} ` },
      fetchImpl: async () => { calls += 1; return { status: 200 }; },
    }),
    InitAuthorizationError,
  );
  assert.equal(calls, 0);
});

test('does not initialize in the same dispatch that confirms a production deployment', async () => {
  let calls = 0;
  await assert.rejects(
    postInitOnce({
      env: { ...testEnv, CONFIRM_PRODUCTION_DEPLOY: 'true' },
      fetchImpl: async () => { calls += 1; return { status: 200 }; },
    }),
    InitAuthorizationError,
  );
  assert.equal(calls, 0);
});

test('does not send a request without the JWT secret', async () => {
  let calls = 0;
  await assert.rejects(
    postInitOnce({
      env: { ...testEnv, JWT_SECRET: '' },
      fetchImpl: async () => { calls += 1; return { status: 200 }; },
    }),
    InitAuthorizationError,
  );
  assert.equal(calls, 0);
});

test('sends exactly one POST to the fixed production endpoint with redirects disabled', async () => {
  let calls = 0;
  let capturedUrl;
  let capturedOptions;

  const status = await postInitOnce({
    env: testEnv,
    fetchImpl: async (url, options) => {
      calls += 1;
      capturedUrl = url;
      capturedOptions = options;
      return { status: 200 };
    },
  });

  assert.equal(calls, 1);
  assert.equal(capturedUrl, PRODUCTION_INIT_URL);
  assert.equal(capturedOptions.method, 'POST');
  assert.deepEqual(capturedOptions.headers, { 'X-Init-Secret': testEnv.JWT_SECRET });
  assert.equal(capturedOptions.redirect, 'error');
  assert.ok(capturedOptions.signal instanceof AbortSignal);
  assert.equal(status, 200);
});

test('does not retry when the single request fails', async () => {
  let calls = 0;
  await assert.rejects(
    postInitOnce({
      env: testEnv,
      fetchImpl: async () => {
        calls += 1;
        throw new Error('simulated network failure');
      },
    }),
    /simulated network failure/,
  );
  assert.equal(calls, 1);
});

test('returns an error status without issuing another request', async () => {
  let calls = 0;
  const status = await postInitOnce({
    env: testEnv,
    fetchImpl: async () => {
      calls += 1;
      return { status: 503 };
    },
  });
  assert.equal(status, 503);
  assert.equal(calls, 1);
});
