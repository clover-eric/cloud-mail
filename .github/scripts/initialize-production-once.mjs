import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const PRODUCTION_INIT_URL = 'https://i30.ltd/api/init';
export const REQUIRED_CONFIRMATION = 'RUN_INIT_ON_PRODUCTION_ONCE';

export class InitAuthorizationError extends Error {}

export async function postInitOnce({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  if (env.RUN_INIT_ONCE !== 'true' || env.CONFIRM_INIT_ONCE !== REQUIRED_CONFIRMATION || env.CONFIRM_PRODUCTION_DEPLOY !== 'false') {
    throw new InitAuthorizationError('Initialization confirmation did not match; no request was sent.');
  }

  if (typeof env.JWT_SECRET !== 'string' || env.JWT_SECRET.length === 0) {
    throw new InitAuthorizationError('JWT_SECRET is unavailable; no request was sent.');
  }

  const response = await fetchImpl(PRODUCTION_INIT_URL, {
    method: 'POST',
    headers: { 'X-Init-Secret': env.JWT_SECRET },
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  });

  return response.status;
}

async function main() {
  try {
    const status = await postInitOnce();
    console.log(`Production initialization endpoint returned HTTP ${status}.`);
    if (status < 200 || status >= 300) process.exitCode = 1;
  } catch (error) {
    if (error instanceof InitAuthorizationError) {
      console.error(error.message);
    } else {
      console.error('The single initialization request failed or timed out; no automatic retry was attempted.');
    }
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
