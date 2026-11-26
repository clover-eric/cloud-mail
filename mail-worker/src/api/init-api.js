import app from '../hono/hono';
import { dbInit } from '../init/init';
import result from '../model/result';

app.post('/init', async (c) => {
	try {
		return await dbInit.init(c, c.req.header('X-Init-Secret'));
	} catch {
		console.error('[init] stage=handler status=failed');
		return c.json(result.fail('Initialization failed', 500), 500);
	}
})
