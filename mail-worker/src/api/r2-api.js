import attService from '../service/att-service';
import app from '../hono/hono';

app.get('/oss/*', async (c) => {
	let key;
	try {
		key = decodeURIComponent(c.req.path.split('/oss/')[1] || '');
	} catch {
		return c.notFound();
	}
	const resp = await attService.toAuthorizedObjResp(c, key, c.req.query('token'));
	if (!resp) {
		return c.notFound();
	}
	return resp;
});

