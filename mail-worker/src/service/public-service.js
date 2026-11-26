import BizError from '../error/biz-error';
import orm from '../entity/orm';
import { and, asc, desc, eq, sql } from 'drizzle-orm';
import saltHashUtils from '../utils/crypto-utils';
import cryptoUtils from '../utils/crypto-utils';
import emailUtils from '../utils/email-utils';
import roleService from './role-service';
import verifyUtils from '../utils/verify-utils';
import { t } from '../i18n/i18n';
import reqUtils from '../utils/req-utils';
import dayjs from 'dayjs';
import { isDel, roleConst } from '../const/entity-const';
import email from '../entity/email';
import attService from './att-service';
import userService from './user-service';
import proxyService from './proxy-service';
import publicTokenUtils from '../utils/public-token';

function createPublicToken() {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

const publicService = {

	async emailList(c, params) {

		let { toEmail, content, subject, sendName, sendEmail, timeSort, num, size, type , isDel } = params

		const query = orm(c).select({
				emailId: email.emailId,
				sendEmail: email.sendEmail,
				sendName: email.name,
				subject: email.subject,
				toEmail: email.toEmail,
				toName: email.toName,
				type: email.type,
				createTime: email.createTime,
				content: email.content,
				text: email.text,
				isDel: email.isDel,
		}).from(email)

		if (!size) {
			size = 20
		}

		if (!num) {
			num = 1
		}

		size = Number(size);
		num = Number(num);

		num = (num - 1) * size;

		let conditions = []

		if (toEmail) {
			conditions.push(sql`${email.toEmail} COLLATE NOCASE LIKE ${toEmail}`)
		}

		if (sendEmail) {
			conditions.push(sql`${email.sendEmail} COLLATE NOCASE LIKE ${sendEmail}`)
		}

		if (sendName) {
			conditions.push(sql`${email.name} COLLATE NOCASE LIKE ${sendName}`)
		}

		if (subject) {
			conditions.push(sql`${email.subject} COLLATE NOCASE LIKE ${subject}`)
		}

		if (content) {
			conditions.push(sql`${email.content} COLLATE NOCASE LIKE ${content}`)
		}

		if (type || type === 0) {
			conditions.push(eq(email.type, type))
		}

		if (isDel || isDel === 0) {
			conditions.push(eq(email.isDel, isDel))
		}

		if (conditions.length === 1) {
			query.where(...conditions)
		} else if (conditions.length > 1) {
			query.where(and(...conditions))
		}

		if (timeSort === 'asc') {
			query.orderBy(asc(email.emailId));
		} else {
			query.orderBy(desc(email.emailId));
		}

		const rows = await query.limit(size).offset(num);
		// 公开邮件列表也把外链图改成 /proxy?url=。
		await proxyService.rewriteList(c, rows);
		await attService.addEmailDownloadUrls(c, rows);
		return rows;

	},

	async addUser(c, params) {
		const { list } = params;

		if (!Array.isArray(list)) {
			throw new BizError('Invalid user list');
		}
		if (list.length === 0) return;

		for (const emailRow of list) {
			if (!verifyUtils.isEmail(emailRow.email)) {
				throw new BizError(t('notEmail'));
			}

			if (!c.env.domain.includes(emailUtils.getDomain(emailRow.email))) {
				throw new BizError(t('notEmailDomain'));
			}

			const { salt, hash } = await saltHashUtils.hashPassword(
				emailRow.password || cryptoUtils.genRandomPwd()
			);

			emailRow.salt = salt;
			emailRow.hash = hash;
		}


		const activeIp = reqUtils.getIp(c);
		const { os, browser, device } = reqUtils.getUserAgent(c);
		const activeTime = dayjs().format('YYYY-MM-DD HH:mm:ss');

		const roleList = await roleService.roleSelectUse(c);
		const defRole = roleList.find(roleRow => roleRow.isDefault === roleConst.isDefault.OPEN);
		if (!defRole) {
			throw new BizError('Default role is not configured');
		}

		const userList = [];

		for (const emailRow of list) {
			let { email, hash, salt, roleName } = emailRow;
			let type = defRole.roleId;

			if (roleName) {
				const roleRow = roleList.find(role => role.name === roleName);
				type = roleRow ? roleRow.roleId : type;
			}

			const userSql = `INSERT INTO user (email, password, salt, type, os, browser, active_ip, create_ip, device, active_time, create_time)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

			const accountSql = `INSERT INTO account (email, name, user_id) VALUES (?, ?, 0)`;

			userList.push(c.env.db.prepare(userSql).bind(
				email, hash, salt, type, os || null, browser || null,
				activeIp, activeIp, device || null, activeTime, activeTime
			));
			userList.push(c.env.db.prepare(accountSql).bind(email, emailUtils.getName(email)));

		}

		userList.push(c.env.db.prepare(`UPDATE account SET user_id = (SELECT user_id FROM user WHERE user.email = account.email) WHERE user_id = 0;`))

		try {
			await c.env.db.batch(userList);
		} catch (e) {
			if(String(e?.message || e).includes('SQLITE_CONSTRAINT')) {
				throw new BizError(t('emailExistDatabase'))
			} else {
				throw e
			}
		}

	},

	async genToken(c, params) {
		await this.verifyUser(c, params);

		const allowedScopes = new Set(['email:read', 'user:create']);
		const scopes = params.scopes;
		if (!Array.isArray(scopes) || scopes.length === 0 || scopes.some(scope => !allowedScopes.has(scope)) || new Set(scopes).size !== scopes.length) {
			throw new BizError('Choose one or more valid public token scopes');
		}

		const expiresInDays = params.expiresInDays === undefined ? 30 : Number(params.expiresInDays);
		if (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 90) {
			throw new BizError('Public token expiry must be between 1 and 90 days');
		}

		const token = createPublicToken();
		const expiresAt = Date.now() + expiresInDays * 24 * 60 * 60 * 1000;
		const key = await publicTokenUtils.publicTokenStorageKey(token);
		await c.env.kv.put(key, JSON.stringify({ scopes, expiresAt }), {
			expirationTtl: expiresInDays * 24 * 60 * 60
		});

		return { token, scopes, expiresAt: new Date(expiresAt).toISOString() };
	},

	async revokeToken(c, params) {
		await this.verifyUser(c, params);
		const key = await publicTokenUtils.publicTokenStorageKey(params.tokenToRevoke);
		if (!key) {
			throw new BizError('Invalid public token');
		}
		await c.env.kv.delete(key);
	},

	async verifyUser(c, params) {

		const { email, password } = params

		const userRow = await userService.selectByEmailIncludeDel(c, email);

		if (email !== c.env.admin) {
			throw new BizError(t('notAdmin'));
		}

		if (!userRow || userRow.isDel === isDel.DELETE) {
			throw new BizError(t('notExistUser'));
		}

		if (!await cryptoUtils.verifyPassword(password, userRow.salt, userRow.password)) {
			throw new BizError(t('IncorrectPwd'));
		}
	}

}

export default publicService
