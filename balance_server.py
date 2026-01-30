"""
AnyRouter 余额查询服务
使用 FastAPI + Playwright 绕过 WAF 查询账号余额
"""

import asyncio
import smtplib
import time
from datetime import datetime
from email.mime.text import MIMEText

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from playwright.async_api import async_playwright
from pydantic import BaseModel

app = FastAPI(title='AnyRouter Balance Query')

# WAF cookies 缓存: {provider: {'cookies': dict, 'expires': float}}
waf_cache: dict = {}
WAF_CACHE_TTL = 300  # 5 分钟

ANYROUTER_CONFIG = {
	'domain': 'https://anyrouter.top',
	'login_path': '/login',
	'user_info_path': '/api/user/self',
	'api_user_key': 'new-api-user',
	'waf_cookie_names': ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'],
}

USER_AGENT = (
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
)


class AccountItem(BaseModel):
	name: str
	# 新认证方式（推荐）
	access_token: str | None = None
	user_id: str | None = None
	# 旧认证方式（兼容）
	cookies: dict | None = None
	api_user: str | None = None

	def uses_new_auth(self) -> bool:
		"""判断是否使用新认证方式"""
		return self.access_token is not None and self.user_id is not None

	def get_user_id(self) -> str:
		"""获取用户ID"""
		return self.user_id if self.user_id else self.api_user


class QueryRequest(BaseModel):
	accounts: list[AccountItem]


class EmailConfig(BaseModel):
	smtp_server: str
	smtp_port: int = 465
	email_user: str
	email_pass: str
	email_to: str


class MonitorStartRequest(BaseModel):
	accounts: list[AccountItem]
	email: EmailConfig
	interval_hours: float = 6
	threshold: float = 10.0


# 监控状态
monitor_state: dict = {
	'running': False,
	'task': None,
	'config': None,
	'last_check': None,
	'next_check': None,
	'alerted_accounts': set(),  # 已告警的账号（避免重复发送）
	'logs': [],  # 最近的监控日志
}


async def get_waf_cookies() -> dict | None:
	"""获取 WAF cookies，带缓存"""
	cached = waf_cache.get('anyrouter')
	if cached and cached['expires'] > time.time():
		return cached['cookies']

	config = ANYROUTER_CONFIG
	login_url = f'{config["domain"]}{config["login_path"]}'
	required = config['waf_cookie_names']

	try:
		async with async_playwright() as p:
			# 使用 Firefox（自带 TLS 实现，兼容性更好）
			browser = await p.firefox.launch(headless=True)
			context = await browser.new_context(
				user_agent=USER_AGENT,
				viewport={'width': 1920, 'height': 1080},
			)
			page = await context.new_page()
			await page.goto(login_url, wait_until='networkidle')
			try:
				await page.wait_for_function('document.readyState === "complete"', timeout=5000)
			except Exception:
				await page.wait_for_timeout(3000)

			cookies = await page.context.cookies()
			waf_cookies = {}
			for cookie in cookies:
				if cookie.get('name') in required:
					waf_cookies[cookie['name']] = cookie['value']

			await browser.close()

		if len(waf_cookies) == len(required):
			waf_cache['anyrouter'] = {
				'cookies': waf_cookies,
				'expires': time.time() + WAF_CACHE_TTL,
			}
			return waf_cookies

		return waf_cookies if waf_cookies else None
	except Exception as e:
		print(f'[WAF] Error: {e}')
		return None


async def query_balance(account: AccountItem, waf_cookies: dict) -> dict:
	"""查询单个账号余额"""
	config = ANYROUTER_CONFIG

	# 判断认证方式
	use_new_auth = account.uses_new_auth()

	if use_new_auth:
		# 新认证方式：仅使用 WAF cookies
		all_cookies = waf_cookies
	else:
		# 旧认证方式：合并 WAF cookies 和用户 session cookies
		all_cookies = {**waf_cookies, **account.cookies}

	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': config['domain'],
		'Origin': config['domain'],
		config['api_user_key']: account.get_user_id(),
	}

	# 新认证方式：添加 Authorization header
	if use_new_auth:
		headers['Authorization'] = account.access_token

	url = f'{config["domain"]}{config["user_info_path"]}'

	try:
		async with httpx.AsyncClient(http2=True, timeout=30.0) as client:
			client.cookies.update(all_cookies)
			resp = await client.get(url, headers=headers)

			if resp.status_code == 200:
				data = resp.json()
				if data.get('success'):
					user_data = data.get('data', {})
					quota = round(user_data.get('quota', 0) / 500000, 2)
					used = round(user_data.get('used_quota', 0) / 500000, 2)
					username = user_data.get('username', '')
					return {
						'name': account.name,
						'success': True,
						'quota': quota,
						'used': used,
						'username': username,
					}
				return {
					'name': account.name,
					'success': False,
					'error': f'API 返回失败: {data.get("message", "Unknown")}',
				}
			return {
				'name': account.name,
				'success': False,
				'error': f'HTTP {resp.status_code}',
			}
	except Exception as e:
		return {
			'name': account.name,
			'success': False,
			'error': str(e)[:100],
		}


def add_monitor_log(msg: str):
	"""添加监控日志，最多保留 50 条"""
	ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	monitor_state['logs'].append({'time': ts, 'message': msg})
	if len(monitor_state['logs']) > 50:
		monitor_state['logs'] = monitor_state['logs'][-50:]
	print(f'[MONITOR {ts}] {msg}')


def send_alert_email(email_cfg: EmailConfig, subject: str, body: str):
	"""发送告警邮件"""
	msg = MIMEText(body, 'plain', 'utf-8')
	msg['From'] = f'AnyRouter Monitor <{email_cfg.email_user}>'
	msg['To'] = email_cfg.email_to
	msg['Subject'] = subject

	with smtplib.SMTP_SSL(email_cfg.smtp_server, email_cfg.smtp_port) as server:
		server.login(email_cfg.email_user, email_cfg.email_pass)
		server.send_message(msg)


async def monitor_loop(config: MonitorStartRequest):
	"""监控主循环"""
	interval_seconds = config.interval_hours * 3600
	add_monitor_log(
		f'监控启动：间隔 {config.interval_hours}h，阈值 ${config.threshold}，共 {len(config.accounts)} 个账号'
	)

	while monitor_state['running']:
		monitor_state['last_check'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		add_monitor_log('开始检测余额...')

		try:
			waf_cookies = await get_waf_cookies()
			if not waf_cookies:
				add_monitor_log('WAF cookies 获取失败，跳过本次检测')
			else:
				tasks = [query_balance(acc, waf_cookies) for acc in config.accounts]
				results = await asyncio.gather(*tasks)

				low_balance = []
				all_balances = []  # 所有账号余额
				total_quota = 0
				total_used = 0

				for r in results:
					if not r.get('success'):
						add_monitor_log(f'{r["name"]}: 查询失败 - {r.get("error", "")}')
						all_balances.append({'name': r['name'], 'success': False, 'error': r.get('error', '')})
						continue

					all_balances.append(r)
					total_quota += r['quota']
					total_used += r['used']

					if r['quota'] < config.threshold:
						if r['name'] not in monitor_state['alerted_accounts']:
							low_balance.append(r)
							monitor_state['alerted_accounts'].add(r['name'])
							add_monitor_log(f'{r["name"]}: 余额 ${r["quota"]} 低于阈值 ${config.threshold}')
					else:
						# 余额恢复，移除告警标记，下次再低于阈值会重新告警
						monitor_state['alerted_accounts'].discard(r['name'])

				if low_balance:
					subject = f'⚠️ AnyRouter 余额告警：{len(low_balance)} 个账号余额不足'
					lines = [f'⚠️ 以下账号余额低于 ${config.threshold}：', '']
					for r in low_balance:
						lines.append(f'  ❗ {r["name"]}：${r["quota"]}')
					lines.extend(['', '=' * 40, '', '📊 所有账号余额汇总：', ''])
					for r in all_balances:
						if r.get('success', True) and 'quota' in r:
							marker = '⚠️' if r['quota'] < config.threshold else '✅'
							lines.append(f'  {marker} {r["name"]}：余额 ${r["quota"]}，已用 ${r["used"]}')
						else:
							lines.append(f'  ❌ {r["name"]}：查询失败')
					lines.extend(
						[
							'',
							f'📈 总计：余额 ${round(total_quota, 2)}，已用 ${round(total_used, 2)}',
							f'⏰ 检测时间：{monitor_state["last_check"]}',
						]
					)
					body = '\n'.join(lines)

					try:
						send_alert_email(config.email, subject, body)
						add_monitor_log(f'告警邮件已发送：{len(low_balance)} 个账号')
					except Exception as e:
						add_monitor_log(f'邮件发送失败：{str(e)[:80]}')
				else:
					add_monitor_log('所有账号余额正常')
		except Exception as e:
			add_monitor_log(f'检测出错：{str(e)[:80]}')

		# 计算下次检测时间
		next_time = datetime.now().timestamp() + interval_seconds
		monitor_state['next_check'] = datetime.fromtimestamp(next_time).strftime('%Y-%m-%d %H:%M:%S')

		# 分段睡眠，便于及时响应停止
		for _ in range(int(interval_seconds)):
			if not monitor_state['running']:
				break
			await asyncio.sleep(1)

	add_monitor_log('监控已停止')


@app.get('/', response_class=HTMLResponse)
async def index():
	with open('templates/index.html', encoding='utf-8') as f:
		return f.read()


@app.post('/api/query')
async def query(req: QueryRequest):
	"""批量查询账号余额"""
	waf_cookies = await get_waf_cookies()
	if not waf_cookies:
		return {'success': False, 'error': 'WAF cookies 获取失败，请稍后重试'}

	tasks = [query_balance(acc, waf_cookies) for acc in req.accounts]
	results = await asyncio.gather(*tasks)

	total_quota = sum(r.get('quota', 0) for r in results if r.get('success'))
	total_used = sum(r.get('used', 0) for r in results if r.get('success'))

	return {
		'success': True,
		'results': results,
		'summary': {
			'total_quota': round(total_quota, 2),
			'total_used': round(total_used, 2),
			'account_count': len(results),
			'success_count': sum(1 for r in results if r.get('success')),
		},
	}


@app.post('/api/monitor/start')
async def monitor_start(req: MonitorStartRequest):
	"""启动余额监控"""
	if monitor_state['running']:
		return {'success': False, 'error': '监控已在运行中'}

	monitor_state['running'] = True
	monitor_state['alerted_accounts'] = set()
	monitor_state['logs'] = []
	monitor_state['config'] = {
		'interval_hours': req.interval_hours,
		'threshold': req.threshold,
		'account_count': len(req.accounts),
		'email_to': req.email.email_to,
	}

	monitor_state['task'] = asyncio.create_task(monitor_loop(req))
	return {'success': True, 'message': '监控已启动'}


@app.post('/api/monitor/stop')
async def monitor_stop():
	"""停止余额监控"""
	if not monitor_state['running']:
		return {'success': False, 'error': '监控未在运行'}

	monitor_state['running'] = False
	if monitor_state['task']:
		monitor_state['task'].cancel()
		monitor_state['task'] = None

	add_monitor_log('收到停止指令')
	return {'success': True, 'message': '监控已停止'}


@app.get('/api/monitor/status')
async def monitor_status():
	"""获取监控状态"""
	return {
		'running': monitor_state['running'],
		'config': monitor_state['config'],
		'last_check': monitor_state['last_check'],
		'next_check': monitor_state['next_check'],
		'alerted_accounts': list(monitor_state['alerted_accounts']),
		'logs': monitor_state['logs'][-20:],
	}


if __name__ == '__main__':
	uvicorn.run(app, host='0.0.0.0', port=8003)
