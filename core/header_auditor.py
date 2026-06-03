"""Security Header Auditor - CORS, CSP, and comprehensive security header analysis"""
import re
import requests
from urllib.parse import urlparse


class HeaderAuditor:
    """Audit HTTP security headers for misconfigurations"""

    # Security headers with expected values and descriptions
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'medium',
            'description': 'HSTS - 强制HTTPS传输安全',
            'check': lambda v: v and 'max-age' in v.lower(),
            'recommendation': '添加 Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'weak_patterns': [
                (r'max-age=(\d+)', lambda m: int(m.group(1)) < 2592000, 'max-age小于30天'),
            ],
        },
        'Content-Security-Policy': {
            'severity': 'medium',
            'description': 'CSP - 内容安全策略，防止XSS/注入',
            'check': lambda v: bool(v),
            'recommendation': "添加 Content-Security-Policy: default-src 'self'",
            'weak_patterns': [
                (r'default-src\s+[^;]*\*', None, 'CSP使用了通配符 *'),
                (r"script-src\s+[^;]*'unsafe-inline'", None, "CSP允许unsafe-inline脚本"),
                (r"script-src\s+[^;]*'unsafe-eval'", None, "CSP允许unsafe-eval"),
            ],
        },
        'X-Content-Type-Options': {
            'severity': 'low',
            'description': '防止MIME类型嗅探攻击',
            'check': lambda v: v and v.lower() == 'nosniff',
            'recommendation': '添加 X-Content-Type-Options: nosniff',
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'description': '防止点击劫持 (Clickjacking)',
            'check': lambda v: v and v.upper() in ('DENY', 'SAMEORIGIN'),
            'recommendation': '添加 X-Frame-Options: DENY 或 SAMEORIGIN',
        },
        'X-XSS-Protection': {
            'severity': 'low',
            'description': '浏览器XSS过滤器',
            'check': lambda v: bool(v),
            'recommendation': '添加 X-XSS-Protection: 1; mode=block',
        },
        'Referrer-Policy': {
            'severity': 'low',
            'description': '控制Referer信息泄露',
            'check': lambda v: bool(v),
            'recommendation': '添加 Referrer-Policy: strict-origin-when-cross-origin',
        },
        'Permissions-Policy': {
            'severity': 'low',
            'description': '控制浏览器功能权限 (camera, microphone, geolocation等)',
            'check': lambda v: bool(v),
            'recommendation': "添加 Permissions-Policy: camera=(), microphone=(), geolocation=()",
        },
        'X-Permitted-Cross-Domain-Policies': {
            'severity': 'low',
            'description': 'Flash/PDF跨域策略',
            'check': lambda v: v and v.lower() == 'none',
            'recommendation': '添加 X-Permitted-Cross-Domain-Policies: none',
        },
        'Cross-Origin-Opener-Policy': {
            'severity': 'low',
            'description': 'COOP - 跨源打开器策略',
            'check': lambda v: bool(v),
            'recommendation': '添加 Cross-Origin-Opener-Policy: same-origin',
        },
        'Cross-Origin-Embedder-Policy': {
            'severity': 'low',
            'description': 'COEP - 跨源嵌入器策略',
            'check': lambda v: bool(v),
            'recommendation': '添加 Cross-Origin-Embedder-Policy: require-corp',
        },
        'Cross-Origin-Resource-Policy': {
            'severity': 'low',
            'description': 'CORP - 跨源资源策略',
            'check': lambda v: bool(v),
            'recommendation': '添加 Cross-Origin-Resource-Policy: same-origin',
        },
    }

    # CORS dangerous configurations
    CORS_TESTS = [
        'https://evil.com',
        'https://attacker.evil.com',
        'null',
        f'https://{"".join(["a"] * 100)}.evil.com',  # Subdomain matching abuse
    ]

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.verify = False
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def full_audit(self, target_url, progress_callback=None):
        """Run full security header audit on a target"""
        self._stop_flag = False
        results = {
            'target': target_url,
            'findings': [],
            'headers': {},
            'cors_tests': [],
            'score': 0,
            'max_score': 0,
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        }

        # Phase 1: Fetch and analyze headers
        if progress_callback:
            progress_callback('获取响应头信息...', 10)

        try:
            resp = self.session.get(target_url, timeout=self.timeout)
            if not resp:
                results['findings'].append({
                    'type': 'fetch_error',
                    'severity': 'info',
                    'description': '无法获取目标响应',
                    'url': target_url,
                })
                return results

            headers = {}
            if resp.headers:
                for k, v in resp.headers.items():
                    headers[k.lower()] = v
            results['headers'] = headers

        except Exception as e:
            results['findings'].append({
                'type': 'fetch_error',
                'severity': 'info',
                'description': f'请求失败: {str(e)}',
                'url': target_url,
            })
            return results

        # Phase 2: Check security headers
        if progress_callback:
            progress_callback('审计安全响应头...', 30)
        self._audit_security_headers(headers, target_url, results)

        # Phase 3: CORS misconfiguration tests
        if progress_callback:
            progress_callback('测试CORS配置...', 55)
        self._audit_cors(target_url, results)

        # Phase 4: Information disclosure
        if progress_callback:
            progress_callback('检测信息泄露...', 75)
        self._check_info_disclosure(headers, target_url, results)

        # Phase 5: Cookie security
        if progress_callback:
            progress_callback('审计Cookie安全...', 90)
        self._audit_cookies(resp, target_url, results)

        # Calculate score
        total_checks = len(self.SECURITY_HEADERS) + 5  # 5 CORS checks + header checks
        passed = total_checks - len([f for f in results['findings'] if f.get('severity') in ('medium', 'high', 'critical')])
        results['score'] = max(0, int(100 * passed / max(total_checks, 1)))
        results['max_score'] = 100

        # Calculate summary
        for f in results['findings']:
            sev = f.get('severity', 'info')
            results['summary'][sev] = results['summary'].get(sev, 0) + 1

        if progress_callback:
            progress_callback('安全头审计完成', 100)

        return results

    def _audit_security_headers(self, headers, url, results):
        """Check all security headers"""
        for header_name, config in self.SECURITY_HEADERS.items():
            if self._stop_flag:
                return
            header_val = headers.get(header_name.lower())

            if header_val is None:
                # Missing header
                results['findings'].append({
                    'type': 'missing_header',
                    'severity': config['severity'],
                    'description': f'缺少安全头: {header_name} - {config["description"]}',
                    'url': url,
                    'recommendation': config.get('recommendation', ''),
                })
            else:
                # Header exists - check if properly configured
                check_fn = config.get('check')
                if check_fn and not check_fn(header_val):
                    results['findings'].append({
                        'type': 'weak_header',
                        'severity': 'low',
                        'description': f'安全头配置不当: {header_name}',
                        'url': url,
                        'evidence': f'当前值: {header_val[:200]}',
                        'recommendation': config.get('recommendation', ''),
                    })

                # Check for weak patterns
                for pattern, check, desc in config.get('weak_patterns', []):
                    match = re.search(pattern, header_val, re.I)
                    if match:
                        if check is None or check(match):
                            results['findings'].append({
                                'type': 'weak_header_config',
                                'severity': 'medium',
                                'description': f'{header_name}: {desc}',
                                'url': url,
                                'evidence': f'值: {header_val[:200]}',
                            })

    def _audit_cors(self, url, results):
        """Test CORS misconfigurations"""
        parsed = urlparse(url)

        for origin in self.CORS_TESTS:
            if self._stop_flag:
                return
            try:
                resp = self.session.get(url, headers={'Origin': origin}, timeout=self.timeout)
                if not resp or not resp.headers:
                    continue

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                acam = resp.headers.get('Access-Control-Allow-Methods', '')
                acah = resp.headers.get('Access-Control-Allow-Headers', '')

                test_result = {
                    'origin': origin,
                    'acao': acao,
                    'acac': acac,
                    'acam': acam,
                    'acah': acah,
                }

                # Wildcard with credentials - critical
                if acao == '*' and acac.lower() == 'true':
                    test_result['vulnerable'] = True
                    results['findings'].append({
                        'type': 'cors_wildcard_credentials',
                        'severity': 'critical',
                        'description': 'CORS配置错误: Access-Control-Allow-Origin=* 配合 Allow-Credentials=true',
                        'url': url,
                        'evidence': f'Origin: {origin} -> ACAO: {acao}, ACAC: {acac}',
                        'recommendation': '不要同时使用 Allow-Origin=* 和 Allow-Credentials=true',
                    })

                # Reflected origin - critical
                elif acao == origin and origin not in (parsed.netloc, f'{parsed.scheme}://{parsed.netloc}'):
                    test_result['vulnerable'] = True
                    severity = 'critical' if acac.lower() == 'true' else 'high'
                    results['findings'].append({
                        'type': 'cors_origin_reflection',
                        'severity': severity,
                        'description': 'CORS配置错误: 任意Origin被服务端反射回响应',
                        'url': url,
                        'evidence': f'发送 Origin: {origin} -> ACAO: {acao}',
                        'recommendation': '实施严格的Origin白名单校验',
                    })

                # Wildcard without credentials - info
                elif acao == '*' and acac.lower() != 'true':
                    test_result['vulnerable'] = False
                    results['findings'].append({
                        'type': 'cors_wildcard',
                        'severity': 'low',
                        'description': 'CORS允许所有来源访问 (无Credentials)',
                        'url': url,
                        'evidence': f'ACAO: *',
                    })

                # Null origin accepted
                elif acao == 'null':
                    test_result['vulnerable'] = True
                    results['findings'].append({
                        'type': 'cors_null_origin',
                        'severity': 'high',
                        'description': 'CORS接受 null 来源 - 可被沙盒iframe利用',
                        'url': url,
                        'evidence': f'Origin: null -> ACAO: null, ACAC: {acac}',
                    })

                results['cors_tests'].append(test_result)

            except Exception:
                pass

    def _check_info_disclosure(self, headers, url, results):
        """Check for information disclosure in headers"""
        # Server version disclosure
        server = headers.get('server', '')
        if server and re.search(r'\d+\.\d+', server):
            results['findings'].append({
                'type': 'server_version_disclosure',
                'severity': 'low',
                'description': f'服务器版本信息泄露: {server}',
                'url': url,
                'recommendation': '隐藏或模糊化Server头中的版本号',
            })

        # X-Powered-By disclosure
        powered_by = headers.get('x-powered-by', '')
        if powered_by:
            results['findings'].append({
                'type': 'powered_by_disclosure',
                'severity': 'low',
                'description': f'技术栈信息泄露: X-Powered-By: {powered_by}',
                'url': url,
                'recommendation': '移除 X-Powered-By 响应头',
            })

        # X-AspNet-Version
        aspnet = headers.get('x-aspnet-version', '')
        if aspnet:
            results['findings'].append({
                'type': 'aspnet_version_disclosure',
                'severity': 'low',
                'description': f'ASP.NET版本泄露: {aspnet}',
                'url': url,
            })

        # X-AspNetMvc-Version
        aspnetmvc = headers.get('x-aspnetmvc-version', '')
        if aspnetmvc:
            results['findings'].append({
                'type': 'aspnetmvc_version_disclosure',
                'severity': 'low',
                'description': f'ASP.NET MVC版本泄露: {aspnetmvc}',
                'url': url,
            })

        # Via header (proxy info)
        via = headers.get('via', '')
        if via:
            results['findings'].append({
                'type': 'via_header_disclosure',
                'severity': 'info',
                'description': f'代理信息泄露: Via: {via}',
                'url': url,
            })

    def _audit_cookies(self, response, url, results):
        """Audit cookie security flags"""
        if not response or not hasattr(response, 'cookies'):
            return

        try:
            # Also parse raw Set-Cookie headers
            set_cookies = []
            if response.headers:
                for k, v in response.headers.items():
                    if k.lower() == 'set-cookie':
                        set_cookies.append(v)

            for cookie_str in set_cookies:
                if self._stop_flag:
                    return
                cookie_lower = cookie_str.lower()
                cookie_name = cookie_str.split('=')[0].strip() if '=' in cookie_str else cookie_str

                # Check Secure flag
                if 'secure' not in cookie_lower and 'https' in url.lower():
                    results['findings'].append({
                        'type': 'cookie_missing_secure',
                        'severity': 'medium',
                        'description': f'Cookie缺少Secure标志: {cookie_name}',
                        'url': url,
                        'recommendation': '为所有Cookie添加Secure标志',
                    })

                # Check HttpOnly flag
                if 'httponly' not in cookie_lower:
                    results['findings'].append({
                        'type': 'cookie_missing_httponly',
                        'severity': 'medium',
                        'description': f'Cookie缺少HttpOnly标志: {cookie_name} (可被XSS窃取)',
                        'url': url,
                        'recommendation': '为Cookie添加HttpOnly标志',
                    })

                # Check SameSite flag
                if 'samesite' not in cookie_lower:
                    results['findings'].append({
                        'type': 'cookie_missing_samesite',
                        'severity': 'low',
                        'description': f'Cookie缺少SameSite标志: {cookie_name}',
                        'url': url,
                        'recommendation': '为Cookie添加SameSite=Lax或Strict',
                    })

        except Exception:
            pass
