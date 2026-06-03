"""Authentication & Authorization Detector - unauth access, IDOR, JWT analysis"""
import re
import json
import time
import base64
import hashlib
import hmac
import requests
from urllib.parse import urlparse, urlencode, parse_qs


class AuthDetector:
    """Detect authentication and authorization vulnerabilities"""

    # JWT weak algorithms
    WEAK_JWT_ALGS = ['none', 'HS256', 'HS384', 'HS512']

    # Common auth header names
    AUTH_HEADERS = ['Authorization', 'X-Auth-Token', 'X-API-Key', 'Token',
                    'X-Access-Token', 'Cookie', 'X-JWT-Token']

    # Common auth cookie names
    AUTH_COOKIES = ['token', 'session', 'jwt', 'auth', 'access_token',
                    'sessionid', 'JSESSIONID', 'PHPSESSID', 'laravel_session']

    # ID patterns for IDOR testing
    ID_PATTERNS = [
        (r'/users?/(\d{1,15})', '/users/{id}'),
        (r'/user/(\d{1,15})', '/user/{id}'),
        (r'/api/users?/(\d{1,15})', '/api/users/{id}'),
        (r'/accounts?/(\d{1,15})', '/accounts/{id}'),
        (r'/orders?/(\d{1,15})', '/orders/{id}'),
        (r'/items?/(\d{1,15})', '/items/{id}'),
        (r'/products?/(\d{1,15})', '/products/{id}'),
        (r'/posts?/(\d{1,15})', '/posts/{id}'),
        (r'/articles?/(\d{1,15})', '/articles/{id}'),
        (r'/comments?/(\d{1,15})', '/comments/{id}'),
        (r'/messages?/(\d{1,15})', '/messages/{id}'),
        (r'/invoices?/(\d{1,15})', '/invoices/{id}'),
        (r'/records?/(\d{1,15})', '/records/{id}'),
        (r'/files?/(\d{1,15})', '/files/{id}'),
        (r'/docs?/(\d{1,15})', '/docs/{id}'),
        (r'/id/(\d{1,15})', '/id/{id}'),
        (r'\?id=(\d{1,15})', '?id={id}'),
    ]

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/html, */*',
        })
        self.session.verify = False
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def full_check(self, target_url, auth_headers=None, progress_callback=None):
        """Run full auth/authorization checks on a target"""
        self._stop_flag = False
        results = {
            'target': target_url,
            'findings': [],
            'idor_candidates': [],
            'jwt_tokens': [],
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        }

        # Phase 1: Unauthenticated access check
        if progress_callback:
            progress_callback('检测未授权访问...', 10)
        self._check_unauth_access(target_url, auth_headers, results)

        # Phase 2: JWT token analysis
        if progress_callback:
            progress_callback('分析JWT令牌...', 30)
        self._analyze_jwt_tokens(target_url, auth_headers, results)

        # Phase 3: IDOR detection
        if progress_callback:
            progress_callback('检测IDOR越权...', 50)
        self._check_idor(target_url, auth_headers, results)

        # Phase 4: Auth bypass patterns
        if progress_callback:
            progress_callback('检测认证绕过...', 75)
        self._check_auth_bypass(target_url, auth_headers, results)

        # Calculate summary
        for f in results['findings']:
            sev = f.get('severity', 'info')
            results['summary'][sev] = results['summary'].get(sev, 0) + 1

        if progress_callback:
            progress_callback('认证检测完成', 100)

        return results

    def _check_unauth_access(self, target_url, auth_headers, results):
        """Test if endpoints are accessible without authentication"""
        parsed = urlparse(target_url)
        base = f'{parsed.scheme}://{parsed.netloc}'

        # Test the target URL itself
        try:
            # Request without any auth headers
            no_auth_session = requests.Session()
            no_auth_session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
            })
            no_auth_session.verify = False

            resp_no_auth = no_auth_session.get(target_url, timeout=self.timeout)

            # If we have auth headers, compare with authenticated request
            if auth_headers:
                resp_with_auth = self.session.get(target_url, headers=auth_headers, timeout=self.timeout)

                if resp_no_auth.status_code == 200 and resp_with_auth.status_code == 200:
                    # Both return 200 - possible unauth access
                    no_auth_len = len(resp_no_auth.content) if resp_no_auth.content else 0
                    with_auth_len = len(resp_with_auth.content) if resp_with_auth.content else 0

                    if no_auth_len > 50 and abs(no_auth_len - with_auth_len) < with_auth_len * 0.3:
                        results['findings'].append({
                            'type': 'unauthenticated_access',
                            'severity': 'high',
                            'description': '接口可在无认证信息时正常访问',
                            'url': target_url,
                            'evidence': f'无认证: {resp_no_auth.status_code} ({no_auth_len}B), 有认证: {resp_with_auth.status_code} ({with_auth_len}B)',
                        })
                    else:
                        results['findings'].append({
                            'type': 'auth_difference',
                            'severity': 'info',
                            'description': '有无认证的响应存在差异（认证可能生效）',
                            'url': target_url,
                            'evidence': f'无认证: {no_auth_len}B, 有认证: {with_auth_len}B',
                        })
                elif resp_no_auth.status_code in (401, 403):
                    results['findings'].append({
                        'type': 'auth_enforced',
                        'severity': 'info',
                        'description': '接口正确返回认证失败状态码',
                        'url': target_url,
                        'evidence': f'无认证返回: {resp_no_auth.status_code}',
                    })
                elif resp_no_auth.status_code == 302 or resp_no_auth.status_code == 301:
                    location = resp_no_auth.headers.get('Location', '')
                    if 'login' in location.lower() or 'auth' in location.lower():
                        results['findings'].append({
                            'type': 'auth_redirect',
                            'severity': 'info',
                            'description': '无认证时被重定向到登录页',
                            'url': target_url,
                            'evidence': f'重定向到: {location}',
                        })

            # Also check common admin/management paths without auth
            admin_paths = ['/admin', '/admin/', '/dashboard', '/manage', '/management',
                           '/api/admin', '/api/manage', '/console', '/backend']
            for path in admin_paths:
                if self._stop_flag:
                    return
                try:
                    admin_url = base + path
                    resp = no_auth_session.get(admin_url, timeout=5, allow_redirects=False)
                    if resp.status_code == 200 and len(resp.content or b'') > 200:
                        results['findings'].append({
                            'type': 'admin_unauthenticated',
                            'severity': 'critical',
                            'description': f'管理路径 {path} 可无认证访问',
                            'url': admin_url,
                            'evidence': f'返回: {resp.status_code}, 大小: {len(resp.content)}B',
                        })
                except Exception:
                    pass

        except Exception:
            pass

    def _analyze_jwt_tokens(self, target_url, auth_headers, results):
        """Analyze JWT tokens for weak algorithms and other issues"""
        tokens = []

        # Extract tokens from auth headers
        if auth_headers:
            for header_name, header_value in auth_headers.items():
                if 'bearer' in str(header_value).lower():
                    token = str(header_value).replace('Bearer ', '').replace('bearer ', '')
                    tokens.append({'source': f'Header: {header_name}', 'token': token})

        # Try to get a token from the response
        try:
            resp = self.session.get(target_url, timeout=self.timeout)
            if resp and resp.text:
                # Look for JWT patterns in response body
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
                found_jwt = re.findall(jwt_pattern, resp.text)
                for jwt_token in found_jwt[:5]:
                    tokens.append({'source': 'Response body', 'token': jwt_token})

                # Check Set-Cookie headers for tokens
                for cookie_name, cookie_value in (resp.cookies or {}).items():
                    if any(ac in cookie_name.lower() for ac in self.AUTH_COOKIES):
                        if re.match(jwt_pattern, str(cookie_value)):
                            tokens.append({'source': f'Cookie: {cookie_name}', 'token': str(cookie_value)})

                # Look for token-like JSON fields
                try:
                    json_data = resp.json()
                    if isinstance(json_data, dict):
                        for key in ['token', 'access_token', 'jwt', 'id_token', 'auth_token']:
                            val = json_data.get(key, '')
                            if val and isinstance(val, str) and re.match(jwt_pattern, val):
                                tokens.append({'source': f'JSON: {key}', 'token': val})
                except Exception:
                    pass

        except Exception:
            pass

        # Analyze each found token
        for token_info in tokens:
            if self._stop_flag:
                return
            token = token_info['token']
            analysis = self._decode_jwt(token)
            analysis['source'] = token_info['source']
            results['jwt_tokens'].append(analysis)

            # Check for weak algorithms
            if analysis.get('algorithm') == 'none':
                results['findings'].append({
                    'type': 'jwt_none_algorithm',
                    'severity': 'critical',
                    'description': 'JWT使用 "none" 算法 - 可被任意伪造',
                    'url': target_url,
                    'evidence': f'算法: none, 来源: {token_info["source"]}',
                })

            # Check for long expiration
            payload = analysis.get('payload', {})
            if isinstance(payload, dict):
                exp = payload.get('exp')
                if exp:
                    import datetime
                    try:
                        exp_time = datetime.datetime.fromtimestamp(exp)
                        if exp_time.year > 2030:
                            results['findings'].append({
                                'type': 'jwt_long_expiry',
                                'severity': 'medium',
                                'description': f'JWT过期时间过长: {exp_time.isoformat()}',
                                'url': target_url,
                                'evidence': f'过期时间: {exp_time.isoformat()}',
                            })
                    except Exception:
                        pass

                # Check for sensitive data in payload
                sensitive_keys = ['password', 'secret', 'ssn', 'credit_card', 'private']
                for sk in sensitive_keys:
                    if sk in str(payload).lower():
                        results['findings'].append({
                            'type': 'jwt_sensitive_data',
                            'severity': 'high',
                            'description': f'JWT payload包含敏感字段: {sk}',
                            'url': target_url,
                            'evidence': f'字段: {sk}',
                        })

    def _decode_jwt(self, token):
        """Decode and analyze a JWT token"""
        result = {
            'valid': False,
            'algorithm': None,
            'header': {},
            'payload': {},
            'errors': [],
        }

        parts = token.split('.')
        if len(parts) != 3:
            result['errors'].append(f'JWT格式错误: {len(parts)}个部分(应为3)')
            return result

        try:
            # Decode header
            header_json = self._base64_decode(parts[0])
            result['header'] = json.loads(header_json)
            result['algorithm'] = result['header'].get('alg', 'unknown')

            # Decode payload
            payload_json = self._base64_decode(parts[1])
            result['payload'] = json.loads(payload_json)
            result['valid'] = True

        except Exception as e:
            result['errors'].append(f'解码失败: {str(e)}')

        return result

    def _base64_decode(self, s):
        """Base64url decode with padding"""
        s = s.replace('-', '+').replace('_', '/')
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        return base64.b64decode(s).decode('utf-8')

    def _check_idor(self, target_url, auth_headers, results):
        """Check for Insecure Direct Object Reference vulnerabilities"""
        parsed = urlparse(target_url)
        path = parsed.path
        query = parsed.query

        for pattern, template in self.ID_PATTERNS:
            if self._stop_flag:
                return
            match = re.search(pattern, target_url)
            if not match:
                continue

            original_id = match.group(1)
            # Test with adjacent IDs
            test_ids = [
                str(int(original_id) + 1),
                str(int(original_id) - 1),
                '1',
                '0',
            ]
            # Also try some common large IDs
            if int(original_id) < 1000:
                test_ids.extend(['100', '999'])

            for test_id in test_ids[:3]:
                if self._stop_flag:
                    return
                try:
                    # Replace the ID in URL
                    test_url = target_url.replace(f'/{original_id}/', f'/{test_id}/', 1)
                    if test_url == target_url:
                        test_url = target_url.replace(f'/{original_id}', f'/{test_id}', 1)
                    if test_url == target_url and f'id={original_id}' in test_url:
                        test_url = target_url.replace(f'id={original_id}', f'id={test_id}', 1)

                    if test_url == target_url:
                        continue

                    # Request original
                    headers_orig = auth_headers if auth_headers else {}
                    resp_orig = self.session.get(target_url, headers=headers_orig, timeout=self.timeout)

                    # Request with different ID
                    resp_test = self.session.get(test_url, headers=headers_orig, timeout=self.timeout)

                    if resp_orig and resp_test:
                        if resp_test.status_code == 200 and resp_orig.status_code == 200:
                            orig_len = len(resp_orig.content or b'')
                            test_len = len(resp_test.content or b'')
                            if test_len > 50 and abs(orig_len - test_len) < orig_len * 0.5:
                                results['findings'].append({
                                    'type': 'potential_idor',
                                    'severity': 'high',
                                    'description': f'可能存在IDOR越权: 替换ID {original_id} -> {test_id}',
                                    'url': test_url,
                                    'evidence': f'原始: {resp_orig.status_code} ({orig_len}B), 替换后: {resp_test.status_code} ({test_len}B)',
                                })
                                results['idor_candidates'].append({
                                    'original_url': target_url,
                                    'test_url': test_url,
                                    'original_id': original_id,
                                    'test_id': test_id,
                                })
                                break  # One finding per pattern is enough

                except Exception:
                    pass

    def _check_auth_bypass(self, target_url, auth_headers, results):
        """Test common authentication bypass techniques"""
        parsed = urlparse(target_url)
        base = f'{parsed.scheme}://{parsed.netloc}'

        bypass_headers_list = [
            # IP-based bypass headers
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Original-URL': parsed.path},
            {'X-Rewrite-URL': parsed.path},
            # Method override
            {'X-HTTP-Method-Override': 'GET'},
            {'X-Method-Override': 'GET'},
        ]

        for bypass_headers in bypass_headers_list:
            if self._stop_flag:
                return
            try:
                merged = dict(auth_headers) if auth_headers else {}
                merged.update(bypass_headers)
                resp = self.session.get(target_url, headers=merged, timeout=self.timeout, allow_redirects=False)

                if resp and resp.status_code == 200:
                    bypass_key = list(bypass_headers.keys())[0]
                    results['findings'].append({
                        'type': 'auth_bypass_header',
                        'severity': 'high',
                        'description': f'可能通过 {bypass_key} 头绕过认证',
                        'url': target_url,
                        'evidence': f'{bypass_key}: {bypass_headers[bypass_key]} -> {resp.status_code}',
                    })

            except Exception:
                pass

        # Try path-based bypass
        bypass_paths = [
            target_url + '%00',
            target_url + '%20',
            target_url.rstrip('/') + '/.',
            target_url.replace(parsed.path, parsed.path + '/..;/'),
        ]

        for bypass_url in bypass_paths:
            if self._stop_flag:
                return
            try:
                resp = self.session.get(bypass_url, headers=auth_headers or {},
                                        timeout=5, allow_redirects=False)
                if resp and resp.status_code == 200 and len(resp.content or b'') > 50:
                    results['findings'].append({
                        'type': 'auth_bypass_path',
                        'severity': 'high',
                        'description': '可能通过路径变形绕过认证',
                        'url': bypass_url,
                        'evidence': f'路径绕过返回: {resp.status_code}',
                    })
                    break
            except Exception:
                pass

    def analyze_jwt_string(self, jwt_string):
        """Public method to analyze a single JWT token string"""
        return self._decode_jwt(jwt_string)
