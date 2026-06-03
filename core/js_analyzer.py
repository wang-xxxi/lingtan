import re
import json
import requests
from urllib.parse import urljoin, urlparse


class JSAnalyzer:
    """Deep analysis of JavaScript files to extract API information"""

    PATTERNS = {
        'fetch_calls': [
            r'fetch\s*\(\s*[`"\']([^`"\']{3,300})[`"\']',
            r'fetch\s*\(\s*`([^`]{3,300})`',
        ],
        'axios_calls': [
            r'axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']{3,300})["\']',
            r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']{3,300})["\']',
            r'axios\([^)]*["\']([^"\']{3,200})["\']',
        ],
        'xhr_urls': [
            r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']{3,300})["\']',
        ],
        'api_base_urls': [
            r'(?:baseURL|BASE_URL|apiUrl|API_URL|api_base|apiBase|api_url|serverUrl|host|domain)\s*[:=]\s*["\']([^"\']{3,200})["\']',
            r'(?:baseURL|BASE_URL|apiUrl|API_URL|baseUrl)\s*[:=]\s*`([^`]{3,200})`',
        ],
        'route_definitions': [
            r'(?:path|route|endpoint|url|uri)\s*[:=]\s*["\']((?:/api|/rest|/v\d|/service|/auth|/graphql)[^"\']{2,200})["\']',
            r'(?:Router|route|app)\s*\.\s*(?:get|post|put|delete|all)\s*\(\s*["\']([^"\']{2,200})["\']',
        ],
        'api_methods': [
            r'(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']{3,300})["\']',
        ],
    }

    API_PREFIXES = [
        '/api/', '/rest/', '/v1/', '/v2/', '/v3/', '/v4/',
        '/graphql', '/service/', '/gateway/',
        '/oauth/', '/auth/', '/token/',
        '/wp-json/', '/admin/', '/manage/',
    ]

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': '*/*',
        })
        self.session.verify = False

    def analyze_url(self, js_url):
        """Fetch and analyze a JavaScript file"""
        if not js_url:
            return {'error': 'URL为空', 'url': ''}

        try:
            resp = self.session.get(js_url, timeout=15)
            if resp.status_code != 200:
                return {'error': f'HTTP {resp.status_code}', 'url': js_url}
            if not resp.text:
                return {'error': '响应内容为空', 'url': js_url}
            return self.analyze_code(resp.text, js_url)
        except requests.exceptions.ConnectionError:
            return {'error': '连接失败', 'url': js_url}
        except requests.exceptions.Timeout:
            return {'error': '请求超时', 'url': js_url}
        except Exception as e:
            return {'error': str(e), 'url': js_url}

    def analyze_code(self, js_code, source_url=''):
        """Analyze JavaScript source code"""
        if not js_code or not isinstance(js_code, str):
            return {'error': '代码为空', 'source_url': source_url}

        results = {
            'source_url': source_url or '',
            'api_endpoints': [],
            'base_urls': [],
            'api_methods': [],
            'graphql_found': False,
            'auth_patterns': [],
            'env_vars': [],
            'code_stats': {},
        }

        try:
            base = urlparse(source_url) if source_url else None
            base_prefix = f'{base.scheme}://{base.netloc}' if base and base.scheme and base.netloc else ''
        except Exception:
            base_prefix = ''

        results['api_endpoints'] = self._extract_endpoints(js_code, base_prefix)
        results['base_urls'] = self._extract_base_urls(js_code)
        results['api_methods'] = self._detect_methods(js_code)
        results['graphql_found'] = self._check_graphql(js_code)
        results['auth_patterns'] = self._find_auth_patterns(js_code)
        results['env_vars'] = self._find_env_vars(js_code)
        results['code_stats'] = {
            'total_lines': js_code.count('\n') + 1,
            'total_chars': len(js_code),
            'api_calls_found': len(results['api_endpoints']),
            'minified': js_code.count('\n') < 5 and len(js_code) > 10000,
        }

        return results

    def _extract_endpoints(self, code, base_prefix):
        """Extract all API endpoint URLs from JS code"""
        endpoints = set()
        if not code:
            return []

        for category, patterns in self.PATTERNS.items():
            if category in ('api_base_urls',):
                continue
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, code)
                except Exception:
                    continue
                for match in matches:
                    if not match or not isinstance(match, str):
                        continue
                    match = match.strip()
                    if not self._is_valid_endpoint(match):
                        continue
                    if match.startswith('http://') or match.startswith('https://'):
                        endpoints.add(match)
                    elif match.startswith('//'):
                        endpoints.add('https:' + match)
                    elif match.startswith('/'):
                        if base_prefix:
                            endpoints.add(base_prefix + match)
                        else:
                            endpoints.add(match)

        # Template literal paths
        try:
            template_pattern = r'`((?:/|[^`]*\$\{[^}]+\})[^`]*(?:api|rest|v\d|service|auth|graphql)[^`]*)`'
            for match in re.findall(template_pattern, code):
                if match and isinstance(match, str) and len(match) > 3:
                    # Simplify template: remove ${} parts
                    simplified = re.sub(r'\$\{[^}]+\}', '{param}', match)
                    if base_prefix and simplified.startswith('/'):
                        endpoints.add(base_prefix + simplified)
                    elif simplified.startswith('/'):
                        endpoints.add(simplified)
        except Exception:
            pass

        result = []
        for ep in endpoints:
            result.append({'url': ep, 'type': 'absolute' if ep.startswith('http') else 'relative'})
        return result

    def _extract_base_urls(self, code):
        """Extract API base URLs"""
        base_urls = set()
        if not code:
            return []
        for pattern in self.PATTERNS.get('api_base_urls', []):
            try:
                matches = re.findall(pattern, code)
                for match in matches:
                    if match and isinstance(match, str):
                        match = match.strip().rstrip('/')
                        if match and (match.startswith('http') or match.startswith('/')):
                            base_urls.add(match)
            except Exception:
                pass
        return list(base_urls)

    def _detect_methods(self, code):
        """Detect which HTTP methods are used"""
        methods = set()
        if not code:
            return []
        for method in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
            try:
                pattern = rf'\.\s*{method}\s*\('
                if re.search(pattern, code, re.IGNORECASE):
                    methods.add(method.upper())
            except Exception:
                pass
        return list(methods)

    def _check_graphql(self, code):
        """Check if the code uses GraphQL"""
        if not code:
            return False
        patterns = [
            r'(?:query|mutation|subscription)\s+\w+\s*[{(]',
            r'graphql`', r'gql`', r'GraphQL',
            r'graphql-request', r'apollo', r'urql', r'relay',
            r'useQuery', r'useMutation', r'useSubscription',
        ]
        try:
            return any(re.search(p, code, re.IGNORECASE) for p in patterns)
        except Exception:
            return False

    def _find_auth_patterns(self, code):
        """Find authentication-related patterns"""
        patterns = []
        if not code:
            return patterns
        auth_checks = [
            (r'(?:token|jwt|bearer|authorization)', 'token-auth'),
            (r'(?:localStorage|sessionStorage)\.(?:get|set)Item\s*\(\s*["\'](?:token|auth|jwt)', 'token-storage'),
            (r'Authorization["\']?\s*:\s*', 'auth-header'),
            (r'(?:cookie|Cookie)["\']?\s*:', 'cookie-auth'),
            (r'interceptor', 'http-interceptor'),
            (r'withCredentials', 'cors-credentials'),
            (r'credentials\s*:\s*["\']include', 'fetch-credentials'),
            (r'setCookie|getCookie|js-cookie|universal-cookie', 'cookie-lib'),
            (r'passport', 'passport-auth'),
            (r'firebase.*auth', 'firebase-auth'),
        ]
        try:
            for pattern, name in auth_checks:
                if re.search(pattern, code, re.IGNORECASE):
                    patterns.append(name)
        except Exception:
            pass
        return patterns

    def _find_env_vars(self, code):
        """Find environment variables related to API"""
        env_vars = []
        if not code:
            return env_vars
        patterns = [
            r'(?:VITE_|NEXT_PUBLIC_|REACT_APP_|VUE_APP_)(?:API|BASE|URL|HOST|KEY)[^=\n]*=\s*["\']?([^\s"\'\n]{3,100})',
            r'process\.env\.(?:REACT_APP_API|NEXT_PUBLIC_API|VUE_APP_API|API_URL)',
        ]
        for pattern in patterns:
            try:
                matches = re.findall(pattern, code)
                for match in matches:
                    if match and isinstance(match, str):
                        env_vars.append(match.strip())
            except Exception:
                pass
        return env_vars

    def _is_valid_endpoint(self, text):
        """Validate if a string is a reasonable API endpoint"""
        if not text or not isinstance(text, str):
            return False
        if len(text) < 3 or len(text) > 500:
            return False
        if not (text.startswith('/') or text.startswith('http') or text.startswith('//')):
            return False
        static_ext = ('.css', '.js', '.mjs', '.png', '.jpg', '.jpeg', '.gif',
                      '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map',
                      '.mp4', '.mp3', '.webm', '.webp', '.pdf', '.zip')
        if any(text.lower().endswith(ext) for ext in static_ext):
            return False
        api_indicators = self.API_PREFIXES + ['.json', '.xml', 'graphql', 'api',
                        'service', 'gateway', 'auth', 'oauth', 'login', 'user',
                        'account', 'token', 'upload', 'download', 'search',
                        'admin', 'manage', 'wp-json']
        try:
            return any(ind in text.lower() for ind in api_indicators)
        except Exception:
            return False

    def analyze_multiple(self, js_urls):
        """Analyze multiple JS files"""
        if not js_urls:
            return {'files_analyzed': 0, 'unique_endpoints': [], 'total_endpoints': 0, 'details': []}

        all_endpoints = set()
        all_results = []

        for url in js_urls[:30]:  # Limit to prevent timeout
            result = self.analyze_url(url)
            all_results.append(result)
            for ep in result.get('api_endpoints', []):
                if isinstance(ep, dict) and ep.get('url'):
                    all_endpoints.add(ep['url'])

        return {
            'files_analyzed': len(all_results),
            'unique_endpoints': list(all_endpoints),
            'total_endpoints': len(all_endpoints),
            'details': all_results,
        }
