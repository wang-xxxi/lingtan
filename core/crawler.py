import re
import json
import time
import hashlib
import random
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
import threading

from core.anti_detection import AntiDetection
from core.deduplicator import Deduplicator


class WebCrawler:
    """Robust web crawler to discover API endpoints from any website"""

    COMMON_API_PATHS = [
        # REST API common paths
        '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4',
        '/rest', '/rest/v1', '/rest/v2',
        '/v1', '/v2', '/v3',
        # Documentation
        '/swagger-ui.html', '/swagger/index.html', '/swagger-ui/',
        '/api-docs', '/v2/api-docs', '/v3/api-docs',
        '/swagger.json', '/swagger/v1/swagger.json',
        '/openapi.json', '/openapi.yaml', '/openapi/v3/api-docs',
        '/api/swagger.json', '/api/openapi.json',
        '/docs', '/redoc', '/doc', '/documentation',
        '/.well-known/openapi', '/.well-known/openid-configuration',
        # Health & Status
        '/actuator', '/actuator/health', '/actuator/info', '/actuator/env',
        '/health', '/healthcheck', '/status', '/ping', '/info', '/version',
        '/_health', '/_status', '/api/health',
        # WordPress
        '/wp-json', '/wp-json/wp/v2', '/wp-admin/admin-ajax.php',
        '/xmlrpc.php', '/wp-login.php',
        # GraphQL
        '/graphql', '/gql', '/graphql/v1',
        # CMS common
        '/admin/api', '/api/admin', '/manage/api',
        # Auth
        '/.auth', '/auth/token', '/oauth/token', '/oauth/authorize',
        '/login', '/signin', '/api/login', '/api/auth',
        # Microservice patterns
        '/service', '/gateway', '/proxy',
        # Common API endpoints
        '/api/user', '/api/users', '/api/config', '/api/settings',
        '/api/menu', '/api/role', '/api/permission', '/api/upload',
        # Sitemap & robots
        '/sitemap.xml', '/robots.txt',
        # Popular frameworks
        '/_next/data', '/_nuxt', '/api/_nuxt',
        '/.env', '/.git/config', '/config.json',
    ]

    API_URL_PATTERNS = [
        r'/api[/\w]*',
        r'/rest[/\w]*',
        r'\.json($|\?)',
        r'/v\d+/',
        r'/graphql',
        r'/oauth',
        r'/token',
        r'/service',
        r'/gateway',
        r'/microservice',
        r'/wp-json',
        r'/admin',
        r'/manage',
    ]

    JS_API_PATTERNS = [
        # fetch / axios / request
        r'(?:fetch|axios\.\w+|\.request|\.get|\.post|\.put|\.delete)\s*\(\s*[`"\']([^`"\']{3,200})[`"\']',
        # URL strings that look like APIs
        r'["\']((?:https?://|//)[^"\']*(?:api|rest|service|gateway|auth|oauth|graphql|v\d)[^"\']*)["\']',
        # Path strings
        r'["\']((?:/api|/rest|/v\d|/service|/gateway|/auth|/graphql|/wp-json)/[^"\'\s<>{}]{2,200})["\']',
        # Base URL patterns
        r'(?:baseURL|apiUrl|apiBase|BASE_URL|API_URL|baseUrl|api_url|serverUrl|endpoint_url|host)\s*[:=]\s*["\']([^"\']{3,200})["\']',
        # Route/path definitions
        r'(?:path|route|endpoint|url|uri|href)\s*[:=]\s*["\']((?:/|https?://)[^"\']{3,200})["\']',
        # Template literals with API paths
        r'`((?:https?://|\$\{[^}]+\}/)[^`]*(?:api|rest|v\d)[^`]*)`',
        # Nuxt/Next API routes
        r'["\']((?:/api/)[^"\']{2,200})["\']',
        # Vue/React router paths
        r'(?:component|redirect).*?["\']((?:/api|/rest)/[^"\']{2,200})["\']',
    ]

    STATIC_EXTENSIONS = (
        '.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif',
        '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.webm', '.webp', '.avi', '.mov', '.flv',
        '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.exe', '.dmg',
        '.msi', '.apk', '.ipa', '.swf', '.bmp', '.tif', '.tiff',
    )

    FRAMEWORK_INDICATORS = {
        'react': [r'__NEXT_DATA__', r'react', r'__REACT', r'_next/static'],
        'vue': [r'__NUXT__', r'vue', r'nuxt', r'_nuxt'],
        'angular': [r'ng-', r'angular', r'_angular'],
        'django': [r'csrfmiddlewaretoken', r'django'],
        'flask': [r'flask', r'werkzeug'],
        'spring': [r'spring', r'actuator'],
        'laravel': [r'laravel', r'_token'],
        'wordpress': [r'wp-content', r'wp-includes', r'wordpress'],
        'express': [r'express'],
        'nextjs': [r'__NEXT_DATA__', r'_next'],
        'nuxtjs': [r'__NUXT__', r'_nuxt'],
    }

    def __init__(self, timeout=12, max_depth=3, max_pages=100):
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.session = requests.Session()
        # Anti-detection: UA rotation, delays, modern headers
        self.anti_detect = AntiDetection(min_delay=0.3, max_delay=1.5, respect_robots=True)
        # Set initial headers via anti-detection
        self.session.headers.update(self.anti_detect.get_headers())
        # Disable SSL warnings for sites with bad certs
        requests.packages.urllib3.disable_warnings()
        self.session.verify = False

        self.visited = set()
        self.found_endpoints = []
        self.js_files = []
        self._seen_keys = set()
        self._stop_flag = False
        self._progress_callback = None
        self._base_netloc = ''
        self._framework = None
        self._errors = []
        self._last_page_url = ''
        self._deduplicator = Deduplicator()
        self._dup_count = 0

    def set_cookies(self, cookies):
        """Inject cookies into the session. Accepts dict {name: value} or list [{name, value}]"""
        if isinstance(cookies, dict):
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        elif isinstance(cookies, list):
            for ck in cookies:
                if isinstance(ck, dict) and ck.get('name'):
                    self.session.cookies.set(ck['name'], ck.get('value', ''))

    def set_progress_callback(self, callback):
        self._progress_callback = callback

    def _report_progress(self, message, progress=None):
        if self._progress_callback:
            try:
                self._progress_callback(message, progress)
            except Exception:
                pass

    def stop(self):
        self._stop_flag = True

    def _safe_get(self, url, **kwargs):
        """Safe HTTP GET with anti-detection headers, delays, and backoff"""
        # Check robots.txt
        if self.anti_detect.should_skip_request(url):
            return None
        # Apply rate limiting delay
        self.anti_detect.wait(url)
        # Rotate headers for this request
        headers = self.anti_detect.get_headers(url, referer=self._last_page_url)
        self.session.headers.update(headers)
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('allow_redirects', True)
            kwargs.setdefault('verify', False)
            resp = self.session.get(url, **kwargs)
            # Handle rate limiting responses
            if resp is not None:
                self.anti_detect.handle_response(resp.status_code, url)
                # Update referer chain on successful page loads
                if resp.status_code == 200:
                    ct = resp.headers.get('content-type', '')
                    if 'html' in ct:
                        self.anti_detect.set_referer(url)
                        self._last_page_url = url
            return resp
        except requests.exceptions.SSLError:
            try:
                kwargs['verify'] = False
                return self.session.get(url, **kwargs)
            except Exception:
                return None
        except Exception:
            return None

    def _safe_request(self, method, url, **kwargs):
        """Safe HTTP request with anti-detection headers and delays"""
        if self.anti_detect.should_skip_request(url):
            return None
        self.anti_detect.wait(url)
        headers = self.anti_detect.get_headers(url, referer=self._last_page_url)
        self.session.headers.update(headers)
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('allow_redirects', True)
            kwargs.setdefault('verify', False)
            resp = self.session.request(method, url, **kwargs)
            if resp is not None:
                self.anti_detect.handle_response(resp.status_code, url)
            return resp
        except Exception:
            return None

    def crawl(self, target_url, deep_scan=True):
        """Main crawl entry point - robust against all edge cases"""
        self._stop_flag = False
        self.visited.clear()
        self.found_endpoints.clear()
        self.js_files.clear()
        self._seen_keys.clear()
        self._errors.clear()

        # Normalize URL
        target_url = self._normalize_url(target_url)
        parsed = urlparse(target_url)
        self._base_netloc = parsed.netloc

        self._report_progress(f'开始爬取 {target_url}', 0)

        try:
            # Phase 1: Initial page fetch and framework detection
            self._report_progress('阶段1: 连接目标并检测框架...', 3)
            initial_resp = self._safe_get(target_url)
            if initial_resp and initial_resp.status_code == 200:
                self._detect_framework(initial_resp.text)
                self._add_endpoint(target_url, 'GET', initial_resp, source='entry')

            # Phase 2: Discover API docs (Swagger/OpenAPI)
            self._report_progress('阶段2: 检测API文档接口...', 8)
            self._check_api_docs(target_url)

            # Phase 3: Crawl HTML pages
            self._report_progress('阶段3: 爬取HTML页面发现接口...', 18)
            self._crawl_pages(target_url, deep_scan)

            # Phase 4: Analyze JavaScript files
            js_count = len(self.js_files)
            self._report_progress(f'阶段4: 分析 {js_count} 个JavaScript文件...', 45)
            self._analyze_js_files()

            # Phase 5: Probe common API paths
            self._report_progress('阶段5: 探测常见API路径...', 65)
            self._probe_common_paths(target_url)

            # Phase 6: Follow redirects for discovered endpoints
            self._report_progress('阶段6: 验证已发现的接口...', 80)
            self._verify_endpoints()

            # Phase 7: Deep analyze top endpoints
            self._report_progress('阶段7: 深度分析接口响应...', 90)
            self._deep_analyze_endpoints()

        except Exception as e:
            self._errors.append(f'Crawl error: {str(e)}')

        result_count = len(self.found_endpoints)
        self._report_progress(f'爬取完成，共发现 {result_count} 个接口', 100)

        return self.found_endpoints

    def _normalize_url(self, url):
        """Normalize URL format"""
        if not url:
            return ''
        url = url.strip()
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
        # Remove trailing slash for consistency
        return url.rstrip('/')

    def _detect_framework(self, html):
        """Detect the web framework used"""
        if not html:
            return
        html_lower = html[:10000].lower()
        for fw, indicators in self.FRAMEWORK_INDICATORS.items():
            for ind in indicators:
                if re.search(ind, html_lower):
                    self._framework = fw
                    return

    def _check_api_docs(self, base_url):
        """Check for Swagger/OpenAPI/GraphQL playground documentation"""
        paths = [
            '/swagger-ui.html', '/swagger/index.html', '/swagger-ui/',
            '/api-docs', '/v2/api-docs', '/v3/api-docs',
            '/swagger.json', '/swagger/v1/swagger.json',
            '/openapi.json', '/openapi.yaml', '/openapi/v3/api-docs',
            '/api/swagger.json', '/api/openapi.json', '/api/swagger.yaml',
            '/docs', '/redoc', '/doc/', '/documentation/',
            '/.well-known/openapi', '/.well-known/openapi.json',
            '/.well-known/openid-configuration',
            '/graphql', '/gql', '/graphiql',
            '/playground', '/graphql/playground',
            '/api/explorer', '/api/console',
        ]

        # Randomize order to avoid predictable scanning patterns
        paths = self.anti_detect.randomize_request_order(paths)

        for path in paths:
            if self._stop_flag:
                return
            try:
                url = urljoin(base_url, path)
                resp = self._safe_get(url, timeout=6)
                if resp is None or resp.status_code != 200:
                    continue
                content = resp.text[:8000] if resp.text else ''
                content_lower = content.lower()
                # Check for API doc indicators
                doc_keywords = ['swagger', 'openapi', 'paths', 'api-docs', 'redoc',
                               'graphiql', 'playground', 'explorer']
                if any(k in content_lower for k in doc_keywords):
                    self._add_endpoint(url, 'GET', resp, source='api-docs')
                    # Parse the spec for embedded endpoints
                    self._parse_api_spec(content, base_url)
            except Exception:
                pass

    def _parse_api_spec(self, content, base_url):
        """Parse OpenAPI/Swagger spec to extract all endpoints"""
        if not content:
            return
        try:
            spec = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            # Try to find JSON embedded in HTML
            try:
                json_match = re.search(r'(\{[\s\S]*"paths"[\s\S]*\})', content)
                if json_match:
                    spec = json.loads(json_match.group(1))
                else:
                    return
            except Exception:
                return

        if not isinstance(spec, dict):
            return

        paths = spec.get('paths', {})
        if not isinstance(paths, dict):
            return

        for path, methods in paths.items():
            if not isinstance(methods, dict) or not path:
                continue
            for method_key, details in methods.items():
                if not isinstance(method_key, str):
                    continue
                method_upper = method_key.upper()
                if method_upper not in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
                    continue
                try:
                    full_url = urljoin(base_url, str(path).lstrip('/'))
                    desc = ''
                    if isinstance(details, dict):
                        desc = details.get('summary', '') or details.get('description', '') or ''
                        if desc:
                            desc = str(desc)[:200]
                    self._add_endpoint(full_url, method_upper, None,
                                       description=desc, source='openapi')
                except Exception:
                    pass

    def _crawl_pages(self, start_url, deep_scan):
        """Crawl HTML pages to find API endpoints - handles all edge cases"""
        queue = [(start_url, 0)]
        pages_crawled = 0

        while queue and not self._stop_flag and pages_crawled < self.max_pages:
            url, depth = queue.pop(0)

            if not url or url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)
            pages_crawled += 1

            resp = self._safe_get(url, timeout=self.timeout)
            if resp is None:
                continue

            content_type = resp.headers.get('content-type', '') if resp.headers else ''
            if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                continue

            # Deduplicate: skip pages with identical content
            if self._deduplicator.is_duplicate(url, resp.text or ''):
                self._dup_count += 1
                continue

            try:
                soup = BeautifulSoup(resp.text or '', 'html.parser')
            except Exception:
                continue

            if soup is None:
                continue

            # Extract API URLs from page content
            self._extract_apis_from_html(soup, url)

            # Find and analyze JS files
            script_tags = soup.find_all('script') if soup else []
            for script in script_tags:
                if not script:
                    continue
                src = script.get('src', '')
                if src:
                    try:
                        js_url = urljoin(url, src)
                        if js_url and js_url not in self.js_files:
                            self.js_files.append(js_url)
                    except Exception:
                        pass
                else:
                    # Inline script
                    script_content = script.string or script.get_text() or ''
                    if script_content and len(script_content) > 10:
                        self._extract_apis_from_js_text(script_content, url)

            # Find CSS files that might contain API references (rare but happens)
            for link in soup.find_all('link', rel='stylesheet'):
                if link:
                    href = link.get('href', '')
                    if href:
                        css_url = urljoin(url, href)
                        # Don't crawl CSS, but track for completeness

            # Find links for deeper crawling
            if deep_scan:
                links = soup.find_all('a', href=True) if soup else []
                # Randomize link order to avoid predictable crawl patterns
                links = self.anti_detect.randomize_request_order(links)
                for link in links:
                    if not link:
                        continue
                    href = link.get('href', '')
                    if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                        continue
                    try:
                        next_url = urljoin(url, href)
                    except Exception:
                        continue
                    parsed_next = urlparse(next_url)
                    parsed_start = urlparse(start_url)
                    if (parsed_next.netloc == parsed_start.netloc and
                        next_url not in self.visited and
                        not self._is_static(next_url)):
                        queue.append((next_url, depth + 1))

            # Extract form actions
            forms = soup.find_all('form') if soup else []
            for form in forms:
                if not form:
                    continue
                action = form.get('action', '')
                if action:
                    try:
                        form_url = urljoin(url, action)
                        method = (form.get('method') or 'GET').upper()
                        self._add_endpoint(form_url, method, resp, source='form')
                    except Exception:
                        pass

    def _extract_apis_from_html(self, soup, base_url):
        """Extract API-like URLs from HTML content - safe against all None types"""
        if not soup:
            return

        try:
            tags = soup.find_all(True)
        except Exception:
            return

        for tag in tags:
            if not tag:
                continue
            try:
                attrs = tag.attrs if hasattr(tag, 'attrs') and tag.attrs else {}
                if not isinstance(attrs, dict):
                    continue
                for attr_name, attr_value in attrs.items():
                    values = attr_value if isinstance(attr_value, list) else [attr_value]
                    for val in values:
                        if not isinstance(val, str):
                            continue
                        if self._looks_like_api(val):
                            try:
                                api_url = urljoin(base_url, val)
                                self._add_endpoint(api_url, 'GET', None, source='html-attr')
                            except Exception:
                                pass
            except Exception:
                continue

        # Check all text for API-like patterns
        try:
            text = soup.get_text() or ''
        except Exception:
            return

        urls = re.findall(r'https?://[^\s<>"\']+', text)
        for url in urls:
            if self._looks_like_api(url):
                self._add_endpoint(url, 'GET', None, source='html-text')

    def _is_static(self, url):
        """Check if URL points to a static resource"""
        if not url:
            return True
        url_path = urlparse(url).path.lower().split('?')[0]
        return any(url_path.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def _looks_like_api(self, text):
        """Check if a string looks like an API endpoint"""
        if not text or not isinstance(text, str):
            return False
        if len(text) < 3 or len(text) > 2000:
            return False
        if self._is_static(text):
            return False
        for pattern in self.API_URL_PATTERNS:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
            except Exception:
                continue
        return False

    def _analyze_js_files(self):
        """Analyze JavaScript files for API endpoints - with randomized order"""
        total = len(self.js_files)
        if total == 0:
            return

        # Prioritize: min/vendor files last, app files first
        prioritized = []
        vendor = []
        for js_url in self.js_files:
            js_lower = js_url.lower()
            if any(v in js_lower for v in ['vendor', 'chunk', 'polyfill', 'node_modules', 'dist/lib']):
                vendor.append(js_url)
            else:
                prioritized.append(js_url)
        # Randomize within each group to avoid predictable patterns
        prioritized = self.anti_detect.randomize_request_order(prioritized)
        vendor = self.anti_detect.randomize_request_order(vendor)
        ordered = prioritized + vendor

        # Limit to first 60 files to prevent excessive scanning
        for i, js_url in enumerate(ordered[:60]):
            if self._stop_flag:
                return
            try:
                pct = 45 + int(20 * (i + 1) / min(total, 60))
                self._report_progress(f'分析JS {i+1}/{min(total, 60)}: {js_url[:55]}...', pct)
                resp = self._safe_get(js_url, timeout=8)
                if resp and resp.status_code == 200 and resp.text:
                    self._extract_apis_from_js_text(resp.text, js_url)
            except Exception:
                pass

    def _extract_apis_from_js_text(self, js_text, base_url):
        """Extract API URLs from JavaScript code - handles all frameworks"""
        if not js_text or not isinstance(js_text, str):
            return
        if len(js_text) < 10:
            return

        base = urlparse(base_url) if base_url else None
        base_prefix = f'{base.scheme}://{base.netloc}' if base and base.scheme and base.netloc else ''

        for pattern in self.JS_API_PATTERNS:
            try:
                matches = re.findall(pattern, js_text)
            except Exception:
                continue

            for match in matches:
                if not match or not isinstance(match, str):
                    continue
                api_path = match.strip()
                if len(api_path) < 3:
                    continue

                try:
                    if api_path.startswith('http://') or api_path.startswith('https://'):
                        full_url = api_path
                    elif api_path.startswith('//'):
                        full_url = 'https:' + api_path
                    elif api_path.startswith('/'):
                        full_url = base_prefix + api_path if base_prefix else api_path
                    elif api_path.startswith('.'):
                        full_url = urljoin(base_url, api_path) if base_url else api_path
                    else:
                        continue

                    if self._looks_like_api(full_url):
                        self._add_endpoint(full_url, 'GET', None, source='javascript')
                except Exception:
                    pass

        # REST-style path patterns (broader matching)
        rest_patterns = [
            r'["\']((?:/api|/rest|/v\d|/service|/gateway|/auth|/graphql|/wp-json)/[^"\'\s<>{}()]{2,200})["\']',
            r'["\']((?:/api|/rest)/[^"\'\s<>{}()]+\{[^}]+\}[^"\'\s]{0,100})["\']',
        ]
        for pattern in rest_patterns:
            try:
                matches = re.findall(pattern, js_text)
            except Exception:
                continue
            for match in matches:
                if not match or not isinstance(match, str) or len(match) < 3:
                    continue
                try:
                    if match.startswith('/'):
                        full_url = base_prefix + match if base_prefix else match
                    elif match.startswith('http'):
                        full_url = match
                    else:
                        continue
                    self._add_endpoint(full_url, 'GET', None, source='javascript')
                except Exception:
                    pass

    def _probe_common_paths(self, base_url):
        """Probe common API paths - with randomized order and rate limiting"""
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            return
        base = f'{parsed.scheme}://{parsed.netloc}'

        # Randomize probe order to avoid predictable scanning patterns
        paths = self.anti_detect.randomize_request_order(self.COMMON_API_PATHS)

        total = len(paths)
        for i, path in enumerate(paths):
            if self._stop_flag:
                return
            try:
                url = base + path
                resp = self._safe_get(url, timeout=5)
                if resp is None:
                    continue
                if resp.status_code < 400:
                    self._add_endpoint(url, 'GET', resp, source='probe')
                elif resp.status_code in (401, 403):
                    # Auth-protected endpoints are still valid APIs
                    self._add_endpoint(url, 'GET', resp, source='probe-auth')
            except Exception:
                pass

    def _verify_endpoints(self):
        """Quick verification of discovered endpoints"""
        verified = 0
        for ep in self.found_endpoints:
            if self._stop_flag or verified >= 30:
                break
            if ep.get('status_code') is None:
                try:
                    resp = self._safe_request(ep.get('method', 'GET'), ep.get('url', ''), timeout=5)
                    if resp:
                        ep['status_code'] = resp.status_code
                        ep['content_type'] = resp.headers.get('content-type', '') if resp.headers else ''
                        verified += 1
                except Exception:
                    pass

    def _deep_analyze_endpoints(self):
        """Send test requests to discovered endpoints for deeper analysis"""
        analyzed = 0
        # Sort: prioritize endpoints without status codes
        sorted_eps = sorted(self.found_endpoints, key=lambda e: (e.get('status_code') is not None, 0))

        for ep in sorted_eps[:40]:
            if self._stop_flag:
                return
            if not ep or not ep.get('url'):
                continue
            analyzed += 1
            try:
                resp = self._safe_request(ep.get('method', 'GET'), ep['url'], timeout=8)
                if resp:
                    ep['status_code'] = resp.status_code
                    ct = resp.headers.get('content-type', '') if resp.headers else ''
                    ep['content_type'] = ct
                    ep['response_size'] = len(resp.content) if resp.content else 0
                    if 'json' in ct.lower() and resp.text:
                        ep['response_sample'] = resp.text[:2000]
            except Exception:
                pass

    def _add_endpoint(self, url, method='GET', response=None, description='', source='crawler'):
        """Add a discovered endpoint - comprehensive deduplication and validation"""
        if not url or not isinstance(url, str):
            return

        # Clean URL
        try:
            url = url.split('#')[0].rstrip('?&')
        except Exception:
            return

        if len(url) < 5 or len(url) > 2000:
            return

        # Skip non-HTTP URLs
        if not url.startswith(('http://', 'https://')):
            return

        # Deduplication
        method = (method or 'GET').upper()
        dedup_key = f'{method}:{url}'
        if dedup_key in self._seen_keys:
            return
        self._seen_keys.add(dedup_key)

        endpoint = {
            'url': url,
            'method': method,
            'status_code': None,
            'content_type': None,
            'response_size': None,
            'response_sample': None,
            'description': description or '',
            'source': source or 'crawler',
            'headers': {},
        }

        if response is not None:
            try:
                endpoint['status_code'] = response.status_code
                ct = response.headers.get('content-type', '') if response.headers else ''
                endpoint['content_type'] = ct
                endpoint['response_size'] = len(response.content) if response.content else 0
                if response.headers:
                    endpoint['headers'] = dict(response.headers)
            except Exception:
                pass

        self.found_endpoints.append(endpoint)


class SingleURLAnalyzer:
    """Quick analysis of a single URL - robust against all errors"""

    def __init__(self):
        self.session = requests.Session()
        self.anti_detect = AntiDetection(min_delay=0.2, max_delay=0.8, respect_robots=False)
        self.session.headers.update(self.anti_detect.get_headers())
        self.session.verify = False

    def set_cookies(self, cookies):
        """Inject cookies into the session. Accepts dict {name: value} or list [{name, value}]"""
        if isinstance(cookies, dict):
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        elif isinstance(cookies, list):
            for ck in cookies:
                if isinstance(ck, dict) and ck.get('name'):
                    self.session.cookies.set(ck['name'], ck.get('value', ''))

    def analyze(self, url, method='GET', headers=None, body=None):
        """Analyze a single endpoint with comprehensive error handling"""
        if not url:
            return {'error': 'URL为空', 'url': ''}

        try:
            # Apply anti-detection delay and headers
            self.anti_detect.wait(url)
            merged_headers = self.anti_detect.get_headers(url)
            if headers and isinstance(headers, dict):
                merged_headers.update(headers)

            resp = self.session.request(
                method or 'GET', url,
                headers=merged_headers,
                data=body if body else None,
                timeout=15,
                allow_redirects=True,
                verify=False,
            )

            resp_headers = dict(resp.headers) if resp.headers else {}
            resp_text = resp.text[:5000] if resp.text else ''
            content_type = resp_headers.get('content-type', '')

            result = {
                'url': url,
                'method': method or 'GET',
                'status_code': resp.status_code,
                'content_type': content_type,
                'response_size': len(resp.content) if resp.content else 0,
                'headers': resp_headers,
                'response_sample': resp_text[:3000],
                'response_time': resp.elapsed.total_seconds() if resp.elapsed else 0,
            }

            # Parse JSON structure
            if 'json' in content_type.lower() and resp_text:
                try:
                    json_data = json.loads(resp_text)
                    result['json_structure'] = self._analyze_json_structure(json_data)
                except (json.JSONDecodeError, ValueError):
                    result['json_structure'] = None

            return result
        except requests.exceptions.ConnectionError:
            return {'error': '连接失败 - 无法连接到目标服务器', 'url': url}
        except requests.exceptions.Timeout:
            return {'error': '请求超时', 'url': url}
        except requests.exceptions.TooManyRedirects:
            return {'error': '重定向次数过多', 'url': url}
        except Exception as e:
            return {'error': f'请求异常: {str(e)}', 'url': url}

    def _analyze_json_structure(self, data, depth=0, max_depth=5):
        """Analyze JSON response structure with depth limiting"""
        if depth > max_depth:
            return '...'
        if isinstance(data, dict):
            structure = {}
            for key, value in data.items():
                if isinstance(value, dict):
                    structure[str(key)] = self._analyze_json_structure(value, depth + 1, max_depth)
                elif isinstance(value, list):
                    if value and len(value) > 0:
                        first = value[0]
                        if isinstance(first, dict):
                            structure[str(key)] = f'array[object] (len={len(value)})'
                        else:
                            structure[str(key)] = f'array[{type(first).__name__}] (len={len(value)})'
                    else:
                        structure[str(key)] = 'array[empty]'
                else:
                    structure[str(key)] = type(value).__name__
            return structure
        elif isinstance(data, list):
            if data:
                return f'array of {type(data[0]).__name__}, length={len(data)}'
            return 'empty array'
        return type(data).__name__
