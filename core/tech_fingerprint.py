"""技术栈指纹识别 — 精确识别框架/CMS/库版本号"""
import re
import json


# 四维指纹库: headers / html_meta / js_globals / file_paths
FINGERPRINT_RULES = [
    # ── 前端框架 ──
    {'name': 'React', 'category': 'frontend', 'version_patterns': [
        r'react@([\d.]+)', r'"react"\s*:\s*"([\d.]+)"',
        r'React\.version\s*=\s*["\']([\d.]+)', r'data-reactroot',
    ], 'html': [r'_reactRoot|react-root|__reactFiber'], 'js': [r'React\.createElement|__REACT_DEVTOOLS_GLOBAL_HOOK__'],
     'confidence_base': 0.9},
    {'name': 'Vue.js', 'category': 'frontend', 'version_patterns': [
        r'vue@([\d.]+)', r'"vue"\s*:\s*"([\d.]+)"',
        r'Vue\.version\s*=\s*["\']([\d.]+)',
    ], 'html': [r'data-v-[a-f0-9]{8}', r'v-bind:|v-on:|v-if=|v-for='], 'js': [r'Vue\.createApp|new Vue\(|__VUE__'],
     'confidence_base': 0.9},
    {'name': 'Angular', 'category': 'frontend', 'version_patterns': [
        r'angular@([\d.]+)', r'Angular (\d+\.\d+\.\d+)',
        r'ng-version="([\d.]+)"',
    ], 'html': [r'ng-app|ng-controller|\[ngClass\]|\\*ngIf'], 'js': [r'@angular/core|ng\.module'],
     'confidence_base': 0.9},
    {'name': 'Next.js', 'category': 'frontend', 'version_patterns': [
        r'next@([\d.]+)', r'"next"\s*:\s*"([\d.]+)"',
    ], 'html': [r'__NEXT_DATA__|_next/static'], 'js': [r'window\.__NEXT_DATA__|next/router'],
     'confidence_base': 0.95},
    {'name': 'Nuxt.js', 'category': 'frontend', 'version_patterns': [
        r'nuxt@([\d.]+)', r'"nuxt"\s*:\s*"([\d.]+)"',
    ], 'html': [r'__NUXT__|_nuxt/'], 'js': [r'window\.__NUXT__|nuxt'],
     'confidence_base': 0.95},
    {'name': 'Svelte', 'category': 'frontend', 'version_patterns': [
        r'svelte@([\d.]+)',
    ], 'html': [r'class="svelte-'], 'js': [r'__svelte|create_svelte_component'],
     'confidence_base': 0.85},
    {'name': 'jQuery', 'category': 'library', 'version_patterns': [
        r'jquery[/.-]v?([\d]+\.[\d]+(?:\.[\d]+)?)', r'jQuery v([\d]+\.[\d]+(?:\.[\d]+)?)',
        r'jquery[.-]?([\d]+\.[\d]+(?:\.[\d]+)?)\.min\.js', r'"jquery"\s*:\s*"([\d]+\.[\d]+(?:\.[\d]+)?)"',
    ], 'html': [], 'js': [r'jQuery\.fn\.jquery|\$\.fn\.jquery|jQuery v'],
     'confidence_base': 0.85},
    {'name': 'Bootstrap', 'category': 'css_framework', 'version_patterns': [
        r'bootstrap@([\d.]+)', r'bootstrap[/.-]v?([\d.]+)',
    ], 'html': [r'data-bs-[a-z]+', r'class="[^"]*btn-primary'], 'js': [r'bootstrap\.Tooltip|bootstrap\.Modal'],
     'confidence_base': 0.8},
    {'name': 'Tailwind CSS', 'category': 'css_framework', 'version_patterns': [
        r'tailwindcss@([\d.]+)',
    ], 'html': [r'class="[^"]*(?:flex|grid|p-\d|m-\d|text-\w+|bg-\w+)-'], 'js': [],
     'confidence_base': 0.7},
    {'name': 'Alpine.js', 'category': 'frontend', 'version_patterns': [
        r'alpinejs@([\d.]+)', r'alpine@([\d.]+)',
    ], 'html': [r'x-data|x-show|x-on:|x-bind:'], 'js': [r'Alpine\.start|Alpine\.data'],
     'confidence_base': 0.85},

    # ── 后端语言 / 框架 ──
    {'name': 'PHP', 'category': 'backend', 'version_patterns': [
        r'X-Powered-By:\s*PHP/([\d.]+)', r'PHP/([\d.]+)',
    ], 'html': [r'\.php(?:\?|")'], 'js': [], 'headers': [r'X-Powered-By.*PHP'],
     'cookies': ['PHPSESSID'], 'confidence_base': 0.9},
    {'name': 'Laravel', 'category': 'backend_framework', 'version_patterns': [
        r'"laravel_version"\s*:\s*"([\d.]+)"', r'laravel_version.*?([\d.]+)',
    ], 'html': [r'laravel_session|XSRF-TOKEN'], 'js': [],
     'cookies': ['laravel_session', 'XSRF-TOKEN'], 'confidence_base': 0.9},
    {'name': 'Django', 'category': 'backend_framework', 'version_patterns': [
        r'Django/([\d.]+)',
    ], 'html': [r'csrfmiddlewaretoken|__admin/'], 'js': [],
     'headers': [r'Server.*gunicorn'], 'cookies': ['csrftoken', 'sessionid'], 'confidence_base': 0.85},
    {'name': 'Flask', 'category': 'backend_framework', 'version_patterns': [
        r'Flask/([\d.]+)',
    ], 'html': [], 'js': [], 'headers': [r'Server.*Werkzeug'],
     'cookies': ['session'], 'confidence_base': 0.7},
    {'name': 'Spring Boot', 'category': 'backend_framework', 'version_patterns': [
        r'spring-boot/([\d.]+)', r'Spring/([\d.]+)',
    ], 'html': [r'jsessionid'], 'js': [],
     'cookies': ['JSESSIONID'], 'confidence_base': 0.85},
    {'name': 'Express', 'category': 'backend_framework', 'version_patterns': [
        r'express/([\d.]+)',
    ], 'html': [], 'js': [], 'headers': [r'X-Powered-By.*Express'],
     'confidence_base': 0.85},
    {'name': 'ASP.NET', 'category': 'backend_framework', 'version_patterns': [
        r'ASP\.NET(?: Core)? ([\d.]+)', r'aspnetcore/([\d.]+)',
    ], 'html': [r'__VIEWSTATE|__EVENTVALIDATION'], 'js': [],
     'headers': [r'X-AspNet-Version|X-Powered-By.*ASP\.NET'],
     'cookies': ['ASP.NET_SessionId', '.AspNetCore'], 'confidence_base': 0.9},
    {'name': 'Ruby on Rails', 'category': 'backend_framework', 'version_patterns': [
        r'Rails ([\d.]+)',
    ], 'html': [r'authenticity_token'], 'js': [],
     'cookies': ['_rails_session'], 'confidence_base': 0.8},
    {'name': 'Node.js', 'category': 'backend', 'version_patterns': [
        r'Node\.js/([\d.]+)',
    ], 'html': [], 'js': [], 'headers': [r'X-Powered-By.*Express|Server.*node'],
     'confidence_base': 0.6},

    # ── CMS ──
    {'name': 'WordPress', 'category': 'cms', 'version_patterns': [
        r'content="WordPress ([\d.]+)"', r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)',
        r'/wp-content/themes/[^/]+/style\.css\?ver=([\d.]+)',
    ], 'html': [r'wp-content/', r'wp-includes/', r'wp-json'], 'js': [r'wp-emoji|wp-embed'],
     'confidence_base': 0.95},
    {'name': 'Joomla', 'category': 'cms', 'version_patterns': [
        r'content="Joomla! ([\d.]+)"', r'/media/jui/js/bootstrap\.min\.js\?ver=([\d.]+)',
    ], 'html': [r'/administrator/', r'com_content'], 'js': [],
     'confidence_base': 0.9},
    {'name': 'Drupal', 'category': 'cms', 'version_patterns': [
        r'Drupal ([\d.]+)', r'drupal\.js\?v=([\d.]+)',
    ], 'html': [r'drupal\.js', r'sites/default/files'], 'js': [r'Drupal\.settings'],
     'confidence_base': 0.9},
    {'name': 'Discuz', 'category': 'cms', 'version_patterns': [
        r'Discuz! ([\d.]+)', r'Discuz_X([\d_]+)',
    ], 'html': [r'discuz_uid', r'forum\.php'], 'js': [r'DISCUZ_CODE'],
     'confidence_base': 0.95},
    {'name': 'DedeCMS', 'category': 'cms', 'version_patterns': [
        r'DedeBIZ v([\d.]+)',
    ], 'html': [r'/dede/', r'/templets/', r'DedeCMS'], 'js': [],
     'confidence_base': 0.9},
    {'name': 'ThinkPHP', 'category': 'cms', 'version_patterns': [
        r'ThinkPHP V([\d.]+)', r'thinkphp[\s/]+([\d.]+)',
    ], 'html': [r'ThinkPHP', r'think_\w+'], 'js': [],
     'confidence_base': 0.9},

    # ── Web 服务器 ──
    {'name': 'Nginx', 'category': 'server', 'version_patterns': [
        r'nginx/([\d.]+)',
    ], 'html': [], 'js': [], 'headers': [r'Server.*nginx'],
     'confidence_base': 0.95},
    {'name': 'Apache', 'category': 'server', 'version_patterns': [
        r'Apache/([\d.]+)',
    ], 'html': [], 'js': [], 'headers': [r'Server.*Apache'],
     'confidence_base': 0.95},
    {'name': 'IIS', 'category': 'server', 'version_patterns': [
        r'IIS/([\d.]+)',
    ], 'html': [], 'js': [], 'headers': [r'Server.*IIS'],
     'confidence_base': 0.95},
    {'name': 'Caddy', 'category': 'server', 'version_patterns': [
        r'Caddy/([\d.]+)',
    ], 'html': [], 'js': [], 'headers': [r'Server.*Caddy'],
     'confidence_base': 0.95},

    # ── CDN / 云 ──
    {'name': 'Cloudflare', 'category': 'cdn', 'version_patterns': [],
     'html': [], 'js': [], 'headers': [r'cf-ray', r'CF-Cache-Status'],
     'confidence_base': 0.95},
    {'name': 'Akamai', 'category': 'cdn', 'version_patterns': [],
     'html': [], 'js': [], 'headers': [r'X-Akamai-Transformed', r'X-Akamai-Request-ID'],
     'confidence_base': 0.95},
    {'name': 'AWS CloudFront', 'category': 'cdn', 'version_patterns': [],
     'html': [], 'js': [], 'headers': [r'X-Amz-Cf-Id', r'X-Cache.*CloudFront'],
     'confidence_base': 0.95},
    {'name': '腾讯云 CDN', 'category': 'cdn', 'version_patterns': [],
     'html': [], 'js': [], 'headers': [r'X-Tencent-UUI', r'X-NWS-LOG-UUID'],
     'confidence_base': 0.95},
    {'name': '阿里云 CDN', 'category': 'cdn', 'version_patterns': [],
     'html': [], 'js': [], 'headers': [r'Ali-Swift-Global-Savetime', r'EagleId'],
     'confidence_base': 0.95},

    # ── 分析 / 监控 ──
    {'name': 'Google Analytics', 'category': 'analytics', 'version_patterns': [
        r'www\.googletagmanager\.com/gtag/js\?id=(G-[\w-]+)',
    ], 'html': [r'googletagmanager\.com', r'gtag\('], 'js': [r'gtag|GoogleAnalyticsObject'],
     'confidence_base': 0.9},
    {'name': '百度统计', 'category': 'analytics', 'version_patterns': [],
     'html': [r'hm\.baidu\.com/hm\.js'], 'js': [r'_hmt\.push'],
     'confidence_base': 0.9},
    {'name': 'Sentry', 'category': 'monitoring', 'version_patterns': [
        r'sentry@([\d.]+)',
    ], 'html': [r'sentry\.io|sentry-cdn'], 'js': [r'Sentry\.init|@sentry/browser'],
     'confidence_base': 0.85},

    # ── JS 库 / 工具 ──
    {'name': 'Axios', 'category': 'library', 'version_patterns': [
        r'axios@([\d.]+)', r'"axios"\s*:\s*"([\d.]+)"',
    ], 'html': [], 'js': [r'axios\.get|axios\.post|axios\.create'],
     'confidence_base': 0.8},
    {'name': 'Lodash', 'category': 'library', 'version_patterns': [
        r'lodash@([\d.]+)', r'lodash/([\d.]+)',
    ], 'html': [], 'js': [r'_\.debounce|_\.throttle|_\.merge|_\.cloneDeep'],
     'confidence_base': 0.8},
    {'name': 'Moment.js', 'category': 'library', 'version_patterns': [
        r'moment@([\d.]+)', r'moment\.js\?v=([\d.]+)',
    ], 'html': [], 'js': [r'moment\(\)|moment\.format'],
     'confidence_base': 0.8},
    {'name': 'Three.js', 'category': 'library', 'version_patterns': [
        r'three@([\d.]+)', r'three\.js.*r(\d+)',
    ], 'html': [], 'js': [r'THREE\.Scene|THREE\.WebGLRenderer'],
     'confidence_base': 0.85},
    {'name': 'Chart.js', 'category': 'library', 'version_patterns': [
        r'chart\.js@([\d.]+)', r'Chart\.js ([\d.]+)',
    ], 'html': [], 'js': [r'new Chart\(|Chart\.defaults'],
     'confidence_base': 0.85},

    # ── 构建工具 ──
    {'name': 'Webpack', 'category': 'build_tool', 'version_patterns': [
        r'webpack/([\d.]+)',
    ], 'html': [r'/static/js/\d+\.\w+\.chunk\.js'], 'js': [r'webpackJsonp|__webpack_require__|__webpack_hash__'],
     'confidence_base': 0.8},
    {'name': 'Vite', 'category': 'build_tool', 'version_patterns': [
        r'vite@([\d.]+)',
    ], 'html': [r'/@vite/client', r'type="module"'], 'js': [r'__vite_|import\.meta\.hot'],
     'confidence_base': 0.9},
    {'name': 'Babel', 'category': 'build_tool', 'version_patterns': [
        r'babel/([\d.]+)',
    ], 'html': [], 'js': [r'_classCallCheck|_defineProperty|_asyncToGenerator'],
     'confidence_base': 0.6},
]


class TechFingerprinter:
    """技术栈指纹识别器 — 四维分析"""

    def __init__(self):
        self._compiled_rules = self._compile_rules()

    def _compile_rules(self):
        compiled = []
        for rule in FINGERPRINT_RULES:
            cr = {
                'name': rule['name'],
                'category': rule.get('category', 'unknown'),
                'confidence_base': rule.get('confidence_base', 0.7),
                'version_patterns': [re.compile(p, re.I) for p in rule.get('version_patterns', [])],
                'html': [re.compile(p, re.I) for p in rule.get('html', [])],
                'js': [re.compile(p, re.I) for p in rule.get('js', [])],
                'headers': [re.compile(p, re.I) for p in rule.get('headers', [])],
                'cookies': rule.get('cookies', []),
            }
            compiled.append(cr)
        return compiled

    def analyze(self, url='', html='', headers=None, cookies=None):
        """分析目标技术栈

        Args:
            url: 目标 URL
            html: 页面 HTML 内容
            headers: 响应头 dict
            cookies: Cookie dict 或字符串

        Returns:
            dict: {
                'technologies': [{'name', 'version', 'category', 'confidence', 'evidence'}],
                'categories': {'frontend': [...], 'backend': [...], ...}
            }
        """
        headers = headers or {}
        header_str = '\n'.join(f'{k}: {v}' for k, v in headers.items()) if isinstance(headers, dict) else str(headers)

        if isinstance(cookies, str):
            cookie_names = [c.strip().split('=')[0] for c in cookies.split(';') if '=' in c]
        elif isinstance(cookies, dict):
            cookie_names = list(cookies.keys())
        else:
            cookie_names = []

        results = []
        for rule in self._compiled_rules:
            evidence = []
            confidence = 0.0
            version = ''

            # 维度 1: 响应头
            for pat in rule['headers']:
                m = pat.search(header_str)
                if m:
                    evidence.append(f'header: {m.group()[:80]}')
                    confidence += 0.35

            # 版本提取 (从响应头)
            if not version:
                for pat in rule['version_patterns']:
                    m = pat.search(header_str)
                    if m and m.lastindex:
                        version = m.group(1)
                        confidence += 0.2
                        break

            # 维度 2: HTML 内容
            if html:
                for pat in rule['html']:
                    m = pat.search(html)
                    if m:
                        evidence.append(f'html: {m.group()[:60]}')
                        confidence += 0.3
                        break

                # 版本提取 (从 HTML)
                if not version:
                    for pat in rule['version_patterns']:
                        m = pat.search(html)
                        if m and m.lastindex:
                            version = m.group(1)
                            confidence += 0.2
                            break

            # 维度 3: JS 全局变量
            if html:
                for pat in rule['js']:
                    m = pat.search(html)
                    if m:
                        evidence.append(f'js: {m.group()[:60]}')
                        confidence += 0.3
                        break

            # 维度 4: Cookie
            for cname in rule['cookies']:
                if cname in cookie_names:
                    evidence.append(f'cookie: {cname}')
                    confidence += 0.25
                    break

            if confidence > 0:
                final_conf = min(confidence * rule['confidence_base'], 1.0)
                results.append({
                    'name': rule['name'],
                    'version': version,
                    'category': rule['category'],
                    'confidence': round(final_conf, 2),
                    'evidence': '; '.join(evidence[:3]),
                })

        # 按置信度排序
        results.sort(key=lambda x: x['confidence'], reverse=True)

        # 按类别分组
        categories = {}
        for r in results:
            cat = r['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(r['name'])

        return {
            'technologies': results,
            'categories': categories,
        }

    def analyze_response(self, resp, html=''):
        """直接从 requests.Response 对象分析（兼容 site_crawler 调用方式）

        Returns:
            list[dict]: 与原 _detect_technologies 返回格式兼容，含 name/category/confidence/evidence
        """
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = {}
        if resp.cookies:
            for c in resp.cookies:
                cookies[c.name] = c.value

        result = self.analyze(url=resp.url, html=html or resp.text, headers=headers, cookies=cookies)

        # 转为兼容格式
        compatible = []
        for t in result['technologies']:
            compatible.append({
                'name': t['name'],
                'category': t['category'],
                'confidence': t['confidence'],
                'evidence': t['evidence'],
            })
        return compatible
