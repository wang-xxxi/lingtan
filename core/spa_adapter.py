"""SPA adapter - detect API calls from JavaScript code to get data from JS-rendered sites"""
import re
from urllib.parse import urljoin


# API call patterns in JavaScript
API_PATTERNS = [
    # fetch() calls
    (re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", re.I), 'fetch'),
    (re.compile(r"""fetch\s*\(\s*`([^`]+)`""", re.I), 'fetch_template'),
    # axios calls
    (re.compile(r"""axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""", re.I), 'axios'),
    (re.compile(r"""axios\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""", re.I), 'axios_config'),
    # jQuery AJAX
    (re.compile(r"""\$\.(ajax|get|post|getJSON)\s*\(\s*['"`]([^'"`]+)['"`]""", re.I), 'jquery'),
    (re.compile(r"""\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""", re.I), 'jquery_config'),
    # XMLHttpRequest
    (re.compile(r"""\.open\s*\(\s*['"`](GET|POST|PUT|DELETE)['"`]\s*,\s*['"`]([^'"`]+)['"`]""", re.I), 'xhr'),
    # GraphQL
    (re.compile(r"""['"`](query|mutation)\s+\w+""", re.I), 'graphql'),
    # API base URL patterns
    (re.compile(r"""(apiUrl|apiBase|baseURL|BASE_URL|api_base|api_url)\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.I), 'api_base'),
    # WebSocket
    (re.compile(r"""new\s+WebSocket\s*\(\s*['"`](wss?://[^'"`]+)['"`]""", re.I), 'websocket'),
    # SSE (Server-Sent Events)
    (re.compile(r"""new\s+EventSource\s*\(\s*['"`]([^'"`]+)['"`]""", re.I), 'sse'),
]

# Patterns for API path construction
ROUTE_PATTERNS = [
    (re.compile(r"""['"`](/api/[^'"`\s]+)['"`]""", re.I), 'api_path'),
    (re.compile(r"""['"`](/v\d+/[^'"`\s]+)['"`]""", re.I), 'versioned_api'),
    (re.compile(r"""['"`](/rest/[^'"`\s]+)['"`]""", re.I), 'rest_path'),
    (re.compile(r"""path\s*[:=]\s*['"`](/[^'"`\s]+)['"`]""", re.I), 'route_path'),
    (re.compile(r"""endpoint\s*[:=]\s*['"`]([^'"`\s]+)['"`]""", re.I), 'endpoint'),
    (re.compile(r"""url\s*[:=]\s*[`'"](/[^'"`\s]*\{[^}]+\}[^'"`\s]*)['"`]""", re.I), 'parameterized_path'),
]


def analyze_js(js_code, base_url=''):
    """Analyze JavaScript code to extract API endpoints and patterns.

    Returns:
        dict with keys:
        - api_calls: list of detected API calls
        - api_paths: list of API path strings found
        - api_base_url: detected base URL for API
        - graphql_endpoints: GraphQL endpoints
        - websocket_endpoints: WebSocket endpoints
        - spa_framework: detected SPA framework
    """
    result = {
        'api_calls': [],
        'api_paths': [],
        'api_base_url': '',
        'graphql_endpoints': [],
        'websocket_endpoints': [],
        'spa_framework': _detect_spa_framework(js_code),
    }

    if not js_code or not isinstance(js_code, str):
        return result

    # Limit analysis to first 500KB of JS
    code = js_code[:500000]

    # Extract API calls
    seen_calls = set()
    for pattern, call_type in API_PATTERNS:
        for m in pattern.finditer(code):
            groups = m.groups()
            if call_type in ('fetch', 'fetch_template', 'axios_config', 'jquery_config', 'xhr', 'sse'):
                url = groups[0] if len(groups) == 1 else groups[-1]
                method = groups[0].upper() if call_type == 'xhr' and len(groups) == 2 else 'GET'
            elif call_type in ('axios', 'jquery'):
                method = groups[0].upper()
                url = groups[1] if len(groups) > 1 else ''
            elif call_type == 'api_base':
                result['api_base_url'] = groups[1] if len(groups) > 1 else groups[0]
                continue
            elif call_type == 'websocket':
                result['websocket_endpoints'].append(groups[0])
                continue
            elif call_type == 'graphql':
                result['graphql_endpoints'].append(m.group()[:200])
                continue
            else:
                url = groups[0] if groups else ''
                method = 'GET'

            url = url.strip()
            if url and not url.startswith(('data:', 'blob:', 'javascript:', '#')):
                if base_url and url.startswith('/'):
                    full_url = urljoin(base_url, url)
                else:
                    full_url = url
                key = f'{method}:{full_url}'
                if key not in seen_calls:
                    seen_calls.add(key)
                    result['api_calls'].append({
                        'method': method,
                        'url': full_url,
                        'raw': url[:500],
                        'type': call_type,
                    })

    # Extract API paths
    seen_paths = set()
    for pattern, _ in ROUTE_PATTERNS:
        for m in pattern.finditer(code):
            path = m.group(1)
            if path and path not in seen_paths and len(path) > 2:
                seen_paths.add(path)
                result['api_paths'].append(path[:300])

    # Deduplicate
    result['websocket_endpoints'] = list(set(result['websocket_endpoints']))[:20]
    result['api_paths'] = result['api_paths'][:50]

    return result


def analyze_page_for_spa(html, base_url=''):
    """Analyze a page to determine if it's an SPA and extract API info.

    Returns:
        dict: combined SPA analysis from inline scripts and external script references
    """
    if not html:
        return {'is_spa': False, 'scripts': [], 'inline_api_calls': {'api_calls': [], 'api_paths': []}}

    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html[:200000], 'lxml')
    except Exception:
        soup = BeautifulSoup(html[:200000], 'html.parser')

    # Detect SPA framework from HTML
    html_str = html[:50000].lower()
    framework = 'unknown'
    if '__next_data__' in html_str or '_next/' in html_str:
        framework = 'nextjs'
    elif '__nuxt__' in html_str or '_nuxt/' in html_str:
        framework = 'nuxtjs'
    elif 'ng-version' in html_str or 'ng-app' in html_str:
        framework = 'angular'
    elif 'react' in html_str and ('root' in html_str or 'app' in html_str):
        framework = 'react'
    elif 'v-bind' in html_str or 'v-if' in html_str or 'v-for' in html_str:
        framework = 'vue'

    # Get external script URLs
    scripts = []
    for s in soup.find_all('script', src=True):
        src = s.get('src', '')
        if src:
            scripts.append({
                'src': urljoin(base_url, src) if base_url and src.startswith('/') else src,
                'framework_hint': framework,
            })

    # Analyze inline scripts
    inline_calls = {'api_calls': [], 'api_paths': []}
    for s in soup.find_all('script'):
        if s.string and len(s.string) > 50:
            analysis = analyze_js(s.string, base_url)
            inline_calls['api_calls'].extend(analysis['api_calls'])
            inline_calls['api_paths'].extend(analysis['api_paths'])

    is_spa = framework != 'unknown' or len(inline_calls['api_calls']) > 3

    return {
        'is_spa': is_spa,
        'framework': framework,
        'scripts': scripts[:30],
        'inline_api_calls': inline_calls,
    }


def _detect_spa_framework(js_code):
    """Detect SPA framework from JavaScript code"""
    if not js_code:
        return 'unknown'
    code = js_code[:10000].lower()

    if 'vue' in code and ('createapp' in code or 'vuex' in code or 'nuxt' in code):
        return 'vue'
    if 'react' in code and ('usestate' in code or 'useeffect' in code or 'createelement' in code):
        return 'react'
    if 'angular' in code or '@component' in code or 'ngmodule' in code:
        return 'angular'
    if 'next' in code and ('getstaticprops' in code or 'getserversideprops' in code):
        return 'nextjs'
    if 'nuxt' in code and ('asyncdata' in code or 'nuxtjs' in code):
        return 'nuxtjs'
    if 'svelte' in code:
        return 'svelte'

    return 'unknown'
