"""API Parameter Miner - extract parameters from JS/HTML and auto-fuzz them"""
import re
import time
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin


class ParamMiner:
    """Mine API parameters from JavaScript source code and test them"""

    # Patterns to extract parameter names from JS code
    PARAM_PATTERNS = [
        # Object property assignments: {key: value}, key: value
        r'["\']?([a-zA-Z_]\w{1,30})["\']?\s*:\s*["\']',
        # Form field names: name="field"
        r'name\s*=\s*["\']([a-zA-Z_]\w{1,30})["\']',
        # URL query params: ?key=value&key2=value2
        r'[?&]([a-zA-Z_]\w{1,30})=',
        # FormData append: formData.append('key', ...)
        r'\.append\s*\(\s*["\']([a-zA-Z_]\w{1,30})["\']',
        # URLSearchParams: new URLSearchParams('key=value')
        r'URLSearchParams.*?["\']([a-zA-Z_]\w{1,30})=',
        # Axios/fetch data: { key: val } or params: { key: val }
        r'(?:data|params|body|payload)\s*[:=]\s*\{[^}]*?([a-zA-Z_]\w{1,30})\s*:',
        # Destructuring: const { key } = response
        r'\{\s*([a-zA-Z_]\w{1,30})(?:\s*,\s*([a-zA-Z_]\w{1,30}))*\s*\}\s*=',
        # Bracket access: obj['key'] or obj["key"]
        r'\[\s*["\']([a-zA-Z_]\w{1,30})["\']\s*\]',
        # React state: useState({ key: val })
        r'setState\s*\(\s*\{[^}]*?([a-zA-Z_]\w{1,30})\s*:',
        # Validation patterns: required: ['key', 'key2']
        r'required\s*:\s*\[([^\]]+)\]',
        # JSON.parse keys
        r'JSON\.parse.*?["\']([a-zA-Z_]\w{1,30})["\']\s*:',
    ]

    # Common parameter names across web apps (fallback wordlist)
    COMMON_PARAMS = [
        'id', 'user_id', 'userId', 'page', 'size', 'limit', 'offset',
        'token', 'access_token', 'refresh_token', 'api_key', 'apikey',
        'q', 'query', 'search', 'keyword', 'type', 'status', 'action',
        'name', 'username', 'email', 'phone', 'password', 'code',
        'callback', 'redirect', 'url', 'next', 'return_url',
        'sort', 'order', 'order_by', 'direction', 'filter',
        'start', 'end', 'from', 'to', 'date', 'time',
        'lang', 'language', 'locale', 'format', 'version',
        'category', 'tag', 'label', 'group', 'role', 'permission',
        'key', 'secret', 'hash', 'sign', 'signature', 'timestamp',
        'nonce', 'state', 'scope', 'grant_type', 'response_type',
        'client_id', 'client_secret', 'redirect_uri',
        'file', 'upload', 'image', 'avatar', 'attachment',
        'data', 'payload', 'content', 'body', 'message',
        'source', 'origin', 'referer', 'platform', 'device',
        'latitude', 'longitude', 'lat', 'lng', 'location',
        'amount', 'price', 'quantity', 'count', 'total',
    ]

    # Noise params to filter out
    NOISE_PARAMS = {
        'var', 'let', 'const', 'function', 'return', 'true', 'false',
        'null', 'undefined', 'this', 'new', 'class', 'import', 'export',
        'from', 'default', 'if', 'else', 'for', 'while', 'switch', 'case',
        'break', 'continue', 'typeof', 'instanceof', 'try', 'catch',
        'throw', 'finally', 'async', 'await', 'yield', 'delete', 'void',
        'html', 'head', 'body', 'div', 'span', 'script', 'style', 'link',
        'src', 'href', 'type', 'rel', 'http', 'https', 'www',
        'width', 'height', 'color', 'font', 'size', 'margin', 'padding',
        'display', 'position', 'flex', 'grid', 'none', 'block', 'inline',
        'border', 'background', 'text', 'line', 'overflow', 'cursor',
        'prototype', 'constructor', 'toString', 'hasOwnProperty',
        'length', 'push', 'pop', 'shift', 'unshift', 'splice',
        'map', 'filter', 'reduce', 'forEach', 'find', 'some', 'every',
        'includes', 'indexOf', 'slice', 'join', 'split', 'replace',
        'json', 'stringify', 'parse', 'keys', 'values', 'entries',
        'Object', 'Array', 'String', 'Number', 'Boolean', 'Date',
        'Math', 'RegExp', 'Error', 'Promise', 'Symbol', 'Proxy',
        'window', 'document', 'navigator', 'location', 'history',
        'console', 'setTimeout', 'setInterval', 'clearTimeout',
        'addEventListener', 'removeEventListener', 'dispatchEvent',
        'getElementById', 'querySelector', 'querySelectorAll',
        'createElement', 'appendChild', 'removeChild', 'innerHTML',
        'className', 'getAttribute', 'setAttribute', 'dataset',
        'preventDefault', 'stopPropagation', 'target', 'currentTarget',
        'node', 'react', 'vue', 'angular', 'webpack', 'babel',
        'module', 'exports', 'require', 'default', 'static',
    }

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': '*/*',
        })
        self.session.verify = False
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def mine_from_js(self, js_code, source_url=''):
        """Extract parameter names from JavaScript source code"""
        if not js_code or not isinstance(js_code, str):
            return {'source': source_url, 'parameters': [], 'count': 0}

        found = set()

        for pattern in self.PARAM_PATTERNS:
            try:
                matches = re.findall(pattern, js_code)
                for match in matches:
                    if isinstance(match, tuple):
                        for m in match:
                            if m and self._is_valid_param(m):
                                found.add(m)
                    elif match and self._is_valid_param(match):
                        found.add(match)
            except Exception:
                continue

        # Extract from URL query strings embedded in JS
        url_params = re.findall(r'[?&]([a-zA-Z_]\w{1,30})=', js_code)
        for p in url_params:
            if self._is_valid_param(p):
                found.add(p)

        params = sorted(found)
        return {
            'source': source_url,
            'parameters': params,
            'count': len(params),
        }

    def mine_from_endpoints(self, endpoints):
        """Mine parameters from a list of discovered endpoints"""
        all_params = {}
        for ep in (endpoints or []):
            if not isinstance(ep, dict):
                continue
            url = ep.get('url', '')
            if not url:
                continue
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for param_name in query_params:
                if self._is_valid_param(param_name):
                    if param_name not in all_params:
                        all_params[param_name] = {'urls': [], 'values': set()}
                    all_params[param_name]['urls'].append(url)
                    for val in query_params[param_name]:
                        all_params[param_name]['values'].add(val[:100])

        result = []
        for name, info in all_params.items():
            result.append({
                'name': name,
                'seen_in': len(info['urls']),
                'sample_values': sorted(info['values'])[:5],
                'urls': info['urls'][:3],
            })
        return sorted(result, key=lambda x: x['seen_in'], reverse=True)

    def fuzz_parameters(self, target_url, discovered_params=None, progress_callback=None):
        """Auto-fuzz parameters on a target URL to test for vulnerabilities"""
        self._stop_flag = False
        results = {
            'target': target_url,
            'tested_params': [],
            'findings': [],
            'summary': {'total_tested': 0, 'interesting': 0, 'errors': 0},
        }

        # Merge discovered params with common params
        test_params = set(self.COMMON_PARAMS)
        if discovered_params:
            for p in discovered_params:
                if isinstance(p, str) and self._is_valid_param(p):
                    test_params.add(p)
                elif isinstance(p, dict):
                    name = p.get('name', '')
                    if name and self._is_valid_param(name):
                        test_params.add(name)

        param_list = sorted(test_params)
        total = len(param_list)

        # Get baseline response
        try:
            baseline_resp = self.session.get(target_url, timeout=self.timeout)
            baseline_len = len(baseline_resp.content) if baseline_resp else 0
            baseline_status = baseline_resp.status_code if baseline_resp else 0
            baseline_body = baseline_resp.text[:3000] if baseline_resp and baseline_resp.text else ''
        except Exception:
            baseline_len = 0
            baseline_status = 0
            baseline_body = ''

        for i, param_name in enumerate(param_list):
            if self._stop_flag:
                break

            if progress_callback:
                pct = int(100 * (i + 1) / max(total, 1))
                progress_callback(f'测试参数 {i+1}/{total}: {param_name}', pct)

            try:
                # Test 1: Add param with a value and see if response changes
                parsed = urlparse(target_url)
                existing_params = parse_qs(parsed.query)
                test_qs = dict(existing_params)
                test_qs[param_name] = 'test123'
                test_url = parsed._replace(query=urlencode(test_qs, doseq=True)).geturl()

                resp = self.session.get(test_url, timeout=self.timeout)
                if resp is None:
                    results['summary']['errors'] += 1
                    continue

                resp_len = len(resp.content) if resp.content else 0
                resp_body = resp.text[:3000] if resp.text else ''

                finding = {
                    'parameter': param_name,
                    'status_code': resp.status_code,
                    'response_size': resp_len,
                }

                # Check if parameter had effect
                if resp.status_code == 200 and baseline_status == 200:
                    size_diff = abs(resp_len - baseline_len)
                    if size_diff > 100 and size_diff < baseline_len * 0.9:
                        finding['type'] = 'reflected_param'
                        finding['severity'] = 'info'
                        finding['description'] = f'参数 {param_name} 影响了响应内容 (大小变化: {size_diff} bytes)'
                        finding['evidence'] = f'原始: {baseline_len}B -> 带参: {resp_len}B'

                        # Check if the test value is reflected in the response
                        if 'test123' in resp_body and 'test123' not in baseline_body:
                            finding['type'] = 'reflected_value'
                            finding['severity'] = 'medium'
                            finding['description'] = f'参数 {param_name} 的值被原样反射到响应中'

                        results['findings'].append(finding)
                        results['summary']['interesting'] += 1

                elif resp.status_code != baseline_status:
                    # Different status code - interesting
                    if resp.status_code in (400, 422):
                        finding['type'] = 'validated_param'
                        finding['severity'] = 'info'
                        finding['description'] = f'参数 {param_name} 被服务端校验 (返回{resp.status_code})'
                        results['findings'].append(finding)

                results['tested_params'].append(param_name)
                results['summary']['total_tested'] += 1

                # Small delay between requests
                time.sleep(0.15)

            except Exception:
                results['summary']['errors'] += 1

        if progress_callback:
            progress_callback('参数挖掘完成', 100)

        return results

    def _is_valid_param(self, name):
        """Check if a string is a valid parameter name"""
        if not name or not isinstance(name, str):
            return False
        if len(name) < 2 or len(name) > 50:
            return False
        if not re.match(r'^[a-zA-Z_]\w*$', name):
            return False
        if name.lower() in self.NOISE_PARAMS:
            return False
        # Skip pure numbers
        if name.isdigit():
            return False
        return True
