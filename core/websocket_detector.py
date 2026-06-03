"""WebSocket endpoint detection and analysis"""
import re
import json


WS_PATTERNS_HTML = [
    r'(?:ws|wss)://[^\s"\'<>]+',
]

WS_PATTERNS_JS = [
    r'new\s+WebSocket\s*\(\s*["\']((?:ws|wss)://[^"\']+)["\']',
    r'\.connect\s*\(\s*["\']((?:ws|wss)://[^"\']+)["\']',
    r'(?:ws|wss)://[^\s"\'<>}\],;]+',
    r'wss?["\s:=]+["\']([^"\']+)',
    r'SOCKET_URL["\s:=]+["\']([^"\']+)',
    r'WS_ENDPOINT["\s:=]+["\']([^"\']+)',
    r'io\.connect\s*\(\s*["\']([^"\']+)["\']',
    r'io\s*\(\s*["\']([^"\']+)["\']',
]

LIBRARY_PATTERNS = {
    'socket.io': [r'socket\.io', r'io\.connect', r'io\s*\('],
    'sockjs': [r'sockjs', r'SockJS'],
    'ws': [r'new\s+WebSocket'],
    'signalr': [r'\.hubConnection', r'signalr', r'\$\.hubConnection'],
    'pusher': [r'Pusher\s*\(', r'new\s+Pusher'],
    'ably': [r'Ably\.Realtime'],
    'firebase': [r'firebase.*database', r'\.database\(\)'],
}


class WebSocketDetector:
    """Detect WebSocket endpoints from web content"""

    def detect_from_html(self, html):
        """Find WebSocket URLs in HTML content"""
        if not html:
            return []
        endpoints = set()
        for pattern in WS_PATTERNS_HTML:
            try:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for m in matches:
                    m = m.strip().rstrip('),;')
                    if self._is_valid_ws_url(m):
                        endpoints.add(m)
            except Exception:
                pass
        return list(endpoints)

    def detect_from_js(self, js_code):
        """Find WebSocket URLs and patterns in JavaScript code"""
        if not js_code:
            return {'endpoints': [], 'libraries': []}
        endpoints = set()
        libraries = set()

        for pattern in WS_PATTERNS_JS:
            try:
                matches = re.findall(pattern, js_code, re.IGNORECASE)
                for m in matches:
                    m = m.strip().rstrip('),;')
                    if self._is_valid_ws_url(m):
                        endpoints.add(m)
            except Exception:
                pass

        # Detect WebSocket libraries
        for lib_name, lib_patterns in LIBRARY_PATTERNS.items():
            for p in lib_patterns:
                try:
                    if re.search(p, js_code, re.IGNORECASE):
                        libraries.add(lib_name)
                        break
                except Exception:
                    pass

        return {
            'endpoints': list(endpoints),
            'libraries': list(libraries),
        }

    def analyze_page(self, page_data):
        """Analyze a single crawled page for WebSocket content"""
        results = {'endpoints': [], 'libraries': []}

        # Check HTML content
        html = page_data.get('html', '')
        if html:
            ws_urls = self.detect_from_html(html)
            results['endpoints'].extend(ws_urls)

        # Check scripts
        scripts = page_data.get('scripts') or []
        for script in scripts:
            src = script.get('src', '') if isinstance(script, dict) else ''
            code = script.get('code', '') if isinstance(script, dict) else ''
            if code:
                js_result = self.detect_from_js(code)
                results['endpoints'].extend(js_result['endpoints'])
                results['libraries'].extend(js_result['libraries'])

        # Check inline script content from html
        if html:
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
            for code in inline_scripts:
                js_result = self.detect_from_js(code)
                results['endpoints'].extend(js_result['endpoints'])
                results['libraries'].extend(js_result['libraries'])

        # Deduplicate
        results['endpoints'] = list(set(results['endpoints']))
        results['libraries'] = list(set(results['libraries']))
        return results

    def scan_pages(self, pages):
        """Scan multiple crawled pages for WebSocket endpoints"""
        all_endpoints = {}
        all_libraries = set()

        for page in pages:
            result = self.analyze_page(page)
            for ep in result['endpoints']:
                if ep not in all_endpoints:
                    all_endpoints[ep] = {
                        'url': ep,
                        'found_on': page.get('url', ''),
                        'protocol': 'wss' if ep.startswith('wss') else 'ws',
                    }
            all_libraries.update(result['libraries'])

        return {
            'endpoints': list(all_endpoints.values()),
            'libraries': list(all_libraries),
            'total_pages_scanned': len(pages),
        }

    def test_connection(self, url, timeout=5):
        """Test WebSocket connection (requires websocket-client)"""
        try:
            import websocket
            ws = websocket.create_connection(url, timeout=timeout)
            info = {
                'connected': True,
                'url': url,
                'subprotocol': ws.subprotocol,
                'headers': dict(ws.handshake_headers) if hasattr(ws, 'handshake_headers') else {},
            }
            ws.close()
            return info
        except ImportError:
            return {'connected': None, 'url': url, 'error': 'websocket-client not installed (pip install websocket-client)'}
        except Exception as e:
            return {'connected': False, 'url': url, 'error': str(e)}

    def _is_valid_ws_url(self, url):
        """Basic validation for WebSocket URLs"""
        if not url or len(url) > 2000:
            return False
        if not (url.startswith('ws://') or url.startswith('wss://')):
            return False
        # Filter out template variables
        if '${' in url or '{' in url:
            return False
        return True
