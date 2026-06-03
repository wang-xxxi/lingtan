"""Login session manager — launches Playwright's Chromium via subprocess, captures cookies via CDP."""
import base64
import json
import os
import select
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse


def _get_chromium_path():
    """Find Playwright's Chromium binary."""
    # Known Playwright install location on Windows
    pw_dir = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'ms-playwright')
    if os.path.isdir(pw_dir):
        for entry in os.listdir(pw_dir):
            if entry.startswith('chromium-') and not entry.endswith('headless'):
                exe = os.path.join(pw_dir, entry, 'chrome-win64', 'chrome.exe')
                if os.path.isfile(exe):
                    return exe
    # Try to get it from Playwright API (one-time call, no persistent state)
    try:
        from playwright.sync_api import sync_playwright
        pw = sync_playwright().start()
        exe = pw.chromium.executable_path
        pw.stop()
        if exe and os.path.isfile(exe):
            return exe
    except Exception:
        pass
    return None


def _find_available_port(start=9222):
    for port in range(start, start + 50):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None


def _ws_encode(message):
    """Encode a WebSocket text frame (client → server, masked)."""
    data = message.encode('utf-8')
    length = len(data)
    frame = bytearray([0x81])
    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(length.to_bytes(2, 'big'))
    else:
        frame.append(0x80 | 127)
        frame.extend(length.to_bytes(8, 'big'))
    mask = os.urandom(4)
    frame.extend(mask)
    for i, b in enumerate(data):
        frame.append(b ^ mask[i % 4])
    return bytes(frame)


def _read_ws_messages(sock, timeout=3):
    """Read and parse WebSocket frames from server (unmasked). Returns list of parsed JSON messages."""
    buf = b''
    deadline = time.time() + timeout
    messages = []
    while time.time() < deadline:
        ready, _, _ = select.select([sock], [], [], 0.5)
        if ready:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break
        # Parse accumulated frames
        while len(buf) >= 2:
            opcode = buf[0] & 0x0f
            length = buf[1] & 0x7f
            hdr_len = 2
            if length == 126:
                if len(buf) < 4:
                    break
                length = int.from_bytes(buf[2:4], 'big')
                hdr_len = 4
            elif length == 127:
                if len(buf) < 10:
                    break
                length = int.from_bytes(buf[2:10], 'big')
                hdr_len = 10
            total = hdr_len + length
            if len(buf) < total:
                break
            payload = buf[hdr_len:total]
            buf = buf[total:]
            if opcode == 0x1 and payload:
                try:
                    messages.append(json.loads(payload.decode('utf-8')))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            elif opcode == 0x8:
                return messages
    return messages


def _cdp_get_cookies(ws_url, page_url, domain):
    """Connect to Chrome CDP via WebSocket, get cookies via multiple methods.
    Returns list of {name, value, domain, path}.
    """
    ws_url = ws_url.replace('ws://', '')
    host_port, path = ws_url.split('/', 1)
    path = '/' + path
    host, port_str = host_port.split(':')
    port = int(port_str)

    sock = socket.create_connection((host, port), timeout=10)
    try:
        # WebSocket handshake
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {host}:{port}\r\n'
            f'Upgrade: websocket\r\n'
            f'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {key}\r\n'
            f'Sec-WebSocket-Version: 13\r\n\r\n'
        )
        sock.sendall(handshake.encode())

        # Read handshake response
        resp_data = b''
        while b'\r\n\r\n' not in resp_data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp_data += chunk
        if b'101' not in resp_data:
            raise Exception(f'WebSocket 握手失败: {resp_data[:200].decode("utf-8", errors="replace")}')
        sock.settimeout(5)

        def send_cmd(cmd_id, method, params=None):
            msg = {'id': cmd_id, 'method': method}
            if params:
                msg['params'] = params
            sock.sendall(_ws_encode(json.dumps(msg)))

        # --- Method 1: Runtime.evaluate('document.cookie') ---
        send_cmd(10, 'Runtime.evaluate', {
            'expression': 'document.cookie',
            'returnByValue': True,
        })
        msgs = _read_ws_messages(sock, timeout=3)
        doc_cookie_str = ''
        for m in msgs:
            if m.get('id') == 10:
                doc_cookie_str = m.get('result', {}).get('result', {}).get('value', '')
                break
        print(f'[Session] document.cookie: {doc_cookie_str[:200] if doc_cookie_str else "(空)"}')

        # --- Method 2: Network.getCookiesForUrls ---
        urls = [page_url, f'http://{domain}/', f'https://{domain}/']
        # Also try base domain variants
        if domain.startswith('www.'):
            bare = domain[4:]
            urls.extend([f'http://{bare}/', f'https://{bare}/'])
        urls = list(dict.fromkeys(urls))  # deduplicate, preserve order

        send_cmd(20, 'Network.getCookiesForUrls', {'urls': urls})
        msgs2 = _read_ws_messages(sock, timeout=3)
        cdp_cookies = []
        for m in msgs2:
            if m.get('id') == 20:
                cdp_cookies = m.get('result', {}).get('cookies', [])
                break
        print(f'[Session] Network.getCookiesForUrls: {len(cdp_cookies)} 个')

        # --- Merge ---
        all_cookies = list(cdp_cookies)
        cdp_names = {(c.get('name', ''), c.get('domain', '')) for c in cdp_cookies}
        if doc_cookie_str:
            for pair in doc_cookie_str.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    key = (name.strip(), domain)
                    if key not in cdp_names:
                        all_cookies.append({
                            'name': name.strip(),
                            'value': value.strip(),
                            'domain': domain,
                            'path': '/',
                        })
        print(f'[Session] 合并: CDP={len(cdp_cookies)} + doc={len(all_cookies) - len(cdp_cookies)} = {len(all_cookies)}')
        return all_cookies
    finally:
        sock.close()


class SessionManager:

    def __init__(self):
        self._browsers = {}  # win_id -> {proc, port, domain, url}

    def open_login_window(self, url, name=None):
        """Launch Chromium with remote debugging. Returns (win_id, domain)."""
        domain = urlparse(url).netloc or url
        if not name:
            name = domain
        win_id = f'sess_{int(time.time() * 1000)}'

        chromium = _get_chromium_path()
        if not chromium:
            raise Exception('未找到 Chromium，请先运行: playwright install chromium')

        port = _find_available_port()
        if not port:
            raise Exception('无法找到可用端口')

        user_data = os.path.join(tempfile.gettempdir(), f'lingtan_{win_id}')
        os.makedirs(user_data, exist_ok=True)

        proc = subprocess.Popen([
            chromium,
            f'--remote-debugging-port={port}',
            f'--user-data-dir={user_data}',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-blink-features=AutomationControlled',
            url,
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        self._browsers[win_id] = {
            'proc': proc,
            'port': port,
            'domain': domain,
            'url': url,
        }
        print(f'[Session] 已启动: win_id={win_id}, port={port}, domain={domain}')
        return win_id, domain

    def get_cookies(self, win_id):
        """Connect to Chrome CDP and capture cookies."""
        entry = self._browsers.get(win_id)
        if not entry:
            return None, 'not_found'

        port = entry['port']
        domain = entry['domain']

        # Check if process is alive
        if entry['proc'].poll() is not None:
            return None, '浏览器窗口已关闭，请重新打开登录窗口'

        try:
            # List tabs via CDP HTTP
            import urllib.request
            req = urllib.request.Request(f'http://127.0.0.1:{port}/json/list')
            with urllib.request.urlopen(req, timeout=5) as resp:
                tabs = json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            return None, f'连接浏览器失败 (端口 {port}): {e}'

        print(f'[Session] 找到 {len(tabs)} 个标签页')

        # Find matching tab
        target = None
        for tab in tabs:
            tab_url = tab.get('url', '')
            if domain in tab_url or entry['url'] in tab_url:
                target = tab
                break
        if not target:
            for tab in tabs:
                if tab.get('type') == 'page':
                    target = tab
                    break
        if not target:
            return None, '未找到可用标签页'

        ws_url = target.get('webSocketDebuggerUrl', '')
        if not ws_url:
            return None, '该标签页不支持远程调试'

        print(f'[Session] 标签页: {target.get("url", "")}')

        try:
            cookies = _cdp_get_cookies(ws_url, entry['url'], domain)
            if cookies:
                print(f'[Session] 成功捕获 {len(cookies)} 个 Cookie')
                return cookies, 'captured'
            else:
                return None, '未获取到 Cookie，请确认已在浏览器中完成登录'
        except Exception as e:
            print(f'[Session] 异常: {e}')
            return None, f'Cookie 获取失败: {e}'

    def close_session(self, win_id):
        entry = self._browsers.pop(win_id, None)
        if entry and entry['proc'].poll() is None:
            entry['proc'].terminate()
            print(f'[Session] 已关闭: win_id={win_id}')

    def get_window_info(self, win_id):
        entry = self._browsers.get(win_id)
        if entry:
            return {'domain': entry.get('domain', ''), 'url': entry.get('url', '')}
        return {'domain': '', 'url': ''}

    @staticmethod
    def _parse_cookies(cookie_str):
        """Parse a Cookie header string into a list of {name, value} dicts."""
        if not cookie_str:
            return []
        result = []
        for pair in cookie_str.split(';'):
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                result.append({'name': name.strip(), 'value': value.strip()})
            elif pair:
                result.append({'name': pair, 'value': ''})
        return result
