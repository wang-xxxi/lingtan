"""Lightweight HTTP proxy server for traffic capture"""
import socket
import threading
import time
import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn


class ProxyHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests as a forward proxy"""

    db = None  # Set by ProxyServer

    def do_GET(self):
        self._forward_request('GET')

    def do_POST(self):
        self._forward_request('POST')

    def do_PUT(self):
        self._forward_request('PUT')

    def do_DELETE(self):
        self._forward_request('DELETE')

    def do_PATCH(self):
        self._forward_request('PATCH')

    def do_OPTIONS(self):
        self._forward_request('OPTIONS')

    def do_HEAD(self):
        self._forward_request('HEAD')

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling"""
        try:
            host_port = self.path.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443

            # Record HTTPS connection
            if self.db:
                try:
                    self.db.add_traffic(
                        method='CONNECT', url=f'{host}:{port}',
                        host=host, path=f':{port}',
                        request_headers=dict(self.headers),
                        status_code=200,
                        content_type='tunnel',
                    )
                except Exception:
                    pass

            # Establish tunnel
            remote = socket.create_connection((host, port), timeout=30)
            self.send_response(200, 'Connection Established')
            self.end_headers()

            # Relay data bidirectionally
            self._tunnel(self.connection, remote)
        except Exception:
            self.send_error(502)

    def _forward_request(self, method):
        """Forward HTTP request and capture traffic"""
        import io
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''

            # Parse target URL
            url = self.path
            if url.startswith('/'):
                # Relative URL - need Host header
                host_header = self.headers.get('Host', '')
                url = f'http://{host_header}{url}'

            # Parse host
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc or self.headers.get('Host', '')
            path = parsed.path or '/'

            # Forward request to target
            try:
                remote = socket.create_connection((host.split(':')[0],
                                                    int(host.split(':')[1]) if ':' in host else 80),
                                                   timeout=30)
            except Exception:
                self.send_error(502, 'Cannot connect to target')
                return

            # Build and send request
            request_line = f'{method} {path}'
            if parsed.query:
                request_line += f'?{parsed.query}'
            request_line += ' HTTP/1.1\r\n'

            remote.sendall(request_line.encode())

            # Forward headers
            headers_dict = dict(self.headers)
            headers_dict['Connection'] = 'close'
            for key, value in headers_dict.items():
                remote.sendall(f'{key}: {value}\r\n'.encode())
            remote.sendall(b'\r\n')

            if body:
                remote.sendall(body)

            # Read response
            response_data = b''
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                response_data += chunk
            remote.close()

            # Parse response
            status_code = 200
            resp_headers = {}
            resp_body = b''
            try:
                header_end = response_data.find(b'\r\n\r\n')
                if header_end > 0:
                    header_section = response_data[:header_end].decode('utf-8', errors='replace')
                    resp_body = response_data[header_end + 4:]

                    # Parse status
                    status_match = re.match(r'HTTP/\S+ (\d+)', header_section)
                    if status_match:
                        status_code = int(status_match.group(1))

                    # Parse headers
                    for line in header_section.split('\r\n')[1:]:
                        if ':' in line:
                            k, v = line.split(':', 1)
                            resp_headers[k.strip()] = v.strip()
                else:
                    resp_body = response_data
            except Exception:
                resp_body = response_data

            content_type = resp_headers.get('Content-Type', '')

            # Limit body size for storage
            body_str = resp_body[:50000].decode('utf-8', errors='replace')
            req_body_str = body[:10000].decode('utf-8', errors='replace') if body else ''

            # Save to database
            if self.db:
                try:
                    self.db.add_traffic(
                        method=method, url=url, host=host, path=path,
                        request_headers=headers_dict,
                        request_body=req_body_str,
                        status_code=status_code,
                        response_headers=resp_headers,
                        response_body=body_str,
                        content_type=content_type,
                    )
                except Exception:
                    pass

            # Send response back to client
            self.send_response(status_code)
            for key, value in resp_headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(resp_body)

        except Exception as e:
            try:
                self.send_error(502, str(e))
            except Exception:
                pass

    def _tunnel(self, client, remote):
        """Bidirectional data relay for CONNECT tunnels"""
        client.setblocking(False)
        remote.setblocking(False)
        sockets = [client, remote]
        deadline = time.time() + 300  # 5 min timeout

        while time.time() < deadline:
            try:
                import select
                readable, _, errors = select.select(sockets, [], sockets, 1)
                if errors:
                    break
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    if s is client:
                        remote.sendall(data)
                    else:
                        client.sendall(data)
            except Exception:
                break

        client.close()
        remote.close()

    def log_message(self, format, *args):
        """Suppress default HTTP logging"""
        pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server"""
    daemon_threads = True
    allow_reuse_address = True


class ProxyServer:
    """Manage the proxy server lifecycle"""

    def __init__(self, db):
        self.db = db
        self.server = None
        self.thread = None
        self._running = False
        self.port = 8088

    @property
    def is_running(self):
        return self._running and self.thread is not None and self.thread.is_alive()

    def start(self, port=8088):
        """Start proxy server in background thread"""
        if self.is_running:
            return False, 'Proxy already running'

        self.port = port
        ProxyHandler.db = self.db

        try:
            self.server = ThreadingHTTPServer(('127.0.0.1', port), ProxyHandler)
            self._running = True
            self.thread = threading.Thread(target=self._serve, daemon=True)
            self.thread.start()
            return True, f'Proxy started on 127.0.0.1:{port}'
        except OSError as e:
            return False, f'Cannot start proxy: {e}'

    def _serve(self):
        try:
            self.server.serve_forever()
        except Exception:
            pass
        finally:
            self._running = False

    def stop(self):
        """Stop the proxy server"""
        if not self.is_running:
            return False, 'Proxy not running'

        self._running = False
        if self.server:
            self.server.shutdown()
            self.server = None
        return True, 'Proxy stopped'

    def get_status(self):
        return {
            'running': self.is_running,
            'port': self.port if self.is_running else None,
            'address': f'127.0.0.1:{self.port}' if self.is_running else None,
        }
