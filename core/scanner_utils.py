import json
import socket
import time
import threading
import hashlib
from urllib.parse import urlparse


class PortScanner:
    """Quick local port scanner to discover running services"""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5901,
        6379, 8000, 8080, 8443, 8888, 9090, 9200, 11211, 27017,
    ]

    SERVICE_NAMES = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
        443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 5901: 'VNC',
        6379: 'Redis', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9090: 'HTTP-Alt',
        9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
    }

    def scan(self, host='127.0.0.1', ports=None, timeout=1):
        """Scan ports on host"""
        if ports is None:
            ports = self.COMMON_PORTS

        results = {
            'host': host,
            'open_ports': [],
            'total_scanned': len(ports),
            'scan_time': 0,
        }

        start = time.time()

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = self.SERVICE_NAMES.get(port, 'unknown')
                    # Try to grab banner
                    banner = ''
                    try:
                        sock.settimeout(1)
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(128).decode('utf-8', errors='ignore').strip()[:100]
                    except Exception:
                        pass

                    results['open_ports'].append({
                        'port': port,
                        'service': service,
                        'banner': banner,
                    })
                sock.close()
            except Exception:
                pass

        results['scan_time'] = round(time.time() - start, 2)
        return results

    def scan_web_ports(self, host='127.0.0.1'):
        """Scan only web-related ports"""
        web_ports = [80, 443, 3000, 4000, 5000, 8000, 8080, 8443, 8888, 9000, 9090]
        return self.scan(host, web_ports, timeout=0.5)


class DiffEngine:
    """Compare two scans to find changes"""

    def compare(self, old_endpoints, new_endpoints):
        """Compare two endpoint lists and return differences"""
        old_set = {}
        new_set = {}

        for ep in (old_endpoints or []):
            if not isinstance(ep, dict):
                continue
            key = f"{ep.get('method', 'GET')}:{ep.get('url', '')}"
            old_set[key] = ep

        for ep in (new_endpoints or []):
            if not isinstance(ep, dict):
                continue
            key = f"{ep.get('method', 'GET')}:{ep.get('url', '')}"
            new_set[key] = ep

        old_keys = set(old_set.keys())
        new_keys = set(new_set.keys())

        added = [new_set[k] for k in (new_keys - old_keys)]
        removed = [old_set[k] for k in (old_keys - new_keys)]

        # Changed (same URL but different properties)
        changed = []
        common = old_keys & new_keys
        for k in common:
            old_ep = old_set[k]
            new_ep = new_set[k]
            diffs = {}
            for field in ['status_code', 'content_type', 'category', 'risk_level']:
                old_val = old_ep.get(field)
                new_val = new_ep.get(field)
                if old_val != new_val and old_val is not None and new_val is not None:
                    diffs[field] = {'old': old_val, 'new': new_val}
            if diffs:
                changed.append({'endpoint': new_ep, 'changes': diffs})

        return {
            'summary': {
                'old_count': len(old_endpoints or []),
                'new_count': len(new_endpoints or []),
                'added': len(added),
                'removed': len(removed),
                'changed': len(changed),
                'unchanged': len(common) - len(changed),
            },
            'added': added,
            'removed': removed,
            'changed': changed,
        }


class BatchScanner:
    """Scan multiple URLs in batch"""

    def __init__(self):
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def scan_urls(self, urls, analyze_fn, max_workers=5, progress_callback=None):
        """Scan multiple URLs and aggregate results"""
        self._stop_flag = False
        all_results = []
        total = len(urls)

        for i, url in enumerate(urls):
            if self._stop_flag:
                break
            if not url or not isinstance(url, str):
                continue

            url = url.strip()
            if not url.startswith('http'):
                url = 'https://' + url

            if progress_callback:
                progress_callback(f'扫描 {i+1}/{total}: {url}', int(100 * (i + 1) / total))

            try:
                result = analyze_fn(url)
                result['batch_index'] = i
                all_results.append(result)
            except Exception as e:
                all_results.append({
                    'url': url,
                    'error': str(e),
                    'batch_index': i,
                })

            time.sleep(0.2)  # Rate limiting

        return {
            'total': total,
            'completed': len(all_results),
            'results': all_results,
        }


class EndpointGrouper:
    """Intelligently group endpoints by resource/pattern"""

    def group(self, endpoints):
        """Group endpoints by resource type"""
        groups = {}

        for ep in (endpoints or []):
            if not isinstance(ep, dict):
                continue
            url = ep.get('url', '')
            if not url:
                continue

            try:
                parsed = urlparse(url)
                path = parsed.path or '/'
            except Exception:
                continue

            # Find the resource group
            segments = [s for s in path.split('/') if s and not s.isdigit() and s not in ('api', 'rest', 'v1', 'v2', 'v3')]
            if segments:
                # Use first meaningful segment as group
                group_key = segments[0]
            else:
                group_key = 'root'

            if group_key not in groups:
                groups[group_key] = {
                    'name': group_key,
                    'endpoints': [],
                    'methods': set(),
                    'risk_levels': {},
                    'categories': set(),
                }

            groups[group_key]['endpoints'].append(ep)
            groups[group_key]['methods'].add(ep.get('method', 'GET'))
            risk = ep.get('risk_level', 'info')
            groups[group_key]['risk_levels'][risk] = groups[group_key]['risk_levels'].get(risk, 0) + 1
            cat = ep.get('category')
            if cat:
                groups[group_key]['categories'].add(cat)

        # Convert sets to lists for JSON serialization
        for g in groups.values():
            g['methods'] = list(g['methods'])
            g['categories'] = list(g['categories'])
            g['count'] = len(g['endpoints'])

        return {
            'groups': list(groups.values()),
            'total_groups': len(groups),
        }


class ChangeMonitor:
    """Monitor endpoints for changes over time"""

    def __init__(self):
        self._snapshots = {}

    def take_snapshot(self, target_id, endpoints):
        """Take a hash snapshot of current endpoints"""
        content = json.dumps(
            sorted([(ep.get('method', ''), ep.get('url', ''), ep.get('status_code', 0))
                    for ep in (endpoints or []) if isinstance(ep, dict)]),
            sort_keys=True
        )
        snapshot = {
            'target_id': target_id,
            'timestamp': time.time(),
            'hash': hashlib.md5(content.encode()).hexdigest(),
            'count': len(endpoints or []),
        }
        if target_id not in self._snapshots:
            self._snapshots[target_id] = []
        self._snapshots[target_id].append(snapshot)
        return snapshot

    def detect_changes(self, target_id):
        """Detect if endpoints changed since last snapshot"""
        snapshots = self._snapshots.get(target_id, [])
        if len(snapshots) < 2:
            return {'changed': False, 'message': '需要至少两个快照进行对比'}

        latest = snapshots[-1]
        previous = snapshots[-2]

        return {
            'changed': latest['hash'] != previous['hash'],
            'previous_count': previous['count'],
            'current_count': latest['count'],
            'time_diff': round(latest['timestamp'] - previous['timestamp'], 1),
        }
