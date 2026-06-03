"""Subdomain Enumerator - certificate transparency + DNS records"""
import re
import time
import json
import socket
import threading
import requests
from urllib.parse import urlparse
from collections import defaultdict


class SubdomainEnumerator:
    """Discover subdomains via certificate transparency and DNS"""

    # Common subdomain prefixes for brute-force
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'dns', 'mx',
        'webmail', 'email', 'imap', 'pop3',
        'admin', 'administrator', 'manage', 'management', 'console', 'portal',
        'api', 'api1', 'api2', 'api-v1', 'api-v2', 'rest', 'graphql', 'grpc',
        'dev', 'develop', 'development', 'test', 'testing', 'staging', 'stage',
        'beta', 'alpha', 'demo', 'sandbox', 'uat', 'qa',
        'app', 'apps', 'web', 'webapp', 'mobile', 'm', 'wap',
        'cdn', 'static', 'assets', 'media', 'img', 'images', 'files',
        'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'es',
        'vpn', 'ssh', 'rdp', 'remote', 'gateway', 'proxy', 'lb', 'load',
        'monitor', 'grafana', 'kibana', 'jenkins', 'gitlab', 'github',
        'ci', 'cd', 'deploy', 'docker', 'k8s', 'kubernetes', 'registry',
        'blog', 'forum', 'wiki', 'docs', 'doc', 'help', 'support', 'status',
        'shop', 'store', 'pay', 'payment', 'billing', 'invoice',
        'cms', 'wp', 'wordpress', 'joomla', 'drupal',
        'old', 'backup', 'bak', 'archive', 'legacy', 'new', 'temp',
        's3', 'oss', 'blob', 'storage', 'bucket',
        'login', 'sso', 'auth', 'oauth', 'ldap', 'ad', 'cas',
        'hr', 'crm', 'erp', 'oa', 'jira', 'confluence', 'bamboo',
        'analytics', 'tracking', 'metrics', 'logs',
        'internal', 'intranet', 'extranet', 'private',
        'edge', 'origin', 'backend', 'frontend', 'service',
    ]

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
        })
        self.session.verify = False
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def enumerate(self, domain, include_bruteforce=False, progress_callback=None):
        """Enumerate subdomains for a given domain"""
        self._stop_flag = False
        domain = self._clean_domain(domain)

        results = {
            'domain': domain,
            'subdomains': [],
            'sources_used': [],
            'dns_records': {},
            'summary': {'total_unique': 0, 'alive': 0, 'sources': 0},
        }

        all_subdomains = set()

        # Phase 1: Certificate transparency
        if progress_callback:
            progress_callback('查询证书透明度日志...', 10)
        ct_subs = self._query_ct_logs(domain)
        all_subdomains.update(ct_subs)
        if ct_subs:
            results['sources_used'].append(f'CT Logs ({len(ct_subs)} found)')

        # Phase 2: DNS records
        if progress_callback:
            progress_callback('查询DNS记录...', 40)
        dns_info = self._query_dns(domain)
        results['dns_records'] = dns_info
        # Extract subdomains from DNS records
        for rtype, records in dns_info.items():
            for record in records:
                if isinstance(record, str) and record.endswith(f'.{domain}'):
                    all_subdomains.add(record.rstrip('.'))

        # Phase 3: Brute-force (optional)
        if include_bruteforce:
            if progress_callback:
                progress_callback('子域名暴力枚举...', 60)
            bruteforce_subs = self._bruteforce(domain)
            all_subdomains.update(bruteforce_subs)
            if bruteforce_subs:
                results['sources_used'].append(f'Bruteforce ({len(bruteforce_subs)} found)')

        # Phase 4: Check which are alive
        if progress_callback:
            progress_callback('验证子域名可达性...', 80)
        subdomain_list = sorted(all_subdomains)
        alive_count = self._check_alive(subdomain_list, results)

        results['subdomains'] = subdomain_list
        results['summary']['total_unique'] = len(subdomain_list)
        results['summary']['alive'] = alive_count
        results['summary']['sources'] = len(results['sources_used'])

        if progress_callback:
            progress_callback(f'子域名枚举完成: 发现 {len(subdomain_list)} 个', 100)

        return results

    def _clean_domain(self, domain):
        """Extract root domain from URL"""
        if not domain:
            return ''
        domain = domain.strip().lower()
        # Remove protocol
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        return domain

    def _query_ct_logs(self, domain):
        """Query certificate transparency logs for subdomains (multi-source, parallel)"""
        all_results = {}
        lock = threading.Lock()

        def _query_crtsh():
            subs = set()
            try:
                url = f'https://crt.sh/?q=%.{domain}&output=json'
                resp = self.session.get(url, timeout=self.timeout + 10)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        for entry in data:
                            name = entry.get('name_value', '')
                            for sub in name.split('\n'):
                                sub = sub.strip().lower()
                                if sub and '*' not in sub and sub.endswith(f'.{domain}'):
                                    subs.add(sub)
            except Exception:
                pass
            with lock:
                all_results['crt.sh'] = subs

        def _query_certspotter():
            subs = set()
            try:
                url = f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names'
                resp = self.session.get(url, timeout=self.timeout + 10)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        for entry in data:
                            dns_names = entry.get('dns_names', [])
                            for name in dns_names:
                                name = name.strip().lower()
                                if name and '*' not in name and (name == domain or name.endswith(f'.{domain}')):
                                    subs.add(name)
            except Exception:
                pass
            with lock:
                all_results['CertSpotter'] = subs

        def _query_otx():
            """AlienVault OTX — community threat intelligence"""
            subs = set()
            try:
                url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
                resp = self.session.get(url, timeout=self.timeout + 10)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    records = data.get('passive_dns', []) if isinstance(data, dict) else []
                    for record in records:
                        hostname = record.get('hostname', '').strip().lower()
                        if hostname and hostname != domain and hostname.endswith(f'.{domain}'):
                            subs.add(hostname)
            except Exception:
                pass
            with lock:
                all_results['AlienVault OTX'] = subs

        def _query_hackertarget():
            """HackerTarget — free passive DNS lookup"""
            subs = set()
            try:
                url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
                resp = self.session.get(url, timeout=self.timeout + 10)
                if resp and resp.status_code == 200 and ',' in resp.text:
                    for line in resp.text.strip().split('\n'):
                        parts = line.split(',')
                        if parts and parts[0].strip().lower().endswith(f'.{domain}'):
                            subs.add(parts[0].strip().lower())
            except Exception:
                pass
            with lock:
                all_results['HackerTarget'] = subs

        # 并发查询所有来源
        threads = []
        for fn in (_query_crtsh, _query_certspotter, _query_otx, _query_hackertarget):
            if self._stop_flag:
                break
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=self.timeout + 15)

        # 合并结果
        subdomains = set()
        for source, subs in all_results.items():
            subdomains.update(subs)

        return subdomains

    def _query_dns(self, domain):
        """Query DNS records for a domain"""
        records = defaultdict(list)

        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']

        for rtype in record_types:
            if self._stop_flag:
                break
            try:
                import subprocess
                # Use nslookup on Windows
                result = subprocess.run(
                    ['nslookup', '-type=' + rtype, domain],
                    capture_output=True, text=True, timeout=5
                )
                output = result.stdout if result.stdout else ''

                if rtype in ('A', 'AAAA'):
                    # Extract IP addresses
                    ips = re.findall(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', output)
                    ips += re.findall(r'Address:\s*([0-9a-fA-F:]+)', output)
                    for ip in ips:
                        if ip and '::' not in ip or ':' in ip:
                            records[rtype].append(ip)
                elif rtype == 'CNAME':
                    cnames = re.findall(r'canonical name\s*=\s*(\S+)', output, re.I)
                    records[rtype] = [c.rstrip('.') for c in cnames if c]
                elif rtype == 'MX':
                    mx = re.findall(r'mail exchanger\s*=\s*\d+\s+(\S+)', output, re.I)
                    records[rtype] = [m.rstrip('.') for m in mx if m]
                elif rtype == 'NS':
                    ns = re.findall(r'nameserver\s*=\s*(\S+)', output, re.I)
                    records[rtype] = [n.rstrip('.') for n in ns if n]
                elif rtype == 'TXT':
                    txts = re.findall(r'text\s*=\s*"([^"]+)"', output, re.I)
                    records[rtype] = txts
            except Exception:
                pass

        # Also try socket-based resolution
        try:
            ips = socket.getaddrinfo(domain, None)
            for ip in ips:
                addr = ip[4][0]
                if addr not in records.get('A', []) and addr not in records.get('AAAA', []):
                    if ':' in addr:
                        records['AAAA'].append(addr)
                    else:
                        records['A'].append(addr)
        except Exception:
            pass

        return dict(records)

    def _bruteforce(self, domain):
        """Brute-force common subdomains"""
        subdomains = set()

        for sub in self.COMMON_SUBDOMAINS:
            if self._stop_flag:
                break
            full = f'{sub}.{domain}'
            try:
                socket.setdefaulttimeout(2)
                ips = socket.getaddrinfo(full, None)
                if ips:
                    subdomains.add(full)
            except (socket.gaierror, socket.timeout, Exception):
                pass

        return subdomains

    def _check_alive(self, subdomains, results):
        """Check if subdomains are reachable via HTTP/HTTPS"""
        alive = 0
        checked = []

        for sub in subdomains[:50]:  # Limit to 50 to avoid excessive requests
            if self._stop_flag:
                break
            info = {'subdomain': sub, 'alive': False, 'ip': '', 'http': False, 'https': False}

            # Resolve DNS
            try:
                ips = socket.getaddrinfo(sub, None)
                if ips:
                    info['ip'] = ips[0][4][0]
            except Exception:
                pass

            # Check HTTP
            for scheme in ('https', 'http'):
                try:
                    resp = self.session.get(f'{scheme}://{sub}/', timeout=5, allow_redirects=True)
                    if resp and resp.status_code < 500:
                        info[scheme] = True
                        info['alive'] = True
                        info['status_code'] = resp.status_code
                        info['title'] = self._extract_title(resp.text[:3000] if resp.text else '')
                except Exception:
                    pass

            if info['alive']:
                alive += 1
            checked.append(info)

        results['subdomains'] = checked if checked else [{'subdomain': s, 'alive': False} for s in subdomains]
        return alive

    def _extract_title(self, html):
        """Extract title from HTML"""
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
            if match:
                return match.group(1).strip()[:100]
        except Exception:
            pass
        return ''
