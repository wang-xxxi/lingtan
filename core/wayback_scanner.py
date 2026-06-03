"""Wayback Machine — 从互联网档案馆发现历史接口"""
import re
import time
import requests
from urllib.parse import urlparse


# 常见 API 路径特征
API_INDICATORS = [
    r'/api/', r'/v\d+/', r'/rest/', r'/graphql', r'/grpc',
    r'\.json$', r'\.xml$', r'/oauth', r'/token',
    r'/admin', r'/console', r'/manage', r'/debug',
    r'/search', r'/query', r'/export', r'/import',
    r'/upload', r'/download', r'/callback', r'/webhook',
]


class WaybackScanner:
    """Wayback Machine 历史接口发现器"""

    def __init__(self, timeout=15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
        })
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def scan(self, domain, max_results=500, progress_callback=None):
        """从 Wayback Machine 获取目标域名的历史 URL

        Args:
            domain: 目标域名或 URL
            max_results: 最大结果数
            progress_callback: (message, pct) 回调

        Returns:
            dict: {'domain', 'total_urls', 'api_urls', 'interesting_urls', 'timeline'}
        """
        self._stop_flag = False
        domain = self._clean_domain(domain)

        if progress_callback:
            progress_callback('查询 Wayback Machine...', 10)

        results = {
            'domain': domain,
            'total_urls': 0,
            'api_urls': [],
            'interesting_urls': [],
            'sensitive_urls': [],
            'timeline': {},
            'sources_used': [],
        }

        # Phase 1: CDX API 查询
        if progress_callback:
            progress_callback('查询 CDX API 获取历史快照...', 20)
        cdx_urls = self._query_cdx(domain, max_results)

        if cdx_urls:
            results['sources_used'].append(f'Wayback CDX ({len(cdx_urls)} URLs)')

        # Phase 2: 从所有 URL 中提取 API 端点
        if progress_callback:
            progress_callback('分析历史 URL...', 50)

        all_urls = set()
        api_urls = set()
        sensitive_urls = set()
        timeline = {}

        for entry in cdx_urls:
            url = entry.get('url', '')
            timestamp = entry.get('timestamp', '')
            if not url:
                continue
            all_urls.add(url)

            # 分类
            if self._is_api_url(url):
                api_urls.add(url)
            if self._is_sensitive_url(url):
                sensitive_urls.add(url)

            # 时间线
            year = timestamp[:4] if timestamp and len(timestamp) >= 4 else 'unknown'
            timeline[year] = timeline.get(year, 0) + 1

        # Phase 3: 查找当前已不存在的 URL（可能有价值）
        if progress_callback:
            progress_callback('检查 URL 可达性...', 70)

        interesting = []
        checked = 0
        api_list = list(api_urls)[:100]
        for url in api_list:
            if self._stop_flag:
                break
            checked += 1
            if progress_callback and checked % 10 == 0:
                pct = 70 + int(20 * checked / max(len(api_list), 1))
                progress_callback(f'检查 URL {checked}/{len(api_list)}...', min(pct, 90))

            status = self._check_url_status(url)
            interesting.append({
                'url': url,
                'last_status': status,
                'disappeared': status in (404, 0, None),
            })

        results['total_urls'] = len(all_urls)
        results['api_urls'] = sorted(list(api_urls))[:200]
        results['interesting_urls'] = interesting[:100]
        results['sensitive_urls'] = sorted(list(sensitive_urls))[:100]
        results['timeline'] = timeline

        if progress_callback:
            progress_callback(f'Wayback 扫描完成: 发现 {len(all_urls)} 个历史 URL, {len(api_urls)} 个 API 端点', 100)

        return results

    def get_urls(self, domain, filter_type='all', max_results=200):
        """简化接口：只返回 URL 列表"""
        result = self.scan(domain, max_results=max_results)
        if filter_type == 'api':
            return result.get('api_urls', [])
        elif filter_type == 'sensitive':
            return result.get('sensitive_urls', [])
        return sorted(set(result.get('api_urls', []) + [u['url'] for u in result.get('interesting_urls', [])]))

    def _query_cdx(self, domain, max_results):
        """查询 Wayback CDX API"""
        urls = []
        try:
            cdx_url = (
                f'https://web.archive.org/cdx/search/cdx?'
                f'url=*.{domain}/*&output=json&fl=original,timestamp,statuscode,mimetype'
                f'&limit={max_results}&filter=statuscode:200&collapse=urlkey'
            )
            resp = self.session.get(cdx_url, timeout=self.timeout + 10)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    headers = data[0]
                    for row in data[1:]:
                        entry = dict(zip(headers, row))
                        urls.append({
                            'url': entry.get('original', ''),
                            'timestamp': entry.get('timestamp', ''),
                            'status': entry.get('statuscode', ''),
                            'mime': entry.get('mimetype', ''),
                        })
        except Exception:
            pass

        # 备选: 也查询原始域名（不带 *）
        if not urls:
            try:
                cdx_url2 = (
                    f'https://web.archive.org/cdx/search/cdx?'
                    f'url={domain}/*&output=json&fl=original,timestamp,statuscode,mimetype'
                    f'&limit={max_results}&collapse=urlkey'
                )
                resp = self.session.get(cdx_url2, timeout=self.timeout + 10)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 1:
                        headers = data[0]
                        for row in data[1:]:
                            entry = dict(zip(headers, row))
                            urls.append({
                                'url': entry.get('original', ''),
                                'timestamp': entry.get('timestamp', ''),
                                'status': entry.get('statuscode', ''),
                                'mime': entry.get('mimetype', ''),
                            })
            except Exception:
                pass

        return urls

    def _check_url_status(self, url):
        """检查 URL 当前状态码"""
        try:
            resp = self.session.head(url, timeout=5, allow_redirects=True)
            return resp.status_code
        except Exception:
            return 0

    @staticmethod
    def _is_api_url(url):
        """判断 URL 是否像 API 端点"""
        url_lower = url.lower()
        for pattern in API_INDICATORS:
            if re.search(pattern, url_lower):
                return True
        # 带参数的 URL 也可能是 API
        parsed = urlparse(url)
        if parsed.query and len(parsed.query.split('&')) >= 1:
            path = parsed.path.lower()
            static_exts = ('.html', '.htm', '.css', '.js', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf')
            if not any(path.endswith(ext) for ext in static_exts):
                return True
        return False

    @staticmethod
    def _is_sensitive_url(url):
        """判断 URL 是否包含敏感路径"""
        sensitive_patterns = [
            r'/admin', r'/manage', r'/console', r'/debug',
            r'\.env', r'\.git', r'\.svn', r'config',
            r'/backup', r'/dump', r'/export',
            r'/phpinfo', r'/server-status',
            r'/wp-admin', r'/wp-login',
            r'/login', r'/signin', r'/auth',
        ]
        url_lower = url.lower()
        for pattern in sensitive_patterns:
            if re.search(pattern, url_lower):
                return True
        return False

    @staticmethod
    def _clean_domain(domain):
        """清理域名为纯域名格式"""
        if not domain:
            return ''
        domain = domain.strip().lower()
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        domain = domain.split('/')[0].split(':')[0]
        return domain
