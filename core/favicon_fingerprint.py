"""Favicon 哈希指纹 — 通过 favicon 的 MurmurHash3 识别同一应用的多域名"""
import hashlib
import re
import struct
import requests


# 已知 CMS/框架的 favicon mmh3 哈希 (Shodan 语法: http.favicon.hash:xxxx)
KNOWN_FAVICON_HASHES = {
    -297069493: 'Jenkins',
    81586312: 'Spring Boot',
    -320513246: 'WordPress 默认',
    116323821: 'WebLogic',
    440924935: 'Zabbix',
    989034219: '通达 OA',
    -454199652: 'Jira',
    1904990496: 'Atlassian Confluence',
    -606508076: 'Grafana',
    -293152929: 'Jetty',
    2107000489: 'Tomcat',
    1829923815: 'Tomcat',
    -1456532508: 'Apache',
    1270249824: 'Elasticsearch',
    202285152: 'Kibana',
    -921498675: 'Django',
    -493207505: 'GitLab',
    -1275385145: 'Harbor',
    195431273: 'ThinkPHP',
    458480128: 'Webmin',
    796983749: 'FortiGate',
    1692631550: 'Cacti',
    597799874: 'Solr',
    -1036356706: 'Nagios',
    -1836498890: 'VMware vCenter',
    721497542: 'phpMyAdmin',
    1074796876: 'HFS',
    -1364747869: 'Docker Registry',
    -648117804: 'Laravel',
    -753195883: 'Struts2',
    -889755238: 'Yii',
    383254803: 'Odoo',
    -372394824: '宝塔面板',
    1601187835: 'RabbitMQ',
    -1072744431: 'MinIO',
}


class FaviconFingerprinter:
    """Favicon 哈希指纹识别器"""

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'image/*,*/*',
        })

    def analyze(self, target_url, html=''):
        """分析目标站点的 favicon 指纹

        Args:
            target_url: 目标 URL
            html: 页面 HTML (用于提取 favicon 路径)

        Returns:
            dict: {'favicon_url', 'hash', 'md5', 'matched_app', 'size'}
        """
        # Step 1: 从 HTML 提取 favicon URL
        favicon_url = self._extract_favicon_url(target_url, html)

        # Step 2: 下载 favicon
        favicon_data = self._download_favicon(favicon_url)
        if not favicon_data:
            # 尝试常见路径
            favicon_url = self._try_common_paths(target_url)
            if favicon_url:
                favicon_data = self._download_favicon(favicon_url)

        if not favicon_data:
            return {
                'favicon_url': '',
                'hash': 0,
                'md5': '',
                'matched_app': '',
                'size': 0,
                'error': '无法获取 favicon',
            }

        # Step 3: 计算哈希
        mmh3_hash = self._murmurhash3(favicon_data)
        md5_hash = hashlib.md5(favicon_data).hexdigest()

        # Step 4: 匹配已知应用
        matched_app = KNOWN_FAVICON_HASHES.get(mmh3_hash, '')

        return {
            'favicon_url': favicon_url,
            'hash': mmh3_hash,
            'md5': md5_hash,
            'matched_app': matched_app,
            'size': len(favicon_data),
        }

    def compare(self, url1, url2):
        """比较两个域名的 favicon 是否相同（判断是否同一应用）

        Returns:
            dict: {'same_favicon': bool, 'hash1', 'hash2', 'matched_app'}
        """
        result1 = self.analyze(url1)
        result2 = self.analyze(url2)
        return {
            'same_favicon': result1['hash'] == result2['hash'] and result1['hash'] != 0,
            'hash1': result1['hash'],
            'hash2': result2['hash'],
            'matched_app': result1.get('matched_app') or result2.get('matched_app'),
        }

    def batch_analyze(self, urls):
        """批量分析多个 URL 的 favicon 指纹

        Returns:
            list[dict]: 每个 URL 的分析结果
        """
        results = []
        for url in urls:
            results.append(self.analyze(url))
        return results

    def find_same_app(self, urls):
        """找出使用相同 favicon 的域名（可能属于同一应用）

        Returns:
            dict: {hash_value: [url_list]}
        """
        groups = {}
        for url in urls:
            result = self.analyze(url)
            h = result['hash']
            if h:
                if h not in groups:
                    groups[h] = []
                groups[h].append({
                    'url': url,
                    'app': result.get('matched_app', ''),
                    'md5': result.get('md5', ''),
                })
        return {str(k): v for k, v in groups.items() if len(v) > 1}

    def _extract_favicon_url(self, base_url, html):
        """从 HTML 中提取 favicon URL"""
        if html:
            # <link rel="icon" href="...">
            patterns = [
                r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']',
                r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut )?icon["\']',
            ]
            for pattern in patterns:
                match = re.search(pattern, html, re.I)
                if match:
                    href = match.group(1)
                    if href.startswith('http'):
                        return href
                    from urllib.parse import urljoin
                    return urljoin(base_url, href)

        # 默认路径
        from urllib.parse import urljoin
        return urljoin(base_url, '/favicon.ico')

    def _try_common_paths(self, base_url):
        """尝试常见的 favicon 路径"""
        from urllib.parse import urljoin
        paths = ['/favicon.ico', '/favicon.png', '/apple-touch-icon.png',
                 '/apple-touch-icon-precomposed.png']
        for path in paths:
            try:
                url = urljoin(base_url, path)
                resp = self.session.head(url, timeout=5)
                if resp.status_code == 200:
                    return url
            except Exception:
                continue
        return ''

    def _download_favicon(self, url):
        """下载 favicon 数据"""
        if not url:
            return None
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and len(resp.content) > 0:
                return resp.content
        except Exception:
            pass
        return None

    @staticmethod
    def _murmurhash3(data, seed=0):
        """计算 MurmurHash3 (与 Shodan 兼容的 32 位有符号整数)"""
        if not data:
            return 0

        data = bytearray(data)
        length = len(data)
        nblocks = length // 4
        h1 = seed & 0xFFFFFFFF

        c1 = 0xCC9E2D51
        c2 = 0x1B873593

        # body
        for block_start in range(0, nblocks * 4, 4):
            k1 = struct.unpack('<I', data[block_start:block_start + 4])[0]

            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF

            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

        # tail
        tail_index = nblocks * 4
        k1 = 0
        tail_size = length & 3

        if tail_size >= 3:
            k1 ^= data[tail_index + 2] << 16
        if tail_size >= 2:
            k1 ^= data[tail_index + 1] << 8
        if tail_size >= 1:
            k1 ^= data[tail_index]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        # finalization
        h1 ^= length
        h1 ^= h1 >> 16
        h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
        h1 ^= h1 >> 13
        h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
        h1 ^= h1 >> 16

        # 转为有符号 32 位整数 (Shodan 格式)
        if h1 >= 0x80000000:
            h1 -= 0x100000000

        return h1
