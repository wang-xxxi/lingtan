"""云存储泄露检测 — 检测 Firebase/S3/Azure/GCS 桶公开访问"""
import re
import time
import requests


# 云存储 URL 模式
CLOUD_PATTERNS = {
    'AWS S3': {
        'url_patterns': [
            r'https?://([a-zA-Z0-9._-]+)\.s3(?:[.-][a-zA-Z0-9-]*)?\.amazonaws\.com[/]?',
            r'https?://s3[.-][a-zA-Z0-9-]*\.amazonaws\.com/([a-zA-Z0-9._-]+)[/]?',
            r's3[.-]?([a-zA-Z0-9-]+)\.amazonaws\.com',
        ],
        'test_methods': ['public_read', 'list_bucket'],
        'severity': 'high',
    },
    'Google Cloud Storage': {
        'url_patterns': [
            r'https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)[/]?',
            r'https?://([a-zA-Z0-9._-]+)\.storage\.googleapis\.com[/]?',
            r'https?://([a-zA-Z0-9._-]+)\.blob\.core\.windows\.net',
        ],
        'test_methods': ['public_read'],
        'severity': 'high',
    },
    'Firebase': {
        'url_patterns': [
            r'https?://([a-zA-Z0-9._-]+)\.firebaseapp\.com[/]?',
            r'https?://([a-zA-Z0-9._-]+)\.web\.app[/]?',
            r'https?://([a-zA-Z0-9._-]+)\.firebaseio\.com[/]?',
            r'https?://firebasestorage\.googleapis\.com/v[0-9]+/b/([a-zA-Z0-9._-]+)[/]?',
        ],
        'test_methods': ['firebase_db', 'firebase_storage'],
        'severity': 'high',
    },
    'Azure Blob': {
        'url_patterns': [
            r'https?://([a-zA-Z0-9._-]+)\.blob\.core\.windows\.net[/]?',
            r'https?://([a-zA-Z0-9._-]+)\.file\.core\.windows\.net[/]?',
        ],
        'test_methods': ['container_list'],
        'severity': 'high',
    },
    '阿里云 OSS': {
        'url_patterns': [
            r'https?://([a-zA-Z0-9._-]+)\.oss[.-][a-zA-Z0-9-]*\.aliyuncs\.com[/]?',
            r'https?://oss[.-][a-zA-Z0-9-]*\.aliyuncs\.com/([a-zA-Z0-9._-]+)[/]?',
        ],
        'test_methods': ['public_read'],
        'severity': 'high',
    },
    '腾讯云 COS': {
        'url_patterns': [
            r'https?://([a-zA-Z0-9._-]+)\.cos[.-][a-zA-Z0-9-]*\.myqcloud\.com[/]?',
            r'https?://cos[.-][a-zA-Z0-9-]*\.myqcloud\.com/([a-zA-Z0-9._-]+)[/]?',
        ],
        'test_methods': ['public_read'],
        'severity': 'high',
    },
}

# 常见的云存储桶名探测
COMMON_BUCKET_SUFFIXES = [
    '', '-static', '-assets', '-media', '-images', '-uploads', '-files',
    '-backup', '-data', '-logs', '-dev', '-staging', '-prod', '-test',
    '-public', '-cdn', '-content', '-storage', '-assets-prod',
]


class CloudStorageDetector:
    """云存储泄露检测器"""

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

    def scan(self, target_url, html='', progress_callback=None):
        """从 HTML 和 URL 中检测云存储泄露

        Args:
            target_url: 目标网站 URL
            html: 页面 HTML (可选)
            progress_callback: (message, pct) 回调

        Returns:
            dict: {'findings': [{'provider', 'url', 'bucket', 'public', 'details'}]}
        """
        self._stop_flag = False
        findings = []
        discovered_buckets = set()

        if progress_callback:
            progress_callback('扫描页面中的云存储 URL...', 10)

        # Phase 1: 从 HTML 中提取云存储 URL
        for provider, info in CLOUD_PATTERNS.items():
            for pattern in info['url_patterns']:
                matches = re.findall(pattern, html or '', re.I)
                for match in matches:
                    bucket = match if isinstance(match, str) else match[0]
                    if bucket and len(bucket) > 2:
                        discovered_buckets.add((provider, bucket))

        # Phase 2: 从 JS 代码中提取
        js_patterns = [
            r'firebase[A-Za-z]*\.initializeApp\(\{[^}]*?"([^"]+)"',
            r's3[^=]*=\s*["\']([^"\']+)',
            r'bucket[^=]*=\s*["\']([^"\']+)',
            r'STORAGE_BUCKET[^=]*=\s*["\']([^"\']+)',
            r'https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com',
            r'https?://[a-zA-Z0-9.-]+\.firebase[a-zA-Z0-9.-]*\.com',
            r'https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net',
            r'https?://[a-zA-Z0-9.-]+\.oss[a-zA-Z0-9.-]*\.aliyuncs\.com',
            r'https?://[a-zA-Z0-9.-]+\.cos[a-zA-Z0-9.-]*\.myqcloud\.com',
        ]
        for pattern in js_patterns:
            matches = re.findall(pattern, html or '', re.I)
            for match in matches:
                if isinstance(match, str) and len(match) > 3:
                    for provider, info in CLOUD_PATTERNS.items():
                        for pp in info['url_patterns']:
                            if re.search(pp, match, re.I):
                                m = re.search(pp, match, re.I)
                                if m:
                                    bucket = m.group(1) if m.lastindex else match
                                    discovered_buckets.add((provider, bucket))

        if progress_callback:
            progress_callback(f'发现 {len(discovered_buckets)} 个云存储引用，验证公开访问...', 30)

        # Phase 3: 验证每个桶的公开访问性
        checked = 0
        for provider, bucket in discovered_buckets:
            if self._stop_flag:
                break
            checked += 1
            if progress_callback:
                pct = 30 + int(60 * checked / max(len(discovered_buckets), 1))
                progress_callback(f'验证云存储 {checked}/{len(discovered_buckets)}...', min(pct, 90))

            result = self._test_bucket(provider, bucket)
            if result:
                findings.append(result)

        # Phase 4: 基于域名猜测桶名并测试
        if progress_callback:
            progress_callback('猜测可能的云存储桶名...', 90)
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]
        domain_clean = domain.replace('www.', '')

        guessed = self._guess_buckets(domain_clean)
        for provider, bucket_url in guessed:
            if self._stop_flag:
                break
            result = self._test_url(provider, bucket_url)
            if result:
                findings.append(result)

        if progress_callback:
            progress_callback(f'云存储检测完成: 发现 {len(findings)} 个', 100)

        return {'findings': findings}

    def _test_bucket(self, provider, bucket_name):
        """测试桶的公开访问性"""
        if provider == 'Firebase':
            return self._test_firebase(bucket_name)
        elif provider in ('AWS S3', '阿里云 OSS', '腾讯云 COS'):
            return self._test_s3_like(provider, bucket_name)
        elif provider == 'Google Cloud Storage':
            return self._test_gcs(bucket_name)
        elif provider == 'Azure Blob':
            return self._test_azure(bucket_name)
        return None

    def _test_firebase(self, bucket):
        """测试 Firebase 数据库/存储公开访问"""
        findings = None
        # 测试 Realtime Database
        db_url = f'https://{bucket}.firebaseio.com/.json'
        try:
            resp = self.session.get(db_url, timeout=self.timeout)
            if resp.status_code == 200 and resp.text and resp.text != 'null':
                findings = {
                    'provider': 'Firebase',
                    'url': db_url,
                    'bucket': bucket,
                    'public': True,
                    'details': 'Firebase Realtime Database 公开可读',
                    'severity': 'critical',
                    'data_size': len(resp.text),
                }
        except Exception:
            pass

        # 测试 Storage
        storage_url = f'https://firebasestorage.googleapis.com/v0/b/{bucket}/o'
        try:
            resp = self.session.get(storage_url, timeout=self.timeout)
            if resp.status_code == 200:
                return {
                    'provider': 'Firebase Storage',
                    'url': storage_url,
                    'bucket': bucket,
                    'public': True,
                    'details': 'Firebase Storage 公开可列',
                    'severity': 'high',
                }
        except Exception:
            pass

        return findings

    def _test_s3_like(self, provider, bucket):
        """测试 S3 兼容存储的公开访问"""
        if provider == 'AWS S3':
            base = f'https://{bucket}.s3.amazonaws.com'
        elif provider == '阿里云 OSS':
            base = f'https://{bucket}.oss-cn-hangzhou.aliyuncs.com'
        elif provider == '腾讯云 COS':
            base = f'https://{bucket}.cos.ap-guangzhou.myqcloud.com'
        else:
            return None

        try:
            resp = self.session.get(base, timeout=self.timeout)
            if resp.status_code == 200:
                is_list = '<ListBucketResult' in resp.text or '<Contents>' in resp.text
                return {
                    'provider': provider,
                    'url': base,
                    'bucket': bucket,
                    'public': True,
                    'details': '可列桶' if is_list else '公开可读',
                    'severity': 'critical' if is_list else 'high',
                }
            elif resp.status_code == 403:
                return {
                    'provider': provider,
                    'url': base,
                    'bucket': bucket,
                    'public': False,
                    'details': '桶存在但需要认证 (403)',
                    'severity': 'info',
                }
        except Exception:
            pass
        return None

    def _test_gcs(self, bucket):
        """测试 Google Cloud Storage"""
        url = f'https://storage.googleapis.com/{bucket}/'
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                return {
                    'provider': 'Google Cloud Storage',
                    'url': url,
                    'bucket': bucket,
                    'public': True,
                    'details': 'GCS 桶公开可访问',
                    'severity': 'high',
                }
        except Exception:
            pass
        return None

    def _test_azure(self, bucket):
        """测试 Azure Blob Storage"""
        url = f'https://{bucket}.blob.core.windows.net/?comp=list'
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and '<EnumerationResults' in resp.text:
                return {
                    'provider': 'Azure Blob',
                    'url': url,
                    'bucket': bucket,
                    'public': True,
                    'details': 'Azure Blob 容器公开可列',
                    'severity': 'critical',
                }
        except Exception:
            pass
        return None

    def _guess_buckets(self, domain):
        """基于域名猜测可能的桶名并测试"""
        results = []
        base_name = domain.split('.')[0]
        for suffix in COMMON_BUCKET_SUFFIXES[:8]:  # 限制数量
            bucket = f'{base_name}{suffix}'
            results.append(('AWS S3', f'https://{bucket}.s3.amazonaws.com'))
        return results

    def _test_url(self, provider, url):
        """快速测试 URL 是否可达"""
        try:
            resp = self.session.head(url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                return {
                    'provider': provider,
                    'url': url,
                    'bucket': url.split('//')[1].split('.')[0],
                    'public': True,
                    'details': '猜测桶名可访问',
                    'severity': 'medium',
                }
        except Exception:
            pass
        return None
