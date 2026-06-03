"""404 页面学习 — 自动识别自定义错误页，减少误报"""
import re
import hashlib
import requests


class ErrorPageDetector:
    """自定义错误页检测器 — 学习目标的 404 行为模式"""

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        })

    def learn(self, base_url):
        """学习目标站点的 404 行为

        Args:
            base_url: 目标基础 URL

        Returns:
            dict: 404 特征指纹
        """
        # 发送多个随机路径请求来学习 404 模式
        random_paths = [
            '/nonexistent_' + hashlib.md5(b'probe1').hexdigest()[:12],
            '/this-page-does-not-exist-xyz123',
            '/a]b[c<d>e?f=g&h=i',
            '/_random_path_404_test_',
            '/nonexist/' + hashlib.md5(b'probe2').hexdigest()[:8] + '.html',
        ]

        not_found_samples = []
        for path in random_paths:
            try:
                url = base_url.rstrip('/') + path
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                not_found_samples.append({
                    'status_code': resp.status_code,
                    'body_len': len(resp.content),
                    'body_hash': hashlib.md5(resp.text[:3000].encode('utf-8', errors='ignore')).hexdigest(),
                    'content_type': resp.headers.get('content-type', ''),
                    'title': self._extract_title(resp.text[:2000]),
                    'body_preview': resp.text[:500],
                })
            except Exception:
                continue

        if not not_found_samples:
            return self._default_fingerprint(base_url)

        # 分析 404 模式
        fp = {
            'base_url': base_url,
            'status_codes': list(set(s['status_code'] for s in not_found_samples)),
            'body_lengths': [s['body_len'] for s in not_found_samples],
            'body_hashes': list(set(s['body_hash'] for s in not_found_samples)),
            'content_types': list(set(s['content_type'] for s in not_found_samples)),
            'titles': [s['title'] for s in not_found_samples if s['title']],
            'learned': True,
            'samples': len(not_found_samples),
        }

        # 判断是否为自定义错误页
        fp['is_custom_error'] = self._detect_custom_error(not_found_samples)

        # 提取自定义错误页的特征
        if fp['is_custom_error']:
            fp['custom_patterns'] = self._extract_error_patterns(not_found_samples)

        return fp

    def is_real_page(self, url, resp, fingerprint):
        """判断一个 200 响应是否是真正的页面（而非伪装的 404）

        Args:
            url: 请求的 URL
            resp: requests.Response 对象
            fingerprint: learn() 返回的指纹

        Returns:
            bool: True = 真实页面, False = 实际是 404
        """
        if not fingerprint or not fingerprint.get('learned'):
            return True

        status = resp.status_code

        # 如果状态码明确是 404
        if status == 404:
            return False

        # 如果状态码是 200，但可能是伪装的 404
        if status == 200 and fingerprint.get('is_custom_error'):
            body_len = len(resp.content)
            body_hash = hashlib.md5(resp.text[:3000].encode('utf-8', errors='ignore')).hexdigest()

            # 检查是否和已知的 404 页面匹配
            if body_hash in fingerprint.get('body_hashes', []):
                return False

            # 检查 body 长度是否和 404 样本接近
            fp_lengths = fingerprint.get('body_lengths', [])
            if fp_lengths:
                avg_404_len = sum(fp_lengths) / len(fp_lengths)
                if abs(body_len - avg_404_len) < 50 and body_len < 2000:
                    return False

            # 检查标题是否匹配 404 模式
            title = self._extract_title(resp.text[:2000])
            if title and title in fingerprint.get('titles', []):
                return False

            # 检查自定义错误模式
            custom_patterns = fingerprint.get('custom_patterns', [])
            for pattern in custom_patterns:
                if re.search(pattern, resp.text[:3000], re.I):
                    return False

        return True

    def filter_results(self, results, fingerprint):
        """过滤扫描结果中的假阳性

        Args:
            results: 扫描结果列表，每个含 'url', 'status_code', 'body'/'response'
            fingerprint: learn() 返回的指纹

        Returns:
            tuple: (real_pages, false_positives)
        """
        real = []
        false_pos = []
        for r in results:
            status = r.get('status_code', 0)
            body = r.get('body', r.get('response', ''))
            url = r.get('url', '')

            if status == 200 and fingerprint.get('is_custom_error'):
                body_hash = hashlib.md5((body or '')[:3000].encode('utf-8', errors='ignore')).hexdigest()
                if body_hash in fingerprint.get('body_hashes', []):
                    false_pos.append(r)
                    continue
            real.append(r)
        return real, false_pos

    def score_reliability(self, fingerprint):
        """评估指纹的可靠性

        Returns:
            dict: {'reliable': bool, 'confidence': float, 'reasons': list}
        """
        if not fingerprint or not fingerprint.get('learned'):
            return {'reliable': False, 'confidence': 0, 'reasons': ['未学习到 404 行为']}

        reasons = []
        confidence = 0.5

        # 所有 404 状态码一致
        statuses = fingerprint.get('status_codes', [])
        if len(statuses) == 1:
            confidence += 0.2
            reasons.append(f'404 状态码一致: {statuses[0]}')
        elif 200 in statuses:
            confidence -= 0.2
            reasons.append('404 路径返回 200，可能是自定义错误页')

        # 自定义错误页检测
        if fingerprint.get('is_custom_error'):
            confidence += 0.1
            reasons.append('检测到自定义错误页')

        # body hash 一致
        hashes = fingerprint.get('body_hashes', [])
        if len(hashes) <= 2:
            confidence += 0.1
            reasons.append('404 响应体基本一致')

        return {
            'reliable': confidence >= 0.4,
            'confidence': round(min(max(confidence, 0), 1.0), 2),
            'reasons': reasons,
        }

    @staticmethod
    def _extract_title(html):
        """提取 HTML 标题"""
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
            if match:
                return match.group(1).strip()[:100]
        except Exception:
            pass
        return ''

    @staticmethod
    def _detect_custom_error(samples):
        """检测是否存在自定义错误页"""
        if not samples:
            return False

        # 如果有 200 响应但路径是随机不存在的
        has_200 = any(s['status_code'] == 200 for s in samples)
        if has_200:
            return True

        # 如果 404 响应体长度一致且有内容
        lengths = [s['body_len'] for s in samples if s['status_code'] == 404]
        if lengths and len(set(lengths)) <= 2 and max(lengths) > 200:
            return True

        return False

    @staticmethod
    def _extract_error_patterns(samples):
        """从 404 样本中提取正则特征"""
        patterns = set()
        for sample in samples:
            body = sample.get('body_preview', '')
            title = ErrorPageDetector._extract_title(body)

            # 从标题中提取关键词
            if title:
                keywords = re.findall(r'\b(?:not found|error|404|missing|不存在|找不到|错误)\b', title, re.I)
                for kw in keywords:
                    patterns.add(re.escape(kw))

            # 常见 404 页面特征文本
            error_texts = re.findall(
                r'(?:page|url|resource|file).{0,30}(?:not found|does not exist|404|missing)',
                body, re.I
            )
            for text in error_texts:
                patterns.add(re.escape(text[:40]))

        return list(patterns)[:5]

    @staticmethod
    def _default_fingerprint(base_url):
        """返回默认指纹"""
        return {
            'base_url': base_url,
            'status_codes': [404],
            'body_lengths': [],
            'body_hashes': [],
            'content_types': [],
            'titles': [],
            'learned': False,
            'is_custom_error': False,
            'samples': 0,
        }
