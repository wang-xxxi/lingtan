"""重复页面过滤 — 识别并过滤内容相同的页面"""
import re
import hashlib
from collections import OrderedDict


class Deduplicator:
    """重复页面过滤器 — 三级过滤: MD5 → 结构哈希 → SimHash"""

    def __init__(self, similarity_threshold=0.85):
        self._seen_hashes = {}      # 结构哈希 → 代表页面 URL
        self._seen_md5 = {}         # 内容 MD5 → 代表页面 URL
        self._simhashes = []         # (url, simhash_int) 列表
        self._threshold = similarity_threshold
        self._duplicates = {}        # {代表页面: [重复页面列表]}

    def is_duplicate(self, url, html):
        """判断页面是否重复

        Args:
            url: 页面 URL
            html: 页面 HTML 内容

        Returns:
            bool: True 表示是重复页面
        """
        if not html or len(html) < 50:
            return False

        # 第一层: 内容 MD5
        content_md5 = hashlib.md5(html.encode('utf-8', errors='ignore')).hexdigest()
        if content_md5 in self._seen_md5:
            rep = self._seen_md5[content_md5]
            if rep not in self._duplicates:
                self._duplicates[rep] = []
            self._duplicates[rep].append(url)
            return True
        self._seen_md5[content_md5] = url

        # 第二层: 结构哈希
        struct_hash = self._structural_hash(html)
        if struct_hash in self._seen_hashes:
            rep = self._seen_hashes[struct_hash]
            if rep not in self._duplicates:
                self._duplicates[rep] = []
            self._duplicates[rep].append(url)
            return True
        self._seen_hashes[struct_hash] = url

        # 第三层: SimHash 近似匹配
        simhash = self._compute_simhash(html)
        for existing_url, existing_hash in self._simhashes:
            similarity = self._simhash_similarity(simhash, existing_hash)
            if similarity >= self._threshold:
                if existing_url not in self._duplicates:
                    self._duplicates[existing_url] = []
                self._duplicates[existing_url].append(url)
                return True

        self._simhashes.append((url, simhash))
        return False

    def filter(self, pages):
        """批量过滤重复页面

        Args:
            pages: list[dict] — 每项含 'url' 和 'html' (或 'body')

        Returns:
            list[dict]: 去重后的页面列表
        """
        unique = []
        for page in pages:
            url = page.get('url', '')
            html = page.get('html', page.get('body', ''))
            if not self.is_duplicate(url, html):
                unique.append(page)
        return unique

    def get_duplicates(self):
        """获取重复页面映射

        Returns:
            dict: {代表页面URL: [重复页面URL列表]}
        """
        return dict(self._duplicates)

    def get_stats(self):
        """获取去重统计

        Returns:
            dict: {total_unique, total_duplicates, duplicate_groups}
        """
        total_dup = sum(len(v) for v in self._duplicates.values())
        return {
            'total_unique': len(self._seen_hashes),
            'total_duplicates': total_dup,
            'duplicate_groups': len(self._duplicates),
        }

    def reset(self):
        """重置所有状态"""
        self._seen_hashes.clear()
        self._seen_md5.clear()
        self._simhashes.clear()
        self._duplicates.clear()

    # ── 内部方法 ──

    @staticmethod
    def _structural_hash(html):
        """计算结构哈希 — 去除动态内容后哈希"""
        # 移除 <script> 和 <style> 标签内容
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.S | re.I)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.S | re.I)
        # 移除 HTML 注释
        text = re.sub(r'<!--.*?-->', '', text, flags=re.S)
        # 移除所有数字（时间戳、ID、Token 等）
        text = re.sub(r'\d+', '', text)
        # 移除空白符
        text = re.sub(r'\s+', '', text)
        # 保留标签结构
        tags = re.findall(r'<(/?\w+)[^>]*>', text)
        structure = ' '.join(tags)
        return hashlib.md5(structure.encode('utf-8', errors='ignore')).hexdigest()

    @staticmethod
    def _compute_simhash(html, hash_bits=64):
        """计算 SimHash — 局部敏感哈希"""
        # 提取文本内容（去除标签）
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text).lower()

        # 提取 3-gram 作为特征
        words = text.split()
        features = set()
        for i in range(len(words) - 2):
            features.add(' '.join(words[i:i + 3]))
        # 也添加单个词
        features.update(words[:500])

        if not features:
            return 0

        # 初始化权重向量
        v = [0] * hash_bits

        for feature in features:
            # 计算特征的哈希
            h = int(hashlib.md5(feature.encode('utf-8', errors='ignore')).hexdigest(), 16)
            for i in range(hash_bits):
                bit = (h >> i) & 1
                if bit:
                    v[i] += 1
                else:
                    v[i] -= 1

        # 生成 SimHash
        simhash = 0
        for i in range(hash_bits):
            if v[i] >= 0:
                simhash |= (1 << i)

        return simhash

    @staticmethod
    def _simhash_similarity(hash1, hash2, hash_bits=64):
        """计算两个 SimHash 的相似度（基于海明距离）"""
        xor = hash1 ^ hash2
        # 数不同的位数
        hamming = bin(xor).count('1')
        return 1.0 - (hamming / hash_bits)
