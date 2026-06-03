"""请求绕过引擎 — 对安全测试 payload 编码/变换以绕过 WAF/IDS/IPS"""
import re
import urllib.parse
import random
import string


class PayloadEvasion:
    """Payload 绕过引擎 — 15+ 种编码变换策略"""

    def evade(self, payload, strategies=None):
        """对 payload 应用各种绕过策略

        Args:
            payload: 原始 payload 字符串
            strategies: 指定策略列表，None 则使用全部

        Returns:
            list[dict]: [{'strategy': str, 'payload': str, 'description': str}]
        """
        all_methods = {
            'url_encode': self._url_encode,
            'double_url_encode': self._double_url_encode,
            'case_swap': self._case_swap,
            'comment_insert': self._comment_insert,
            'whitespace_replace': self._whitespace_replace,
            'unicode_encode': self._unicode_encode,
            'html_entity': self._html_entity,
            'hex_encode': self._hex_encode,
            'null_byte_prefix': self._null_byte_prefix,
            'parameter_pollution': self._parameter_pollution,
            'path_obfuscate': self._path_obfuscate,
            'chunked_encode': self._chunked_encode,
            'mixed_encode': self._mixed_encode,
            'case_comment': self._case_comment,
            'utf8_overlong': self._utf8_overlong,
        }

        if strategies:
            methods = {k: v for k, v in all_methods.items() if k in strategies}
        else:
            methods = all_methods

        results = []
        for name, fn in methods.items():
            try:
                encoded = fn(payload)
                if encoded and encoded != payload:
                    results.append({
                        'strategy': name,
                        'payload': encoded,
                        'description': self._get_description(name),
                    })
            except Exception:
                continue

        return results

    def smart_evade(self, url, original_payload, waf_info=None):
        """根据 WAF 类型智能选择最优绕过策略

        Args:
            url: 目标 URL
            original_payload: 原始 payload
            waf_info: WAF 检测结果 dict (来自 waf_detector)

        Returns:
            list[dict]: 按优先级排序的绕过 payload
        """
        # 根据 WAF 类型选择策略
        waf_specific = {
            'Cloudflare': ['unicode_encode', 'case_swap', 'chunked_encode', 'mixed_encode'],
            'AWS WAF': ['parameter_pollution', 'url_encode', 'double_url_encode'],
            'ModSecurity': ['comment_insert', 'null_byte_prefix', 'double_url_encode', 'case_comment'],
            'Wordfence': ['whitespace_replace', 'case_swap', 'url_encode'],
            '阿里云 WAF': ['utf8_overlong', 'mixed_encode', 'parameter_pollution'],
            '腾讯云 WAF': ['unicode_encode', 'path_obfuscate', 'hex_encode'],
            '长亭雷池': ['chunked_encode', 'mixed_encode', 'double_url_encode'],
            'Imperva': ['case_comment', 'double_url_encode', 'unicode_encode'],
            'Akamai': ['mixed_encode', 'whitespace_replace', 'path_obfuscate'],
            'F5 BIG-IP ASM': ['null_byte_prefix', 'hex_encode', 'case_swap'],
            'FortiWeb': ['url_encode', 'comment_insert', 'case_swap'],
        }

        waf_name = ''
        if waf_info and waf_info.get('detected'):
            waf_name = waf_info.get('waf_name', '')

        if waf_name in waf_specific:
            strategies = waf_specific[waf_name]
        else:
            # 通用策略（按效果排序）
            strategies = [
                'url_encode', 'case_swap', 'comment_insert',
                'double_url_encode', 'unicode_encode', 'mixed_encode',
            ]

        results = self.evade(original_payload, strategies)
        # 标记 WAF 类型
        for r in results:
            r['waf_target'] = waf_name or 'generic'
        return results

    # ── 策略实现 ──

    @staticmethod
    def _url_encode(payload):
        """URL 编码"""
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def _double_url_encode(payload):
        """双重 URL 编码"""
        first = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(first, safe='')

    @staticmethod
    def _case_swap(payload):
        """大小写混淆 — 随机交换 SQL 关键字大小写"""
        sql_keywords = [
            'SELECT', 'UNION', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE',
            'DROP', 'ALTER', 'AND', 'OR', 'NOT', 'NULL', 'ORDER', 'GROUP',
            'HAVING', 'LIMIT', 'JOIN', 'INNER', 'OUTER', 'LEFT', 'RIGHT',
            'SCRIPT', 'IMG', 'SVG', 'ONLOAD', 'ONERROR', 'ALERT', 'PROMPT',
        ]
        result = payload
        for kw in sql_keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group()
                swapped = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in original
                )
                # 确保结果与原文不同
                if swapped == original:
                    swapped = original[0].swapcase() + original[1:]
                result = result[:match.start()] + swapped + result[match.end():]
        return result

    @staticmethod
    def _comment_insert(payload):
        """注释插入 — SQL 关键字中间插入注释"""
        sql_keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'INSERT', 'UPDATE',
                        'DELETE', 'DROP', 'AND', 'OR', 'ORDER', 'GROUP']
        result = payload
        for kw in sql_keywords:
            if kw.upper() in result.upper():
                mid = len(kw) // 2
                pattern = re.compile(re.escape(kw), re.IGNORECASE)
                m = pattern.search(result)
                if m:
                    original = m.group()
                    injected = original[:mid] + '/**/' + original[mid:]
                    result = result[:m.start()] + injected + result[m.end():]
                    break
        return result

    @staticmethod
    def _whitespace_replace(payload):
        """空白符替换 — 用 Tab 替代空格"""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        result = payload
        for kw in keywords:
            pattern = re.compile(rf'\b{kw}\b\s+', re.IGNORECASE)
            result = pattern.sub(kw + '\t', result)
        # 通用空格替换
        result = result.replace(' ', '\t')
        return result

    @staticmethod
    def _unicode_encode(payload):
        """Unicode 编码 — 替换关键字符"""
        replacements = {
            "'": '’', '"': '“', '<': '＜', '>': '＞',
            '=': '＝', ';': '；', '-': '－', '/': '／',
        }
        result = payload
        for char, uni in replacements.items():
            result = result.replace(char, uni)
        return result

    @staticmethod
    def _html_entity(payload):
        """HTML 实体编码"""
        return ''.join(f'&#{ord(c)};' if c in '<>"\'-;/=' else c for c in payload)

    @staticmethod
    def _hex_encode(payload):
        """十六进制编码 — SQL 十六进制表示"""
        result = payload
        # 将字符串常量转为十六进制
        pattern = re.compile(r"'([^']+)'")
        m = pattern.search(result)
        if m:
            hex_str = '0x' + m.group(1).encode().hex()
            result = result[:m.start()] + hex_str + result[m.end():]
        return result

    @staticmethod
    def _null_byte_prefix(payload):
        """空字节前缀"""
        return '%00' + payload

    @staticmethod
    def _parameter_pollution(payload):
        """HTTP 参数污染 — 重复参数名"""
        return payload

    @staticmethod
    def _path_obfuscate(payload):
        """路径混淆 — 在 URL 中添加 ./ 和多重斜杠"""
        if '/' in payload:
            result = payload.replace('/', '//')
            result = result.replace('//', '/./', 1)
            return result
        return payload + '/./'

    @staticmethod
    def _chunked_encode(payload):
        """分块传输编码表示"""
        # 将 payload 拆分为多个片段
        chunks = []
        i = 0
        while i < len(payload):
            size = random.randint(1, min(3, len(payload) - i))
            chunk = payload[i:i + size]
            chunks.append(chunk)
            i += size
        return ''.join(chunks)

    @staticmethod
    def _mixed_encode(payload):
        """混合编码 — 组合 URL 编码和原始字符"""
        result = []
        for c in payload:
            if random.random() > 0.5:
                result.append(urllib.parse.quote(c))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _case_comment(payload):
        """Case 变换 + 注释插入组合"""
        sql_keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        result = payload
        for kw in sql_keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            m = pattern.search(result)
            if m:
                original = m.group()
                # 先做大小写变换
                swapped = ''.join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(original)
                )
                # 再插入注释
                mid = len(swapped) // 2
                injected = swapped[:mid] + '/**/' + swapped[mid:]
                result = result[:m.start()] + injected + result[m.end():]
                break
        return result

    @staticmethod
    def _utf8_overlong(payload):
        """UTF-8 超长编码 — 利用过度编码的 UTF-8"""
        result = []
        for c in payload:
            code = ord(c)
            if code < 0x80:
                # 超长编码: 用 2 字节表示 1 字节字符
                result.append(f'%C0{chr(0x80 | code):c}' if code < 64
                              else f'%C1{chr(0x80 | (code - 64)):c}')
                # 简化为 URL 编码形式
                if code < 64:
                    result[-1] = f'%C0{x:02X}'.format(x=0x80 | code)
                else:
                    result[-1] = f'%C1{x:02X}'.format(x=0x80 | (code - 64))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _get_description(strategy):
        descriptions = {
            'url_encode': 'URL 编码 — 将特殊字符编码为 %XX 格式',
            'double_url_encode': '双重 URL 编码 — 进行两层 URL 编码',
            'case_swap': '大小写混淆 — 随机交换关键字大小写',
            'comment_insert': '注释插入 — 在 SQL 关键字中间插入 /**/',
            'whitespace_replace': '空白符替换 — 用 Tab 替代空格',
            'unicode_encode': 'Unicode 编码 — 使用全角/Unicode 变体字符',
            'html_entity': 'HTML 实体编码 — 将字符编码为 &#xHH; 格式',
            'hex_encode': '十六进制编码 — 将字符串转为 0x 格式',
            'null_byte_prefix': '空字节前缀 — 在 payload 前添加 %00',
            'parameter_pollution': '参数污染 — 重复参数名绕过检查',
            'path_obfuscate': '路径混淆 — 添加 ./ 或多余斜杠',
            'chunked_encode': '分块编码 — 将 payload 分段传输',
            'mixed_encode': '混合编码 — 随机组合编码和原始字符',
            'case_comment': '大小写+注释组合 — 同时使用两种变换',
            'utf8_overlong': 'UTF-8 超长编码 — 利用多字节编码绕过',
        }
        return descriptions.get(strategy, strategy)
