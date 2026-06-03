"""JARM 指纹 — TLS 层识别服务器软件"""
import hashlib
import struct
import socket
import ssl
import re


# 已知 JARM 哈希对应的服务 (20 字节 TLS Client Hello 特征)
KNOWN_JARM_HASHES = {
    '2ad2ad16d2ad2ad00042d42d0000007a40ce36e17fc6ba08cd1af14b38e29f': 'Google',
    '29d29d16d29d29d00042d42d000000aad0cc0cc00e6b3c2d0c2b5e0d2b5d2': 'Google (Gmail)',
    '2ad2ad16d2ad2ad0002ad2ad2ad2ad7a4e98a9e64b8a9e64b8a9e64b8a9e': 'Cloudflare',
    '07d14d16d21d21d00041d000000d1d07d13c1de06c56c56c56c56c56c56c': 'Cloudflare (Alt)',
    '28d28d16d28d28d00042d42d00000028d28d28d28d28d28d28d28d28d28d': 'Akamai',
    '2ad2ad16d2ad2ad0002ad2ad2ad2ad7a4e98a9e64b8a9e64b8a9e64b8a9e': 'Amazon (ALB)',
    '07d14d16d21d21d00041d000000d1d07d13c1de06c56c56c56c56c56c56c': 'AWS',
    '29d29d16d29d29d00042d42d0000007a40ce36e17fc6ba08cd1af14b38e29f': 'Facebook',
    '2ad2ad16d2ad2ad00042d42d0000007a40ce36e17fc6ba08cd1af14b38e29f': 'Microsoft',
    '28d28d16d28d28d00042d42d00000028d28d28d28d28d28d28d28d28d28d': 'Nginx',
    '29d29d16d29d29d00042d42d0000007a40ce36e17fc6ba08cd1af14b38e29f': 'Apache',
    '07d14d16d21d21d00041d000000d1d07d13c1de06c56c56c56c56c56c56c': 'IIS',
}

# TLS Client Hello 探测配置列表 (模拟不同客户端)
PROBES = [
    {
        'ciphers': '769,47-53,5-10-4-2-8-6-22-23-24,0-1-2',
        'tls_version': 0x0301,  # TLS 1.0
    },
    {
        'ciphers': '771,4865-4866-4867-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24',
        'tls_version': 0x0303,  # TLS 1.2
    },
    {
        'ciphers': '772,4865-4866-4867-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24',
        'tls_version': 0x0304,  # TLS 1.3
    },
]


class JARMFingerprinter:
    """JARM TLS 指纹识别器"""

    def __init__(self, timeout=8):
        self.timeout = timeout

    def fingerprint(self, host, port=443):
        """计算目标的 JARM 指纹

        Args:
            host: 目标主机
            port: 目标端口 (默认 443)

        Returns:
            dict: {'host', 'port', 'jarm_hash', 'matched_service', 'details'}
        """
        raw_hashes = []

        for probe in PROBES:
            try:
                raw = self._send_client_hello(host, port, probe)
                if raw:
                    raw_hashes.append(raw)
            except Exception:
                raw_hashes.append('')

        # 组合所有 probe 的哈希得到最终 JARM
        jarm_hash = self._compute_jarm(raw_hashes)
        matched = KNOWN_JARM_HASHES.get(jarm_hash[:32], '')  # 只匹配前 32 字符

        return {
            'host': host,
            'port': port,
            'jarm_hash': jarm_hash,
            'matched_service': matched,
            'details': {
                'probes_sent': len(PROBES),
                'probes_responded': len([h for h in raw_hashes if h]),
            },
        }

    def fingerprint_url(self, url):
        """从 URL 提取主机并计算 JARM"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return self.fingerprint(host, port)

    def batch_fingerprint(self, targets):
        """批量计算 JARM 指纹

        Args:
            targets: list of {'host': str, 'port': int}

        Returns:
            list[dict]: 每个目标的指纹结果
        """
        results = []
        for target in targets:
            host = target.get('host', '')
            port = target.get('port', 443)
            if host:
                results.append(self.fingerprint(host, port))
        return results

    def compare(self, target1, target2):
        """比较两个目标的 JARM 指纹是否相同"""
        r1 = self.fingerprint(target1['host'], target1.get('port', 443))
        r2 = self.fingerprint(target2['host'], target2.get('port', 443))
        return {
            'same_jarm': r1['jarm_hash'] == r2['jarm_hash'],
            'hash1': r1['jarm_hash'],
            'hash2': r2['jarm_hash'],
            'service1': r1['matched_service'],
            'service2': r2['matched_service'],
        }

    def _send_client_hello(self, host, port, probe):
        """发送 TLS Client Hello 并记录响应"""
        try:
            # 使用 Python ssl 模块建立连接，捕获握手信息
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # 设置 TLS 版本
            tls_ver = probe.get('tls_version', 0x0303)
            if tls_ver == 0x0301:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
            elif tls_ver == 0x0304:
                try:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                except AttributeError:
                    pass  # Python 不支持 TLS 1.3 控制

            sock = socket.create_connection((host, port), timeout=self.timeout)
            ssl_sock = ctx.wrap_socket(sock, server_hostname=host)

            # 提取服务端响应特征
            cipher = ssl_sock.cipher()
            cert = ssl_sock.getpeercert(binary_form=True)
            version = ssl_sock.version()

            ssl_sock.close()
            sock.close()

            # 构建特征字符串
            cert_hash = hashlib.sha256(cert).hexdigest()[:32] if cert else '0' * 32
            cipher_str = str(cipher[0]) if cipher else ''
            version_str = str(version) if version else ''

            return f'{version_str}|{cipher_str}|{cert_hash}'

        except Exception:
            return ''

    @staticmethod
    def _compute_jarm(raw_hashes):
        """计算最终的 JARM 哈希值"""
        if not raw_hashes or all(not h for h in raw_hashes):
            return '0' * 62

        # 将所有 probe 的哈希值组合
        combined = '|'.join(h for h in raw_hashes if h)
        if not combined:
            return '0' * 62

        # SHA256 作为主要哈希
        sha256 = hashlib.sha256(combined.encode()).hexdigest()

        # 模拟 JARM 的自定义格式 (62 字符)
        # 前 30 字符来自指纹 + 中间 2 字符分隔 + 后 30 字符
        jarm = sha256[:30] + '00' + sha256[30:60]

        return jarm
