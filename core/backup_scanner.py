"""备份文件探测 — 自动测试备份/临时/编辑器残留文件泄露"""
import re
import time
import requests


# 备份文件路径模式: (路径模板, 描述)
BACKUP_PATHS = [
    # ── 编辑器残留 ──
    ('{base}.bak', '备份文件 (.bak)'),
    ('{base}.old', '旧版本文件 (.old)'),
    ('{base}.orig', '原始文件 (.orig)'),
    ('{base}.save', '保存文件 (.save)'),
    ('{base}.swp', 'Vim 交换文件 (.swp)'),
    ('{base}.swo', 'Vim 交换文件 (.swo)'),
    ('{base}~', '编辑器备份 (~)'),
    ('{base}.tmp', '临时文件 (.tmp)'),
    ('{base}.bk', '备份文件 (.bk)'),
    ('.#.{base}', 'Emacs 锁文件'),
    ('{base}.copy', '副本文件'),
    # ── 归档文件 ──
    ('{base}.zip', 'ZIP 归档'),
    ('{base}.tar.gz', 'TAR.GZ 归档'),
    ('{base}.tar', 'TAR 归档'),
    ('{base}.rar', 'RAR 归档'),
    ('{base}.7z', '7z 归档'),
    ('{base}.tgz', 'TGZ 归档'),
    # ── 常见备份目录 ──
    ('backup/{base}', 'backup 目录'),
    ('bak/{base}', 'bak 目录'),
    ('old/{base}', 'old 目录'),
    ('tmp/{base}', 'tmp 目录'),
    ('temp/{base}', 'temp 目录'),
    # ── 常见泄露路径 ──
    ('.git/HEAD', 'Git 仓库泄露'),
    ('.git/config', 'Git 配置泄露'),
    ('.svn/entries', 'SVN 仓库泄露'),
    ('.svn/wc.db', 'SVN 数据库泄露'),
    ('.hg/store/00manifest.i', 'Mercurial 仓库泄露'),
    ('.bzr/README', 'Bazaar 仓库泄露'),
    ('.DS_Store', 'macOS 目录索引'),
    ('Thumbs.db', 'Windows 缩略图缓存'),
    ('WEB-INF/web.xml', 'Java WEB-INF 泄露'),
    ('.env', '环境变量文件泄露'),
    ('.env.local', '本地环境变量泄露'),
    ('.env.production', '生产环境变量泄露'),
    ('config.json', '配置文件泄露'),
    ('config.yaml', '配置文件泄露'),
    ('config.yml', '配置文件泄露'),
    ('application.properties', 'Spring 配置泄露'),
    ('phpinfo.php', 'PHP 信息泄露'),
    ('info.php', 'PHP 信息泄露'),
    ('server-status', 'Apache 状态页'),
    ('server-info', 'Apache 信息页'),
    ('elmah.axd', 'ELMAH 错误日志'),
    ('trace.axd', 'ASP.NET 跟踪'),
    ('web.config', 'IIS 配置泄露'),
    ('.htaccess', 'Apache 配置泄露'),
    ('crossdomain.xml', 'Flash 跨域策略'),
    ('sitemap.xml', '站点地图'),
    ('robots.txt', '爬虫规则'),
    ('wp-config.php.bak', 'WordPress 配置备份'),
    ('wp-config.php.old', 'WordPress 配置旧版'),
    ('db.sqlite3', 'SQLite 数据库泄露'),
    ('database.sqlite', 'SQLite 数据库泄露'),
    ('backup.sql', 'SQL 备份泄露'),
    ('dump.sql', 'SQL 导出泄露'),
]


class BackupScanner:
    """备份文件探测器"""

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

    def scan(self, base_url, progress_callback=None):
        """扫描目标 URL 的备份文件泄露

        Args:
            base_url: 目标 URL (如 https://example.com)
            progress_callback: (message, pct) 回调

        Returns:
            dict: {'url', 'findings': [{'path', 'url', 'status_code', 'size', 'description', 'severity'}]}
        """
        self._stop_flag = False
        parsed = base_url.rstrip('/')
        # 提取基础路径用于生成备份路径
        parts = parsed.rsplit('/', 1)
        if len(parts) == 2:
            domain_base = parts[0]
            page_base = parts[1] or 'index'
        else:
            domain_base = parsed
            page_base = 'index'

        if not page_base or page_base.endswith('.html') or page_base.endswith('.php') or page_base.endswith('.jsp'):
            page_base = page_base.rsplit('.', 1)[0] if '.' in page_base else page_base

        findings = []
        total = len(BACKUP_PATHS)
        checked = 0

        # 先获取正常页面的基线响应
        try:
            baseline = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            baseline_len = len(baseline.content)
            baseline_status = baseline.status_code
        except Exception:
            baseline_len = 0
            baseline_status = 200

        for path_tpl, desc in BACKUP_PATHS:
            if self._stop_flag:
                break
            checked += 1
            if progress_callback and checked % 5 == 0:
                pct = int(100 * checked / max(total, 1))
                progress_callback(f'探测备份文件 {checked}/{total}...', pct)

            try:
                full_path = path_tpl.format(base=page_base)
                test_url = f'{domain_base}/{full_path}'
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                if resp.status_code == 200:
                    size = len(resp.content)
                    # 过滤：大小不能和正常页面完全一样（可能是同一个页面）
                    if size != baseline_len or baseline_status != 200:
                        # 额外验证：检查内容是否像真实文件（非空、非错误页）
                        if size > 0 and self._looks_like_real_file(resp.text, desc):
                            severity = self._assess_severity(desc, size)
                            findings.append({
                                'path': full_path,
                                'url': test_url,
                                'status_code': resp.status_code,
                                'size': size,
                                'description': desc,
                                'severity': severity,
                            })
                elif resp.status_code in (401, 403):
                    # 存在但被禁止访问 — 也值得关注
                    findings.append({
                        'path': full_path,
                        'url': test_url,
                        'status_code': resp.status_code,
                        'size': len(resp.content),
                        'description': f'{desc} (存在但被拒绝访问)',
                        'severity': 'low',
                    })
            except Exception:
                continue

        if progress_callback:
            progress_callback(f'备份文件探测完成: 发现 {len(findings)} 个', 100)

        return {'url': base_url, 'findings': findings}

    def scan_endpoint(self, url, progress_callback=None):
        """对单个 API 端点路径进行备份探测"""
        return self.scan(url, progress_callback)

    @staticmethod
    def _looks_like_real_file(text, desc):
        """检查响应是否看起来像真实文件"""
        if not text or len(text) < 10:
            return False
        text_lower = text.lower()

        # 常见的 404/错误页面特征
        error_indicators = [
            'not found', '404 error', 'page not found',
            'does not exist', '找不到', '不存在',
            'the requested url was not found',
            'no such file or directory',
        ]
        for indicator in error_indicators:
            if indicator in text_lower and len(text) < 500:
                return False

        # Git/SVN 特定检查
        if 'git' in desc.lower() and ('ref:' in text or '[core]' in text):
            return True
        if 'svn' in desc.lower() and ('dir' in text[:10] or 'file' in text[:10]):
            return True
        if '.env' in desc.lower() and '=' in text:
            return True
        if '.ds_store' in desc.lower() and len(text) > 100:
            return True

        # 一般文件：有内容且不像错误页就认为可能是真的
        if len(text) > 50:
            return True
        return False

    @staticmethod
    def _assess_severity(desc, size):
        """根据文件类型评估严重程度"""
        desc_lower = desc.lower()
        high_risk = ['.env', 'git', 'svn', 'database', 'sql', 'dump', 'web.xml', 'config', 'wp-config']
        medium_risk = ['bak', 'old', 'backup', 'orig', '.htaccess', 'web.config', 'phpinfo']

        for keyword in high_risk:
            if keyword in desc_lower:
                return 'high'
        for keyword in medium_risk:
            if keyword in desc_lower:
                return 'medium'
        if size > 10000:
            return 'medium'
        return 'low'
