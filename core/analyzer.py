import re
import json
from urllib.parse import urlparse, parse_qs


CATEGORY_PATTERNS = {
    'authentication': {
        'patterns': [
            r'/auth[/\w]*', r'/login', r'/signin', r'/sign-in', r'/oauth',
            r'/token', r'/jwt', r'/sso', r'/cas[/\w]*', r'/saml',
            r'/register', r'/signup', r'/sign-up', r'/verify',
            r'/captcha', r'/mfa', r'/2fa', r'/otp', r'/code',
            r'/password', r'/forgot', r'/reset', r'/logout',
            r'/session', r'/refresh',
        ],
        'keywords': ['auth', 'login', 'token', 'session', 'jwt', 'oauth', 'password',
                     'credential', '认证', '登录', '注册', '验证码', '登出'],
        'description': '身份认证相关接口',
        'risk': 'high'
    },
    'user': {
        'patterns': [
            r'/user[s]?[/\w]*', r'/account[s]?[/\w]*', r'/profile[/\w]*',
            r'/member[s]?[/\w]*', r'/me[/\w]*', r'/my[/\w]*',
            r'/customer[/\w]*', r'/client[/\w]*',
        ],
        'keywords': ['user', 'account', 'profile', 'member', 'customer',
                     '用户', '账号', '个人信息', '客户'],
        'description': '用户管理相关接口',
        'risk': 'medium'
    },
    'payment': {
        'patterns': [
            r'/pay[/\w]*', r'/payment[s]?[/\w]*', r'/order[s]?[/\w]*',
            r'/billing[/\w]*', r'/invoice[s]?[/\w]*', r'/transaction[s]?[/\w]*',
            r'/wallet[/\w]*', r'/recharge[/\w]*', r'/refund[/\w]*',
            r'/alipay', r'/wechat.*pay', r'/stripe', r'/paypal',
            r'/trade[/\w]*', r'/purchase[/\w]*', r'/subscription[/\w]*',
        ],
        'keywords': ['pay', 'order', 'billing', 'transaction', 'wallet',
                     '支付', '订单', '交易', '钱包', '充值', '退款', '订阅'],
        'description': '支付交易相关接口',
        'risk': 'critical'
    },
    'data_query': {
        'patterns': [
            r'/api/v?\d*/list', r'/api/v?\d*/search', r'/api/v?\d*/query',
            r'/api/v?\d*/get', r'/api/v?\d*/find', r'/api/v?\d*/detail',
            r'/api/v?\d*/info', r'/api/v?\d*/page',
        ],
        'keywords': ['list', 'search', 'query', 'get', 'find', 'detail', 'page',
                     '列表', '搜索', '查询', '详情'],
        'description': '数据查询接口',
        'risk': 'low'
    },
    'data_modify': {
        'patterns': [
            r'/api/v?\d*/create', r'/api/v?\d*/add', r'/api/v?\d*/update',
            r'/api/v?\d*/edit', r'/api/v?\d*/delete', r'/api/v?\d*/remove',
            r'/api/v?\d*/save', r'/api/v?\d*/set', r'/api/v?\d*/modify',
        ],
        'keywords': ['create', 'add', 'update', 'edit', 'delete', 'remove', 'save',
                     '新增', '修改', '删除', '保存'],
        'description': '数据增删改接口',
        'risk': 'medium'
    },
    'file': {
        'patterns': [
            r'/upload[/\w]*', r'/download[/\w]*', r'/file[s]?[/\w]*',
            r'/image[s]?[/\w]*', r'/avatar[/\w]*', r'/media[/\w]*',
            r'/attachment[s]?[/\w]*', r'/resource[s]?[/\w]*',
            r'/oss[/\w]*', r'/cdn[/\w]*', r'/storage[/\w]*',
            r'/blob[/\w]*', r'/asset[s]?[/\w]*',
        ],
        'keywords': ['upload', 'download', 'file', 'image', 'media', 'oss', 'storage',
                     '上传', '下载', '文件', '图片', '资源', '存储'],
        'description': '文件上传下载接口',
        'risk': 'medium'
    },
    'admin': {
        'patterns': [
            r'/admin[/\w]*', r'/manage[/\w]*', r'/management[/\w]*',
            r'/backend[/\w]*', r'/console[/\w]*', r'/dashboard[/\w]*',
            r'/system[/\w]*', r'/config[/\w]*', r'/setting[s]?[/\w]*',
            r'/super[/\w]*', r'/operator[/\w]*',
        ],
        'keywords': ['admin', 'manage', 'system', 'config', 'setting', 'operator',
                     '后台', '管理', '配置', '设置', '系统'],
        'description': '管理后台接口',
        'risk': 'high'
    },
    'notification': {
        'patterns': [
            r'/notif[y|ication|ications][/ \w]*', r'/message[s]?[/\w]*',
            r'/sms[/\w]*', r'/email[/\w]*', r'/push[/\w]*',
            r'/alert[s]?[/\w]*', r'/announce[/\w]*', r'/mail[/\w]*',
        ],
        'keywords': ['notify', 'message', 'sms', 'email', 'push', 'mail',
                     '通知', '消息', '短信', '邮件', '推送'],
        'description': '消息通知接口',
        'risk': 'medium'
    },
    'third_party': {
        'patterns': [
            r'/wechat[/\w]*', r'/weixin[/\w]*', r'/alipay[/\w]*',
            r'/qq[/\w]*', r'/weibo[/\w]*', r'/douyin[/\w]*',
            r'/map[s]?[/\w]*', r'/geocode[/\w]*', r'/geolocation[/\w]*',
            r'/captcha[/\w]*', r'/recaptcha[/\w]*', r'/geetest[/\w]*',
            r'/share[/\w]*', r'/social[/\w]*',
        ],
        'keywords': ['wechat', 'weixin', 'alipay', 'qq', 'weibo', 'map', 'captcha',
                     '第三方', '微信', '支付宝', '地图', '验证码', '分享'],
        'description': '第三方服务接口',
        'risk': 'medium'
    },
    'statistics': {
        'patterns': [
            r'/stat[s]?[/\w]*', r'/analytics[/\w]*', r'/report[s]?[/\w]*',
            r'/track[/\w]*', r'/log[s]?[/\w]*', r'/monitor[/\w]*',
            r'/metric[s]?[/\w]*', r'/dashboard[/\w]*', r'/data[/\w]*',
        ],
        'keywords': ['stat', 'analytics', 'report', 'track', 'log', 'metric',
                     '统计', '分析', '报表', '埋点', '监控', '数据'],
        'description': '数据统计与分析接口',
        'risk': 'low'
    },
    'config': {
        'patterns': [
            r'/config[/\w]*', r'/setting[s]?[/\w]*', r'/option[s]?[/\w]*',
            r'/env[/\w]*', r'/init[/\w]*', r'/version[/\w]*',
            r'/dictionary[/\w]*', r'/dict[/\w]*', r'/enum[/\w]*',
            r'/constant[/\w]*', r'/metadata[/\w]*',
        ],
        'keywords': ['config', 'setting', 'option', 'init', 'version', 'dict', 'metadata',
                     '配置', '设置', '初始化', '版本', '字典', '元数据'],
        'description': '配置与初始化接口',
        'risk': 'info'
    },
    'websocket': {
        'patterns': [
            r'/ws[/\w]*', r'/wss[/\w]*', r'/socket[/\w]*',
            r'/websocket[/\w]*', r'/sse[/\w]*', r'/stream[/\w]*',
            r'/live[/\w]*', r'/realtime[/\w]*', r'/event[s]?[/\w]*',
        ],
        'keywords': ['ws', 'websocket', 'socket', 'stream', 'realtime', 'event',
                     '实时', '推送', '长连接', '事件'],
        'description': 'WebSocket/实时通信接口',
        'risk': 'info'
    },
    'graphql': {
        'patterns': [
            r'/graphql', r'/gql', r'/query',
        ],
        'keywords': ['graphql', 'gql', 'mutation', 'subscription'],
        'description': 'GraphQL接口',
        'risk': 'info'
    },
    'search': {
        'patterns': [
            r'/search[/\w]*', r'/suggest[/\w]*', r'/autocomplete[/\w]*',
            r'/hot[/\w]*', r'/trending[/\w]*', r'/recommend[/\w]*',
        ],
        'keywords': ['search', 'suggest', 'autocomplete', 'hot', 'trending', 'recommend',
                     '搜索', '建议', '热门', '推荐', '自动完成'],
        'description': '搜索与推荐接口',
        'risk': 'low'
    },
    'content': {
        'patterns': [
            r'/article[s]?[/\w]*', r'/post[s]?[/\w]*', r'/blog[/\w]*',
            r'/news[/\w]*', r'/content[/\w]*', r'/cms[/\w]*',
            r'/category[/\w]*', r'/tag[s]?[/\w]*', r'/comment[s]?[/\w]*',
            r'/review[s]?[/\w]*', r'/feedback[/\w]*',
        ],
        'keywords': ['article', 'post', 'blog', 'news', 'content', 'cms', 'comment',
                     '文章', '帖子', '内容', '评论', '反馈', '分类', '标签'],
        'description': '内容管理接口',
        'risk': 'low'
    },
    'database': {
        'patterns': [
            r'/db[/\w]*', r'/database[/\w]*', r'/sql[/\w]*',
            r'/backup[/\w]*', r'/export[/\w]*', r'/import[/\w]*',
            r'/migration[/\w]*', r'/seed[/\w]*',
        ],
        'keywords': ['database', 'backup', 'export', 'import', 'migration',
                     '数据库', '备份', '导出', '导入', '迁移'],
        'description': '数据库相关接口',
        'risk': 'high'
    },
    'devops': {
        'patterns': [
            r'/deploy[/\w]*', r'/build[/\w]*', r'/ci[/\w]*', r'/cd[/\w]*',
            r'/jenkins[/\w]*', r'/docker[/\w]*', r'/k8s[/\w]*',
            r'/pipeline[/\w]*', r'/release[/\w]*',
        ],
        'keywords': ['deploy', 'build', 'ci', 'cd', 'jenkins', 'docker', 'k8s',
                     '部署', '构建', '发布', '流水线'],
        'description': 'DevOps/部署接口',
        'risk': 'high'
    },
}

SENSITIVE_PATTERNS = {
    'phone': r'(?:1[3-9]\d{9}|\+?\d{2,3}[- ]?\d{3,4}[- ]?\d{4})',
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'id_card': r'[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]',
    'bank_card': r'\d{16,19}',
    'password_field': r'"(password|passwd|pwd|secret|token|key|credential|access_token)":\s*"[^"]*"',
    'api_key': r'"(api_key|apikey|api-key|access_key|secret_key|app_key|app_secret)":\s*"[^"]+"',
    'jwt': r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+',
    'private_ip': r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    'aws_key': r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
    'connection_string': r'(?:mongodb|mysql|postgres|redis|amqp)://[^\s"\']+',
}

RISK_PATTERNS = {
    'sql_injection': [r'(?:id|page|size|sort|order|filter|where|keyword|name|search)=\w+'],
    'idor': [r'/\d{4,}', r'id=\d+', r'uid=\d+', r'user_id=\d+'],
    'ssrf': [r'(?:url|callback|redirect|proxy|target|dest|destUrl)=.*http'],
    'file_upload': [r'upload', r'file', r'multipart', r'form-data'],
    'sensitive_in_url': [r'password', r'token', r'secret', r'key', r'credential'],
    'open_redirect': [r'(?:redirect|url|next|return|goto|target)='],
    'debug_mode': [r'(?:debug|trace|test|dev)=true', r'stacktrace', r'stack_trace'],
}


class APIAnalyzer:
    """Analyze and categorize API endpoints - fully null-safe"""

    def __init__(self):
        self.category_patterns = CATEGORY_PATTERNS
        self.sensitive_patterns = SENSITIVE_PATTERNS
        self.risk_patterns = RISK_PATTERNS

    def analyze_url(self, url, method='GET', body=None, response=None, headers=None):
        """Comprehensive analysis of a single API endpoint"""
        result = {
            'category': 'other',
            'description': '',
            'risk_level': 'info',
            'parameters': [],
            'sensitive_data': [],
            'security_issues': [],
        }

        url = url or ''
        method = (method or 'GET').upper()

        try:
            parsed = urlparse(url)
            path = (parsed.path or '').lower()
            params = parse_qs(parsed.query or '')
        except Exception:
            path = ''
            params = {}

        # 1. Categorize by URL path
        category, desc, risk = self._categorize_path(path, method)
        result['category'] = category
        result['description'] = desc
        result['risk_level'] = risk

        # 2. Extract parameters
        result['parameters'] = self._extract_parameters(url, body)

        # 3. Detect sensitive data in response
        if response:
            result['sensitive_data'] = self._detect_sensitive_data(response)

        # 4. Security analysis
        result['security_issues'] = self._security_analysis(url, method, body, headers)

        # 5. Generate description if not set
        if not result['description']:
            result['description'] = self._generate_description(url, method, params)

        return result

    def _categorize_path(self, path, method):
        """Categorize with scoring and null safety"""
        if not path or not isinstance(path, str):
            return 'other', '', 'info'

        best_match = None
        best_score = 0
        best_desc = ''
        best_risk = 'info'

        for cat_name, cat_info in self.category_patterns.items():
            score = 0
            patterns = cat_info.get('patterns', [])
            keywords = cat_info.get('keywords', [])

            for pattern in patterns:
                try:
                    if re.search(pattern, path, re.IGNORECASE):
                        score += 2
                except Exception:
                    pass

            for keyword in keywords:
                if keyword and keyword in path:
                    score += 1

            if score > best_score:
                best_score = score
                best_match = cat_name
                best_desc = cat_info.get('description', '')
                best_risk = cat_info.get('risk', 'info')

        # Adjust risk based on HTTP method
        if method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            risk_order = ['info', 'low', 'medium', 'high', 'critical']
            if best_risk in risk_order:
                idx = risk_order.index(best_risk)
                best_risk = risk_order[min(idx + 1, len(risk_order) - 1)]

        return best_match or 'other', best_desc, best_risk

    def _extract_parameters(self, url, body=None):
        """Extract parameters with null safety"""
        params = []
        if not url:
            return params

        try:
            parsed = urlparse(url)

            # URL query parameters
            query = parsed.query or ''
            for key, values in parse_qs(query).items():
                if key:
                    params.append({
                        'name': str(key),
                        'in': 'query',
                        'value': values[0] if values and len(values) == 1 else values,
                        'required': True
                    })

            # URL path parameters
            path = parsed.path or ''
            segments = path.split('/')
            for seg in segments:
                if not seg:
                    continue
                if seg.isdigit() or (seg and seg[0] == ':'):
                    params.append({
                        'name': seg if not seg.isdigit() else 'id',
                        'in': 'path',
                        'value': seg,
                        'required': True
                    })
        except Exception:
            pass

        # Body parameters
        if body and isinstance(body, str) and len(body) > 0:
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    for key, value in body_data.items():
                        if key:
                            params.append({
                                'name': str(key),
                                'in': 'body',
                                'type': type(value).__name__,
                                'required': True
                            })
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        return params

    def _detect_sensitive_data(self, response_text):
        """Detect sensitive data with null safety"""
        findings = []
        if not response_text or not isinstance(response_text, str):
            return findings

        text = response_text[:8000]

        for name, pattern in self.sensitive_patterns.items():
            try:
                matches = re.findall(pattern, text)
                if matches:
                    findings.append({
                        'type': str(name),
                        'count': len(matches),
                        'samples': [str(m)[:50] for m in matches[:3]]
                    })
            except Exception:
                pass

        return findings

    def _security_analysis(self, url, method, body, headers):
        """Security analysis with null safety"""
        issues = []
        url = url or ''
        body = body or ''

        try:
            parsed = urlparse(url)
            path = parsed.path or ''
        except Exception:
            path = ''

        full_text = f'{url} {body}'

        # SQL injection points
        try:
            for pattern in self.risk_patterns.get('sql_injection', []):
                if re.search(pattern, full_text, re.IGNORECASE):
                    issues.append({
                        'type': 'potential_sqli',
                        'description': '参数可能被注入SQL语句',
                        'severity': 'medium'
                    })
                    break
        except Exception:
            pass

        # IDOR patterns
        try:
            for pattern in self.risk_patterns.get('idor', []):
                if re.search(pattern, path):
                    issues.append({
                        'type': 'potential_idor',
                        'description': '路径含可预测ID，可能越权访问',
                        'severity': 'medium'
                    })
                    break
        except Exception:
            pass

        # Sensitive data in URL
        try:
            for pattern in self.risk_patterns.get('sensitive_in_url', []):
                if re.search(pattern, full_text, re.IGNORECASE):
                    issues.append({
                        'type': 'sensitive_in_url',
                        'description': 'URL或参数中包含敏感信息',
                        'severity': 'high'
                    })
                    break
        except Exception:
            pass

        # Open redirect
        try:
            for pattern in self.risk_patterns.get('open_redirect', []):
                if re.search(pattern, full_text, re.IGNORECASE):
                    issues.append({
                        'type': 'open_redirect',
                        'description': '可能存在开放重定向漏洞',
                        'severity': 'medium'
                    })
                    break
        except Exception:
            pass

        # Debug mode
        try:
            for pattern in self.risk_patterns.get('debug_mode', []):
                if re.search(pattern, full_text, re.IGNORECASE):
                    issues.append({
                        'type': 'debug_mode',
                        'description': '可能暴露调试信息',
                        'severity': 'low'
                    })
                    break
        except Exception:
            pass

        # No HTTPS
        try:
            if url.startswith('http://'):
                issues.append({
                    'type': 'no_https',
                    'description': '使用非加密HTTP连接',
                    'severity': 'medium'
                })
        except Exception:
            pass

        return issues

    def _generate_description(self, url, method, params):
        """Generate human-readable description with null safety"""
        try:
            parsed = urlparse(url or '')
            path = parsed.path or ''
        except Exception:
            return f'{method} 请求'

        segments = [s for s in path.split('/') if s and s != 'api' and not s.isdigit()]

        desc_parts = []

        method_map = {
            'GET': '获取', 'POST': '创建/提交', 'PUT': '更新',
            'DELETE': '删除', 'PATCH': '部分更新',
            'HEAD': '探测', 'OPTIONS': '查询支持的方法',
        }
        desc_parts.append(method_map.get(method, method))

        if segments:
            resource = segments[-1].replace('_', ' ').replace('-', ' ')
            desc_parts.append(resource)
        elif path and path != '/':
            desc_parts.append(path.strip('/'))

        return ' '.join(desc_parts) if desc_parts else f'{method} {path}'

    def batch_analyze(self, endpoints):
        """Analyze a list of endpoints with null safety"""
        if not endpoints or not isinstance(endpoints, list):
            return []

        results = []
        for ep in endpoints:
            if not ep or not isinstance(ep, dict):
                continue
            try:
                analysis = self.analyze_url(
                    url=ep.get('url', ''),
                    method=ep.get('method', 'GET'),
                    body=ep.get('request_body'),
                    response=ep.get('response_sample'),
                    headers=ep.get('headers')
                )
                ep.update(analysis)
                results.append(ep)
            except Exception:
                # Still include the endpoint even if analysis fails
                ep.setdefault('category', 'other')
                ep.setdefault('description', '')
                ep.setdefault('risk_level', 'info')
                ep.setdefault('parameters', [])
                ep.setdefault('sensitive_data', [])
                ep.setdefault('security_issues', [])
                results.append(ep)
        return results

    def generate_api_summary(self, endpoints):
        """Generate a human-readable summary of discovered APIs"""
        if not endpoints:
            return "未发现任何API接口。"

        categories = {}
        for ep in endpoints:
            if not ep or not isinstance(ep, dict):
                continue
            cat = ep.get('category', 'other') or 'other'
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(ep)

        total = len(endpoints)
        summary_lines = [f"共发现 {total} 个API接口，分布在 {len(categories)} 个分类中：\n"]

        for cat, eps in sorted(categories.items(), key=lambda x: -len(x[1])):
            cat_info = self.category_patterns.get(cat, {})
            cat_desc = cat_info.get('description', cat)
            summary_lines.append(f"\n### {cat_desc} ({cat}) - {len(eps)} 个接口")
            for ep in eps[:10]:
                risk = ep.get('risk_level', 'info') or 'info'
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                        'low': '🟢', 'info': '🔵'}.get(risk, '⚪')
                summary_lines.append(f"  {icon} [{ep.get('method', 'GET')}] {ep.get('url', '')}")
                desc = ep.get('description', '')
                if desc:
                    summary_lines.append(f"     → {desc}")
            if len(eps) > 10:
                summary_lines.append(f"  ... 还有 {len(eps) - 10} 个接口")

        return '\n'.join(summary_lines)
