"""YAML 模板引擎 — 加载和执行社区贡献的检测规则"""
import os
import re
import json
import time
import hashlib
import requests


# 内置模板示例（无需 PyYAML 依赖，用简化的 dict 格式）
BUILTIN_TEMPLATES = [
    {
        'id': 'tech-spring-boot',
        'info': {
            'name': 'Spring Boot Actuator 检测',
            'author': '灵探',
            'severity': 'medium',
            'description': '检测 Spring Boot Actuator 端点是否未授权访问',
            'tags': ['spring', 'actuator', 'info-leak'],
        },
        'requests': [
            {
                'method': 'GET',
                'path': ['/actuator', '/actuator/health', '/actuator/env', '/actuator/info'],
                'matchers': [
                    {'type': 'status', 'value': [200]},
                    {'type': 'word', 'words': ['status', 'components', 'UP'], 'condition': 'or'},
                ],
            },
        ],
    },
    {
        'id': 'tech-swagger',
        'info': {
            'name': 'Swagger/OpenAPI 检测',
            'author': '灵探',
            'severity': 'low',
            'description': '检测 Swagger UI 和 OpenAPI 规范文件',
            'tags': ['swagger', 'api-docs'],
        },
        'requests': [
            {
                'method': 'GET',
                'path': ['/swagger-ui.html', '/swagger/', '/swagger-ui/', '/api-docs',
                         '/swagger.json', '/swagger/v1/swagger.json', '/v2/api-docs',
                         '/openapi.json', '/openapi.yaml', '/docs'],
                'matchers': [
                    {'type': 'word', 'words': ['swagger', 'openapi', 'api-docs', 'Swagger UI'], 'condition': 'or'},
                ],
            },
        ],
    },
    {
        'id': 'tech-git-exposure',
        'info': {
            'name': 'Git 仓库泄露检测',
            'author': '灵探',
            'severity': 'high',
            'description': '检测 .git 目录是否可通过 Web 访问',
            'tags': ['git', 'exposure', 'misconfig'],
        },
        'requests': [
            {
                'method': 'GET',
                'path': ['/.git/HEAD', '/.git/config', '/.git/index'],
                'matchers': [
                    {'type': 'status', 'value': [200]},
                    {'type': 'word', 'words': ['ref:', 'repositoryformatversion', 'DIRC'], 'condition': 'or'},
                ],
            },
        ],
    },
    {
        'id': 'tech-database-admin',
        'info': {
            'name': '数据库管理面板检测',
            'author': '灵探',
            'severity': 'medium',
            'description': '检测 phpMyAdmin / Adminer 等数据库管理面板',
            'tags': ['database', 'admin', 'phpmyadmin'],
        },
        'requests': [
            {
                'method': 'GET',
                'path': ['/phpmyadmin/', '/phpMyAdmin/', '/adminer.php', '/adminer/',
                         '/mysql/', '/dbadmin/', '/pma/'],
                'matchers': [
                    {'type': 'word', 'words': ['phpMyAdmin', 'Adminer', 'mysql_connect', 'Welcome to phpMyAdmin'],
                     'condition': 'or'},
                ],
            },
        ],
    },
    {
        'id': 'tech-admin-panels',
        'info': {
            'name': '管理后台检测',
            'author': '灵探',
            'severity': 'medium',
            'description': '检测常见的管理后台入口',
            'tags': ['admin', 'login', 'panel'],
        },
        'requests': [
            {
                'method': 'GET',
                'path': ['/admin', '/admin/', '/administrator/', '/manage', '/manage/',
                         '/dashboard', '/panel', '/backend', '/wp-admin',
                         '/login', '/signin', '/user/login'],
                'matchers': [
                    {'type': 'status', 'value': [200]},
                    {'type': 'word', 'words': ['login', 'admin', 'password', 'username', 'sign in', '登录'],
                     'condition': 'or', 'part': 'body'},
                ],
            },
        ],
    },
    {
        'id': 'tech-graphql-introspection',
        'info': {
            'name': 'GraphQL 内省查询检测',
            'author': '灵探',
            'severity': 'medium',
            'description': '检测 GraphQL 端点是否允许内省查询',
            'tags': ['graphql', 'introspection'],
        },
        'requests': [
            {
                'method': 'POST',
                'path': ['/graphql', '/api/graphql', '/query', '/v1/graphql'],
                'body': '{"query":"{ __schema { queryType { name } } }"}',
                'headers': {'Content-Type': 'application/json'},
                'matchers': [
                    {'type': 'word', 'words': ['__schema', 'queryType', 'mutationType'], 'condition': 'and'},
                ],
            },
        ],
    },
    {
        'id': 'tech-dns-rebinding',
        'info': {
            'name': 'DNS Rebinding 检测',
            'author': '灵探',
            'severity': 'high',
            'description': '检测服务器是否接受 DNS Rebinding 请求',
            'tags': ['ssrf', 'dns-rebinding'],
        },
        'requests': [
            {
                'method': 'GET',
                'path': ['/{host_header}'],
                'matchers': [
                    {'type': 'status', 'value': [200, 301, 302, 403]},
                ],
                'note': '此模板需要替换 {host_header} 为测试值',
            },
        ],
    },
    {
        'id': 'tech-http-request-smuggling',
        'info': {
            'name': 'HTTP 请求走私基础检测',
            'author': '灵探',
            'severity': 'high',
            'description': '检测 HTTP 请求走私漏洞 (CL.TE / TE.CL)',
            'tags': ['smuggling', 'http', 'desync'],
        },
        'requests': [
            {
                'method': 'POST',
                'path': ['/'],
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '6',
                },
                'body': '0\r\n\r\nX',
                'matchers': [
                    {'type': 'status', 'value': [400, 502, 503, 504]},
                    {'type': 'time', 'operator': 'gt', 'value': 3},
                ],
                'condition': 'or',
            },
        ],
    },
]


class TemplateEngine:
    """YAML 模板引擎 — 执行检测规则"""

    def __init__(self, timeout=10, template_dir=None):
        self.timeout = timeout
        self.template_dir = template_dir
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        })
        self._stop_flag = False
        self.templates = list(BUILTIN_TEMPLATES)

        # 尝试从目录加载自定义模板
        if template_dir and os.path.isdir(template_dir):
            self._load_external_templates(template_dir)

    def stop(self):
        self._stop_flag = True

    def list_templates(self):
        """列出所有可用模板"""
        return [
            {
                'id': t['id'],
                'name': t['info'].get('name', ''),
                'severity': t['info'].get('severity', 'info'),
                'description': t['info'].get('description', ''),
                'tags': t['info'].get('tags', []),
            }
            for t in self.templates
        ]

    def run_template(self, template_id, target_url):
        """执行单个模板

        Returns:
            dict: {'template_id', 'matched': bool, 'results': [...]}
        """
        template = None
        for t in self.templates:
            if t['id'] == template_id:
                template = t
                break
        if not template:
            return {'template_id': template_id, 'error': '模板不存在'}

        return self._execute_template(template, target_url)

    def run_all(self, target_url, severity_filter=None, tag_filter=None, progress_callback=None):
        """执行所有模板

        Args:
            target_url: 目标 URL
            severity_filter: 只执行指定严重程度的模板 (如 ['high', 'critical'])
            tag_filter: 只执行包含指定标签的模板
            progress_callback: 进度回调

        Returns:
            dict: {'target', 'total_templates', 'matched_count', 'results': [...]}
        """
        self._stop_flag = False
        matched_templates = self.templates

        if severity_filter:
            matched_templates = [t for t in matched_templates if t['info'].get('severity') in severity_filter]
        if tag_filter:
            matched_templates = [t for t in matched_templates
                                 if any(tag in t['info'].get('tags', []) for tag in tag_filter)]

        results = []
        total = len(matched_templates)
        matched_count = 0

        for i, template in enumerate(matched_templates):
            if self._stop_flag:
                break
            if progress_callback:
                pct = int(100 * (i + 1) / max(total, 1))
                progress_callback(f'执行模板 {i + 1}/{total}: {template["info"].get("name", template["id"])}', pct)

            result = self._execute_template(template, target_url)
            if result.get('matched'):
                matched_count += 1
            results.append(result)

        return {
            'target': target_url,
            'total_templates': total,
            'matched_count': matched_count,
            'results': results,
        }

    def add_template(self, template_dict):
        """添加自定义模板"""
        if isinstance(template_dict, dict) and 'id' in template_dict and 'requests' in template_dict:
            self.templates.append(template_dict)
            return True
        return False

    def _execute_template(self, template, target_url):
        """执行单个模板"""
        base = target_url.rstrip('/')
        reqs = template.get('requests', [])
        all_matches = []

        for req_def in reqs:
            if self._stop_flag:
                break

            method = req_def.get('method', 'GET').upper()
            paths = req_def.get('path', [])
            if isinstance(paths, str):
                paths = [paths]
            extra_headers = req_def.get('headers', {})
            body = req_def.get('body', '')
            matchers = req_def.get('matchers', [])
            condition = req_def.get('condition', 'or')

            for path in paths:
                try:
                    url = base + path
                    start_time = time.time()
                    headers = dict(extra_headers)

                    if method == 'POST':
                        resp = self.session.post(url, data=body, headers=headers,
                                                 timeout=self.timeout, allow_redirects=False)
                    elif method == 'HEAD':
                        resp = self.session.head(url, headers=headers,
                                                 timeout=self.timeout, allow_redirects=False)
                    else:
                        resp = self.session.get(url, headers=headers,
                                                timeout=self.timeout, allow_redirects=False)
                    elapsed = time.time() - start_time

                    match_result = self._evaluate_matchers(matchers, resp, elapsed, condition)
                    if match_result['matched']:
                        all_matches.append({
                            'url': url,
                            'method': method,
                            'status_code': resp.status_code,
                            'body_size': len(resp.content),
                            'match_details': match_result['details'],
                        })

                except Exception:
                    continue

        return {
            'template_id': template['id'],
            'name': template['info'].get('name', ''),
            'severity': template['info'].get('severity', 'info'),
            'matched': len(all_matches) > 0,
            'matches': all_matches,
        }

    def _evaluate_matchers(self, matchers, resp, elapsed, condition='or'):
        """评估匹配条件"""
        if not matchers:
            return {'matched': False, 'details': []}

        details = []
        results = []

        for matcher in matchers:
            mtype = matcher.get('type', '')
            matched = False

            if mtype == 'status':
                expected = matcher.get('value', [])
                matched = resp.status_code in expected
                details.append(f'status={resp.status_code} in {expected}: {matched}')

            elif mtype == 'word':
                words = matcher.get('words', [])
                part = matcher.get('part', 'body')
                mcond = matcher.get('condition', 'or')
                text = resp.text[:5000] if part == 'body' else str(resp.headers)

                if mcond == 'and':
                    matched = all(w.lower() in text.lower() for w in words)
                else:
                    matched = any(w.lower() in text.lower() for w in words)
                details.append(f'word[{mcond}] in {part}: {matched}')

            elif mtype == 'regex':
                patterns = matcher.get('regex', [])
                if isinstance(patterns, str):
                    patterns = [patterns]
                part = matcher.get('part', 'body')
                text = resp.text[:5000] if part == 'body' else str(resp.headers)
                for pattern in patterns:
                    if re.search(pattern, text, re.I):
                        matched = True
                        break
                details.append(f'regex in {part}: {matched}')

            elif mtype == 'time':
                operator = matcher.get('operator', 'gt')
                value = matcher.get('value', 0)
                if operator == 'gt':
                    matched = elapsed > value
                elif operator == 'lt':
                    matched = elapsed < value
                details.append(f'time {operator} {value}s (actual {elapsed:.2f}s): {matched}')

            results.append(matched)

        if condition == 'and':
            final = all(results)
        else:
            final = any(results)

        return {'matched': final, 'details': details}

    def _load_external_templates(self, template_dir):
        """从目录加载外部模板文件"""
        for fname in os.listdir(template_dir):
            if fname.endswith('.json'):
                try:
                    with open(os.path.join(template_dir, fname), 'r', encoding='utf-8') as f:
                        tpl = json.load(f)
                    if isinstance(tpl, dict) and 'id' in tpl:
                        self.templates.append(tpl)
                except Exception:
                    pass
