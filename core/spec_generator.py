import json
import re
import time
from urllib.parse import urlparse, parse_qs


class OpenAPIGenerator:
    """Generate OpenAPI 3.0 specification from discovered endpoints"""

    def generate(self, endpoints, title='灵探 Auto-Generated Spec',
                 version='1.0.0', description=None, base_url=None):
        """Generate OpenAPI 3.0 spec from endpoint list"""
        if not endpoints:
            return None

        # Determine base URL
        if not base_url:
            base_url = self._infer_base_url(endpoints)

        # Group endpoints by path pattern
        paths = self._group_endpoints(endpoints)

        spec = {
            'openapi': '3.0.3',
            'info': {
                'title': title,
                'version': version,
                'description': description or f'自动生成的API文档 - 共{len(endpoints)}个接口',
                'contact': {'name': '灵探'},
            },
            'servers': [{'url': base_url}] if base_url else [],
            'paths': {},
            'tags': [],
        }

        # Collect tags
        categories = set()
        for ep in endpoints:
            cat = ep.get('category', 'default')
            if cat and cat != 'other':
                categories.add(cat)

        tag_descriptions = {
            'authentication': '身份认证', 'user': '用户管理', 'payment': '支付交易',
            'data_query': '数据查询', 'data_modify': '数据修改', 'file': '文件管理',
            'admin': '管理后台', 'notification': '消息通知', 'third_party': '第三方服务',
            'statistics': '数据统计', 'config': '配置管理', 'websocket': '实时通信',
            'graphql': 'GraphQL', 'search': '搜索', 'content': '内容管理',
        }
        spec['tags'] = [
            {'name': cat, 'description': tag_descriptions.get(cat, cat)}
            for cat in sorted(categories)
        ]

        # Generate path items
        for path_pattern, path_eps in paths.items():
            path_item = {}
            for ep in path_eps:
                method = (ep.get('method') or 'GET').lower()
                if method not in ('get', 'post', 'put', 'delete', 'patch', 'head', 'options'):
                    continue

                operation = self._build_operation(ep, path_pattern)
                path_item[method] = operation

            if path_item:
                spec['paths'][path_pattern] = path_item

        return spec

    def _infer_base_url(self, endpoints):
        """Infer base URL from endpoints"""
        urls = [ep.get('url', '') for ep in endpoints if ep.get('url')]
        if not urls:
            return ''

        # Count domains
        domains = {}
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    key = f'{parsed.scheme}://{parsed.netloc}'
                    domains[key] = domains.get(key, 0) + 1
            except Exception:
                pass

        if domains:
            return max(domains, key=domains.get)
        return ''

    def _group_endpoints(self, endpoints):
        """Group endpoints by path pattern (replace IDs with {id})"""
        groups = {}
        for ep in endpoints:
            url = ep.get('url', '')
            if not url:
                continue
            try:
                parsed = urlparse(url)
                path = parsed.path or '/'
            except Exception:
                continue

            # Replace numeric segments with {id}
            pattern = re.sub(r'/\d{1,10}', '/{id}', path)

            if pattern not in groups:
                groups[pattern] = []
            groups[pattern].append(ep)

        return groups

    def _build_operation(self, ep, path_pattern):
        """Build an OpenAPI operation object"""
        operation = {
            'summary': ep.get('description') or f'{ep.get("method", "GET")} {path_pattern}',
            'responses': {},
            'tags': [],
        }

        # Add tag from category
        cat = ep.get('category')
        if cat and cat != 'other':
            operation['tags'].append(cat)

        # Add description
        desc = ep.get('description', '')
        if desc:
            operation['description'] = desc

        # Add parameters
        params = ep.get('parameters')
        if params:
            try:
                if isinstance(params, str):
                    params = json.loads(params)
                if isinstance(params, list):
                    operation['parameters'] = []
                    for p in params:
                        if isinstance(p, dict):
                            operation['parameters'].append({
                                'name': p.get('name', 'param'),
                                'in': p.get('in', 'query'),
                                'required': p.get('required', False),
                                'schema': {'type': self._infer_type(p.get('value', ''))},
                            })
            except Exception:
                pass

        # Path parameters
        path_params = re.findall(r'\{(\w+)\}', path_pattern)
        if path_params:
            if 'parameters' not in operation:
                operation['parameters'] = []
            for pp in path_params:
                if not any(p.get('name') == pp for p in operation['parameters']):
                    operation['parameters'].append({
                        'name': pp,
                        'in': 'path',
                        'required': True,
                        'schema': {'type': 'integer' if pp == 'id' else 'string'},
                    })

        # Add request body for POST/PUT/PATCH
        method = (ep.get('method') or 'GET').upper()
        if method in ('POST', 'PUT', 'PATCH'):
            req_body = ep.get('request_body')
            if req_body:
                try:
                    json_data = json.loads(req_body)
                    if isinstance(json_data, dict):
                        operation['requestBody'] = {
                            'required': True,
                            'content': {
                                'application/json': {
                                    'schema': self._json_to_schema(json_data),
                                }
                            }
                        }
                except Exception:
                    operation['requestBody'] = {
                        'content': {
                            'application/json': {
                                'schema': {'type': 'object'}
                            }
                        }
                    }
            else:
                operation['requestBody'] = {
                    'content': {
                        'application/json': {
                            'schema': {'type': 'object'}
                        }
                    }
                }

        # Response
        status = ep.get('status_code', 200) or 200
        resp_sample = ep.get('response_sample')
        resp_obj = {'description': '成功'}

        if resp_sample:
            try:
                json_data = json.loads(resp_sample)
                resp_obj['content'] = {
                    'application/json': {
                        'schema': self._json_to_schema(json_data),
                    }
                }
            except Exception:
                pass

        operation['responses'][str(status)] = resp_obj
        if status != 200:
            operation['responses']['200'] = {'description': '成功'}

        # Security hint
        risk = ep.get('risk_level', 'info')
        if risk in ('high', 'critical'):
            operation['security'] = [{'bearerAuth': []}]

        return operation

    def _json_to_schema(self, data):
        """Convert JSON data to OpenAPI schema"""
        if isinstance(data, dict):
            properties = {}
            for key, value in data.items():
                properties[str(key)] = self._json_to_schema(value)
            return {'type': 'object', 'properties': properties}
        elif isinstance(data, list):
            if data:
                return {'type': 'array', 'items': self._json_to_schema(data[0])}
            return {'type': 'array', 'items': {}}
        elif isinstance(data, bool):
            return {'type': 'boolean'}
        elif isinstance(data, int):
            return {'type': 'integer'}
        elif isinstance(data, float):
            return {'type': 'number'}
        elif isinstance(data, str):
            return {'type': 'string'}
        return {'type': 'string'}

    def _infer_type(self, value):
        """Infer JSON schema type from value"""
        if isinstance(value, bool):
            return 'boolean'
        if isinstance(value, int):
            return 'integer'
        if isinstance(value, float):
            return 'number'
        if isinstance(value, list):
            return 'array'
        if isinstance(value, dict):
            return 'object'
        return 'string'

    def to_json(self, spec, pretty=True):
        """Export spec as JSON string"""
        return json.dumps(spec, ensure_ascii=False, indent=2 if pretty else None)

    def save_to_file(self, spec, filepath):
        """Save spec to file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(spec, f, ensure_ascii=False, indent=2)
        return filepath


class CurlGenerator:
    """Generate cURL commands from endpoint data"""

    def generate(self, url, method='GET', headers=None, body=None, cookies=None):
        """Generate a cURL command string"""
        parts = ['curl']

        # Method
        if method and method.upper() != 'GET':
            parts.append(f'-X {method.upper()}')

        # Headers
        if headers and isinstance(headers, dict):
            for key, value in headers.items():
                safe_key = str(key).replace("'", "'\\''")
                safe_val = str(value).replace("'", "'\\''")
                parts.append(f"-H '{safe_key}: {safe_val}'")

        # Body
        if body:
            safe_body = str(body).replace("'", "'\\''")
            parts.append(f"-d '{safe_body}'")

        # URL (always last)
        safe_url = str(url).replace("'", "'\\''")
        parts.append(f"'{safe_url}'")

        return ' \\\n  '.join(parts)

    def generate_from_endpoint(self, endpoint):
        """Generate cURL from an endpoint dict"""
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        headers = {}
        body = endpoint.get('request_body', '')

        # Parse headers
        ep_headers = endpoint.get('headers')
        if ep_headers:
            try:
                headers = ep_headers if isinstance(ep_headers, dict) else json.loads(ep_headers)
            except Exception:
                pass

        # Add Content-Type for body requests
        if body and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        return self.generate(url, method, headers, body or None)
