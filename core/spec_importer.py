"""OpenAPI/Swagger Spec Importer - import .json/.yaml specs and generate test cases"""
import re
import json
import os
from urllib.parse import urljoin


class SpecImporter:
    """Import and parse OpenAPI/Swagger specifications"""

    SUPPORTED_VERSIONS = ['2.0', '3.0', '3.1']

    def __init__(self):
        self._spec_cache = None

    def import_from_text(self, text, filename=''):
        """Import spec from raw text (JSON or YAML)"""
        if not text or not text.strip():
            return {'error': '文件内容为空'}

        # Try JSON first
        try:
            spec = json.loads(text)
            return self._parse_spec(spec, filename or 'inline')
        except (json.JSONDecodeError, ValueError):
            pass

        # Try YAML
        spec = self._parse_yaml(text)
        if spec:
            return self._parse_spec(spec, filename or 'inline')

        return {'error': '无法解析文件，不是有效的JSON或YAML格式'}

    def import_from_url(self, url):
        """Import spec from a URL"""
        try:
            import requests
            resp = requests.get(url, timeout=15, verify=False,
                              headers={'User-Agent': '灵探/1.0', 'Accept': 'application/json, text/plain, */*'})
            if resp.status_code != 200:
                return {'error': f'HTTP {resp.status_code}'}
            return self.import_from_text(resp.text, url)
        except Exception as e:
            return {'error': f'获取失败: {str(e)}'}

    def import_from_file(self, filepath):
        """Import spec from a local file"""
        if not os.path.exists(filepath):
            return {'error': '文件不存在'}
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
            return self.import_from_text(text, os.path.basename(filepath))
        except Exception as e:
            return {'error': f'读取失败: {str(e)}'}

    def _parse_spec(self, spec, source=''):
        """Parse an OpenAPI/Swagger spec dict"""
        if not isinstance(spec, dict):
            return {'error': '无效的规范格式'}

        # Detect version
        version = self._detect_version(spec)
        if not version:
            return {'error': '未识别的API规范版本'}

        info = spec.get('info', {}) or {}
        title = info.get('title', 'Untitled API')
        description = info.get('description', '')

        # Extract base URL
        base_url = self._extract_base_url(spec, version)

        # Extract endpoints
        endpoints = self._extract_endpoints(spec, version, base_url)

        # Extract schemas/models
        schemas = self._extract_schemas(spec, version)

        # Generate test cases
        test_cases = self._generate_test_cases(endpoints, base_url)

        return {
            'source': source,
            'version': version,
            'title': title,
            'description': description[:500] if description else '',
            'base_url': base_url,
            'endpoints': endpoints,
            'schemas': schemas,
            'test_cases': test_cases,
            'summary': {
                'total_endpoints': len(endpoints),
                'total_schemas': len(schemas),
                'total_test_cases': len(test_cases),
                'by_method': self._count_by_method(endpoints),
                'by_tag': self._count_by_tag(endpoints),
            },
        }

    def _detect_version(self, spec):
        """Detect OpenAPI/Swagger version"""
        # OpenAPI 3.x
        oa = spec.get('openapi', '')
        if oa and str(oa).startswith('3'):
            return str(oa)
        # Swagger 2.x
        sw = spec.get('swagger', '')
        if sw and str(sw).startswith('2'):
            return str(sw)
        # Infer from structure
        if 'paths' in spec:
            if 'components' in spec:
                return '3.0'
            if 'definitions' in spec:
                return '2.0'
        return None

    def _extract_base_url(self, spec, version):
        """Extract the base URL from spec"""
        if version.startswith('2'):
            # Swagger 2.0: host + basePath + schemes
            host = spec.get('host', 'localhost')
            base_path = spec.get('basePath', '/')
            schemes = spec.get('schemes', ['https'])
            scheme = schemes[0] if schemes else 'https'
            return f'{scheme}://{host}{base_path}'.rstrip('/')
        else:
            # OpenAPI 3.x: servers
            servers = spec.get('servers', [])
            if servers:
                return servers[0].get('url', '').rstrip('/')
        return ''

    def _extract_endpoints(self, spec, version, base_url):
        """Extract all endpoints from spec"""
        endpoints = []
        paths = spec.get('paths', {}) or {}

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters
            path_params = path_item.get('parameters', []) or []

            for method in ('get', 'post', 'put', 'delete', 'patch', 'head', 'options'):
                operation = path_item.get(method)
                if not operation or not isinstance(operation, dict):
                    continue

                # Merge path-level params with operation-level params
                op_params = operation.get('parameters', []) or []
                all_params = path_params + op_params

                # Extract parameter info
                parameters = []
                for param in all_params:
                    if not isinstance(param, dict):
                        continue
                    parameters.append({
                        'name': param.get('name', ''),
                        'in': param.get('in', 'query'),
                        'required': param.get('required', False),
                        'type': self._get_param_type(param, version),
                        'description': param.get('description', ''),
                        'example': param.get('example') or param.get('default'),
                    })

                # Request body (OpenAPI 3.x)
                request_body = None
                rb = operation.get('requestBody')
                if rb and isinstance(rb, dict):
                    content = rb.get('content', {}) or {}
                    for ct, ct_obj in content.items():
                        if 'json' in ct or 'form' in ct:
                            schema = ct_obj.get('schema', {}) or {}
                            request_body = {
                                'content_type': ct,
                                'schema': self._resolve_schema_ref(spec, schema),
                                'required': rb.get('required', False),
                            }
                            break

                # Response info
                responses = {}
                for code, resp_obj in (operation.get('responses', {}) or {}).items():
                    if not isinstance(resp_obj, dict):
                        continue
                    responses[str(code)] = {
                        'description': resp_obj.get('description', ''),
                    }

                tags = operation.get('tags', []) or []
                summary = operation.get('summary', '') or operation.get('operationId', '')

                url = base_url + path if base_url else path

                endpoints.append({
                    'url': url,
                    'path': path,
                    'method': method.upper(),
                    'summary': summary,
                    'tags': tags,
                    'parameters': parameters,
                    'request_body': request_body,
                    'responses': responses,
                    'deprecated': operation.get('deprecated', False),
                    'security': operation.get('security'),
                    'source': 'spec-import',
                })

        return endpoints

    def _get_param_type(self, param, version):
        """Get parameter type across spec versions"""
        if version.startswith('2'):
            return param.get('type', 'string')
        else:
            schema = param.get('schema', {}) or {}
            return schema.get('type', 'string')

    def _resolve_schema_ref(self, spec, schema):
        """Resolve $ref references in schema"""
        if not isinstance(schema, dict):
            return schema
        if '$ref' in schema:
            ref = schema['$ref']
            # #/definitions/User or #/components/schemas/User
            parts = ref.lstrip('#/').split('/')
            node = spec
            for p in parts:
                node = node.get(p, {}) if isinstance(node, dict) else {}
            return node
        return schema

    def _extract_schemas(self, spec, version):
        """Extract schema/model definitions"""
        schemas = {}
        if version.startswith('2'):
            defs = spec.get('definitions', {}) or {}
            for name, schema in defs.items():
                schemas[name] = self._summarize_schema(schema)
        else:
            comps = spec.get('components', {}) or {}
            comp_schemas = comps.get('schemas', {}) or {}
            for name, schema in comp_schemas.items():
                schemas[name] = self._summarize_schema(schema)
        return schemas

    def _summarize_schema(self, schema):
        """Summarize a schema definition"""
        if not isinstance(schema, dict):
            return {'type': str(type(schema).__name__)}
        props = schema.get('properties', {}) or {}
        fields = []
        for name, prop in props.items():
            fields.append({
                'name': name,
                'type': prop.get('type', 'object') if isinstance(prop, dict) else 'object',
                'required': name in (schema.get('required', []) or []),
            })
        return {
            'type': schema.get('type', 'object'),
            'fields': fields,
            'field_count': len(fields),
        }

    def _generate_test_cases(self, endpoints, base_url):
        """Auto-generate test cases from endpoints"""
        test_cases = []
        for ep in endpoints:
            url = ep.get('url', '')
            method = ep.get('method', 'GET')

            # Basic request test
            test_cases.append({
                'name': f'{method} {ep.get("path", url)}',
                'method': method,
                'url': url,
                'description': ep.get('summary', ''),
                'expected_status': 200,
            })

            # Auth bypass test for secured endpoints
            if ep.get('security'):
                test_cases.append({
                    'name': f'{method} {ep.get("path")} (无认证)',
                    'method': method,
                    'url': url,
                    'description': '测试无认证头访问',
                    'headers': {'Authorization': ''},
                    'expected_status': [401, 403],
                })

            # Required param missing test
            for param in ep.get('parameters', []):
                if param.get('required'):
                    test_cases.append({
                        'name': f'{method} {ep.get("path")} (缺少{param["name"]})',
                        'method': method,
                        'url': url,
                        'description': f'测试缺少必需参数 {param["name"]}',
                        'remove_param': param['name'],
                        'expected_status': [400, 422],
                    })

            # For POST/PUT/PATCH, test empty body
            if method in ('POST', 'PUT', 'PATCH') and ep.get('request_body'):
                test_cases.append({
                    'name': f'{method} {ep.get("path")} (空body)',
                    'method': method,
                    'url': url,
                    'body': '{}',
                    'headers': {'Content-Type': 'application/json'},
                    'description': '测试空请求体',
                    'expected_status': [400, 422],
                })

        return test_cases

    def _count_by_method(self, endpoints):
        counts = {}
        for ep in endpoints:
            m = ep.get('method', 'GET')
            counts[m] = counts.get(m, 0) + 1
        return counts

    def _count_by_tag(self, endpoints):
        counts = {}
        for ep in endpoints:
            for tag in ep.get('tags', []):
                counts[tag] = counts.get(tag, 0) + 1
        return counts

    def _parse_yaml(self, text):
        """Minimal YAML parser for OpenAPI specs (handles common cases without PyYAML)"""
        try:
            # For simple YAML structures, try to parse key-value pairs
            # and then convert nested structures
            result = {}
            lines = text.split('\n')
            current_key = None
            in_json_block = False
            json_buffer = []

            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue

                # Detect inline JSON
                if stripped.startswith('{') or stripped.startswith('['):
                    in_json_block = True
                    json_buffer = [stripped]
                    continue
                if in_json_block:
                    json_buffer.append(stripped)
                    if stripped.endswith('}') or stripped.endswith(']'):
                        in_json_block = False
                        json_str = ' '.join(json_buffer)
                        try:
                            result[current_key] = json.loads(json_str)
                        except Exception:
                            result[current_key] = json_str
                    continue

            return result if result else None
        except Exception:
            return None
