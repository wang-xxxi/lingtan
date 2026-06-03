"""Traffic Analyzer - extract sensitive info, API endpoints, tokens from captured traffic"""
import re
import json
from urllib.parse import urlparse, parse_qs


class TrafficAnalyzer:
    """Analyze captured HTTP traffic for security insights"""

    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        'phone_cn': r'\b1[3-9]\d{9}\b',
        'idcard_cn': r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
        'credit_card': r'\b(?:4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5})\b',
        'ip_private': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        'aws_key': r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
        'jwt_token': r'\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b',
        'api_key_generic': r'(?:api[_-]?key|apikey|api[_-]?secret|token|access[_-]?token|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        'bearer_token': r'[Bb]earer\s+([a-zA-Z0-9_\-\.]{20,})',
        'password_param': r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?([^\s"\',}{\]]{4,})["\']?',
    }

    # Auth-related header patterns
    AUTH_HEADERS = {
        'Authorization': r'.*',
        'X-Api-Key': r'.*',
        'X-Auth-Token': r'.*',
        'Cookie': r'.*',
        'Set-Cookie': r'.*',
    }

    def __init__(self):
        pass

    def analyze_traffic(self, traffic_list):
        """Analyze a list of traffic records"""
        results = {
            'total_requests': len(traffic_list),
            'endpoints_found': [],
            'sensitive_data': [],
            'auth_tokens': [],
            'api_parameters': {},
            'hosts': {},
            'methods': {},
            'status_codes': {},
            'content_types': {},
            'findings': [],
        }

        seen_endpoints = set()

        for record in (traffic_list or []):
            if not isinstance(record, dict):
                continue

            url = record.get('url', '') or ''
            method = record.get('method', 'GET') or 'GET'
            host = record.get('host', '') or ''
            path = record.get('path', '') or ''
            status = record.get('status_code', 0) or 0
            ct = record.get('content_type', '') or ''
            req_headers = record.get('request_headers', {}) or {}
            resp_headers = record.get('response_headers', {}) or {}
            req_body = record.get('request_body', '') or ''
            resp_body = record.get('response_body', '') or ''

            # Count stats
            if host:
                results['hosts'][host] = results['hosts'].get(host, 0) + 1
            results['methods'][method] = results['methods'].get(method, 0) + 1
            status_group = f'{status // 100}xx'
            results['status_codes'][status_group] = results['status_codes'].get(status_group, 0) + 1
            if ct:
                base_ct = ct.split(';')[0].strip()
                results['content_types'][base_ct] = results['content_types'].get(base_ct, 0) + 1

            # Extract API endpoints
            endpoint_key = f'{method}:{host}{path}'
            if endpoint_key not in seen_endpoints and path and not self._is_static(path):
                seen_endpoints.add(endpoint_key)
                params = parse_qs(urlparse(url).query) if url else {}
                results['endpoints_found'].append({
                    'url': url,
                    'method': method,
                    'host': host,
                    'path': path,
                    'status_code': status,
                    'content_type': ct,
                    'param_count': len(params),
                    'params': list(params.keys())[:10],
                })

            # Extract auth tokens from request headers
            self._extract_auth_tokens(req_headers, results['auth_tokens'], 'request')

            # Extract auth tokens from response headers (Set-Cookie)
            self._extract_auth_tokens(resp_headers, results['auth_tokens'], 'response')

            # Scan for sensitive data in bodies
            for body, label in [(req_body, 'request'), (resp_body, 'response')]:
                if body and len(body) < 100000:
                    findings = self._scan_sensitive_data(body, label, url)
                    results['sensitive_data'].extend(findings)

            # Scan headers for sensitive data
            for header_name, header_val in {**req_headers, **resp_headers}.items():
                if isinstance(header_val, str):
                    findings = self._scan_sensitive_data(header_val, 'header', f'{header_name}')
                    results['sensitive_data'].extend(finding for finding in findings if finding['type'] != 'email')

            # Extract API parameters from request body
            if req_body and method in ('POST', 'PUT', 'PATCH'):
                params = self._extract_params_from_body(req_body)
                if params:
                    key = f'{method}:{path}'
                    if key not in results['api_parameters']:
                        results['api_parameters'][key] = set()
                    results['api_parameters'][key].update(params)

        # Deduplicate sensitive data
        seen_sensitive = set()
        unique_sensitive = []
        for item in results['sensitive_data']:
            key = f'{item["type"]}:{item["value"][:30]}'
            if key not in seen_sensitive:
                seen_sensitive.add(key)
                unique_sensitive.append(item)
        results['sensitive_data'] = unique_sensitive

        # Convert sets to lists for JSON
        for key in results['api_parameters']:
            results['api_parameters'][key] = sorted(results['api_parameters'][key])

        # Generate summary findings
        results['findings'] = self._generate_findings(results)
        results['summary'] = {
            'total_hosts': len(results['hosts']),
            'total_endpoints': len(results['endpoints_found']),
            'total_auth_tokens': len(results['auth_tokens']),
            'total_sensitive': len(results['sensitive_data']),
            'total_findings': len(results['findings']),
        }

        return results

    def analyze_single(self, record):
        """Analyze a single traffic record"""
        return self.analyze_traffic([record] if record else [])

    def _is_static(self, path):
        """Check if path is a static resource"""
        static_ext = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                      '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webp')
        path_lower = path.lower().split('?')[0]
        return any(path_lower.endswith(ext) for ext in static_ext)

    def _extract_auth_tokens(self, headers, tokens_list, source):
        """Extract authentication tokens from headers"""
        if not isinstance(headers, dict):
            return
        for name, value in headers.items():
            if not isinstance(value, str):
                continue
            name_lower = name.lower()

            # Authorization header
            if name_lower == 'authorization':
                if value.startswith('Bearer '):
                    token = value[7:]
                    tokens_list.append({
                        'type': 'Bearer Token',
                        'source': source,
                        'header': name,
                        'value': token[:20] + '...' if len(token) > 20 else token,
                        'full_length': len(token),
                    })
                elif value.startswith('Basic '):
                    tokens_list.append({
                        'type': 'Basic Auth',
                        'source': source,
                        'header': name,
                        'value': 'Basic ***',
                    })
                else:
                    tokens_list.append({
                        'type': 'Authorization',
                        'source': source,
                        'header': name,
                        'value': value[:30] + '...' if len(value) > 30 else value,
                    })

            # API key headers
            elif name_lower in ('x-api-key', 'x-auth-token', 'x-access-token', 'token'):
                tokens_list.append({
                    'type': 'API Key',
                    'source': source,
                    'header': name,
                    'value': value[:20] + '...' if len(value) > 20 else value,
                })

            # Cookie
            elif name_lower in ('cookie', 'set-cookie'):
                # Check for session tokens in cookies
                session_matches = re.findall(r'(?:session[_-]?id|sid|token|auth|jwt)=([^;\s]+)', value, re.I)
                for match in session_matches:
                    tokens_list.append({
                        'type': 'Session Cookie',
                        'source': source,
                        'header': name,
                        'value': match[:20] + '...' if len(match) > 20 else match,
                    })

    def _scan_sensitive_data(self, text, context, location):
        """Scan text for sensitive data patterns"""
        findings = []
        if not text or not isinstance(text, str):
            return findings

        for dtype, pattern in self.SENSITIVE_PATTERNS.items():
            try:
                matches = re.findall(pattern, text)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else (match[1] if len(match) > 1 else '')
                    if not match or len(match) < 4:
                        continue

                    # Mask the value for display
                    masked = self._mask_value(match, dtype)
                    if masked:
                        findings.append({
                            'type': dtype,
                            'value': masked,
                            'context': context,
                            'location': location,
                        })
            except Exception:
                pass

        return findings

    def _mask_value(self, value, dtype):
        """Mask a sensitive value for safe display"""
        if not value:
            return ''
        if dtype == 'email':
            parts = value.split('@')
            if len(parts) == 2:
                name = parts[0]
                masked_name = name[0] + '***' + (name[-1] if len(name) > 1 else '')
                return f'{masked_name}@{parts[1]}'
        elif dtype == 'phone_cn':
            return value[:3] + '****' + value[-4:]
        elif dtype == 'idcard_cn':
            return value[:3] + '***********' + value[-4:]
        elif dtype == 'credit_card':
            return value[:4] + ' **** **** ' + value[-4:]
        elif dtype in ('aws_key', 'api_key_generic', 'bearer_token', 'jwt_token'):
            return value[:6] + '...' + value[-4:] if len(value) > 10 else value[:4] + '***'
        elif dtype == 'password_param':
            return '***'
        elif dtype == 'ip_private':
            return value
        return value[:4] + '***' if len(value) > 4 else '***'

    def _extract_params_from_body(self, body):
        """Extract parameter names from request body"""
        params = set()
        if not body:
            return params

        body = body.strip()

        # Try JSON
        if body.startswith('{') or body.startswith('['):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    params.update(data.keys())
                elif isinstance(data, list) and data and isinstance(data[0], dict):
                    params.update(data[0].keys())
            except (json.JSONDecodeError, ValueError):
                pass

        # Try form data
        if '=' in body and '&' in body:
            for pair in body.split('&'):
                if '=' in pair:
                    key = pair.split('=')[0].strip()
                    if key:
                        params.add(key)

        # Try JSON-like key extraction
        json_keys = re.findall(r'"([a-zA-Z_]\w{1,50})"\s*:', body)
        params.update(json_keys)

        return params

    def _generate_findings(self, results):
        """Generate security findings from analysis"""
        findings = []

        # Check for sensitive data exposure
        if results['sensitive_data']:
            by_type = {}
            for item in results['sensitive_data']:
                by_type[item['type']] = by_type.get(item['type'], 0) + 1
            for dtype, count in by_type.items():
                severity = 'high' if dtype in ('credit_card', 'idcard_cn', 'aws_key', 'password_param') else 'medium'
                findings.append({
                    'type': 'sensitive_data_exposure',
                    'severity': severity,
                    'description': f'检测到 {count} 处 {dtype} 类型敏感数据',
                    'count': count,
                })

        # Check for unencrypted auth tokens
        http_auth = [t for t in results['auth_tokens'] if t.get('source') == 'request']
        if http_auth:
            findings.append({
                'type': 'auth_tokens_in_traffic',
                'severity': 'info',
                'description': f'流量中包含 {len(http_auth)} 个认证令牌',
                'count': len(http_auth),
            })

        # Check for internal IPs
        internal_ips = [s for s in results['sensitive_data'] if s['type'] == 'ip_private']
        if internal_ips:
            findings.append({
                'type': 'internal_ip_exposure',
                'severity': 'low',
                'description': f'检测到 {len(internal_ips)} 个内网IP地址泄露',
                'count': len(internal_ips),
            })

        return findings
