import json
import os
from urllib.parse import urlparse, parse_qs


class HARAnalyzer:
    """Analyze HAR files exported from browser dev tools"""

    STATIC_EXTENSIONS = (
        '.css', '.js', '.mjs', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.mp4', '.mp3',
        '.webp', '.webm', '.avi', '.mov', '.pdf', '.zip',
    )

    def analyze(self, har_path):
        results = {
            'file': os.path.basename(har_path) if har_path else '',
            'total_requests': 0,
            'endpoints': [],
            'domains': [],
            'methods': {},
            'content_types': {},
            'error_requests': 0,
        }

        if not har_path or not os.path.exists(har_path):
            results['error'] = '文件不存在'
            return results

        try:
            with open(har_path, 'r', encoding='utf-8') as f:
                har = json.load(f)
        except json.JSONDecodeError as e:
            results['error'] = f'HAR文件JSON格式错误: {str(e)}'
            return results
        except UnicodeDecodeError:
            try:
                with open(har_path, 'r', encoding='utf-8-sig') as f:
                    har = json.load(f)
            except Exception as e:
                results['error'] = f'文件编码错误: {str(e)}'
                return results
        except Exception as e:
            results['error'] = f'文件读取错误: {str(e)}'
            return results

        if not isinstance(har, dict):
            results['error'] = 'HAR文件结构无效'
            return results

        log = har.get('log', {})
        if not isinstance(log, dict):
            results['error'] = 'HAR文件缺少log字段'
            return results

        entries = log.get('entries', [])
        if not isinstance(entries, list):
            results['error'] = 'HAR文件缺少entries字段'
            return results

        results['total_requests'] = len(entries)
        seen = set()
        domains = set()

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            request = entry.get('request', {})
            response = entry.get('response', {})

            if not isinstance(request, dict):
                request = {}
            if not isinstance(response, dict):
                response = {}

            url = request.get('url', '')
            method = (request.get('method') or 'GET').upper()

            if not url or not isinstance(url, str):
                continue

            # Skip static resources
            if self._is_static(url):
                continue

            # Count methods
            results['methods'][method] = results['methods'].get(method, 0) + 1

            # Content types
            resp_content_type = ''
            resp_headers = response.get('headers', [])
            if isinstance(resp_headers, list):
                for header in resp_headers:
                    if isinstance(header, dict) and header.get('name', '').lower() == 'content-type':
                        resp_content_type = header.get('value', '')
                        break

            if resp_content_type:
                ct_base = resp_content_type.split(';')[0].strip()
                results['content_types'][ct_base] = results['content_types'].get(ct_base, 0) + 1

            # Count errors
            status = response.get('status', 0)
            if isinstance(status, (int, float)) and status >= 400:
                results['error_requests'] += 1

            # Deduplicate
            dedup_key = f'{method}:{url}'
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Extract request headers
            req_headers = {}
            for h in request.get('headers', []):
                if isinstance(h, dict) and h.get('name'):
                    req_headers[str(h['name'])] = str(h.get('value', ''))

            # Request body
            req_body = ''
            post_data = request.get('postData', {})
            if isinstance(post_data, dict):
                req_body = str(post_data.get('text', '') or '')[:3000]

            # Query params
            params = []
            for p in request.get('queryString', []):
                if isinstance(p, dict) and p.get('name'):
                    params.append({'name': str(p['name']), 'value': str(p.get('value', ''))})

            # Response body
            resp_content = response.get('content', {})
            resp_body = ''
            if isinstance(resp_content, dict):
                resp_body = str(resp_content.get('text', '') or '')[:3000]

            # Extract domain
            try:
                parsed = urlparse(url)
                if parsed and parsed.netloc:
                    domains.add(parsed.netloc)
            except Exception:
                pass

            endpoint = {
                'url': url,
                'method': method,
                'status_code': status if isinstance(status, (int, float)) else 0,
                'content_type': resp_content_type,
                'response_size': response.get('bodySize', 0) or 0,
                'parameters': params,
                'headers': req_headers,
                'request_body': req_body,
                'response_sample': resp_body,
                'source': 'har',
                'time_ms': entry.get('time', 0) or 0,
            }

            results['endpoints'].append(endpoint)

        results['domains'] = list(domains)
        results['api_count'] = len(results['endpoints'])
        return results

    def _is_static(self, url):
        if not url or not isinstance(url, str):
            return True
        try:
            url_lower = urlparse(url).path.lower().split('?')[0]
            return any(url_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS)
        except Exception:
            return True


class BurpXMLAnalyzer:
    """Analyze Burp Suite XML export files"""

    def analyze(self, xml_path):
        results = {
            'file': os.path.basename(xml_path) if xml_path else '',
            'endpoints': [],
            'domains': [],
        }

        if not xml_path or not os.path.exists(xml_path):
            results['error'] = '文件不存在'
            return results

        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()

            if root is None:
                results['error'] = 'XML文件为空'
                return results

            domains = set()

            items = root.findall('.//item')
            if not items:
                items = root.findall('.//request')
            if not items:
                # Try raw format
                items = [root]

            for item in items:
                if not isinstance(item, type(root)):
                    continue

                url = ''
                method = 'GET'
                status = '0'
                req_body = ''
                resp_body = ''

                # Try to extract fields
                url_elem = item.find('url')
                if url_elem is not None and url_elem.text:
                    url = url_elem.text.strip()

                method_elem = item.find('method')
                if method_elem is not None and method_elem.text:
                    method = method_elem.text.strip().upper()

                status_elem = item.find('status')
                if status_elem is not None and status_elem.text:
                    status = status_elem.text.strip()

                req_elem = item.find('request')
                if req_elem is not None and req_elem.text:
                    req_body = req_elem.text[:3000]

                resp_elem = item.find('response')
                if resp_elem is not None and resp_elem.text:
                    resp_body = resp_elem.text[:3000]

                if not url:
                    continue

                try:
                    parsed = urlparse(url)
                    if parsed and parsed.netloc:
                        domains.add(parsed.netloc)
                except Exception:
                    pass

                status_code = 0
                try:
                    status_code = int(status) if status.isdigit() else 0
                except (ValueError, TypeError):
                    pass

                results['endpoints'].append({
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'request_body': req_body,
                    'response_sample': resp_body,
                    'source': 'burp',
                })

            results['domains'] = list(domains)

        except ET.ParseError as e:
            results['error'] = f'XML解析错误: {str(e)}'
        except Exception as e:
            results['error'] = str(e)

        results['endpoint_count'] = len(results.get('endpoints', []))
        return results
