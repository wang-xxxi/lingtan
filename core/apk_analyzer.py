import re
import json
import zipfile
import os
from urllib.parse import urlparse


class APKAnalyzer:
    """Analyze Android APK files to extract API endpoints"""

    API_PATTERNS = [
        r'https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})(?::\d{1,5})?/[a-zA-Z0-9/._?&=%@#-]+',
        r'https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})(?::\d{1,5})?(?:/[a-zA-Z0-9._-]*)?',
        r'/api/[a-zA-Z0-9/._-]+',
        r'/v\d+/[a-zA-Z0-9/._-]+',
        r'/rest/[a-zA-Z0-9/._-]+',
        r'/service/[a-zA-Z0-9/._-]+',
        r'/gateway/[a-zA-Z0-9/._-]+',
        r'/auth/[a-zA-Z0-9/._-]+',
        r'/oauth/[a-zA-Z0-9/._-]+',
    ]

    API_KEYWORDS = [
        'api', 'rest', 'graphql', 'endpoint', 'baseurl', 'apiurl',
        'server', 'host', 'domain', 'service', 'gateway',
        'token', 'authorization', 'bearer', 'oauth',
        'json', 'xml', 'protobuf', 'grpc',
    ]

    def analyze(self, apk_path):
        results = {
            'file': os.path.basename(apk_path) if apk_path else '',
            'file_size': 0,
            'app_info': {},
            'endpoints': [],
            'network_config': [],
            'domains': [],
            'permissions': [],
            'security_notes': [],
        }

        if not apk_path or not os.path.exists(apk_path):
            results['error'] = '文件不存在'
            return results

        try:
            results['file_size'] = os.path.getsize(apk_path)
        except Exception:
            pass

        try:
            if not zipfile.is_zipfile(apk_path):
                results['error'] = '文件不是有效的ZIP/APK格式'
                return results

            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist() if zf else []

                results['app_info'] = self._extract_manifest_info(zf)
                results['network_config'] = self._extract_network_config(zf, file_list)
                results['endpoints'] = self._scan_for_endpoints(zf, file_list)
                smali_endpoints = self._scan_smali_strings(zf, file_list)
                if smali_endpoints:
                    results['endpoints'].extend(smali_endpoints)

                all_urls = [ep.get('url', '') for ep in results['endpoints'] if isinstance(ep, dict)]
                results['domains'] = list(self._extract_domains(all_urls))
                results['security_notes'] = self._check_security(zf, file_list, results['endpoints'])
                results['permissions'] = results.get('app_info', {}).get('permissions', [])

        except Exception as e:
            results['error'] = str(e)

        results['endpoint_count'] = len(results.get('endpoints', []))
        results['domain_count'] = len(results.get('domains', []))
        return results

    def _extract_manifest_info(self, zf):
        info = {'permissions': []}
        if not zf:
            return info
        try:
            if 'AndroidManifest.xml' in zf.namelist():
                manifest_data = zf.read('AndroidManifest.xml')
                text = manifest_data.decode('utf-8', errors='ignore')
                pkg_match = re.search(r'package="([^"]+)"', text)
                if pkg_match:
                    info['package'] = pkg_match.group(1)
                perms = re.findall(r'uses-permission[^>]*name="([^"]+)"', text)
                info['permissions'] = perms or []
        except Exception:
            pass
        return info

    def _extract_network_config(self, zf, file_list):
        configs = []
        if not zf or not file_list:
            return configs
        for cf in file_list:
            if 'network_security_config' in cf or 'network_config' in cf:
                try:
                    data = zf.read(cf).decode('utf-8', errors='ignore')
                    configs.append({'file': cf, 'content': (data or '')[:2000]})
                except Exception:
                    pass
        return configs

    def _scan_for_endpoints(self, zf, file_list):
        endpoints = []
        seen = set()
        if not zf or not file_list:
            return endpoints
        scan_exts = ('.xml', '.json', '.properties', '.txt', '.cfg', '.conf', '.ini', '.yaml', '.yml')
        for filename in file_list:
            if not filename:
                continue
            if any(filename.lower().endswith(ext) for ext in scan_exts):
                try:
                    data = zf.read(filename).decode('utf-8', errors='ignore')
                    if not data:
                        continue
                    found = self._extract_urls_from_text(data, filename)
                    for ep in found:
                        if isinstance(ep, dict) and ep.get('url') and ep['url'] not in seen:
                            seen.add(ep['url'])
                            endpoints.append(ep)
                except Exception:
                    pass
        return endpoints

    def _scan_smali_strings(self, zf, file_list):
        endpoints = []
        seen = set()
        if not zf or not file_list:
            return endpoints
        resource_files = [f for f in file_list if isinstance(f, str) and f.startswith('res/') and f.endswith('.xml')]
        for rf in resource_files:
            try:
                data = zf.read(rf).decode('utf-8', errors='ignore')
                if not data:
                    continue
                found = self._extract_urls_from_text(data, rf)
                for ep in found:
                    if isinstance(ep, dict) and ep.get('url') and ep['url'] not in seen:
                        seen.add(ep['url'])
                        endpoints.append(ep)
            except Exception:
                pass
        return endpoints

    def _extract_urls_from_text(self, text, source):
        endpoints = []
        if not text or not isinstance(text, str):
            return endpoints
        for pattern in self.API_PATTERNS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
            except Exception:
                continue
            for url in matches:
                if not url or not isinstance(url, str):
                    continue
                url = url.strip().rstrip('.,;:')
                if self._is_api_url(url):
                    endpoints.append({
                        'url': url,
                        'method': 'UNKNOWN',
                        'source': f'apk:{source}',
                        'confidence': self._calculate_confidence(url),
                    })
        return endpoints

    def _is_api_url(self, url):
        if not url or not isinstance(url, str) or len(url) < 8:
            return False
        static_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.woff', '.ttf', '.ico', '.webp')
        if any(url.lower().endswith(ext) for ext in static_ext):
            return False
        api_indicators = self.API_KEYWORDS + ['login', 'user', 'account', 'token', 'upload', 'download', 'wp-json']
        url_lower = url.lower()
        return any(ind in url_lower for ind in api_indicators) or '/api/' in url or bool(re.search(r'/v\d+/', url))

    def _calculate_confidence(self, url):
        score = 0.5
        if '/api/' in str(url):
            score += 0.2
        if re.search(r'/v\d+/', str(url)):
            score += 0.15
        if str(url).startswith('https://'):
            score += 0.05
        if any(kw in str(url).lower() for kw in self.API_KEYWORDS):
            score += 0.1
        return min(score, 1.0)

    def _extract_domains(self, urls):
        domains = set()
        for url in urls:
            if not url or not isinstance(url, str):
                continue
            try:
                parsed = urlparse(url)
                if parsed and parsed.netloc:
                    domains.add(parsed.netloc)
            except Exception:
                pass
        return domains

    def _check_security(self, zf, file_list, endpoints):
        notes = []
        if not endpoints:
            return notes
        http_eps = [ep for ep in endpoints if isinstance(ep, dict) and ep.get('url', '').startswith('http://')]
        if http_eps:
            notes.append(f'发现 {len(http_eps)} 个使用HTTP(非加密)的接口')
        if file_list:
            for f in file_list:
                if isinstance(f, str) and 'AndroidManifest.xml' in f:
                    try:
                        data = zf.read(f).decode('utf-8', errors='ignore') if zf else ''
                        if data and 'debuggable="true"' in data:
                            notes.append('应用开启了调试模式(debuggable=true)')
                    except Exception:
                        pass
        return notes


class IPAAnalyzer:
    """Analyze iOS IPA files to extract API endpoints"""

    API_PATTERNS = [
        r'https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})(?::\d{1,5})?/[a-zA-Z0-9/._?&=%@#-]+',
        r'https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})(?::\d{1,5})?(?:/[a-zA-Z0-9._-]*)?',
    ]

    def analyze(self, ipa_path):
        results = {
            'file': os.path.basename(ipa_path) if ipa_path else '',
            'file_size': 0,
            'app_info': {},
            'endpoints': [],
            'domains': [],
            'security_notes': [],
        }

        if not ipa_path or not os.path.exists(ipa_path):
            results['error'] = '文件不存在'
            return results

        try:
            results['file_size'] = os.path.getsize(ipa_path)
        except Exception:
            pass

        try:
            if not zipfile.is_zipfile(ipa_path):
                results['error'] = '文件不是有效的ZIP/IPA格式'
                return results

            with zipfile.ZipFile(ipa_path, 'r') as zf:
                file_list = zf.namelist() if zf else []

                plist_files = [f for f in file_list if isinstance(f, str) and f.endswith('Info.plist')]
                for pf in plist_files:
                    try:
                        data = zf.read(pf)
                        if data:
                            results['app_info'] = self._parse_plist(data)
                    except Exception:
                        pass

                endpoints = set()
                for filename in file_list:
                    if not isinstance(filename, str):
                        continue
                    if any(filename.endswith(ext) for ext in ['.plist', '.json', '.xml', '.strings', '.swift', '.m', '.h', '.js']):
                        try:
                            data = zf.read(filename).decode('utf-8', errors='ignore')
                            if not data:
                                continue
                            for pattern in self.API_PATTERNS:
                                try:
                                    matches = re.findall(pattern, data)
                                    for url in matches:
                                        if url and isinstance(url, str) and self._is_api_url(url):
                                            endpoints.add(url)
                                except Exception:
                                    pass
                        except Exception:
                            pass

                results['endpoints'] = [
                    {'url': url, 'method': 'UNKNOWN', 'source': 'ipa'}
                    for url in endpoints
                ]

                for url in endpoints:
                    try:
                        parsed = urlparse(url)
                        if parsed and parsed.netloc:
                            results['domains'].append(parsed.netloc)
                    except Exception:
                        pass

        except Exception as e:
            results['error'] = str(e)

        results['endpoint_count'] = len(results.get('endpoints', []))
        return results

    def _parse_plist(self, data):
        info = {}
        if not data:
            return info
        try:
            text = data.decode('utf-8', errors='ignore')
            if not text:
                return info
            bundle_match = re.search(r'CFBundleIdentifier.*?<string>([^<]+)</string>', text, re.DOTALL)
            if bundle_match:
                info['bundle_id'] = bundle_match.group(1).strip()
            name_match = re.search(r'CFBundleDisplayName.*?<string>([^<]+)</string>', text, re.DOTALL)
            if name_match:
                info['display_name'] = name_match.group(1).strip()
            version_match = re.search(r'CFBundleShortVersionString.*?<string>([^<]+)</string>', text, re.DOTALL)
            if version_match:
                info['version'] = version_match.group(1).strip()
        except Exception:
            pass
        return info

    def _is_api_url(self, url):
        if not url or not isinstance(url, str) or len(url) < 10:
            return False
        static_ext = ('.png', '.jpg', '.gif', '.svg', '.css', '.woff', '.ttf', '.ico', '.webp')
        return not any(url.lower().endswith(ext) for ext in static_ext)


class MiniProgramAnalyzer:
    """Analyze WeChat Mini Program packages"""

    def analyze(self, mp_path):
        results = {
            'file': os.path.basename(mp_path) if mp_path else '',
            'endpoints': [],
            'domains': [],
        }

        if not mp_path or not os.path.exists(mp_path):
            results['error'] = '文件不存在'
            return results

        try:
            if not zipfile.is_zipfile(mp_path):
                results['error'] = '文件不是有效的压缩包格式'
                return results

            with zipfile.ZipFile(mp_path, 'r') as zf:
                file_list = zf.namelist() if zf else []
                domains = set()

                for filename in file_list:
                    if not isinstance(filename, str):
                        continue
                    if filename.endswith(('.js', '.json', '.wxml', '.wxss')):
                        try:
                            data = zf.read(filename).decode('utf-8', errors='ignore')
                            if data:
                                eps = self._extract_from_miniprogram(data, filename)
                                results['endpoints'].extend(eps)
                        except Exception:
                            pass

                for ep in results['endpoints']:
                    if isinstance(ep, dict):
                        try:
                            parsed = urlparse(ep.get('url', ''))
                            if parsed and parsed.netloc:
                                domains.add(parsed.netloc)
                        except Exception:
                            pass

                results['domains'] = list(domains)

        except Exception as e:
            results['error'] = str(e)

        results['endpoint_count'] = len(results.get('endpoints', []))
        return results

    def _extract_from_miniprogram(self, code, source):
        endpoints = []
        if not code or not isinstance(code, str):
            return endpoints

        patterns = [
            r'wx\.(?:request|uploadFile|downloadFile)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'(?:url|api|endpoint)\s*[=:]\s*["\']((?:https?://|/)[^"\']+)["\']',
            r'["\']((?:https?://)[^"\']*(?:api|rest|service|gateway|auth)[^"\']*)["\']',
            r'["\']((?:/api|/rest|/v\d)/[^"\']+)["\']',
            r'(?:baseUrl|BASE_URL|apiUrl|serverUrl)\s*[=:]\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            try:
                matches = re.findall(pattern, code, re.IGNORECASE)
            except Exception:
                continue
            for url in matches:
                if url and isinstance(url, str) and len(url.strip()) > 5:
                    endpoints.append({
                        'url': url.strip(),
                        'method': 'UNKNOWN',
                        'source': f'miniprogram:{source}',
                    })

        return endpoints
