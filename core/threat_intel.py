"""外部情报集成 — Shodan / Censys / FOFA 查询"""
import re
import requests


class ThreatIntel:
    """外部威胁情报查询"""

    def __init__(self, timeout=15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
        })

    def query_shodan(self, domain, api_key=''):
        """查询 Shodan

        Args:
            domain: 目标域名
            api_key: Shodan API key (可选，无 key 时使用免费接口)

        Returns:
            dict: {'source', 'domain', 'results': [...], 'error': str}
        """
        results = {'source': 'Shodan', 'domain': domain, 'results': [], 'error': ''}

        # 免费 DNS 解析查询
        try:
            url = f'https://dns.shodan.io/dns/domain/{domain}'
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                # 提取子域名
                subdomains = data.get('subdomains', [])
                for sub in subdomains:
                    results['results'].append({
                        'type': 'subdomain',
                        'value': f'{sub}.{domain}',
                    })
                # 提取 DNS 记录
                dns_data = data.get('data', [])
                for record in dns_data:
                    results['results'].append({
                        'type': 'dns_record',
                        'record_type': record.get('type', ''),
                        'value': record.get('value', ''),
                        'subdomain': record.get('subdomain', ''),
                    })
        except Exception as e:
            results['error'] = f'DNS 查询失败: {str(e)}'

        # 有 API key 时搜索主机
        if api_key:
            try:
                search_url = f'https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}'
                resp = self.session.get(search_url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    for match in data.get('matches', [])[:20]:
                        results['results'].append({
                            'type': 'host',
                            'ip': match.get('ip_str', ''),
                            'port': match.get('port', ''),
                            'service': match.get('product', ''),
                            'org': match.get('org', ''),
                            'location': f'{match.get("location", {}).get("city", "")}, {match.get("location", {}).get("country_name", "")}',
                        })
            except Exception as e:
                results['error'] += f' | 主机搜索失败: {str(e)}'

        return results

    def query_censys(self, domain, api_id='', api_secret=''):
        """查询 Censys

        免费模式：通过 Web 搜索
        API 模式：需要 api_id + api_secret
        """
        results = {'source': 'Censys', 'domain': domain, 'results': [], 'error': ''}

        if api_id and api_secret:
            try:
                url = f'https://search.censys.io/api/v2/hosts/search?q={domain}&per_page=20'
                resp = self.session.get(url, timeout=self.timeout, auth=(api_id, api_secret))
                if resp.status_code == 200:
                    data = resp.json()
                    for hit in data.get('result', {}).get('hits', []):
                        results['results'].append({
                            'type': 'host',
                            'ip': hit.get('ip', ''),
                            'services': [
                                {'port': s.get('port', ''), 'service': s.get('service_name', '')}
                                for s in hit.get('services', [])
                            ],
                            'location': hit.get('location', {}).get('country_code', ''),
                            'autonomous_system': hit.get('autonomous_system', {}).get('name', ''),
                        })
                elif resp.status_code == 401:
                    results['error'] = 'Censys API 认证失败，请检查 API ID/Secret'
            except Exception as e:
                results['error'] = f'查询失败: {str(e)}'
        else:
            # 免费模式：通过证书搜索
            try:
                url = f'https://search.censys.io/certificates/search?q={domain}&per_page=10'
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    results['results'].append({
                        'type': 'info',
                        'value': 'Censys 证书搜索可用（需浏览器访问）',
                        'url': f'https://search.censys.io/search?resource=hosts&q={domain}',
                    })
            except Exception:
                pass

        return results

    def query_fofa(self, domain, email='', api_key=''):
        """查询 FOFA

        免费模式：通过 Web 页面
        API 模式：需要 email + api_key
        """
        results = {'source': 'FOFA', 'domain': domain, 'results': [], 'error': ''}

        if email and api_key:
            try:
                import base64
                query_str = f'domain="{domain}"'
                query_b64 = base64.b64encode(query_str.encode()).decode()
                url = f'https://fofa.info/api/v1/search/all?email={email}&key={api_key}&qbase64={query_b64}&size=20'
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('error'):
                        results['error'] = f'FOFA 错误: {data.get("errmsg", data["error"])}'
                    else:
                        for item in data.get('results', []):
                            if len(item) >= 4:
                                results['results'].append({
                                    'type': 'host',
                                    'url': item[0],
                                    'ip': item[1],
                                    'port': item[2],
                                    'title': item[3] if len(item) > 3 else '',
                                    'domain': item[4] if len(item) > 4 else '',
                                })
            except Exception as e:
                results['error'] = f'查询失败: {str(e)}'
        else:
            results['results'].append({
                'type': 'info',
                'value': 'FOFA 搜索可用（需浏览器访问）',
                'url': f'https://fofa.info/result?qbase64=',
                'note': '配置 email + api_key 后可自动查询',
            })

        return results

    def query_all(self, domain, shodan_key='', censys_id='', censys_secret='',
                  fofa_email='', fofa_key=''):
        """并发查询所有情报源"""
        all_results = []
        errors = []

        # Shodan (免费 DNS 查询总是执行)
        shodan = self.query_shodan(domain, api_key=shodan_key)
        all_results.append(shodan)
        if shodan['error']:
            errors.append(f'Shodan: {shodan["error"]}')

        # Censys
        censys = self.query_censys(domain, api_id=censys_id, api_secret=censys_secret)
        all_results.append(censys)
        if censys['error']:
            errors.append(f'Censys: {censys["error"]}')

        # FOFA
        fofa = self.query_fofa(domain, email=fofa_email, api_key=fofa_key)
        all_results.append(fofa)
        if fofa['error']:
            errors.append(f'FOFA: {fofa["error"]}')

        # 汇总
        total_findings = sum(len(r['results']) for r in all_results)

        return {
            'domain': domain,
            'sources': all_results,
            'total_findings': total_findings,
            'errors': errors,
        }

    @staticmethod
    def extract_domain(url):
        """从 URL 提取域名"""
        if '://' in url:
            url = url.split('://', 1)[1]
        return url.split('/')[0].split(':')[0]
