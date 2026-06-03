"""Automation script generator from crawled data"""
import json
import re
from urllib.parse import urlparse, parse_qs


class ScriptGenerator:
    """Generate automation scripts from crawled data"""

    def generate_python_requests(self, endpoints):
        """Generate Python requests script from endpoint list"""
        if not endpoints:
            return '# 没有接口数据\n'

        lines = [
            '"""灵探 - 自动生成的API测试脚本"""',
            'import requests',
            '',
            'BASE_URL = ""  # 请填入目标域名',
            'session = requests.Session()',
            "session.headers.update({",
            "    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',",
            "    'Accept': 'application/json',",
            "})",
            'session.verify = False',
            '',
        ]

        for i, ep in enumerate(endpoints[:50]):
            if not isinstance(ep, dict):
                continue
            url = ep.get('url', '')
            method = (ep.get('method') or 'GET').upper()
            desc = ep.get('description', '') or ep.get('category', '') or ''

            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', urlparse(url).path.strip('/'))[:40] or f'endpoint_{i}'
            safe_name = re.sub(r'_+', '_', safe_name).strip('_')

            if desc:
                lines.append(f'# {desc}')
            parsed = urlparse(url)
            path = parsed.path or '/'
            query = parsed.query
            if query:
                path += '?' + query

            if method == 'GET':
                lines.append(f'def test_{safe_name}():')
                lines.append(f'    resp = session.get(f"{{BASE_URL}}{path}")')
            elif method == 'POST':
                body = ep.get('request_body', '')
                lines.append(f'def test_{safe_name}():')
                if body:
                    try:
                        json.loads(body)
                        lines.append(f'    data = {body}')
                    except Exception:
                        lines.append(f'    data = {repr(body)}')
                    lines.append(f'    resp = session.post(f"{{BASE_URL}}{path}", json=data)')
                else:
                    lines.append(f'    resp = session.post(f"{{BASE_URL}}{path}", json={{}})')
            elif method == 'PUT':
                lines.append(f'def test_{safe_name}():')
                lines.append(f'    resp = session.put(f"{{BASE_URL}}{path}", json={{}})')
            elif method == 'DELETE':
                lines.append(f'def test_{safe_name}():')
                lines.append(f'    resp = session.delete(f"{{BASE_URL}}{path}")')
            else:
                lines.append(f'def test_{safe_name}():')
                lines.append(f'    resp = session.request("{method}", f"{{BASE_URL}}{path}")')

            lines.append(f'    print(f"[{method}] {path} -> {{resp.status_code}} ({{len(resp.content)}} bytes)")')
            lines.append(f'    return resp')
            lines.append('')

        lines.append('')
        lines.append('if __name__ == "__main__":')
        funcs = []
        for i, ep in enumerate(endpoints[:50]):
            if not isinstance(ep, dict):
                continue
            url = ep.get('url', '')
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', urlparse(url).path.strip('/'))[:40] or f'endpoint_{i}'
            safe_name = re.sub(r'_+', '_', safe_name).strip('_')
            funcs.append(f'    test_{safe_name}()')
        lines.extend(funcs)
        lines.append('    print("All tests completed")')

        return '\n'.join(lines)

    def generate_playwright_script(self, pages, endpoints=None):
        """Generate Playwright automation script from crawled pages"""
        if not pages:
            return '# 没有页面数据\n'

        lines = [
            '"""灵探 - 自动生成的Playwright自动化脚本"""',
            'from playwright.sync_api import sync_playwright',
            'import time',
            '',
            'def run_automation():',
            '    with sync_playwright() as p:',
            '        browser = p.chromium.launch(headless=True)',
            '        context = browser.new_context(',
            "            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',",
            '        )',
            '        page = context.new_page()',
            '',
        ]

        for i, pg in enumerate(pages[:30]):
            if not isinstance(pg, dict):
                continue
            url = pg.get('url', '')
            title = pg.get('title', '')
            forms = pg.get('forms') or []

            if title:
                lines.append(f'        # Page: {title}')
            lines.append(f'        print(f"Visiting: {url}")')
            lines.append(f'        page.goto("{url}")')
            lines.append(f'        time.sleep(1)')

            # Auto-fill forms
            for form in forms:
                action = form.get('action', '')
                method = (form.get('method') or 'GET').upper()
                fields = form.get('fields') or []

                lines.append(f'        # Form: {method} {action}')
                for field in fields:
                    fname = field.get('name', '')
                    ftype = field.get('type', 'text')
                    if not fname:
                        continue
                    if ftype in ('text', 'email', 'url', 'search', 'tel'):
                        lines.append(f'        try: page.fill("[name=\\"{fname}\\"]", "test")')
                        lines.append(f'        except: pass')
                    elif ftype == 'password':
                        lines.append(f'        try: page.fill("[name=\\"{fname}\\"]", "Test1234!")')
                        lines.append(f'        except: pass')

                if method == 'POST' and fields:
                    lines.append(f'        # Submit form (uncomment to enable)')
                    lines.append(f'        # try: page.click("[type=\\"submit\\"]")')
                    lines.append(f'        # except: pass')
                    lines.append(f'        # time.sleep(2)')

            lines.append('')

        lines.append('        # Capture screenshot')
        lines.append('        page.screenshot(path="site_screenshot.png")')
        lines.append('        print("Automation completed")')
        lines.append('        browser.close()')
        lines.append('')
        lines.append('if __name__ == "__main__":')
        lines.append('    run_automation()')

        return '\n'.join(lines)

    def generate_curl_batch(self, endpoints):
        """Generate batch cURL commands from endpoints"""
        if not endpoints:
            return '# 没有接口数据\n'

        lines = ['#!/bin/bash', '# 灵探 - 自动生成的cURL测试脚本', '']

        for ep in endpoints[:50]:
            if not isinstance(ep, dict):
                continue
            url = ep.get('url', '')
            method = (ep.get('method') or 'GET').upper()
            desc = ep.get('description', '') or ep.get('category', '')

            if desc:
                lines.append(f'# {desc}')

            cmd = f'curl -s -o /dev/null -w "%{{http_code}}"'
            if method != 'GET':
                cmd += f' -X {method}'
            body = ep.get('request_body', '')
            if body and method in ('POST', 'PUT', 'PATCH'):
                safe_body = body.replace("'", "'\\''")
                cmd += f" -H 'Content-Type: application/json' -d '{safe_body}'"
            cmd += f" '{url}'"
            lines.append(f'echo "Testing: {method} {url}"')
            lines.append(cmd)
            lines.append('echo ""')
            lines.append('')

        return '\n'.join(lines)
