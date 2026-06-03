import json
import csv
import os
import time


class DataExporter:
    """Export API endpoint data in various formats"""

    from core.path_resolver import get_exports_dir
    EXPORT_DIR = get_exports_dir()

    def __init__(self):
        os.makedirs(self.EXPORT_DIR, exist_ok=True)

    def export_json(self, endpoints, filename=None):
        """Export as JSON"""
        if not filename:
            filename = f'api_export_{int(time.time())}.json'
        filepath = os.path.join(self.EXPORT_DIR, filename)

        export_data = {
            'export_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_count': len(endpoints),
            'endpoints': endpoints
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)

        return filepath

    def export_csv(self, endpoints, filename=None):
        """Export as CSV"""
        if not filename:
            filename = f'api_export_{int(time.time())}.csv'
        filepath = os.path.join(self.EXPORT_DIR, filename)

        if not endpoints:
            with open(filepath, 'w', encoding='utf-8-sig') as f:
                f.write('No data')
            return filepath

        fieldnames = ['url', 'method', 'status_code', 'content_type', 'category',
                      'description', 'risk_level', 'source', 'response_size']

        with open(filepath, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for ep in endpoints:
                row = {k: ep.get(k, '') for k in fieldnames}
                writer.writerow(row)

        return filepath

    def export_markdown(self, endpoints, filename=None):
        """Export as Markdown document"""
        if not filename:
            filename = f'api_report_{int(time.time())}.md'
        filepath = os.path.join(self.EXPORT_DIR, filename)

        lines = [
            '# API接口分析报告',
            f'\n生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'接口总数: {len(endpoints)}\n',
        ]

        # Group by category
        categories = {}
        for ep in endpoints:
            cat = ep.get('category', 'other') or 'other'
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(ep)

        # Summary table
        lines.append('## 分类概览\n')
        lines.append('| 分类 | 数量 | 高风险 | 中风险 | 低风险 |')
        lines.append('|------|------|--------|--------|--------|')
        for cat, eps in sorted(categories.items(), key=lambda x: -len(x[1])):
            high = sum(1 for e in eps if e.get('risk_level') in ('high', 'critical'))
            medium = sum(1 for e in eps if e.get('risk_level') == 'medium')
            low = sum(1 for e in eps if e.get('risk_level') == 'low')
            lines.append(f'| {cat} | {len(eps)} | {high} | {medium} | {low} |')

        # Detailed listing
        lines.append('\n## 详细接口列表\n')
        for cat, eps in sorted(categories.items(), key=lambda x: -len(x[1])):
            lines.append(f'\n### {cat} ({len(eps)} 个接口)\n')
            for ep in eps:
                risk = ep.get('risk_level', 'info')
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}.get(risk, '⚪')
                lines.append(f'{icon} **[{ep.get("method", "GET")}]** `{ep.get("url", "")}`')
                if ep.get('description'):
                    lines.append(f'   - {ep["description"]}')
                if ep.get('status_code'):
                    lines.append(f'   - 状态码: {ep["status_code"]}')
                if ep.get('parameters'):
                    lines.append(f'   - 参数: {json.dumps(ep["parameters"], ensure_ascii=False)}')
                lines.append('')

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        return filepath

    def export_postman_collection(self, endpoints, filename=None):
        """Export as Postman Collection v2.1"""
        if not filename:
            filename = f'postman_collection_{int(time.time())}.json'
        filepath = os.path.join(self.EXPORT_DIR, filename)

        items = []
        for ep in endpoints:
            item = {
                'name': ep.get('description') or ep.get('url', ''),
                'request': {
                    'method': ep.get('method', 'GET'),
                    'header': [],
                    'url': {
                        'raw': ep.get('url', ''),
                    }
                }
            }
            # Parse URL for Postman format
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(ep.get('url', ''))
            item['request']['url'] = {
                'raw': ep.get('url', ''),
                'protocol': parsed.scheme,
                'host': parsed.netloc.split('.'),
                'path': parsed.path.strip('/').split('/'),
            }
            if parsed.query:
                qs = parse_qs(parsed.query)
                item['request']['url']['query'] = [
                    {'key': k, 'value': v[0] if len(v) == 1 else v}
                    for k, v in qs.items()
                ]

            items.append(item)

        collection = {
            'info': {
                'name': '灵探 Export',
                'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
            },
            'item': items,
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(collection, f, ensure_ascii=False, indent=2)

        return filepath
