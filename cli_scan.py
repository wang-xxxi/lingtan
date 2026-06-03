#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
灵探 - CI/CD 命令行扫描工具
用于 Jenkins / GitLab CI / GitHub Actions 等CI/CD流水线

用法:
    py cli_scan.py --url https://example.com
    py cli_scan.py --url https://example.com --security --fail-on high
    py cli_scan.py --url https://example.com --output results.json --json-only
    py cli_scan.py --spec swagger.json --url https://api.example.com

退出码:
    0  扫描成功，无高危发现
    1  扫描成功，发现高危接口 (CI卡点触发)
    2  扫描失败或参数错误
"""

import os
import sys
import json
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


SEVERITY_LEVELS = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def severity_at_least(level, threshold):
    """Check if level meets threshold"""
    return SEVERITY_LEVELS.get(level, 0) >= SEVERITY_LEVELS.get(threshold, 3)


def scan(args):
    """Run the full scan pipeline and return structured results"""
    from core.crawler import WebCrawler
    from core.analyzer import APIAnalyzer
    from core.fuzzer import APIFuzzer
    from core.spec_importer import SpecImporter
    from core.auth_detector import AuthDetector
    from core.header_auditor import HeaderAuditor
    from core.traffic_analyzer import TrafficAnalyzer
    from core.database import Database

    result = {
        'tool': '灵探',
        'version': '2.0',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'target': args.url or args.spec or '',
        'scan_type': 'cli',
        'config': {
            'depth': args.depth,
            'max_pages': args.max_pages,
            'security': args.security,
            'auth_check': args.auth_check,
            'header_audit': args.header_audit,
            'fail_on': args.fail_on,
        },
        'phases': {},
        'summary': {
            'total_endpoints': 0,
            'risk_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'security_findings': 0,
            'passed': True,
            'exit_code': 0,
        },
        'endpoints': [],
        'security_issues': [],
        'errors': [],
    }

    start_time = time.time()
    db = Database()

    # ── Phase 1: Spec Import (if provided) ──
    if args.spec:
        print('[1/6] 导入API规范...', file=sys.stderr)
        importer = SpecImporter()
        if os.path.exists(args.spec):
            spec_result = importer.import_from_file(args.spec)
        else:
            spec_result = importer.import_from_url(args.spec)

        if 'error' in spec_result:
            result['errors'].append(f'规范导入失败: {spec_result["error"]}')
        else:
            result['phases']['spec_import'] = {
                'endpoints': spec_result.get('summary', {}).get('total_endpoints', 0),
                'test_cases': spec_result.get('summary', {}).get('total_test_cases', 0),
            }
            for ep in spec_result.get('endpoints', []):
                result['endpoints'].append({
                    'url': ep.get('url', ''),
                    'method': ep.get('method', 'GET'),
                    'source': 'spec-import',
                    'category': ','.join(ep.get('tags', [])),
                    'description': ep.get('summary', ''),
                    'risk_level': 'info',
                })

    # ── Phase 2: Web Crawl ──
    if args.url:
        max_depth = 3 if args.depth == 'deep' else (1 if args.depth == 'shallow' else 2)
        print(f'[{"1" if not args.spec else "2"}/6] 爬取目标 {args.url} (depth={max_depth}, pages={args.max_pages})...', file=sys.stderr)

        crawler = WebCrawler(max_depth=max_depth, max_pages=args.max_pages)
        crawl_results = crawler.crawl(args.url, deep_scan=(args.depth != 'shallow'))

        analyzer = APIAnalyzer()
        analyzed = analyzer.batch_analyze(crawl_results)

        result['phases']['crawl'] = {
            'endpoints_found': len(analyzed or []),
            'js_files': len(crawler.js_files),
            'errors': len(crawler._errors),
        }

        for ep in (analyzed or []):
            if not ep or not isinstance(ep, dict):
                continue
            result['endpoints'].append({
                'url': ep.get('url', ''),
                'method': ep.get('method', 'GET'),
                'status_code': ep.get('status_code'),
                'content_type': ep.get('content_type', ''),
                'source': ep.get('source', 'crawler'),
                'category': ep.get('category', ''),
                'risk_level': ep.get('risk_level', 'info'),
                'description': ep.get('description', ''),
            })

        # Save to DB for subsequent phases
        try:
            target_id = db.add_target(args.url, 'cli-scan', args.url)
            for ep in (analyzed or []):
                if not ep or not isinstance(ep, dict):
                    continue
                db.add_endpoint(
                    target_id=target_id,
                    url=str(ep.get('url', ''))[:2000],
                    method=str(ep.get('method', 'GET'))[:10],
                    status_code=ep.get('status_code'),
                    content_type=str(ep.get('content_type', ''))[:200],
                    source='cli-scan',
                    risk_level=str(ep.get('risk_level', 'info'))[:20],
                    category=str(ep.get('category', ''))[:50],
                    description=str(ep.get('description', ''))[:500],
                )
        except Exception:
            pass

    # ── Phase 3: Security Scan ──
    if args.security and args.url:
        phase_num = '3' if not args.spec else '4'
        print(f'[{phase_num}/6] 安全扫描...', file=sys.stderr)
        try:
            fuzzer = APIFuzzer()
            endpoints_for_fuzz = db.get_all_endpoints(limit=200)
            fuzz_results = fuzzer.full_scan(args.url, endpoints=endpoints_for_fuzz)

            result['phases']['security'] = fuzz_results.get('summary', {}) if isinstance(fuzz_results, dict) else {}

            for issue in (fuzz_results.get('vulnerabilities', []) if isinstance(fuzz_results, dict) else []):
                severity = issue.get('severity', 'medium')
                result['security_issues'].append({
                    'type': issue.get('type', ''),
                    'severity': severity,
                    'url': issue.get('url', ''),
                    'description': issue.get('description', ''),
                    'evidence': issue.get('evidence', ''),
                })
                if severity_at_least(severity, 'low'):
                    result['summary']['risk_counts'][severity] = result['summary']['risk_counts'].get(severity, 0) + 1
        except Exception as e:
            result['errors'].append(f'安全扫描异常: {str(e)}')

    # ── Phase 4: Auth Check ──
    if args.auth_check and args.url:
        phase_num = '4' if not args.security else '5'
        print(f'[{phase_num}/6] 认证检测...', file=sys.stderr)
        try:
            detector = AuthDetector()
            auth_results = detector.full_check(args.url)
            auth_findings = auth_results.get('findings', []) if isinstance(auth_results, dict) else []

            result['phases']['auth_check'] = {
                'findings': len(auth_findings),
                'jwt_tokens': len(auth_results.get('jwt_tokens', []) if isinstance(auth_results, dict) else []),
            }

            for finding in auth_findings:
                severity = finding.get('severity', 'medium')
                result['security_issues'].append({
                    'type': finding.get('type', 'auth'),
                    'severity': severity,
                    'url': args.url,
                    'description': finding.get('description', ''),
                    'evidence': finding.get('evidence', ''),
                })
                if severity_at_least(severity, 'low'):
                    result['summary']['risk_counts'][severity] = result['summary']['risk_counts'].get(severity, 0) + 1
        except Exception as e:
            result['errors'].append(f'认证检测异常: {str(e)}')

    # ── Phase 5: Header Audit ──
    if args.header_audit and args.url:
        phase_num = '5'
        print(f'[{phase_num}/6] 安全头审计...', file=sys.stderr)
        try:
            auditor = HeaderAuditor()
            header_results = auditor.full_audit(args.url)
            header_findings = header_results.get('findings', []) if isinstance(header_results, dict) else []

            result['phases']['header_audit'] = {
                'score': header_results.get('score', 0) if isinstance(header_results, dict) else 0,
                'findings': len(header_findings),
            }

            for finding in header_findings:
                severity = finding.get('severity', 'low')
                result['security_issues'].append({
                    'type': finding.get('type', 'header'),
                    'severity': severity,
                    'url': args.url,
                    'description': finding.get('description', ''),
                    'evidence': finding.get('evidence', ''),
                    'recommendation': finding.get('recommendation', ''),
                })
                if severity_at_least(severity, 'low'):
                    result['summary']['risk_counts'][severity] = result['summary']['risk_counts'].get(severity, 0) + 1
        except Exception as e:
            result['errors'].append(f'安全头审计异常: {str(e)}')

    # ── Build Summary ──
    result['summary']['total_endpoints'] = len(result['endpoints'])
    result['summary']['security_findings'] = len(result['security_issues'])
    result['elapsed_seconds'] = round(time.time() - start_time, 2)

    # Recount risk levels from endpoints
    for ep in result['endpoints']:
        risk = ep.get('risk_level', 'info')
        if risk in result['summary']['risk_counts']:
            pass  # already counted from security issues

    # CI gate: check if any findings meet fail threshold
    fail_threshold = args.fail_on
    if fail_threshold and fail_threshold != 'none':
        for issue in result['security_issues']:
            if severity_at_least(issue.get('severity', 'info'), fail_threshold):
                result['summary']['passed'] = False
                result['summary']['exit_code'] = 1
                result['summary']['fail_reason'] = f'发现 {issue.get("severity")} 级别安全问题: {issue.get("type")}'
                break

    # Also check endpoint risk levels
    if result['summary']['passed'] and fail_threshold and fail_threshold != 'none':
        for ep in result['endpoints']:
            risk = ep.get('risk_level', 'info')
            if severity_at_least(risk, fail_threshold):
                result['summary']['passed'] = False
                result['summary']['exit_code'] = 1
                result['summary']['fail_reason'] = f'发现 {risk} 级别接口: {ep.get("method")} {ep.get("url")}'
                break

    return result


def main():
    parser = argparse.ArgumentParser(
        description='灵探 - CI/CD命令行扫描工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --url https://example.com
  %(prog)s --url https://api.example.com --security --fail-on high
  %(prog)s --url https://example.com --output results.json --json-only
  %(prog)s --spec swagger.json --url https://api.example.com --security
  %(prog)s --url https://example.com --depth deep --max-pages 200 --auth-check --header-audit

退出码:
  0  扫描成功，无高危发现
  1  扫描成功，发现高危接口 (CI卡点触发)
  2  扫描失败或参数错误
        """,
    )

    # Target options
    target_group = parser.add_argument_group('目标')
    target_group.add_argument('--url', '-u', help='扫描目标URL')
    target_group.add_argument('--spec', '-s', help='OpenAPI/Swagger规范文件路径或URL')

    # Scan options
    scan_group = parser.add_argument_group('扫描选项')
    scan_group.add_argument('--depth', '-d', choices=['shallow', 'normal', 'deep'], default='normal',
                            help='爬取深度 (default: normal)')
    scan_group.add_argument('--max-pages', '-p', type=int, default=100,
                            help='最大爬取页面数 (default: 100)')
    scan_group.add_argument('--security', action='store_true',
                            help='启用安全扫描 (SQLi/XSS/敏感路径)')
    scan_group.add_argument('--auth-check', action='store_true',
                            help='启用认证检测 (未授权访问/IDOR/JWT)')
    scan_group.add_argument('--header-audit', action='store_true',
                            help='启用安全头审计 (CORS/CSP/HSTS)')
    scan_group.add_argument('--all', action='store_true',
                            help='启用所有检测 (--security --auth-check --header-audit)')

    # CI options
    ci_group = parser.add_argument_group('CI/CD选项')
    ci_group.add_argument('--output', '-o', help='输出JSON结果到文件')
    ci_group.add_argument('--json-only', action='store_true',
                            help='仅输出JSON (抑制进度信息，适合管道使用)')
    ci_group.add_argument('--fail-on', choices=['none', 'info', 'low', 'medium', 'high', 'critical'],
                          default='high', help='CI卡点阈值: 发现该级别及以上则退出码非零 (default: high)')
    ci_group.add_argument('--quiet', '-q', action='store_true',
                            help='静默模式 (仅输出错误)')

    args = parser.parse_args()

    # Validate
    if not args.url and not args.spec:
        parser.error('请指定 --url 或 --spec (至少一个)')

    # --all shorthand
    if args.all:
        args.security = True
        args.auth_check = True
        args.header_audit = True

    # Ensure dependencies
    try:
        import flask
        import requests
        import bs4
        import lxml
    except ImportError as e:
        print(f'缺少依赖: {e}. 请运行: pip install flask requests beautifulsoup4 lxml', file=sys.stderr)
        sys.exit(2)

    try:
        result = scan(args)
    except Exception as e:
        error_result = {
            'tool': '灵探',
            'error': str(e),
            'summary': {'passed': False, 'exit_code': 2},
        }
        if not args.quiet:
            print(json.dumps(error_result, indent=2, ensure_ascii=False))
        sys.exit(2)

    # Output
    json_output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_output)
        if not args.quiet and not args.json_only:
            print(f'结果已保存到: {args.output}', file=sys.stderr)

    if args.json_only:
        print(json_output)
    elif not args.quiet:
        # Print summary to stderr
        s = result['summary']
        elapsed = result.get('elapsed_seconds', 0)
        passed_str = 'PASS' if s['passed'] else 'FAIL'
        color = '\033[92m' if s['passed'] else '\033[91m'
        print(f'\n{"=" * 50}', file=sys.stderr)
        print(f'{color}[{passed_str}]\033[0m 扫描完成 ({elapsed}s)', file=sys.stderr)
        print(f'  接口总数: {s["total_endpoints"]}', file=sys.stderr)
        print(f'  安全发现: {s["security_findings"]}', file=sys.stderr)
        if s['security_findings'] > 0:
            counts = s.get('risk_counts', {})
            parts = []
            for level in ('critical', 'high', 'medium', 'low'):
                if counts.get(level, 0) > 0:
                    parts.append(f'{level}={counts[level]}')
            if parts:
                print(f'  风险分布: {", ".join(parts)}', file=sys.stderr)
        if not s['passed']:
            print(f'  \033[91mCI卡点: {s.get("fail_reason", "高危发现")}\033[0m', file=sys.stderr)
        print(f'{"=" * 50}', file=sys.stderr)

        # Also print JSON to stdout for piping
        print(json_output)

    sys.exit(result['summary']['exit_code'])


if __name__ == '__main__':
    main()
