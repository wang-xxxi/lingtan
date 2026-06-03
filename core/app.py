import os
import sys
import json
import time
import traceback
import threading
import webbrowser
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

from core.path_resolver import get_base_dir, get_data_dir, get_exports_dir, get_reports_dir
from core.database import Database
from core.analyzer import APIAnalyzer
from core.crawler import WebCrawler, SingleURLAnalyzer
from core.js_analyzer import JSAnalyzer
from core.apk_analyzer import APKAnalyzer, IPAAnalyzer, MiniProgramAnalyzer
from core.har_analyzer import HARAnalyzer, BurpXMLAnalyzer
from core.exporter import DataExporter
from core.fuzzer import APIFuzzer
from core.spec_generator import OpenAPIGenerator, CurlGenerator
from core.scanner_utils import PortScanner, DiffEngine, BatchScanner, EndpointGrouper, ChangeMonitor
from core.site_crawler import SiteCrawler
from core.site_analyzer import SiteAnalyzer
from core.script_generator import ScriptGenerator
from core.proxy_server import ProxyServer
from core.graphql_analyzer import GraphQLAnalyzer
from core.websocket_detector import WebSocketDetector
from core.report_generator import ReportGenerator
from core.task_manager import TaskManager
from core.plugin_manager import PluginManager
from core.param_miner import ParamMiner
from core.auth_detector import AuthDetector
from core.header_auditor import HeaderAuditor
from core.subdomain_enum import SubdomainEnumerator
from core.spec_importer import SpecImporter
from core.traffic_analyzer import TrafficAnalyzer
from core.session_manager import SessionManager
from core.waf_detector import WAFDetector
from core.tech_fingerprint import TechFingerprinter
from core.payload_evasion import PayloadEvasion
from core.scan_checkpoint import ScanCheckpoint
from core.backup_scanner import BackupScanner
from core.cloud_storage_detector import CloudStorageDetector
from core.favicon_fingerprint import FaviconFingerprinter
from core.forbidden_bypass import ForbiddenBypass
from core.wayback_scanner import WaybackScanner
from core.error_page_detector import ErrorPageDetector
from core.oast_detector import OASTDetector
from core.template_engine import TemplateEngine
from core.threat_intel import ThreatIntel
from core.sarif_exporter import SARIFExporter
from core.jarm_fingerprint import JARMFingerprinter
from core import page_classifier

BASE_DIR = get_base_dir()
TEMPLATE_DIR = os.path.join(BASE_DIR, 'web', 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'web', 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(get_data_dir(), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = Database()
analyzer = APIAnalyzer()
exporter = DataExporter()
proxy_server = ProxyServer(db)
graphql_analyzer = GraphQLAnalyzer()
ws_detector = WebSocketDetector()
report_gen = ReportGenerator()
task_manager = TaskManager(db)
plugin_mgr = PluginManager()
change_monitor = ChangeMonitor()
diff_engine = DiffEngine()
traffic_analyzer = TrafficAnalyzer()
session_manager = SessionManager()
waf_detector = WAFDetector()
tech_fingerprinter = TechFingerprinter()
payload_evasion = PayloadEvasion()
scan_checkpoint = ScanCheckpoint(db)
backup_scanner = BackupScanner()
cloud_detector = CloudStorageDetector()
favicon_fp = FaviconFingerprinter()
forbidden_bypass = ForbiddenBypass()
wayback_scanner = WaybackScanner()
error_page_detector = ErrorPageDetector()
oast_detector = OASTDetector()
template_engine = TemplateEngine()
threat_intel = ThreatIntel()
sarif_exporter = SARIFExporter()
jarm_fingerprinter = JARMFingerprinter()

scan_state = {
    'active': False,
    'type': '',
    'target': '',
    'progress': 0,
    'message': '',
    'results': [],
    'start_time': 0,
    'error': None,
}


def scan_progress(message, progress=None):
    scan_state['message'] = message
    if progress is not None:
        scan_state['progress'] = progress


def safe_strip(val, max_len=2000):
    """Safely strip and truncate a string value"""
    if val is None:
        return ''
    val = str(val).strip()
    if len(val) > max_len:
        return val[:max_len]
    return val


# ─── Page Routes ───

@app.route('/')
def index():
    return render_template('index.html')


# ─── API Routes ───

@app.route('/api/scan/web', methods=['POST'])
def scan_website():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    deep = data.get('deep_scan', True)

    if not url:
        return jsonify({'error': '请提供目标URL'}), 400

    if scan_state.get('active'):
        return jsonify({'error': '已有扫描任务正在运行，请先停止或等待完成'}), 400

    def run_scan():
        global scan_state
        scan_state.update({
            'active': True, 'type': 'web', 'target': url,
            'progress': 0, 'message': '开始扫描...', 'results': [],
            'start_time': time.time(), 'error': None,
        })
        try:
            max_depth = 3 if deep else 1
            max_pages = 120 if deep else 20
            crawler = WebCrawler(max_depth=max_depth, max_pages=max_pages)
            crawler.set_progress_callback(scan_progress)
            # Auto-inject session cookies if available
            cookies, _ = db.get_cookies_for_url(url)
            if cookies:
                crawler.set_cookies(cookies)
            results = crawler.crawl(url, deep_scan=deep)

            scan_state['message'] = '分析接口中...'
            analyzed = analyzer.batch_analyze(results)

            target_id = db.add_target(url, 'website', url)
            for ep in (analyzed or []):
                if not ep or not isinstance(ep, dict):
                    continue
                try:
                    db.add_endpoint(
                        target_id=target_id,
                        url=safe_strip(ep.get('url', '')),
                        method=safe_strip(ep.get('method', 'GET'), 10),
                        status_code=ep.get('status_code'),
                        content_type=safe_strip(ep.get('content_type', ''), 200),
                        response_size=ep.get('response_size'),
                        parameters=ep.get('parameters'),
                        headers=ep.get('headers'),
                        response_sample=safe_strip(ep.get('response_sample', '')),
                        category=safe_strip(ep.get('category', ''), 50),
                        description=safe_strip(ep.get('description', ''), 500),
                        risk_level=safe_strip(ep.get('risk_level', 'info'), 20),
                        source=safe_strip(ep.get('source', 'web-scan'), 50),
                    )
                except Exception:
                    pass

            scan_state['results'] = analyzed or []
            scan_state['message'] = f'扫描完成，发现 {len(analyzed or [])} 个接口'
            scan_state['progress'] = 100
        except Exception as e:
            scan_state['error'] = str(e)
            scan_state['message'] = f'扫描出错: {str(e)}'
            traceback.print_exc()
        finally:
            scan_state['active'] = False

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({'message': '扫描已启动', 'target': url})


@app.route('/api/scan/analyze-url', methods=['POST'])
def analyze_single_url():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    method = safe_strip(data.get('method', 'GET'), 10)
    headers = data.get('headers') or {}
    body = data.get('body', '')

    if not url:
        return jsonify({'error': '请提供URL'}), 400

    try:
        sa = SingleURLAnalyzer()
        cookies, _ = db.get_cookies_for_url(url)
        if cookies:
            sa.set_cookies(cookies)
        result = sa.analyze(url, method, headers=headers, body=body)
        if 'error' not in result:
            analysis = analyzer.analyze_url(url, method, body, result.get('response_sample'))
            result.update(analysis)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'分析异常: {str(e)}', 'url': url})


@app.route('/api/scan/js', methods=['POST'])
def analyze_js():
    data = request.json or {}
    js_url = safe_strip(data.get('url', ''))

    if not js_url:
        return jsonify({'error': '请提供JS文件URL'}), 400

    try:
        jsa = JSAnalyzer()
        result = jsa.analyze_url(js_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'JS分析异常: {str(e)}', 'url': js_url})


@app.route('/api/scan/batch-js', methods=['POST'])
def analyze_batch_js():
    data = request.json or {}
    urls = data.get('urls', [])
    if not urls or not isinstance(urls, list):
        return jsonify({'error': '请提供JS文件URL列表'}), 400

    try:
        jsa = JSAnalyzer()
        result = jsa.analyze_multiple(urls[:30])
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'批量JS分析异常: {str(e)}'})


@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': '未选择文件'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': '未选择文件'}), 400

    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'error': '文件名无效'}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(filepath)
    except Exception as e:
        return jsonify({'error': f'文件保存失败: {str(e)}'}), 500

    file_type = request.form.get('type', 'auto')
    ext = os.path.splitext(filename)[1].lower()

    if file_type == 'auto':
        type_map = {
            '.apk': 'apk', '.ipa': 'ipa', '.har': 'har',
            '.xml': 'burp', '.zip': 'miniprogram', '.wxapkg': 'miniprogram',
        }
        file_type = type_map.get(ext, 'har')

    results = {}
    try:
        analyzer_map = {
            'apk': APKAnalyzer,
            'ipa': IPAAnalyzer,
            'miniprogram': MiniProgramAnalyzer,
            'har': HARAnalyzer,
            'burp': BurpXMLAnalyzer,
        }
        analyzer_cls = analyzer_map.get(file_type)
        if analyzer_cls:
            results = analyzer_cls().analyze(filepath)
        else:
            results = {'error': f'不支持的文件类型: {file_type}'}

        # Save to database
        if results and results.get('endpoints'):
            target_id = db.add_target(filename, file_type, filename)
            for ep in results['endpoints']:
                if not ep or not isinstance(ep, dict):
                    continue
                try:
                    analysis = analyzer.analyze_url(
                        safe_strip(ep.get('url', '')),
                        safe_strip(ep.get('method', 'UNKNOWN'), 10),
                        ep.get('request_body'),
                        ep.get('response_sample')
                    )
                    db.add_endpoint(
                        target_id=target_id,
                        url=safe_strip(ep.get('url', '')),
                        method=safe_strip(ep.get('method', 'UNKNOWN'), 10),
                        status_code=ep.get('status_code'),
                        content_type=safe_strip(ep.get('content_type', ''), 200),
                        parameters=ep.get('parameters'),
                        headers=ep.get('headers'),
                        request_body=safe_strip(ep.get('request_body', '')),
                        response_sample=safe_strip(ep.get('response_sample', '')),
                        category=safe_strip(analysis.get('category', ''), 50),
                        description=safe_strip(analysis.get('description', ''), 500),
                        risk_level=safe_strip(analysis.get('risk_level', 'info'), 20),
                        source=file_type,
                    )
                except Exception:
                    pass
    except Exception as e:
        results = {'error': f'分析失败: {str(e)}', 'trace': traceback.format_exc()}
    finally:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass

    return jsonify(results)


@app.route('/api/upload/batch', methods=['POST'])
def upload_batch():
    if 'files' not in request.files:
        return jsonify({'error': '未选择文件'}), 400

    files = request.files.getlist('files')
    all_results = []

    type_map = {
        '.apk': ('apk', APKAnalyzer), '.ipa': ('ipa', IPAAnalyzer),
        '.har': ('har', HARAnalyzer), '.zip': ('miniprogram', MiniProgramAnalyzer),
        '.wxapkg': ('miniprogram', MiniProgramAnalyzer), '.xml': ('burp', BurpXMLAnalyzer),
    }

    for file in files:
        if not file.filename:
            continue
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(filepath)
            ext = os.path.splitext(filename)[1].lower()
            info = type_map.get(ext)
            if info:
                _, cls = info
                r = cls().analyze(filepath)
            else:
                r = {'error': f'不支持的格式: {ext}', 'file': filename}
            all_results.append(r)
        except Exception as e:
            all_results.append({'error': str(e), 'file': filename})
        finally:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass

    return jsonify({'results': all_results, 'total_files': len(all_results)})


@app.route('/api/endpoints', methods=['GET'])
def get_endpoints():
    target_id = request.args.get('target_id', type=int)
    category = request.args.get('category')
    search = safe_strip(request.args.get('search', ''))

    try:
        if search:
            endpoints = db.search_endpoints(search)
        else:
            endpoints = db.get_all_endpoints(target_id=target_id, category=category)
        return jsonify({'endpoints': endpoints or [], 'total': len(endpoints or [])})
    except Exception as e:
        return jsonify({'endpoints': [], 'total': 0, 'error': str(e)})


@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        return jsonify(db.get_endpoint_stats())
    except Exception as e:
        return jsonify({'error': str(e), 'total_endpoints': 0, 'total_targets': 0,
                        'by_category': {}, 'by_method': {}, 'by_risk': {}, 'by_source': {}})


@app.route('/api/targets', methods=['GET'])
def get_targets():
    try:
        return jsonify(db.get_targets() or [])
    except Exception:
        return jsonify([])


@app.route('/api/export/<format>', methods=['GET'])
def export_data(format):
    try:
        endpoints = db.export_all()
    except Exception as e:
        return jsonify({'error': f'数据导出失败: {str(e)}'}), 500

    if not endpoints:
        return jsonify({'error': '没有可导出的数据，请先进行扫描'}), 400

    try:
        format_map = {
            'json': exporter.export_json,
            'csv': exporter.export_csv,
            'markdown': exporter.export_markdown,
            'md': exporter.export_markdown,
            'postman': exporter.export_postman_collection,
        }
        export_fn = format_map.get(format)
        if not export_fn:
            return jsonify({'error': f'不支持的格式: {format}，支持: json, csv, markdown, postman'}), 400

        filepath = export_fn(endpoints)
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'error': f'导出失败: {str(e)}'}), 500


@app.route('/api/clear', methods=['POST'])
def clear_data():
    try:
        # Stop any active scan
        scan_state['active'] = False
        # Close all browser sessions
        for win_id in list(session_manager._browsers.keys()):
            session_manager.close_session(win_id)
        db.clear_all()
        return jsonify({'message': '数据已清除'})
    except Exception as e:
        return jsonify({'error': f'清除失败: {str(e)}'}), 500


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    return jsonify(scan_state)


@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    scan_state['active'] = False
    scan_state['message'] = '扫描已停止'
    return jsonify({'message': '扫描已停止'})


@app.route('/api/scan/batch', methods=['POST'])
def batch_scan():
    data = request.json or {}
    urls = data.get('urls', [])
    if not urls or not isinstance(urls, list):
        return jsonify({'error': '请提供URL列表'}), 400

    results = []
    from core.crawler import WebCrawler

    for url in urls[:50]:
        url = safe_strip(url)
        if not url:
            continue
        if not url.startswith('http'):
            url = 'https://' + url
        try:
            crawler = WebCrawler(max_depth=2, max_pages=30)
            raw_eps = crawler.crawl(url, deep_scan=True)
            eps = analyzer.batch_analyze(raw_eps) if raw_eps else []
            # Save to DB
            target_id = db.add_target(url)
            if target_id and eps:
                for ep in eps[:100]:
                    if not isinstance(ep, dict):
                        continue
                    try:
                        db.add_endpoint(
                            target_id=target_id,
                            url=safe_strip(ep.get('url', '')),
                            method=safe_strip(ep.get('method', 'GET'), 10),
                            status_code=ep.get('status_code'),
                            content_type=safe_strip(ep.get('content_type', ''), 200),
                            response_size=ep.get('response_size'),
                            category=safe_strip(ep.get('category', ''), 50),
                            description=safe_strip(ep.get('description', ''), 500),
                            risk_level=safe_strip(ep.get('risk_level', 'info'), 20),
                            source=safe_strip(ep.get('source', 'batch-scan'), 50),
                        )
                    except Exception:
                        pass
            results.append({
                'url': url,
                'endpoints': eps or [],
                'endpoint_count': len(eps or []),
            })
        except Exception as e:
            results.append({
                'url': url,
                'error': str(e),
                'endpoints': [],
            })

    return jsonify({
        'total': len(urls[:50]),
        'completed': len(results),
        'results': results,
    })


@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    if not url:
        return jsonify({'error': '请提供URL'}), 400

    import requests as req
    try:
        resp = req.get(url, timeout=10, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return jsonify({
            'status': resp.status_code,
            'content_type': resp.headers.get('content-type', ''),
            'size': len(resp.content),
            'time': resp.elapsed.total_seconds(),
            'reachable': True,
            'headers': dict(resp.headers),
        })
    except req.exceptions.ConnectionError:
        return jsonify({'reachable': False, 'error': '连接失败，无法访问目标服务器'})
    except req.exceptions.Timeout:
        return jsonify({'reachable': False, 'error': '连接超时'})
    except Exception as e:
        return jsonify({'reachable': False, 'error': str(e)})


@app.route('/api/scan/progress', methods=['GET'])
def get_progress():
    return jsonify({
        'active': scan_state.get('active', False),
        'progress': scan_state.get('progress', 0),
        'message': scan_state.get('message', ''),
        'type': scan_state.get('type', ''),
        'target': scan_state.get('target', ''),
        'error': scan_state.get('error'),
        'elapsed': time.time() - scan_state['start_time'] if scan_state.get('start_time') else 0,
    })


@app.route('/api/endpoint/<int:endpoint_id>', methods=['GET'])
def get_endpoint_detail(endpoint_id):
    """Get detailed info for a single endpoint"""
    try:
        all_eps = db.get_all_endpoints(limit=10000)
        for ep in (all_eps or []):
            if ep.get('id') == endpoint_id:
                return jsonify(ep)
        return jsonify({'error': '未找到该接口'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Security Scan (Fuzzer) ───

fuzz_state = {'active': False, 'progress': 0, 'message': '', 'results': None}

@app.route('/api/security/scan', methods=['POST'])
def security_scan():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    if not url:
        return jsonify({'error': '请提供目标URL'}), 400
    if fuzz_state.get('active'):
        return jsonify({'error': '已有安全扫描在运行'}), 400

    def run_fuzz():
        fuzz_state.update({'active': True, 'progress': 0, 'message': '开始安全扫描...', 'results': None})
        try:
            endpoints = db.get_all_endpoints(limit=200)
            fuzzer = APIFuzzer()
            results = fuzzer.full_scan(
                url, endpoints=endpoints,
                progress_callback=lambda m, p: fuzz_state.update({'message': m, 'progress': p})
            )
            fuzz_state['results'] = results
            fuzz_state['message'] = '安全扫描完成'
            fuzz_state['progress'] = 100
        except Exception as e:
            fuzz_state['message'] = f'安全扫描出错: {str(e)}'
        finally:
            fuzz_state['active'] = False

    threading.Thread(target=run_fuzz, daemon=True).start()
    return jsonify({'message': '安全扫描已启动'})


@app.route('/api/security/progress', methods=['GET'])
def security_progress():
    return jsonify(fuzz_state)


@app.route('/api/security/stop', methods=['POST'])
def security_stop():
    fuzz_state['active'] = False
    fuzz_state['message'] = '已停止'
    return jsonify({'message': '安全扫描已停止'})


# ─── OpenAPI Spec Generation ───

@app.route('/api/export/openapi', methods=['GET', 'POST'])
def export_openapi():
    try:
        endpoints = db.export_all()
    except Exception:
        return jsonify({'error': '数据导出失败'}), 500
    if not endpoints:
        return jsonify({'error': '没有数据，请先扫描'}), 400

    title = '灵探 自动生成文档'
    version = '1.0.0'
    if request.method == 'POST' and request.is_json:
        data = request.json or {}
        title = safe_strip(data.get('title', title), 200)
        version = safe_strip(data.get('version', version), 50)
    else:
        title = request.args.get('title', title)

    gen = OpenAPIGenerator()
    spec = gen.generate(endpoints, title=title, version=version)
    if not spec:
        return jsonify({'error': '生成失败'}), 500

    return jsonify(spec)


@app.route('/api/export/openapi/file', methods=['GET'])
def export_openapi_file():
    try:
        endpoints = db.export_all()
    except Exception:
        return jsonify({'error': '数据导出失败'}), 500
    if not endpoints:
        return jsonify({'error': '没有数据'}), 400

    gen = OpenAPIGenerator()
    spec = gen.generate(endpoints)
    if not spec:
        return jsonify({'error': '生成失败'}), 500

    filepath = os.path.join(get_exports_dir(), f'openapi_{int(time.time())}.json')
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    gen.save_to_file(spec, filepath)
    return send_file(filepath, as_attachment=True, download_name='openapi.json')


# ─── cURL Generation ───

@app.route('/api/curl/<int:endpoint_id>', methods=['GET'])
def get_curl(endpoint_id):
    try:
        all_eps = db.get_all_endpoints(limit=10000)
        ep = None
        for e in (all_eps or []):
            if e.get('id') == endpoint_id:
                ep = e
                break
        if not ep:
            return jsonify({'error': '未找到接口'}), 404
        gen = CurlGenerator()
        return jsonify({'curl': gen.generate_from_endpoint(ep)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Port Scanner ───

@app.route('/api/tools/portscan', methods=['POST'])
def port_scan():
    data = request.json or {}
    host = safe_strip(data.get('host', '127.0.0.1'))
    web_only = data.get('web_only', False)
    scan_type = safe_strip(data.get('type', 'web' if web_only else 'full'), 20)

    try:
        scanner = PortScanner()
        if scan_type == 'web':
            results = scanner.scan_web_ports(host)
        else:
            results = scanner.scan(host)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Diff Comparison ───

@app.route('/api/tools/diff', methods=['POST'])
def diff_compare():
    data = request.json or {}
    old_target_id = data.get('old_target_id')
    new_target_id = data.get('new_target_id')

    try:
        all_eps = db.get_all_endpoints(limit=10000) or []
        if old_target_id and new_target_id:
            old_eps = [ep for ep in all_eps if ep.get('target_id') == old_target_id]
            new_eps = [ep for ep in all_eps if ep.get('target_id') == new_target_id]
        else:
            # Compare by discovery time - split endpoints into two halves
            if not all_eps:
                return jsonify({'error': '没有数据，请先扫描'}), 400
            sorted_eps = sorted(all_eps, key=lambda e: e.get('discovered_at', 0))
            mid = max(1, len(sorted_eps) // 2)
            old_eps = sorted_eps[:mid]
            new_eps = sorted_eps[mid:]

        engine = DiffEngine()
        result = engine.compare(old_eps, new_eps)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Endpoint Grouping ───

@app.route('/api/tools/group', methods=['GET', 'POST'])
def group_endpoints():
    try:
        endpoints = db.get_all_endpoints(limit=5000)
        grouper = EndpointGrouper()
        result = grouper.group(endpoints)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Request Builder (send custom request) ───

@app.route('/api/tools/request', methods=['POST'])
def send_request():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    method = safe_strip(data.get('method', 'GET'), 10).upper()
    headers = data.get('headers') or {}
    body = data.get('body', '')

    if not url:
        return jsonify({'error': '请提供URL'}), 400

    import requests as req
    try:
        merged = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        if isinstance(headers, dict):
            merged.update({str(k): str(v) for k, v in headers.items()})

        start = time.time()
        resp = req.request(
            method, url,
            headers=merged,
            data=body if body else None,
            timeout=15,
            verify=False,
            allow_redirects=True,
        )
        elapsed = time.time() - start

        resp_headers = dict(resp.headers) if resp.headers else {}
        resp_text = resp.text[:10000] if resp.text else ''

        result = {
            'status_code': resp.status_code,
            'headers': resp_headers,
            'body': resp_text,
            'body_size': len(resp.content) if resp.content else 0,
            'time': round(elapsed, 3),
            'url': resp.url,
        }

        # Generate cURL
        gen = CurlGenerator()
        result['curl'] = gen.generate(url, method, merged, body or None)

        # Save to request history
        try:
            db.add_history(method, url, headers=merged, body=body or None,
                          status_code=resp.status_code,
                          response_size=len(resp.content) if resp.content else 0,
                          elapsed=round(elapsed, 3))
        except Exception:
            pass

        # Auto-analyze response
        if 'json' in resp_headers.get('content-type', '').lower():
            try:
                json.loads(resp_text)
                result['is_json'] = True
            except Exception:
                result['is_json'] = False

        return jsonify(result)
    except req.exceptions.ConnectionError:
        return jsonify({'error': '连接失败'}), 502
    except req.exceptions.Timeout:
        return jsonify({'error': '请求超时'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ═══════════════════════════════════════════
# ─── Site Crawl + Tech Detection ───
# ═══════════════════════════════════════════

site_crawl_state = {
    'active': False, 'progress': 0, 'message': '',
    'pages_found': 0, 'start_time': 0, 'error': None,
    'target': '', 'result': None,
}

@app.route('/api/site/crawl', methods=['POST'])
def site_crawl():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    max_pages = min(int(data.get('max_pages', 100) or 100), 500)

    if not url:
        return jsonify({'error': '请提供目标URL'}), 400

    if site_crawl_state.get('active'):
        return jsonify({'error': '已有爬取任务正在运行'}), 400

    def run_site_crawl():
        site_crawl_state.update({
            'active': True, 'progress': 0, 'message': '开始全站爬取...',
            'pages_found': 0, 'start_time': time.time(), 'error': None,
            'target': url, 'result': None,
        })
        try:
            def progress_cb(msg, pct):
                site_crawl_state['message'] = msg
                site_crawl_state['progress'] = pct

            crawler = SiteCrawler(max_pages=max_pages)
            crawler.set_progress_callback(progress_cb)
            cookies, _ = db.get_cookies_for_url(url)
            if cookies:
                crawler.set_cookies(cookies)
            result = crawler.crawl(url)

            if result.get('error'):
                site_crawl_state['error'] = result['error']
                site_crawl_state['message'] = f'爬取出错: {result["error"]}'
                return

            # Save to DB
            target_id = db.add_target(url, 'site-crawl', url)
            pages = result.get('pages') or []
            for page in pages:
                if not isinstance(page, dict):
                    continue
                try:
                    db.add_crawled_page(
                        target_id=target_id,
                        url=page.get('url', ''),
                        status_code=page.get('status_code'),
                        content_type=page.get('content_type'),
                        title=page.get('title'),
                        meta_description=page.get('meta_description'),
                        headings=page.get('headings'),
                        links=page.get('links'),
                        images=page.get('images'),
                        forms=page.get('forms'),
                        scripts=page.get('scripts'),
                        stylesheets=page.get('stylesheets'),
                        assets=page.get('assets'),
                        technologies=page.get('technologies'),
                        seo_data=page.get('seo_data'),
                        performance=page.get('performance'),
                        html_tags=page.get('html_tags'),
                        page_size=page.get('page_size'),
                        depth=page.get('depth', 0),
                        parent_url=page.get('parent_url'),
                    )
                except Exception:
                    pass

            for tech in (result.get('technologies') or []):
                if not isinstance(tech, dict):
                    continue
                try:
                    db.add_site_technology(
                        target_id=target_id,
                        name=tech.get('name', ''),
                        category=tech.get('category'),
                        confidence=tech.get('confidence', 0),
                        evidence=tech.get('evidence'),
                    )
                except Exception:
                    pass

            site_crawl_state['pages_found'] = len(pages)
            site_crawl_state['result'] = {
                'summary': result.get('summary', {}),
                'technologies': result.get('technologies', []),
            }
            site_crawl_state['message'] = f'爬取完成，共 {len(pages)} 个页面'
            site_crawl_state['progress'] = 100

        except Exception as e:
            site_crawl_state['error'] = str(e)
            site_crawl_state['message'] = f'爬取出错: {str(e)}'
            traceback.print_exc()
        finally:
            site_crawl_state['active'] = False

    threading.Thread(target=run_site_crawl, daemon=True).start()
    return jsonify({'message': '全站爬取已启动'})


@app.route('/api/site/progress', methods=['GET'])
def site_progress():
    return jsonify({
        'active': site_crawl_state.get('active', False),
        'progress': site_crawl_state.get('progress', 0),
        'message': site_crawl_state.get('message', ''),
        'pages_found': site_crawl_state.get('pages_found', 0),
        'target': site_crawl_state.get('target', ''),
        'error': site_crawl_state.get('error'),
        'result': site_crawl_state.get('result'),
        'elapsed': time.time() - site_crawl_state['start_time'] if site_crawl_state.get('start_time') else 0,
    })


@app.route('/api/site/stop', methods=['POST'])
def site_stop():
    site_crawl_state['active'] = False
    site_crawl_state['message'] = '已停止'
    return jsonify({'message': '爬取已停止'})


@app.route('/api/site/pages', methods=['GET'])
def site_pages():
    target_id = request.args.get('target_id', type=int)
    limit = request.args.get('limit', 500, type=int)
    try:
        pages = db.get_crawled_pages(target_id=target_id, limit=limit)
        return jsonify({'pages': pages, 'total': len(pages)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/site/page/<int:page_id>', methods=['GET'])
def site_page_detail(page_id):
    try:
        page = db.get_crawled_page(page_id)
        if not page:
            return jsonify({'error': '未找到页面'}), 404
        return jsonify(page)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/site/technologies', methods=['GET'])
def site_technologies():
    target_id = request.args.get('target_id', type=int)
    try:
        techs = db.get_site_technologies(target_id=target_id)
        return jsonify({'technologies': techs, 'total': len(techs)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/site/sitemap', methods=['GET'])
def site_sitemap():
    target_id = request.args.get('target_id', type=int)
    try:
        pages = db.get_crawled_pages(target_id=target_id, limit=1000)
        if not pages:
            return jsonify({'error': '没有爬取数据，请先进行全站爬取'}), 400

        # Build tree from pages
        url_to_page = {}
        children_map = {}
        for p in pages:
            url = p.get('url', '')
            url_to_page[url] = p
            parent = p.get('parent_url')
            if parent not in children_map:
                children_map[parent] = []
            children_map[parent].append(p)

        def build_node(url):
            page = url_to_page.get(url, {})
            node = {
                'id': page.get('id'),
                'url': url,
                'title': page.get('title', ''),
                'status_code': page.get('status_code'),
                'content_type': (page.get('content_type') or '').split(';')[0].strip(),
                'depth': page.get('depth', 0),
                'children': [],
            }
            for child in sorted(children_map.get(url, []), key=lambda x: x.get('url', '')):
                child_url = child.get('url', '')
                if child_url in url_to_page:
                    node['children'].append(build_node(child_url))
            return node

        # Find root
        root_url = None
        min_depth = 999
        for p in pages:
            d = p.get('depth', 0)
            if d < min_depth:
                min_depth = d
                root_url = p.get('url')

        # Also check for orphan pages (parent_url not in our data)
        tree = build_node(root_url) if root_url else {'url': '', 'title': '', 'children': []}
        return jsonify(tree)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Assets ───

@app.route('/api/site/assets', methods=['GET'])
def site_assets():
    target_id = request.args.get('target_id', type=int)
    asset_type = request.args.get('type', '')
    try:
        pages = db.get_crawled_pages(target_id=target_id, limit=2000)
        all_assets = []
        seen = set()
        for page in pages:
            for asset in (page.get('assets') or []):
                if not isinstance(asset, dict):
                    continue
                aurl = asset.get('url', '')
                if not aurl or aurl in seen:
                    continue
                seen.add(aurl)
                atype = asset.get('type', 'unknown')
                if asset_type and atype != asset_type:
                    continue
                all_assets.append({
                    'url': aurl,
                    'type': atype,
                    'source_page': page.get('url', ''),
                })

        type_counts = {}
        for a in all_assets:
            t = a['type']
            type_counts[t] = type_counts.get(t, 0) + 1

        return jsonify({
            'assets': all_assets,
            'total': len(all_assets),
            'type_counts': type_counts,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/site/assets/download', methods=['POST'])
def site_assets_download():
    """Download selected assets as a ZIP file"""
    data = request.json or {}
    urls = data.get('urls', [])
    if not urls:
        return jsonify({'error': '请提供要下载的资源URL'}), 400

    import zipfile
    import io as iobuf
    import requests as req
    from urllib.parse import urlparse

    zip_buffer = iobuf.BytesIO()
    count = 0
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for url in urls[:200]:
            try:
                resp = req.get(url, timeout=10, verify=False, headers={
                    'User-Agent': 'Mozilla/5.0'
                })
                if resp.status_code == 200 and resp.content:
                    parsed = urlparse(url)
                    filename = parsed.path.strip('/').replace('/', '_') or f'file_{count}'
                    ext = '.' + filename.rsplit('.', 1)[-1] if '.' in filename else ''
                    if not ext:
                        ct = resp.headers.get('Content-Type', '')
                        if 'css' in ct:
                            filename += '.css'
                        elif 'javascript' in ct:
                            filename += '.js'
                    zf.writestr(filename, resp.content)
                    count += 1
            except Exception:
                continue

    if count == 0:
        return jsonify({'error': '无法下载任何资源'}), 400

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'api_hunter_assets_{int(time.time())}.zip',
    )


# ─── SEO Analysis ───

@app.route('/api/site/seo', methods=['POST'])
def site_seo_analyze():
    target_id = None
    if request.is_json:
        target_id = (request.json or {}).get('target_id')
    try:
        pages = db.get_crawled_pages(target_id=target_id, limit=2000)
        if not pages:
            return jsonify({'error': '没有爬取数据，请先进行全站爬取'}), 400
        analyzer_inst = SiteAnalyzer()
        result = analyzer_inst.analyze(pages)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Script Generation ───

@app.route('/api/scripts/generate', methods=['POST'])
def scripts_generate():
    data = request.json or {}
    script_type = safe_strip(data.get('type', 'python'), 20)
    target_id = data.get('target_id')

    try:
        gen = ScriptGenerator()
        endpoints = db.get_all_endpoints(limit=200)
        pages = db.get_crawled_pages(target_id=target_id, limit=100)

        if script_type == 'python':
            script = gen.generate_python_requests(endpoints)
        elif script_type == 'playwright':
            script = gen.generate_playwright_script(pages, endpoints)
        elif script_type == 'curl':
            script = gen.generate_curl_batch(endpoints)
        else:
            return jsonify({'error': f'不支持的脚本类型: {script_type}'}), 400

        return jsonify({'script': script, 'type': script_type})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Proxy Routes ───

@app.route('/api/proxy/start', methods=['POST'])
def proxy_start():
    data = request.json or {}
    port = int(data.get('port', 8088))
    ok, msg = proxy_server.start(port)
    return jsonify({'success': ok, 'message': msg, 'status': proxy_server.get_status()})

@app.route('/api/proxy/stop', methods=['POST'])
def proxy_stop():
    ok, msg = proxy_server.stop()
    return jsonify({'success': ok, 'message': msg, 'status': proxy_server.get_status()})

@app.route('/api/proxy/status')
def proxy_status():
    return jsonify(proxy_server.get_status())

@app.route('/api/proxy/traffic')
def proxy_traffic():
    host = request.args.get('host')
    method = request.args.get('method')
    keyword = request.args.get('keyword')
    limit = int(request.args.get('limit', 200))
    rows = db.get_traffic(host=host, method=method, keyword=keyword, limit=limit)
    return jsonify(rows)

@app.route('/api/proxy/traffic/<int:tid>')
def proxy_traffic_detail(tid):
    detail = db.get_traffic_detail(tid)
    if not detail:
        return jsonify({'error': 'Record not found'}), 404
    return jsonify(detail)

@app.route('/api/proxy/clear', methods=['POST'])
def proxy_clear():
    db.clear_traffic()
    return jsonify({'success': True})


# ─── GraphQL Routes ───

@app.route('/api/graphql/introspect', methods=['POST'])
def graphql_introspect():
    data = request.json or {}
    url = data.get('url', '')
    headers = data.get('headers')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    result = graphql_analyzer.introspect(url, headers)
    return jsonify(result)

@app.route('/api/graphql/find', methods=['POST'])
def graphql_find():
    data = request.json or {}
    html = data.get('html', '')
    js_code = data.get('js_code', '')
    endpoints = graphql_analyzer.find_endpoints(html, js_code)
    return jsonify({'endpoints': endpoints})


# ─── WebSocket Routes ───

@app.route('/api/websocket/detect')
def websocket_detect():
    pages = db.get_crawled_pages(limit=200)
    result = ws_detector.scan_pages(pages)
    return jsonify(result)

@app.route('/api/websocket/test', methods=['POST'])
def websocket_test():
    data = request.json or {}
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    result = ws_detector.test_connection(url)
    return jsonify(result)


# ─── Report Routes ───

@app.route('/api/report/generate', methods=['POST'])
def report_generate():
    try:
        data = request.json or {}
        target_id = data.get('target_id')
        endpoints = db.get_all_endpoints(limit=500)
        stats = db.get_endpoint_stats()
        targets = db.get_targets()
        technologies = db.get_site_technologies(target_id=target_id)
        pages = db.get_crawled_pages(target_id=target_id, limit=200)

        # Run SEO if we have pages
        seo_result = None
        if pages:
            seo_result = SiteAnalyzer().analyze(pages)

        report = report_gen.generate(
            endpoints=endpoints, stats=stats, targets=targets,
            technologies=technologies, seo_result=seo_result, pages=pages,
            security_results=fuzz_state.get('results'),
        )
        return jsonify({'success': True, 'filename': report['filename']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/download/<filename>')
def report_download(filename):
    safe_name = secure_filename(filename)
    if not safe_name.endswith('.html'):
        safe_name += '.html'
    filepath = os.path.join(get_reports_dir(), safe_name)
    if not os.path.exists(filepath):
        return jsonify({'error': 'Report not found'}), 404
    return send_file(filepath, as_attachment=True, download_name=safe_name)


# ─── Task Queue Routes ───

@app.route('/api/tasks')
def get_tasks():
    limit = int(request.args.get('limit', 50))
    tasks = db.list_tasks(limit=limit)
    return jsonify(tasks)

@app.route('/api/tasks/<task_id>')
def get_task_detail(task_id):
    task = db.get_task(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(task)

@app.route('/api/tasks/<task_id>/stop', methods=['POST'])
def stop_task(task_id):
    ok, msg = task_manager.stop(task_id)
    return jsonify({'success': ok, 'message': msg})


# ─── Plugin Routes ───

@app.route('/api/plugins')
def get_plugins():
    plugins = plugin_mgr.list_plugins()
    return jsonify(plugins)

@app.route('/api/plugins/install', methods=['POST'])
def install_plugin():
    data = request.json or {}
    plugin_json = data.get('json') or data.get('content')
    if not plugin_json:
        return jsonify({'error': 'Plugin JSON required'}), 400
    ok, msg = plugin_mgr.install(plugin_json)
    return jsonify({'success': ok, 'message': msg})

@app.route('/api/plugins/<name>/toggle', methods=['POST'])
def toggle_plugin(name):
    ok, msg = plugin_mgr.toggle(name)
    return jsonify({'success': ok, 'message': msg})

@app.route('/api/plugins/<name>', methods=['DELETE'])
def delete_plugin(name):
    ok, msg = plugin_mgr.uninstall(name)
    return jsonify({'success': ok, 'message': msg})

@app.route('/api/plugins/example')
def plugin_example():
    return jsonify(plugin_mgr.get_example())


# ─── Parameter Mining Routes ───

param_state = {'active': False, 'progress': 0, 'message': '', 'results': None}

@app.route('/api/param/mine', methods=['POST'])
def param_mine():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    if not url:
        return jsonify({'error': '请提供目标URL'}), 400
    if param_state.get('active'):
        return jsonify({'error': '已有参数挖掘任务在运行'}), 400

    def run_mine():
        param_state.update({'active': True, 'progress': 0, 'message': '开始参数挖掘...', 'results': None})
        try:
            miner = ParamMiner()

            # Mine params from existing endpoints
            endpoints = db.get_all_endpoints(limit=500)
            mined_params = miner.mine_from_endpoints(endpoints)

            # Mine params from JS files
            js_analyzer = JSAnalyzer()
            js_params = []
            for ep in (endpoints or []):
                url_val = ep.get('url', '') if isinstance(ep, dict) else ''
                if url_val and url_val.endswith('.js'):
                    try:
                        resp = requests.get(url_val, timeout=8, verify=False)
                        if resp and resp.text:
                            result = miner.mine_from_js(resp.text, url_val)
                            js_params.extend(result.get('parameters', []))
                    except Exception:
                        pass

            # Merge discovered params
            all_param_names = set()
            for p in mined_params:
                all_param_names.add(p['name'])
            all_param_names.update(js_params[:100])

            param_state['message'] = f'发现 {len(all_param_names)} 个参数，开始Fuzz测试...'
            param_state['progress'] = 30

            # Auto-fuzz on target
            results = miner.fuzz_parameters(
                url, discovered_params=list(all_param_names),
                progress_callback=lambda m, p: param_state.update({'message': m, 'progress': 30 + int(p * 0.7)})
            )

            results['mined_from_endpoints'] = mined_params[:50]
            results['mined_from_js'] = sorted(js_params)[:50]
            param_state['results'] = results
            param_state['progress'] = 100
            param_state['message'] = f'参数挖掘完成: 测试 {results["summary"]["total_tested"]} 个参数'
        except Exception as e:
            param_state['message'] = f'参数挖掘出错: {str(e)}'
        finally:
            param_state['active'] = False

    threading.Thread(target=run_mine, daemon=True).start()
    return jsonify({'message': '参数挖掘已启动'})


@app.route('/api/param/progress', methods=['GET'])
def param_progress():
    return jsonify(param_state)


@app.route('/api/param/stop', methods=['POST'])
def param_stop():
    param_state['active'] = False
    param_state['message'] = '已停止'
    return jsonify({'message': '参数挖掘已停止'})


# ─── Auth Detection Routes ───

auth_state = {'active': False, 'progress': 0, 'message': '', 'results': None}

@app.route('/api/auth/check', methods=['POST'])
def auth_check():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    auth_headers = data.get('auth_headers') or {}
    if not url:
        return jsonify({'error': '请提供目标URL'}), 400
    if auth_state.get('active'):
        return jsonify({'error': '已有认证检测任务在运行'}), 400

    def run_auth():
        auth_state.update({'active': True, 'progress': 0, 'message': '开始认证检测...', 'results': None})
        try:
            detector = AuthDetector()
            results = detector.full_check(
                url, auth_headers=auth_headers,
                progress_callback=lambda m, p: auth_state.update({'message': m, 'progress': p})
            )
            auth_state['results'] = results
            auth_state['message'] = '认证检测完成'
            auth_state['progress'] = 100
        except Exception as e:
            auth_state['message'] = f'认证检测出错: {str(e)}'
        finally:
            auth_state['active'] = False

    threading.Thread(target=run_auth, daemon=True).start()
    return jsonify({'message': '认证检测已启动'})


@app.route('/api/auth/progress', methods=['GET'])
def auth_progress():
    return jsonify(auth_state)


@app.route('/api/auth/stop', methods=['POST'])
def auth_stop():
    auth_state['active'] = False
    auth_state['message'] = '已停止'
    return jsonify({'message': '认证检测已停止'})


@app.route('/api/auth/jwt/analyze', methods=['POST'])
def jwt_analyze():
    data = request.json or {}
    token = data.get('token', '')
    if not token:
        return jsonify({'error': '请提供JWT令牌'}), 400
    detector = AuthDetector()
    result = detector.analyze_jwt_string(token)
    return jsonify(result)


# ─── Header Audit Routes ───

header_state = {'active': False, 'progress': 0, 'message': '', 'results': None}

@app.route('/api/header/audit', methods=['POST'])
def header_audit():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    if not url:
        return jsonify({'error': '请提供目标URL'}), 400
    if header_state.get('active'):
        return jsonify({'error': '已有安全头审计任务在运行'}), 400

    def run_audit():
        header_state.update({'active': True, 'progress': 0, 'message': '开始安全头审计...', 'results': None})
        try:
            auditor = HeaderAuditor()
            results = auditor.full_audit(
                url,
                progress_callback=lambda m, p: header_state.update({'message': m, 'progress': p})
            )
            header_state['results'] = results
            header_state['message'] = f'安全头审计完成 (评分: {results.get("score", 0)}/100)'
            header_state['progress'] = 100
        except Exception as e:
            header_state['message'] = f'安全头审计出错: {str(e)}'
        finally:
            header_state['active'] = False

    threading.Thread(target=run_audit, daemon=True).start()
    return jsonify({'message': '安全头审计已启动'})


@app.route('/api/header/progress', methods=['GET'])
def header_progress():
    return jsonify(header_state)


@app.route('/api/header/stop', methods=['POST'])
def header_stop():
    header_state['active'] = False
    header_state['message'] = '已停止'
    return jsonify({'message': '安全头审计已停止'})


# ─── Subdomain Enumeration Routes ───

sub_state = {'active': False, 'progress': 0, 'message': '', 'results': None}

@app.route('/api/subdomain/enum', methods=['POST'])
def subdomain_enum():
    data = request.json or {}
    domain = safe_strip(data.get('domain', ''))
    bruteforce = data.get('bruteforce', False)
    if not domain:
        return jsonify({'error': '请提供目标域名'}), 400
    if sub_state.get('active'):
        return jsonify({'error': '已有子域名枚举任务在运行'}), 400

    def run_enum():
        sub_state.update({'active': True, 'progress': 0, 'message': '开始子域名枚举...', 'results': None})
        try:
            enumerator = SubdomainEnumerator()
            results = enumerator.enumerate(
                domain, include_bruteforce=bruteforce,
                progress_callback=lambda m, p: sub_state.update({'message': m, 'progress': p})
            )
            sub_state['results'] = results
            sub_state['message'] = f'子域名枚举完成: 发现 {results["summary"]["total_unique"]} 个子域名'
            sub_state['progress'] = 100
        except Exception as e:
            sub_state['message'] = f'子域名枚举出错: {str(e)}'
        finally:
            sub_state['active'] = False

    threading.Thread(target=run_enum, daemon=True).start()
    return jsonify({'message': '子域名枚举已启动'})


@app.route('/api/subdomain/progress', methods=['GET'])
def subdomain_progress():
    return jsonify(sub_state)


@app.route('/api/subdomain/stop', methods=['POST'])
def subdomain_stop():
    sub_state['active'] = False
    sub_state['message'] = '已停止'
    return jsonify({'message': '子域名枚举已停止'})


# ─── OpenAPI Spec Import Routes ───

@app.route('/api/spec/import', methods=['POST'])
def spec_import():
    importer = SpecImporter()
    data = request.json or {}

    # Import from URL
    url = safe_strip(data.get('url', ''))
    if url:
        result = importer.import_from_url(url)
        if 'error' not in result:
            _save_imported_endpoints(result)
        return jsonify(result)

    # Import from text content
    content = data.get('content', '')
    filename = data.get('filename', '')
    if content:
        result = importer.import_from_text(content, filename)
        if 'error' not in result:
            _save_imported_endpoints(result)
        return jsonify(result)

    return jsonify({'error': '请提供URL或文件内容'}), 400


@app.route('/api/spec/import/file', methods=['POST'])
def spec_import_file():
    importer = SpecImporter()
    if 'file' not in request.files:
        return jsonify({'error': '请选择文件'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': '文件名为空'}), 400

    try:
        content = f.read().decode('utf-8', errors='replace')
        result = importer.import_from_text(content, f.filename)
        if 'error' not in result:
            _save_imported_endpoints(result)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'文件读取失败: {str(e)}'}), 500


def _save_imported_endpoints(result):
    """Save imported spec endpoints to database"""
    try:
        target_id = db.add_target(
            result.get('base_url', '') or result.get('source', ''),
            'openapi-spec',
            result.get('base_url', '')
        )
        for ep in (result.get('endpoints') or []):
            try:
                db.add_endpoint(
                    target_id=target_id,
                    url=safe_strip(ep.get('url', ''), 2000),
                    method=safe_strip(ep.get('method', 'GET'), 10),
                    category=safe_strip(','.join(ep.get('tags', [])), 50),
                    description=safe_strip(ep.get('summary', ''), 500),
                    source='spec-import',
                )
            except Exception:
                pass
    except Exception:
        pass


# ─── Change Monitor Routes ───

@app.route('/api/monitor/snapshot', methods=['POST'])
def monitor_snapshot():
    data = request.json or {}
    target_id = data.get('target_id', 'default')
    endpoints = db.get_all_endpoints(limit=5000)
    snapshot = change_monitor.take_snapshot(target_id, endpoints)
    return jsonify({
        'message': f'快照已创建: {snapshot["count"]} 个接口',
        'snapshot': snapshot,
    })


@app.route('/api/monitor/changes', methods=['GET'])
def monitor_changes():
    target_id = request.args.get('target_id', 'default')
    result = change_monitor.detect_changes(target_id)
    # Add detailed diff if changed
    if result.get('changed'):
        snapshots = change_monitor._snapshots.get(target_id, [])
        if len(snapshots) >= 2:
            # Re-fetch current endpoints for detailed diff
            current = db.get_all_endpoints(limit=5000)
            # We need to store old endpoints for proper diff
            # For now, provide count-based diff info
            pass
    return jsonify(result)


@app.route('/api/monitor/snapshots', methods=['GET'])
def monitor_snapshots():
    target_id = request.args.get('target_id', 'default')
    snapshots = change_monitor._snapshots.get(target_id, [])
    return jsonify({
        'target_id': target_id,
        'snapshots': snapshots,
        'count': len(snapshots),
    })


@app.route('/api/monitor/diff', methods=['POST'])
def monitor_diff():
    """Compare two endpoint lists"""
    data = request.json or {}
    old_endpoints = data.get('old', [])
    new_endpoints = data.get('new', [])
    if not old_endpoints or not new_endpoints:
        # Default: compare DB endpoints vs provided list
        db_endpoints = db.get_all_endpoints(limit=5000)
        if new_endpoints:
            result = diff_engine.compare(db_endpoints, new_endpoints)
        else:
            return jsonify({'error': '请提供对比数据'}), 400
    else:
        result = diff_engine.compare(old_endpoints, new_endpoints)
    return jsonify(result)


# ─── Traffic Analysis Routes ───

@app.route('/api/traffic/analyze', methods=['POST'])
def traffic_analyze():
    """Analyze all captured traffic"""
    try:
        traffic = db.get_traffic(limit=1000)
        if not traffic:
            return jsonify({'error': '暂无捕获的流量数据，请先启动流量代理'})
        results = traffic_analyzer.analyze_traffic(traffic)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'分析失败: {str(e)}'}), 500


@app.route('/api/traffic/analyze/<int:traffic_id>', methods=['GET'])
def traffic_analyze_single(traffic_id):
    """Analyze a single traffic record"""
    try:
        record = db.get_traffic_detail(traffic_id)
        if not record:
            return jsonify({'error': '未找到该流量记录'}), 404
        results = traffic_analyzer.analyze_traffic([record])
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'分析失败: {str(e)}'}), 500


# ─── CI/CD Integration Routes ───

@app.route('/api/ci/scan', methods=['POST'])
def ci_scan():
    """Run a full scan pipeline and return structured results for CI/CD"""
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    spec_path = safe_strip(data.get('spec', ''))
    security = data.get('security', False)
    auth_check = data.get('auth_check', False)
    header_audit = data.get('header_audit', False)
    fail_on = data.get('fail_on', 'high')
    depth = data.get('depth', 'normal')
    max_pages = data.get('max_pages', 100)

    if not url and not spec_path:
        return jsonify({'error': '请提供 url 或 spec 参数'}), 400

    # Build args object for scan()
    class CIArgs:
        pass
    args = CIArgs()
    args.url = url
    args.spec = spec_path
    args.security = security
    args.auth_check = auth_check
    args.header_audit = header_audit
    args.fail_on = fail_on
    args.depth = depth
    args.max_pages = int(max_pages) if str(max_pages).isdigit() else 100

    try:
        import cli_scan
        result = cli_scan.scan(args)
        status_code = 200 if result['summary']['passed'] else 422
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': f'扫描异常: {str(e)}', 'summary': {'passed': False, 'exit_code': 2}}), 500


@app.route('/api/ci/health', methods=['GET'])
def ci_health():
    """Health check endpoint for CI/CD pipelines"""
    return jsonify({
        'status': 'ok',
        'tool': '灵探',
        'version': '2.0',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'modules': {
            'crawler': True,
            'fuzzer': True,
            'analyzer': True,
            'auth_detector': True,
            'header_auditor': True,
            'spec_importer': True,
        },
    })


# ─── Favorites Routes ───

@app.route('/api/favorites', methods=['GET'])
def get_favorites_list():
    favs = db.get_favorites()
    fav_set = db.get_favorite_set()
    return jsonify({'favorites': favs, 'favorite_set': sorted(fav_set)})


@app.route('/api/favorites/toggle', methods=['POST'])
def toggle_favorite():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    method = safe_strip(data.get('method', 'GET'), 10).upper()
    label = safe_strip(data.get('label', ''), 200)
    if not url:
        return jsonify({'error': '请提供URL'}), 400
    fav_set = db.get_favorite_set()
    key = f'{method}:{url}'
    if key in fav_set:
        db.remove_favorite(url, method)
        return jsonify({'favorited': False, 'message': '已取消收藏'})
    else:
        db.add_favorite(url, method, label)
        return jsonify({'favorited': True, 'message': '已收藏'})


# ─── Request History Routes ───

@app.route('/api/history', methods=['GET'])
def get_request_history():
    limit = request.args.get('limit', 100, type=int)
    history = db.get_history(limit=limit)
    return jsonify({'history': history, 'total': len(history)})


@app.route('/api/history', methods=['DELETE'])
def clear_request_history():
    db.clear_history()
    return jsonify({'message': '历史记录已清除'})


@app.route('/api/history/<int:hist_id>', methods=['DELETE'])
def delete_history_item(hist_id):
    try:
        c = db.conn.cursor()
        c.execute('DELETE FROM request_history WHERE id=?', (hist_id,))
        db.conn.commit()
        return jsonify({'message': '已删除'})
    except Exception:
        return jsonify({'error': '删除失败'}), 500


# ─── Dependency Graph Route ───

@app.route('/api/graph/data', methods=['GET'])
def graph_data():
    """Build graph data from crawled pages for visualization"""
    target_id = request.args.get('target_id', type=int)
    try:
        pages = db.get_crawled_pages(target_id=target_id, limit=500)
        if not pages:
            # Fallback: build from endpoints
            endpoints = db.get_all_endpoints(limit=500)
            return jsonify(_build_graph_from_endpoints(endpoints))

        nodes = []
        edges = []
        seen_urls = set()

        for p in pages:
            url = p.get('url', '')
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            from urllib.parse import urlparse
            parsed = urlparse(url)
            label = parsed.path or '/'
            if len(label) > 40:
                label = '...' + label[-37:]
            nodes.append({
                'id': url,
                'label': label,
                'title': p.get('title', ''),
                'status': p.get('status_code', 0),
                'depth': p.get('depth', 0),
            })

            # Edges: parent -> this page
            parent = p.get('parent_url', '')
            if parent:
                edges.append({'source': parent, 'target': url})

            # Edges: this page -> its links
            links = p.get('links') or []
            if isinstance(links, list):
                for link in links:
                    href = link.get('href', '') if isinstance(link, dict) else ''
                    if href:
                        edges.append({'source': url, 'target': href})

        return jsonify({'nodes': nodes, 'edges': edges, 'total_nodes': len(nodes), 'total_edges': len(edges)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _build_graph_from_endpoints(endpoints):
    """Build graph from endpoints when no crawled pages exist"""
    from urllib.parse import urlparse
    nodes = []
    edges = []
    seen = set()

    for ep in (endpoints or []):
        url = ep.get('url', '') if isinstance(ep, dict) else ''
        if not url or url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        label = parsed.path or '/'
        if len(label) > 40:
            label = '...' + label[-37:]
        nodes.append({
            'id': url,
            'label': label,
            'method': ep.get('method', 'GET'),
            'status': ep.get('status_code', 0),
            'category': ep.get('category', ''),
        })

    # Build edges from URL path hierarchy
    for i, n1 in enumerate(nodes):
        p1 = urlparse(n1['id']).path.rstrip('/')
        for j, n2 in enumerate(nodes):
            if i == j:
                continue
            p2 = urlparse(n2['id']).path.rstrip('/')
            # If p2 starts with p1 + '/', it's a child of p1
            if p1 and p2.startswith(p1 + '/') and '/' not in p2[len(p1) + 1:].strip('/'):
                edges.append({'source': n1['id'], 'target': n2['id']})

    return {'nodes': nodes, 'edges': edges, 'total_nodes': len(nodes), 'total_edges': len(edges)}


# ─── Session Routes ───

@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    sessions = db.get_sessions()
    return jsonify({'sessions': sessions})


@app.route('/api/sessions/open', methods=['POST'])
def open_session_window():
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    name = safe_strip(data.get('name', ''), 100)
    if not url:
        return jsonify({'error': '请提供URL'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        win_id, domain = session_manager.open_login_window(url, name or None)
        return jsonify({'success': True, 'win_id': win_id, 'domain': domain, 'message': '浏览器窗口已打开，请在窗口中完成登录后点击「捕获」'})
    except Exception as e:
        return jsonify({'error': f'打开窗口失败: {str(e)}'}), 500


@app.route('/api/sessions/capture/<win_id>', methods=['POST'])
def capture_session(win_id):
    cookies_list, status = session_manager.get_cookies(win_id)
    if status == 'not_found':
        return jsonify({'error': '未找到该登录窗口，请确认已点击"打开登录窗口"'}), 400
    if status != 'captured' or not cookies_list:
        return jsonify({'error': status or '捕获失败'}), 400

    # Save to database
    win_info = session_manager.get_window_info(win_id)
    domain = win_info.get('domain', '')
    url = win_info.get('url', '')
    name = domain or '未命名会话'
    sid = db.add_session(name, domain, url, cookies_list)
    return jsonify({
        'success': True,
        'session_id': sid,
        'cookie_count': len(cookies_list),
        'message': f'已捕获 {len(cookies_list)} 个 Cookie'
    })


@app.route('/api/sessions/close/<win_id>', methods=['POST'])
def close_session_window(win_id):
    session_manager.close_session(win_id)
    return jsonify({'success': True})


@app.route('/api/sessions/<int:sid>', methods=['DELETE'])
def delete_session_route(sid):
    db.delete_session(sid)
    return jsonify({'success': True})


# ─── Crawl Rules Routes ───

@app.route('/api/crawl-rules', methods=['GET'])
def list_crawl_rules():
    from core.crawl_rules import get_example_rules
    rules = db.get_crawl_rules()
    examples = [r.to_dict() for r in get_example_rules()]
    return jsonify({'rules': rules, 'examples': examples, 'page_types': page_classifier.PAGE_TYPE_LABELS})


@app.route('/api/crawl-rules', methods=['POST'])
def create_crawl_rule():
    from core.crawl_rules import CrawlRule
    data = request.json or {}
    name = safe_strip(data.get('name', ''), 100) or '未命名规则'
    url_pattern = safe_strip(data.get('url_pattern', ''), 500)
    config = {k: v for k, v in data.items() if k not in ('name', 'url_pattern')}
    # Validate
    rule = CrawlRule.from_dict({'name': name, 'url_pattern': url_pattern, **config})
    rid = db.add_crawl_rule(name, url_pattern, rule.to_dict())
    return jsonify({'success': True, 'id': rid})


@app.route('/api/crawl-rules/<int:rid>', methods=['DELETE'])
def delete_crawl_rule_route(rid):
    db.delete_crawl_rule(rid)
    return jsonify({'success': True})


@app.route('/api/crawl-rules/examples', methods=['GET'])
def get_crawl_rule_examples():
    from core.crawl_rules import get_example_rules
    return jsonify({'examples': [r.to_dict() for r in get_example_rules()]})


# ─── Intelligent Analysis Routes ───

@app.route('/api/analyze/classify', methods=['POST'])
def classify_page():
    from core.page_classifier import classify
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    html = data.get('html', '')
    if not url:
        return jsonify({'error': '请提供URL'}), 400
    result = classify(url, html_text=html)
    return jsonify(result)


@app.route('/api/analyze/extract', methods=['POST'])
def extract_structured_data():
    from core.data_extractor import extract_all
    data = request.json or {}
    html = data.get('html', '')
    url = safe_strip(data.get('url', ''))
    if not html:
        # Fetch the URL first
        try:
            import requests as req
            resp = req.get(url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            html = resp.text
        except Exception as e:
            return jsonify({'error': f'获取页面失败: {str(e)}'}), 400
    result = extract_all(html, url)
    return jsonify(result)


@app.route('/api/analyze/pagination', methods=['POST'])
def detect_pagination():
    from core.pagination_detector import detect
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    html = data.get('html', '')
    if not url:
        return jsonify({'error': '请提供URL'}), 400
    result = detect(url, html)
    return jsonify(result)


@app.route('/api/analyze/spa', methods=['POST'])
def analyze_spa():
    from core.spa_adapter import analyze_page_for_spa
    data = request.json or {}
    url = safe_strip(data.get('url', ''))
    html = data.get('html', '')
    if not url and not html:
        return jsonify({'error': '请提供URL或HTML'}), 400
    if not html and url:
        try:
            import requests as req
            resp = req.get(url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            html = resp.text
        except Exception as e:
            return jsonify({'error': f'获取页面失败: {str(e)}'}), 400
    result = analyze_page_for_spa(html, url)
    return jsonify(result)


# ─── WAF 检测 ───


@app.route('/api/waf/detect', methods=['POST'])
def api_waf_detect():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    try:
        result = waf_detector.detect(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── 技术栈指纹 ───


@app.route('/api/tech/fingerprint', methods=['POST'])
def api_tech_fingerprint():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    try:
        import requests as req
        resp = req.get(url, timeout=10, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        html = resp.text[:20000] if resp.text else ''
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = {c.name: c.value for c in resp.cookies}
        result = tech_fingerprinter.analyze(url=url, html=html, headers=headers, cookies=cookies)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Payload 绕过测试 ───


@app.route('/api/evasion/test', methods=['POST'])
def api_evasion_test():
    data = request.json or {}
    payload = data.get('payload', "' OR '1'='1")
    url = data.get('url', '')
    waf_info = data.get('waf_info')
    try:
        if waf_info and waf_info.get('detected'):
            results = payload_evasion.smart_evade(url, payload, waf_info)
        else:
            results = payload_evasion.evade(payload)
        return jsonify({'payload': payload, 'evaded': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── 扫描断点续传 ───


@app.route('/api/scan/checkpoints', methods=['GET'])
def api_list_checkpoints():
    try:
        checkpoints = scan_checkpoint.list_active()
        return jsonify({'checkpoints': checkpoints})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/checkpoints/<checkpoint_id>', methods=['DELETE'])
def api_delete_checkpoint(checkpoint_id):
    try:
        scan_checkpoint.delete(checkpoint_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── 备份文件探测 ───


backup_scan_state = {'active': False, 'progress': 0, 'message': '', 'results': None}


@app.route('/api/backup/scan', methods=['POST'])
def api_backup_scan():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    if backup_scan_state.get('active'):
        return jsonify({'error': '已有备份探测在运行'}), 400

    def run():
        backup_scan_state.update({'active': True, 'progress': 0, 'message': '开始备份探测...', 'results': None})
        try:
            results = backup_scanner.scan(url, progress_callback=lambda m, p: backup_scan_state.update({'message': m, 'progress': p}))
            backup_scan_state['results'] = results
        except Exception as e:
            backup_scan_state['message'] = f'备份探测出错: {str(e)}'
        finally:
            backup_scan_state['active'] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'message': '备份文件探测已启动'})


@app.route('/api/backup/progress', methods=['GET'])
def api_backup_progress():
    return jsonify(backup_scan_state)


# ─── 云存储泄露检测 ───


@app.route('/api/cloud/scan', methods=['POST'])
def api_cloud_scan():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    html = data.get('html', '')
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    try:
        if not html:
            import requests as req
            resp = req.get(url, timeout=10, verify=False)
            html = resp.text[:50000] if resp.text else ''
        results = cloud_detector.scan(url, html=html)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Favicon 指纹 ───


@app.route('/api/favicon/analyze', methods=['POST'])
def api_favicon_analyze():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    try:
        import requests as req
        resp = req.get(url, timeout=10, verify=False)
        html = resp.text[:20000] if resp.text else ''
        result = favicon_fp.analyze(url, html=html)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/favicon/compare', methods=['POST'])
def api_favicon_compare():
    data = request.json or {}
    url1 = safe_strip(data.get('url1'))
    url2 = safe_strip(data.get('url2'))
    if not url1 or not url2:
        return jsonify({'error': '请提供 url1 和 url2'}), 400
    try:
        result = favicon_fp.compare(url1, url2)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── 403/401 绕过 ───


forbidden_state = {'active': False, 'progress': 0, 'message': '', 'results': None}


@app.route('/api/forbidden/scan', methods=['POST'])
def api_forbidden_scan():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    if forbidden_state.get('active'):
        return jsonify({'error': '已有绕过测试在运行'}), 400

    def run():
        forbidden_state.update({'active': True, 'progress': 0, 'message': '开始 403 绕过测试...', 'results': None})
        try:
            results = forbidden_bypass.scan(url, progress_callback=lambda m, p: forbidden_state.update({'message': m, 'progress': p}))
            forbidden_state['results'] = results
        except Exception as e:
            forbidden_state['message'] = f'绕过测试出错: {str(e)}'
        finally:
            forbidden_state['active'] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'message': '403 绕过测试已启动'})


@app.route('/api/forbidden/progress', methods=['GET'])
def api_forbidden_progress():
    return jsonify(forbidden_state)


# ─── Wayback Machine ───


wayback_state = {'active': False, 'progress': 0, 'message': '', 'results': None}


@app.route('/api/wayback/scan', methods=['POST'])
def api_wayback_scan():
    data = request.json or {}
    domain = safe_strip(data.get('url') or data.get('domain'))
    if not domain:
        return jsonify({'error': '请提供目标域名'}), 400
    if wayback_state.get('active'):
        return jsonify({'error': '已有 Wayback 查询在运行'}), 400

    def run():
        wayback_state.update({'active': True, 'progress': 0, 'message': '查询 Wayback Machine...', 'results': None})
        try:
            results = wayback_scanner.scan(domain, progress_callback=lambda m, p: wayback_state.update({'message': m, 'progress': p}))
            wayback_state['results'] = results
        except Exception as e:
            wayback_state['message'] = f'Wayback 查询出错: {str(e)}'
        finally:
            wayback_state['active'] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'message': 'Wayback 查询已启动'})


@app.route('/api/wayback/progress', methods=['GET'])
def api_wayback_progress():
    return jsonify(wayback_state)


# ─── 404 页面学习 ───


@app.route('/api/errorpage/learn', methods=['POST'])
def api_errorpage_learn():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    try:
        fp = error_page_detector.learn(url)
        reliability = error_page_detector.score_reliability(fp)
        return jsonify({'fingerprint': fp, 'reliability': reliability})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── OAST 带外检测 ───


oast_state = {'active': False, 'progress': 0, 'message': '', 'results': None}


@app.route('/api/oast/scan', methods=['POST'])
def api_oast_scan():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    param = safe_strip(data.get('param', 'id'))
    method = safe_strip(data.get('method', 'GET'), 10)
    if not url:
        return jsonify({'error': '请提供 URL'}), 400
    if oast_state.get('active'):
        return jsonify({'error': '已有 OAST 检测在运行'}), 400

    def run():
        oast_state.update({'active': True, 'progress': 0, 'message': '开始 OAST 带外检测...', 'results': None})
        try:
            results = oast_detector.scan(
                url, param, method=method,
                progress_callback=lambda m, p: oast_state.update({'message': m, 'progress': p})
            )
            oast_state['results'] = results
        except Exception as e:
            oast_state['message'] = f'OAST 检测出错: {str(e)}'
        finally:
            oast_state['active'] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'message': 'OAST 带外检测已启动'})


@app.route('/api/oast/progress', methods=['GET'])
def api_oast_progress():
    return jsonify(oast_state)


@app.route('/api/oast/stop', methods=['POST'])
def api_oast_stop():
    oast_detector.stop()
    oast_state['active'] = False
    oast_state['message'] = '已停止'
    return jsonify({'message': 'OAST 检测已停止'})


# ─── YAML 模板引擎 ───


@app.route('/api/templates/list', methods=['GET'])
def api_templates_list():
    try:
        templates = template_engine.list_templates()
        return jsonify({'templates': templates, 'total': len(templates)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/templates/run', methods=['POST'])
def api_templates_run():
    data = request.json or {}
    url = safe_strip(data.get('url'))
    template_id = data.get('template_id')
    severity_filter = data.get('severity_filter')
    tag_filter = data.get('tag_filter')
    if not url:
        return jsonify({'error': '请提供目标 URL'}), 400
    try:
        if template_id:
            result = template_engine.run_template(template_id, url)
        else:
            result = template_engine.run_all(url, severity_filter=severity_filter, tag_filter=tag_filter)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/templates/add', methods=['POST'])
def api_templates_add():
    data = request.json or {}
    try:
        ok = template_engine.add_template(data)
        return jsonify({'success': ok})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── 外部威胁情报 ───


intel_state = {'active': False, 'progress': 0, 'message': '', 'results': None}


@app.route('/api/intel/query', methods=['POST'])
def api_intel_query():
    data = request.json or {}
    domain = safe_strip(data.get('domain') or data.get('url'))
    shodan_key = safe_strip(data.get('shodan_key', ''))
    censys_id = safe_strip(data.get('censys_id', ''))
    censys_secret = safe_strip(data.get('censys_secret', ''))
    fofa_email = safe_strip(data.get('fofa_email', ''))
    fofa_key = safe_strip(data.get('fofa_key', ''))
    if not domain:
        return jsonify({'error': '请提供目标域名'}), 400
    if intel_state.get('active'):
        return jsonify({'error': '已有情报查询在运行'}), 400

    # Auto-extract domain from URL
    if '://' in domain:
        domain = threat_intel.extract_domain(domain)

    def run():
        intel_state.update({'active': True, 'progress': 0, 'message': '查询威胁情报...', 'results': None})
        try:
            results = threat_intel.query_all(
                domain, shodan_key=shodan_key,
                censys_id=censys_id, censys_secret=censys_secret,
                fofa_email=fofa_email, fofa_key=fofa_key
            )
            intel_state['results'] = results
            intel_state['progress'] = 100
            intel_state['message'] = f'查询完成，共 {results.get("total_findings", 0)} 条结果'
        except Exception as e:
            intel_state['message'] = f'情报查询出错: {str(e)}'
        finally:
            intel_state['active'] = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'message': '威胁情报查询已启动'})


@app.route('/api/intel/progress', methods=['GET'])
def api_intel_progress():
    return jsonify(intel_state)


# ─── SARIF 导出 ───


@app.route('/api/export/sarif', methods=['GET', 'POST'])
def api_export_sarif():
    try:
        endpoints = db.export_all()
    except Exception:
        return jsonify({'error': '数据导出失败'}), 500

    source_url = ''
    if request.method == 'POST' and request.is_json:
        source_url = safe_strip((request.json or {}).get('url', ''))
    else:
        source_url = request.args.get('url', '')

    # Build scan_results from endpoints
    vulns = []
    sensitive_files = []
    missing_headers = []
    for ep in (endpoints or []):
        if not isinstance(ep, dict):
            continue
        risk = ep.get('risk_level', 'info')
        if risk in ('critical', 'high', 'medium'):
            issues = ep.get('security_issues') or []
            if isinstance(issues, list):
                for issue in issues:
                    if isinstance(issue, dict):
                        vulns.append({
                            'type': issue.get('type', 'unknown'),
                            'severity': risk,
                            'description': issue.get('description', ''),
                            'url': ep.get('url', ''),
                            'parameter': ep.get('category', ''),
                            'evidence': issue.get('evidence', ''),
                        })

    scan_results = {
        'vulnerabilities': vulns,
        'sensitive_files': sensitive_files,
        'missing_headers': missing_headers,
    }

    try:
        sarif = sarif_exporter.export(scan_results, source_url=source_url)
        return jsonify(sarif)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/sarif/file', methods=['GET'])
def api_export_sarif_file():
    try:
        endpoints = db.export_all()
    except Exception:
        return jsonify({'error': '数据导出失败'}), 500

    source_url = request.args.get('url', '')
    vulns = []
    for ep in (endpoints or []):
        if not isinstance(ep, dict):
            continue
        risk = ep.get('risk_level', 'info')
        if risk in ('critical', 'high', 'medium'):
            issues = ep.get('security_issues') or []
            if isinstance(issues, list):
                for issue in issues:
                    if isinstance(issue, dict):
                        vulns.append({
                            'type': issue.get('type', 'unknown'),
                            'severity': risk,
                            'description': issue.get('description', ''),
                            'url': ep.get('url', ''),
                            'parameter': ep.get('category', ''),
                            'evidence': issue.get('evidence', ''),
                        })

    scan_results = {'vulnerabilities': vulns, 'sensitive_files': [], 'missing_headers': []}
    filepath = os.path.join(get_exports_dir(), f'sarif_{int(time.time())}.sarif')
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    try:
        sarif_exporter.export_to_file(scan_results, filepath, source_url=source_url)
        return send_file(filepath, as_attachment=True, download_name='results.sarif')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── JARM TLS 指纹 ───


@app.route('/api/jarm/fingerprint', methods=['POST'])
def api_jarm_fingerprint():
    data = request.json or {}
    host = safe_strip(data.get('host') or data.get('url'))
    port = int(data.get('port', 443))
    if not host:
        return jsonify({'error': '请提供目标主机'}), 400
    # Extract host from URL if needed
    if '://' in host:
        from urllib.parse import urlparse
        parsed = urlparse(host)
        host = parsed.hostname or host
        if parsed.port:
            port = parsed.port
    try:
        result = jarm_fingerprinter.fingerprint(host, port)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/jarm/compare', methods=['POST'])
def api_jarm_compare():
    data = request.json or {}
    t1 = data.get('target1', {})
    t2 = data.get('target2', {})
    if not t1.get('host') or not t2.get('host'):
        return jsonify({'error': '请提供两个目标的 host'}), 400
    try:
        result = jarm_fingerprinter.compare(t1, t2)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Error Handlers ───

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': '接口不存在'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': f'服务器内部错误: {str(e)}'}), 500


def open_browser(port):
    time.sleep(1.5)
    webbrowser.open(f'http://localhost:{port}')


def start_server(port=8888, open_brow=True):
    if open_brow:
        threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    app.run(host='127.0.0.1', port=port, debug=False, threaded=True)
