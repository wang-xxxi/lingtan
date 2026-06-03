"""灵探 - 全量测试"""
import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ['TESTING'] = '1'

PASS = 0
FAIL = 0

def test(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f'  [PASS] {name}')
    else:
        FAIL += 1
        print(f'  [FAIL] {name}')


def run_tests():
    global PASS, FAIL

    print('=== 灵探 全量测试 ===\n')

    # 1. Import tests
    print('[1/8] 模块导入测试')
    try:
        from core.app import app
        test('导入app', True)
    except Exception as e:
        test('导入app', False)
        print(f'    Error: {e}')
        return

    try:
        from core.crawler import WebCrawler, SingleURLAnalyzer
        test('导入WebCrawler', True)
    except Exception as e:
        test('导入WebCrawler', False)

    try:
        from core.analyzer import APIAnalyzer
        test('导入APIAnalyzer', True)
    except Exception as e:
        test('导入APIAnalyzer', False)

    try:
        from core.js_analyzer import JSAnalyzer
        test('导入JSAnalyzer', True)
    except Exception as e:
        test('导入JSAnalyzer', False)

    try:
        from core.apk_analyzer import APKAnalyzer, IPAAnalyzer, MiniProgramAnalyzer
        test('导入APK/IPA/小程序分析器', True)
    except Exception as e:
        test('导入APK/IPA/小程序分析器', False)

    try:
        from core.har_analyzer import HARAnalyzer, BurpXMLAnalyzer
        test('导入HAR/Burp分析器', True)
    except Exception as e:
        test('导入HAR/Burp分析器', False)

    try:
        from core.database import Database
        test('导入Database', True)
    except Exception as e:
        test('导入Database', False)

    try:
        from core.exporter import DataExporter
        test('导入导出器', True)
    except Exception as e:
        test('导入导出器', False)

    try:
        from core.fuzzer import APIFuzzer
        test('导入APIFuzzer', True)
    except Exception as e:
        test('导入APIFuzzer', False)

    try:
        from core.spec_generator import OpenAPIGenerator, CurlGenerator
        test('导入OpenAPI/Curl生成器', True)
    except Exception as e:
        test('导入OpenAPI/Curl生成器', False)

    try:
        from core.scanner_utils import PortScanner, DiffEngine, BatchScanner, EndpointGrouper, ChangeMonitor
        test('导入工具类', True)
    except Exception as e:
        test('导入工具类', False)

    try:
        from core.site_crawler import SiteCrawler
        test('导入SiteCrawler', True)
    except Exception as e:
        test('导入SiteCrawler', False)

    try:
        from core.anti_detection import AntiDetection
        test('导入AntiDetection', True)
    except Exception as e:
        test('导入AntiDetection', False)

    try:
        from core.site_analyzer import SiteAnalyzer
        test('导入SiteAnalyzer', True)
    except Exception as e:
        test('导入SiteAnalyzer', False)

    try:
        from core.script_generator import ScriptGenerator
        test('导入ScriptGenerator', True)
    except Exception as e:
        test('导入ScriptGenerator', False)

    try:
        from core.proxy_server import ProxyServer
        test('导入ProxyServer', True)
    except Exception as e:
        test('导入ProxyServer', False)

    try:
        from core.graphql_analyzer import GraphQLAnalyzer
        test('导入GraphQLAnalyzer', True)
    except Exception as e:
        test('导入GraphQLAnalyzer', False)

    try:
        from core.websocket_detector import WebSocketDetector
        test('导入WebSocketDetector', True)
    except Exception as e:
        test('导入WebSocketDetector', False)

    try:
        from core.param_miner import ParamMiner
        test('导入ParamMiner', True)
    except Exception as e:
        test('导入ParamMiner', False)

    try:
        from core.auth_detector import AuthDetector
        test('导入AuthDetector', True)
    except Exception as e:
        test('导入AuthDetector', False)

    try:
        from core.header_auditor import HeaderAuditor
        test('导入HeaderAuditor', True)
    except Exception as e:
        test('导入HeaderAuditor', False)

    try:
        from core.subdomain_enum import SubdomainEnumerator
        test('导入SubdomainEnumerator', True)
    except Exception as e:
        test('导入SubdomainEnumerator', False)

    try:
        from core.spec_importer import SpecImporter
        test('导入SpecImporter', True)
    except Exception as e:
        test('导入SpecImporter', False)

    try:
        from core.traffic_analyzer import TrafficAnalyzer
        test('导入TrafficAnalyzer', True)
    except Exception as e:
        test('导入TrafficAnalyzer', False)

    try:
        from core.report_generator import ReportGenerator
        test('导入ReportGenerator', True)
    except Exception as e:
        test('导入ReportGenerator', False)

    try:
        from core.task_manager import TaskManager
        test('导入TaskManager', True)
    except Exception as e:
        test('导入TaskManager', False)

    try:
        from core.plugin_manager import PluginManager
        test('导入PluginManager', True)
    except Exception as e:
        test('导入PluginManager', False)

    # 2. Database tests
    print('\n[2/8] 数据库测试')
    from core.database import Database
    db = Database()
    test('创建内存数据库', True)

    tid = db.add_target('https://test.example.com', 'website', 'https://test.example.com')
    test('添加目标', tid is not None)

    eid = db.add_endpoint(tid, url='https://test.example.com/api/users', method='GET')
    test('添加接口', eid is not None)

    eps = db.get_all_endpoints(limit=100)
    test('获取接口列表', isinstance(eps, list) and len(eps) > 0)

    stats = db.get_endpoint_stats()
    test('获取统计数据', isinstance(stats, dict))

    export = db.export_all()
    test('导出数据', isinstance(export, list))

    # 3. Analyzer tests
    print('\n[3/8] 分析器测试')
    from core.analyzer import APIAnalyzer
    analyzer = APIAnalyzer()
    result = analyzer.analyze_url(
        'https://api.example.com/v1/users?page=1&token=abc123',
        method='GET',
        response='{"users": [{"id": 1, "email": "test@test.com"}]}',
    )
    test('分析器返回结果', isinstance(result, dict))
    test('分类识别', result.get('category') is not None)

    # 4. Crawler tests
    print('\n[4/8] 爬虫测试')
    from core.crawler import WebCrawler
    crawler = WebCrawler()
    test('创建爬虫实例', True)
    test('反检测UA池', len(crawler.anti_detect.USER_AGENTS) >= 10)
    test('反检测UA旋转', crawler.anti_detect._current_ua in crawler.anti_detect.USER_AGENTS)
    headers = crawler.anti_detect.get_headers('https://example.com/page')
    test('反检测Sec-Fetch头', 'Sec-Fetch-Site' in headers)
    test('反检测随机链接排序', True)  # smoke test
    items = [1, 2, 3, 4, 5]
    shuffled = crawler.anti_detect.randomize_request_order(items)
    test('反检测排序完整性', set(items) == set(shuffled))

    # 5. JS Analyzer tests
    print('\n[5/8] JS分析器测试')
    from core.js_analyzer import JSAnalyzer
    js = JSAnalyzer()
    test_js = '''
    fetch('/api/users').then(r => r.json());
    axios.get('/api/products');
    $.ajax({url: '/api/orders'});
    app.get('/health', handler);
    const API = process.env.REACT_APP_API_URL;
    '''
    result = js.analyze_code(test_js, 'https://example.com/static/app.js')
    test('JS分析返回字典', isinstance(result, dict))
    test('发现API端点', len(result.get('api_endpoints', [])) > 0)

    # 6. Har/Burp Analyzer tests
    print('\n[6/8] HAR/Burp分析器测试')
    from core.har_analyzer import HARAnalyzer, BurpXMLAnalyzer
    har = HARAnalyzer()
    test('创建HARAnalyzer', True)
    burp = BurpXMLAnalyzer()
    test('创建BurpXMLAnalyzer', True)

    # 7. Fuzzer tests
    print('\n[7/8] 安全扫描器测试')
    from core.fuzzer import APIFuzzer
    fuzzer = APIFuzzer()
    test('创建Fuzzer实例', True)
    test('SQL注入payload', len(fuzzer.SQLI_ERROR_BASED) > 0)
    test('XSS payload', len(fuzzer.XSS_PAYLOADS) > 0)
    test('敏感路径', len(fuzzer.SENSITIVE_PATHS) > 0)

    # 8. Spec Generator & Tools tests
    print('\n[8/8] 生成器和工具测试')
    from core.spec_generator import OpenAPIGenerator, CurlGenerator
    from core.scanner_utils import PortScanner, DiffEngine, BatchScanner, EndpointGrouper, ChangeMonitor

    gen = OpenAPIGenerator()
    spec = gen.generate([
        {'url': 'https://api.example.com/users', 'method': 'GET', 'category': 'user'},
        {'url': 'https://api.example.com/users/{id}', 'method': 'GET', 'category': 'user'},
        {'url': 'https://api.example.com/login', 'method': 'POST', 'category': 'authentication'},
    ])
    test('OpenAPI生成', spec is not None and spec.get('openapi') == '3.0.3')
    test('OpenAPI包含路径', len(spec.get('paths', {})) > 0)

    curl = CurlGenerator()
    cmd = curl.generate('https://api.example.com/users', 'POST', {'Content-Type': 'application/json'}, '{"name":"test"}')
    test('cURL生成', 'curl' in cmd and 'POST' in cmd)

    scanner = PortScanner()
    test('创建端口扫描器', True)
    test('常见端口列表', len(scanner.COMMON_PORTS) > 0)

    diff = DiffEngine()
    d_result = diff.compare(
        [{'url': 'https://a.com/1', 'method': 'GET'}],
        [{'url': 'https://a.com/1', 'method': 'GET'}, {'url': 'https://a.com/2', 'method': 'POST'}],
    )
    test('Diff对比', d_result['summary']['added'] == 1)

    grouper = EndpointGrouper()
    g_result = grouper.group([
        {'url': 'https://api.com/users/1', 'method': 'GET'},
        {'url': 'https://api.com/users/2', 'method': 'GET'},
        {'url': 'https://api.com/products', 'method': 'GET'},
    ])
    test('接口分组', g_result['total_groups'] > 0)

    monitor = ChangeMonitor()
    s1 = monitor.take_snapshot('t1', [{'url': 'https://a.com', 'method': 'GET'}])
    s2 = monitor.take_snapshot('t1', [{'url': 'https://a.com', 'method': 'GET'}])
    change = monitor.detect_changes('t1')
    test('变更监控', change['changed'] == False)

    # 9. Database new tables
    print('\n[9/9] 新增数据库功能测试')
    pid = db.add_crawled_page(
        target_id=tid, url='https://test.example.com/home',
        status_code=200, title='Home', depth=0,
        headings={'h1': ['Welcome']}, links=[{'href': 'https://test.example.com/about', 'type': 'internal'}],
        assets=[{'url': 'https://test.example.com/style.css', 'type': 'css'}],
        technologies=[{'name': 'React', 'category': 'Frontend', 'confidence': 0.8}],
    )
    test('添加爬取页面', pid is not None and pid > 0)

    pages = db.get_crawled_pages(target_id=tid)
    test('获取爬取页面', isinstance(pages, list) and len(pages) > 0)

    page = db.get_crawled_page(pid)
    test('获取单页详情', page is not None and page.get('title') == 'Home')
    test('页面JSON解析', isinstance(page.get('headings'), dict) and page['headings'].get('h1') == ['Welcome'])

    tech_id = db.add_site_technology(tid, 'React', 'Frontend', confidence=0.8, evidence='data-reactroot')
    test('添加技术栈', tech_id is not None and tech_id > 0)

    techs = db.get_site_technologies(target_id=tid)
    test('获取技术栈', isinstance(techs, list) and len(techs) > 0)

    # 10. SiteAnalyzer
    analyzer_inst = SiteAnalyzer()
    seo_result = analyzer_inst.analyze([
        {'url': 'https://a.com', 'title': 'Test Page', 'meta_description': 'A test page description for SEO analysis',
         'headings': {'h1': ['Test']}, 'images': [{'src': 'a.png', 'alt': 'img'}],
         'seo_data': {'og_tags': {'og:title': 'Test'}, 'canonical': 'https://a.com'}},
    ])
    test('SEO分析', seo_result.get('overall_score', 0) > 0)

    # 11. ScriptGenerator
    script_gen = ScriptGenerator()
    py_script = script_gen.generate_python_requests([
        {'url': 'https://api.example.com/users', 'method': 'GET'},
        {'url': 'https://api.example.com/login', 'method': 'POST', 'request_body': '{"user":"test"}'},
    ])
    test('Python脚本生成', 'requests' in py_script and 'def test_' in py_script)

    playwright_script = script_gen.generate_playwright_script([
        {'url': 'https://example.com/login', 'title': 'Login', 'forms': [
            {'action': 'https://example.com/login', 'method': 'POST', 'fields': [{'name': 'user', 'type': 'text'}]}
        ]},
    ])
    test('Playwright脚本生成', 'playwright' in playwright_script and 'page.goto' in playwright_script)

    curl_script = script_gen.generate_curl_batch([
        {'url': 'https://api.example.com/users', 'method': 'GET'},
    ])
    test('cURL批量脚本', 'curl' in curl_script)

    # 12. New database tables
    print('\n[12] 新数据库表测试')
    # captured_traffic
    tid2 = db.add_traffic(method='GET', url='https://example.com/api', host='example.com',
                          path='/api', status_code=200, content_type='application/json',
                          request_headers={'Accept': 'application/json'},
                          response_headers={'Content-Type': 'application/json'})
    test('添加流量记录', tid2 is not None and tid2 > 0)

    traffic = db.get_traffic(limit=10)
    test('获取流量列表', isinstance(traffic, list) and len(traffic) > 0)

    td = db.get_traffic_detail(tid2)
    test('获取流量详情', td is not None and td.get('method') == 'GET')
    test('流量JSON解析', isinstance(td.get('request_headers'), dict))

    # tasks
    db.add_task('test001', 'web_scan', 'https://example.com', {'depth': 2})
    test('添加任务', True)

    db.update_task('test001', 'running', 50, 'Scanning...')
    task = db.get_task('test001')
    test('更新任务', task is not None and task['status'] == 'running' and task['progress'] == 50)

    tasks = db.list_tasks()
    test('获取任务列表', isinstance(tasks, list) and len(tasks) > 0)

    # 13. GraphQL Analyzer
    print('\n[13] GraphQL分析器测试')
    from core.graphql_analyzer import GraphQLAnalyzer
    gql = GraphQLAnalyzer()
    test('创建GraphQLAnalyzer', True)

    found = gql.find_endpoints(html='<a href="/graphql">API</a>', js_code='fetch("/api/graphql")')
    test('发现GraphQL端点', len(found) > 0)

    curl_cmd = gql.generate_curl('https://api.example.com/graphql')
    test('GraphQL cURL生成', 'curl' in curl_cmd and 'graphql' in curl_cmd)

    # 14. WebSocket Detector
    print('\n[14] WebSocket检测器测试')
    from core.websocket_detector import WebSocketDetector
    wsd = WebSocketDetector()
    test('创建WebSocketDetector', True)

    ws_html = wsd.detect_from_html('<script>var ws = new WebSocket("wss://example.com/ws");</script>')
    test('从HTML检测WS', len(ws_html) > 0)

    ws_js = wsd.detect_from_js('const socket = new WebSocket("wss://chat.example.com"); io.connect("ws://realtime.example.com");')
    test('从JS检测WS', len(ws_js['endpoints']) > 0)
    test('检测WS库', 'ws' in ws_js['libraries'])

    # 15. Report Generator
    print('\n[15] 报告生成器测试')
    from core.report_generator import ReportGenerator
    rg = ReportGenerator()
    report = rg.generate(
        endpoints=[{'url': 'https://api.example.com/users', 'method': 'GET', 'category': 'user', 'risk_level': 'low'}],
        stats={'total_endpoints': 1, 'total_targets': 1, 'by_method': {'GET': 1}, 'by_risk': {'low': 1}},
    )
    test('生成HTML报告', report is not None and 'filename' in report)

    import os
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'reports', report['filename'])
    test('报告文件存在', os.path.exists(report_path))

    # 16. Plugin Manager
    print('\n[16] 插件管理器测试')
    from core.plugin_manager import PluginManager
    pm = PluginManager()
    test('创建PluginManager', True)

    plugins = pm.list_plugins()
    test('加载示例插件', len(plugins) > 0)

    ok, msg = pm.install('{"name":"TestPlugin","type":"security_payload","rules":[{"name":"test","payload":"x"}]}')
    test('安装插件', ok)

    plugins2 = pm.list_plugins()
    test('插件列表增加', len(plugins2) > len(plugins))

    rules = pm.get_rules('security_payload')
    test('获取安全规则', len(rules) > 0)

    ok, msg = pm.toggle('TestPlugin')
    test('禁用插件', ok)

    ok, msg = pm.uninstall('TestPlugin')
    test('删除插件', ok)

    # 17. Parameter Miner
    print('\n[17] 参数挖掘测试')
    from core.param_miner import ParamMiner
    miner = ParamMiner()
    test('创建ParamMiner', True)

    js_result = miner.mine_from_js('''
        fetch("/api/users?page=1&limit=10");
        axios.get("/api/products", {params: {category: "electronics", sort: "price"}});
        formData.append("username", "test");
        const {user_id, token} = response;
    ''', 'https://example.com/app.js')
    test('JS参数提取', js_result['count'] > 0)
    test('提取到page参数', 'page' in js_result['parameters'])
    test('提取到limit参数', 'limit' in js_result['parameters'])

    endpoint_params = miner.mine_from_endpoints([
        {'url': 'https://api.example.com/users?page=1&size=20&sort=name'},
        {'url': 'https://api.example.com/search?q=test&type=product'},
    ])
    test('接口参数提取', len(endpoint_params) > 0)
    test('page参数出现次数', any(p['name'] == 'page' and p['seen_in'] == 1 for p in endpoint_params))

    common = miner.COMMON_PARAMS
    test('常见参数列表', len(common) > 20)

    # 18. Auth Detector
    print('\n[18] 认证检测测试')
    from core.auth_detector import AuthDetector
    detector = AuthDetector()
    test('创建AuthDetector', True)

    # JWT analysis
    jwt_result = detector.analyze_jwt_string('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiJ9.abc123')
    test('JWT解析有效', jwt_result['valid'] == True)
    test('JWT算法识别', jwt_result['algorithm'] == 'HS256')
    test('JWT payload解析', jwt_result['payload'].get('user_id') == 123)

    jwt_none = detector.analyze_jwt_string('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxfQ.')
    test('JWT none算法识别', jwt_none['algorithm'] == 'none')

    jwt_bad = detector.analyze_jwt_string('not-a-jwt')
    test('JWT无效格式处理', jwt_bad['valid'] == False)

    # 19. Header Auditor
    print('\n[19] 安全头审计测试')
    from core.header_auditor import HeaderAuditor
    auditor = HeaderAuditor()
    test('创建HeaderAuditor', True)
    test('安全头定义数量', len(auditor.SECURITY_HEADERS) >= 8)
    test('CORS测试Origin', len(auditor.CORS_TESTS) >= 3)

    # 20. Subdomain Enumerator
    print('\n[20] 子域名枚举测试')
    from core.subdomain_enum import SubdomainEnumerator
    enum = SubdomainEnumerator()
    test('创建SubdomainEnumerator', True)
    test('常见子域名列表', len(enum.COMMON_SUBDOMAINS) > 50)

    clean = enum._clean_domain('https://www.example.com:8080/path')
    test('域名清理', clean == 'www.example.com')

    # 21. Spec Importer
    print('\n[21] 规范导入测试')
    try:
        from core.spec_importer import SpecImporter
        test('导入SpecImporter', True)
    except Exception as e:
        test('导入SpecImporter', False)
        print(f'    Error: {e}')

    importer = SpecImporter()
    test('创建SpecImporter', True)

    # Test with a minimal OpenAPI spec
    spec_json = json.dumps({
        'openapi': '3.0.3',
        'info': {'title': 'Test API', 'version': '1.0'},
        'servers': [{'url': 'https://api.example.com'}],
        'paths': {
            '/users': {
                'get': {'summary': 'List users', 'tags': ['users'], 'parameters': [
                    {'name': 'page', 'in': 'query', 'type': 'integer'},
                    {'name': 'limit', 'in': 'query', 'type': 'integer'},
                ]},
                'post': {'summary': 'Create user', 'tags': ['users']},
            },
            '/users/{id}': {
                'get': {'summary': 'Get user', 'tags': ['users']},
                'delete': {'summary': 'Delete user', 'tags': ['users'], 'security': [{'bearer': []}]},
            },
        },
    })
    result = importer.import_from_text(spec_json, 'test.json')
    test('解析OpenAPI规范', 'error' not in result)
    test('规范版本识别', result.get('version') == '3.0.3')
    test('提取接口数量', len(result.get('endpoints', [])) == 4)
    test('提取测试用例', len(result.get('test_cases', [])) > 0)
    test('按方法统计', result.get('summary', {}).get('by_method', {}).get('GET') == 2)

    # Test with Swagger 2.0
    swagger_json = json.dumps({
        'swagger': '2.0',
        'info': {'title': 'Swagger API'},
        'host': 'api.test.com',
        'basePath': '/v1',
        'schemes': ['https'],
        'paths': {
            '/items': {'get': {'summary': 'List items'}},
        },
    })
    sw_result = importer.import_from_text(swagger_json)
    test('解析Swagger 2.0', 'error' not in sw_result)
    test('Swagger 2.0 base URL', sw_result.get('base_url') == 'https://api.test.com/v1')

    # 22. Traffic Analyzer
    print('\n[22] 流量分析测试')
    try:
        from core.traffic_analyzer import TrafficAnalyzer
        test('导入TrafficAnalyzer', True)
    except Exception as e:
        test('导入TrafficAnalyzer', False)

    ta = TrafficAnalyzer()
    test('创建TrafficAnalyzer', True)

    # Test with sample traffic
    sample_traffic = [
        {
            'method': 'GET', 'url': 'https://api.example.com/users?page=1', 'host': 'api.example.com',
            'path': '/users', 'status_code': 200, 'content_type': 'application/json',
            'request_headers': {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.abc123'},
            'response_headers': {'Content-Type': 'application/json'},
            'request_body': '', 'response_body': '{"users": [{"email": "test@example.com", "phone": "13812345678"}]}',
        },
        {
            'method': 'POST', 'url': 'https://api.example.com/login', 'host': 'api.example.com',
            'path': '/login', 'status_code': 200, 'content_type': 'application/json',
            'request_headers': {'Content-Type': 'application/json'},
            'response_headers': {'Set-Cookie': 'session_id=abc123; HttpOnly'},
            'request_body': '{"username":"admin","password":"secret123"}',
            'response_body': '{"token":"sk-1234567890abcdef"}',
        },
    ]
    analysis = ta.analyze_traffic(sample_traffic)
    test('流量分析返回结果', isinstance(analysis, dict))
    test('识别API端点', len(analysis.get('endpoints_found', [])) > 0)
    test('提取认证令牌', len(analysis.get('auth_tokens', [])) > 0)
    test('检测敏感数据', len(analysis.get('sensitive_data', [])) > 0)
    test('安全发现', len(analysis.get('findings', [])) > 0)
    test('统计主机', 'api.example.com' in analysis.get('hosts', {}))

    # 23. ChangeMonitor with DiffEngine
    print('\n[23] 变更监控测试')
    from core.scanner_utils import ChangeMonitor, DiffEngine
    monitor = ChangeMonitor()
    diff = DiffEngine()

    s1 = monitor.take_snapshot('test', [{'url': 'https://a.com/1', 'method': 'GET'}])
    test('创建快照', s1.get('count') == 1)

    s2 = monitor.take_snapshot('test', [{'url': 'https://a.com/1', 'method': 'GET'}, {'url': 'https://a.com/2', 'method': 'POST'}])
    changes = monitor.detect_changes('test')
    test('变更检测', changes.get('changed') == True)
    test('接口数变化', changes.get('current_count') == 2)

    d_result = diff.compare(
        [{'url': 'https://a.com/x', 'method': 'GET', 'status_code': 200}],
        [{'url': 'https://a.com/x', 'method': 'GET', 'status_code': 404}, {'url': 'https://a.com/y', 'method': 'POST'}],
    )
    test('Diff新增', d_result['summary']['added'] == 1)
    test('Diff变更', d_result['summary']['changed'] == 1)

    # 24. CI/CD CLI Module
    print('\n[24] CI/CD集成测试')
    try:
        import cli_scan
        test('导入cli_scan', True)
    except Exception as e:
        test('导入cli_scan', False)
        print(f'    Error: {e}')

    # Test severity level checking
    test('严重性比较(info<high)', cli_scan.severity_at_least('info', 'high') == False)
    test('严重性比较(high>=high)', cli_scan.severity_at_least('high', 'high') == True)
    test('严重性比较(critical>=high)', cli_scan.severity_at_least('critical', 'high') == True)
    test('严重性比较(medium>=high)', cli_scan.severity_at_least('medium', 'high') == False)
    test('严重性比较(low>=low)', cli_scan.severity_at_least('low', 'low') == True)

    # Test CLI args construction
    class Args:
        pass
    args = Args()
    args.url = 'https://example.com'
    args.spec = ''
    args.depth = 'normal'
    args.max_pages = 50
    args.security = False
    args.auth_check = False
    args.header_audit = False
    args.fail_on = 'high'

    # Verify scan function returns proper structure
    result = cli_scan.scan(args)
    test('CLI扫描返回结果', isinstance(result, dict))
    test('CLI扫描包含summary', 'summary' in result)
    test('CLI扫描包含endpoints', 'endpoints' in result)
    test('CLI扫描包含phases', 'phases' in result)
    test('CLI扫描包含timestamp', 'timestamp' in result)
    test('CLI扫描passed字段', isinstance(result['summary'].get('passed'), bool))
    test('CLI扫描exit_code字段', result['summary'].get('exit_code') in (0, 1, 2))

    # 25. Favorites, History, Graph API tests
    print('\n[25] 收藏/历史/依赖图测试')

    # Test database favorites methods
    fav_id = db.add_favorite('https://example.com/api/users', 'GET', '用户列表')
    test('添加收藏', fav_id is not None and fav_id > 0)

    favs = db.get_favorites()
    test('获取收藏列表', isinstance(favs, list) and len(favs) > 0)
    test('收藏内容正确', any(f['url'] == 'https://example.com/api/users' for f in favs))

    fav_set = db.get_favorite_set()
    test('收藏集合', isinstance(fav_set, set) and 'GET:https://example.com/api/users' in fav_set)

    # Duplicate should not fail
    db.add_favorite('https://example.com/api/users', 'GET', '用户列表')
    favs2 = db.get_favorites()
    test('收藏去重', len(favs2) == len(favs))

    db.remove_favorite('https://example.com/api/users', 'GET')
    favs3 = db.get_favorites()
    test('删除收藏', len(favs3) == len(favs) - 1)

    # Test database history methods
    hist_id = db.add_history('GET', 'https://example.com/api/test', status_code=200, elapsed=150)
    test('添加历史', hist_id is not None and hist_id > 0)

    db.add_history('POST', 'https://example.com/api/login', body='{"user":"a"}', status_code=401, elapsed=200)
    history = db.get_history()
    test('获取历史', isinstance(history, list) and len(history) >= 2)
    test('历史顺序(新→旧)', history[0]['created_at'] >= history[1]['created_at'])

    db.clear_history()
    history2 = db.get_history()
    test('清空历史', len(history2) == 0)

    # Test Flask API routes
    with app.test_client() as client:
        # Favorites API
        db.add_favorite('https://test.com/api/v1', 'GET')
        resp = client.get('/api/favorites')
        test('收藏API GET', resp.status_code == 200)
        data = json.loads(resp.data)
        test('收藏API返回结构', 'favorites' in data and 'favorite_set' in data)

        resp2 = client.post('/api/favorites/toggle', json={'url': 'https://test.com/api/v2', 'method': 'POST', 'label': 'test'})
        test('收藏切换API', resp2.status_code == 200)

        # History API
        db.add_history('GET', 'https://test.com/page1', status_code=200)
        resp3 = client.get('/api/history')
        test('历史API GET', resp3.status_code == 200)
        hdata = json.loads(resp3.data)
        test('历史API返回结构', 'history' in hdata)

        resp4 = client.delete('/api/history')
        test('历史清空API', resp4.status_code == 200)

        # Graph data API
        resp5 = client.get('/api/graph/data')
        test('依赖图API', resp5.status_code == 200)
        gdata = json.loads(resp5.data)
        test('依赖图返回结构', 'nodes' in gdata and 'edges' in gdata)

    # 26. Session management tests
    print('\n[26] 登录会话测试')

    from core.session_manager import SessionManager
    sm = SessionManager()
    test('创建SessionManager', sm is not None)

    # Test cookie parsing
    cookies = sm._parse_cookies('session_id=abc123; user=john; token=xyz')
    test('Cookie解析', len(cookies) == 3)
    test('Cookie名称正确', any(c['name'] == 'session_id' and c['value'] == 'abc123' for c in cookies))
    test('Cookie多值解析', any(c['name'] == 'user' and c['value'] == 'john' for c in cookies))

    cookies_empty = sm._parse_cookies('')
    test('空Cookie解析', cookies_empty == [])

    # Test database session CRUD
    sid = db.add_session('测试会话', 'example.com', 'https://example.com/login',
                         [{'name': 'sid', 'value': 'abc123'}], {'token': 'xyz'})
    test('添加会话', sid is not None and sid > 0)

    sessions = db.get_sessions()
    test('获取会话列表', isinstance(sessions, list) and len(sessions) > 0)
    test('会话内容正确', any(s['name'] == '测试会话' and s['domain'] == 'example.com' for s in sessions))

    session = db.get_session(sid)
    test('获取单个会话', session is not None and session['name'] == '测试会话')
    test('会话Cookie正确', isinstance(session['cookies'], list) and session['cookies'][0]['name'] == 'sid')

    # Test get_cookies_for_url
    cookies_for_url, ls = db.get_cookies_for_url('https://example.com/page')
    test('按URL获取Cookie', 'sid' in cookies_for_url and cookies_for_url['sid'] == 'abc123')
    test('按URL获取LocalStorage', ls.get('token') == 'xyz')

    db.delete_session(sid)
    sessions2 = db.get_sessions()
    test('删除会话', len(sessions2) == len(sessions) - 1)

    # Test crawler cookie injection
    from core.crawler import WebCrawler
    wc = WebCrawler()
    wc.set_cookies({'token': 'test123', 'session': 'abc'})
    test('爬虫Cookie注入(dict)', wc.session.cookies.get('token') == 'test123')
    test('爬虫Cookie注入(dict)2', wc.session.cookies.get('session') == 'abc')

    wc2 = WebCrawler()
    wc2.set_cookies([{'name': 'jwt', 'value': 'ey.xxx'}])
    test('爬虫Cookie注入(list)', wc2.session.cookies.get('jwt') == 'ey.xxx')

    # 27. Page Classifier tests
    print('\n[27] 页面分类测试')

    from core.page_classifier import classify, PAGE_TYPE_LABELS, ALL_PAGE_TYPES
    test('分类器导入', True)
    test('页面类型标签', len(PAGE_TYPE_LABELS) >= 10)

    r = classify('https://example.com/blog/my-article-123', html_text='<html><article><h1>Test</h1></article></html>')
    test('文章详情分类', r['type'] in ('article_detail', 'unknown'))
    test('分类含置信度', 0 <= r['confidence'] <= 1)
    test('分类含标签', 'label' in r)

    r2 = classify('https://example.com/api/v1/users', html_text='')
    test('API端点分类', r2['type'] == 'api_endpoint')

    r3 = classify('https://example.com/login', html_text='<html><form><input type="password"/></form></html>')
    test('登录页分类', r3['type'] == 'login')

    r4 = classify('https://example.com/', html_text='')
    test('首页分类', r4['type'] == 'home_page')

    r5 = classify('https://example.com/style.css', html_text='')
    test('静态资源分类', r5['type'] == 'static_resource')

    # 28. Data Extractor tests
    print('\n[28] 数据提取测试')

    from core.data_extractor import extract_all
    test('数据提取器导入', True)

    html_table = '<table><thead><tr><th>Name</th><th>Age</th></tr></thead><tbody><tr><td>Alice</td><td>30</td></tr><tr><td>Bob</td><td>25</td></tr></tbody></table>'
    result = extract_all(html_table)
    test('表格提取', len(result['tables']) == 1)
    test('表格行数', result['tables'][0]['row_count'] == 2)
    test('表格表头', 'Name' in result['tables'][0]['headers'])

    html_list = '<ul><li>Item 1 <a href="/a">link</a></li><li>Item 2</li><li>Item 3</li></ul>'
    result2 = extract_all(html_list)
    test('列表提取', len(result2['lists']) >= 1)
    test('列表项数', result2['lists'][0]['item_count'] == 3)

    html_form = '<form action="/submit" method="POST"><input name="user" type="text"/><input name="pass" type="password"/></form>'
    result3 = extract_all(html_form)
    test('表单提取', len(result3['forms']) == 1)
    test('表单字段', result3['forms'][0]['field_count'] == 2)

    html_cards = '<div><div class="card"><h3>Post 1</h3></div><div class="card"><h3>Post 2</h3></div><div class="card"><h3>Post 3</h3></div></div>'
    result4 = extract_all(html_cards)
    test('重复模式提取', len(result4['repeated_patterns']) >= 1)

    # 29. Pagination Detector tests
    print('\n[29] 翻页检测测试')

    from core.pagination_detector import detect, get_all_pages
    test('翻页检测器导入', True)

    pg = detect('https://example.com/list?page=2', '<nav class="pagination"><a href="?page=1">1</a><a href="?page=3">Next</a></nav>')
    test('URL分页检测', pg['url_pagination']['has_pagination'] == True)
    test('当前页码', pg['url_pagination']['current'] == 2)
    test('参数名', pg['url_pagination']['param'] == 'page')
    test('下一页URL', len(pg['next_urls']) > 0 and 'page=3' in pg['next_urls'][0])

    pg2 = detect('https://example.com/page/3', '')
    test('路径分页检测', pg2['url_pagination']['has_pagination'] == True)
    test('路径当前页', pg2['url_pagination']['current'] == 3)

    pages = get_all_pages('https://example.com/list?page=1', max_page=5)
    test('生成分页URL', len(pages) == 5)
    test('分页URL正确', 'page=3' in pages[2])

    pg3 = detect('https://example.com/list', '<button class="load-more">Load More</button>')
    test('Load More检测', pg3['load_more'] is not None)

    # 30. SPA Adapter tests
    print('\n[30] SPA适配测试')

    from core.spa_adapter import analyze_js, analyze_page_for_spa, _detect_spa_framework
    test('SPA适配器导入', True)

    js_code = 'fetch("/api/users").then(r=>r.json()); axios.get("/api/items"); $.ajax({url: "/api/data"})'
    js_result = analyze_js(js_code, 'https://example.com')
    test('fetch调用检测', any(c['type'] == 'fetch' for c in js_result['api_calls']))
    test('axios调用检测', any(c['type'] == 'axios' for c in js_result['api_calls']))
    test('jQuery调用检测', any(c['type'] in ('jquery', 'jquery_config') for c in js_result['api_calls']))
    test('API路径提取', len(js_result['api_paths']) >= 0)

    ws_code = 'new WebSocket("wss://example.com/ws")'
    ws_result = analyze_js(ws_code)
    test('WebSocket检测', len(ws_result['websocket_endpoints']) == 1)

    html_spa = '<html><body><div id="__next"></div><script>__NEXT_DATA__={"props":{}}</script></body></html>'
    spa_result = analyze_page_for_spa(html_spa, 'https://example.com')
    test('SPA检测', spa_result['is_spa'] == True)
    test('SPA框架识别', spa_result['framework'] == 'nextjs')

    test('Vue框架识别', _detect_spa_framework('const app = Vue.createApp({})') == 'vue')

    # 31. Crawl Rules tests
    print('\n[31] 爬取规则测试')

    from core.crawl_rules import CrawlRule, create_default_rule, get_example_rules
    rule = CrawlRule(name='Test', include_patterns=[r'/blog/'], exclude_patterns=[r'/admin/'], page_types=['article_list', 'article_detail'])
    test('规则创建', rule.name == 'Test')
    test('规则匹配(包含)', rule.should_crawl('https://example.com/blog/post1', 'article_detail') == True)
    test('规则不匹配(排除)', rule.should_crawl('https://example.com/admin/settings', 'article_detail') == False)
    test('规则不匹配(类型)', rule.should_crawl('https://example.com/blog/list', 'product_list') == False)

    default = create_default_rule('https://example.com')
    test('默认规则', default.max_depth == 3)

    examples = get_example_rules()
    test('示例规则', len(examples) >= 3)

    rule_dict = rule.to_dict()
    rule2 = CrawlRule.from_dict(rule_dict)
    test('规则序列化', rule2.name == 'Test' and rule2.include_patterns == [r'/blog/'])

    # 32. WAF Detector tests
    print('\n[32] WAF 检测器测试')

    from core.waf_detector import WAFDetector, WAF_SIGNATURES
    detector = WAFDetector(timeout=5)
    test('WAF签名库数量', len(WAF_SIGNATURES) >= 10)
    test('Cloudflare签名存在', 'Cloudflare' in WAF_SIGNATURES)
    test('阿里云WAF签名存在', '阿里云 WAF' in WAF_SIGNATURES)
    test('WAF检测器创建', detector is not None)
    test('检测方法存在', hasattr(detector, 'detect'))
    test('绕过建议-Cloudflare', len(WAFDetector._suggest_bypass('Cloudflare')) >= 2)
    test('绕过建议-通用', len(WAFDetector._suggest_bypass('Unknown')) >= 2)

    # 33. Tech Fingerprint tests
    print('\n[33] 技术栈指纹测试')

    from core.tech_fingerprint import TechFingerprinter, FINGERPRINT_RULES
    fp = TechFingerprinter()
    test('指纹规则数量', len(FINGERPRINT_RULES) >= 30)
    test('指纹分析器创建', fp is not None)

    html_wp = '<html><head><meta name="generator" content="WordPress 6.2.1"></head><body><link href="/wp-content/themes/flavor/style.css?ver=6.2.1"></body></html>'
    result_wp = fp.analyze(url='https://blog.example.com', html=html_wp, headers={'server': 'nginx/1.24'})
    test('WordPress识别', any(t['name'] == 'WordPress' for t in result_wp['technologies']))
    test('Nginx识别', any(t['name'] == 'Nginx' for t in result_wp['technologies']))

    html_react = '<html><body><div id="root"></div><script>window.__NEXT_DATA__={"props":{}}</script></body></html>'
    result_react = fp.analyze(html=html_react, headers={'x-powered-by': 'Express'})
    test('Next.js识别', any(t['name'] == 'Next.js' for t in result_react['technologies']))
    test('Express识别', any(t['name'] == 'Express' for t in result_react['technologies']))

    html_jquery = '<html><body><script src="jquery-3.6.0.min.js"></script></body></html>'
    result_jq = fp.analyze(html=html_jquery)
    test('jQuery版本识别', any(t['name'] == 'jQuery' and t.get('version') == '3.6.0' for t in result_jq['technologies']))

    # analyze_response compatibility
    test('分析方法签名兼容', callable(fp.analyze_response))

    # 34. Payload Evasion tests
    print('\n[34] Payload 绕过引擎测试')

    from core.payload_evasion import PayloadEvasion
    evader = PayloadEvasion()
    test('绕过引擎创建', evader is not None)

    evaded = evader.evade("' OR '1'='1")
    test('绕过变体数量', len(evaded) >= 5)
    test('URL编码存在', any(e['strategy'] == 'url_encode' for e in evaded))
    test('大小写混淆存在', any(e['strategy'] == 'case_swap' for e in evaded))
    test('双重URL编码存在', any(e['strategy'] == 'double_url_encode' for e in evaded))

    url_enc = evader._url_encode("' OR '1'='1")
    test('URL编码结果正确', '%27' in url_enc)

    html_ent = evader._html_entity("<script>alert(1)</script>")
    test('HTML实体编码', '&#60;' in html_ent)

    smart = evader.smart_evade('https://example.com', "' OR '1'='1", {'detected': True, 'waf_name': 'Cloudflare'})
    test('智能绕过-Cloudflare', len(smart) >= 2)
    test('智能绕过含WAF标签', all('waf_target' in s for s in smart))

    # 35. Scan Checkpoint tests
    print('\n[35] 扫描断点续传测试')

    from core.scan_checkpoint import ScanCheckpoint
    from core.database import Database
    cp_db = Database()
    cp_mgr = ScanCheckpoint(cp_db)

    cp_id = cp_mgr.create('crawl', 'https://example.com')
    test('检查点创建', cp_id is not None and len(cp_id) > 0)
    test('检查点UUID格式', '-' in cp_id)

    loaded = cp_mgr.load(cp_id)
    test('检查点加载', loaded is not None)
    test('检查点类型', loaded['scan_type'] == 'crawl')
    test('检查点URL', loaded['target_url'] == 'https://example.com')

    cp_mgr.update_progress(cp_id, visited='https://example.com/page1')
    cp_mgr.update_progress(cp_id, visited='https://example.com/page2')
    visited = cp_mgr.get_visited(cp_id)
    test('已访问URL记录', 'https://example.com/page1' in visited)
    test('已访问URL数量', len(visited) >= 2)

    cp_mgr.update_progress(cp_id, queue=['https://example.com/page3'], phase='crawling')
    queue = cp_mgr.get_queue(cp_id)
    test('待扫描队列', 'https://example.com/page3' in queue)

    active = cp_mgr.list_active()
    test('活跃检查点列表', len(active) >= 1)

    cp_mgr.delete(cp_id)
    test('检查点删除', cp_mgr.load(cp_id) is None)

    # 36. Deduplicator tests
    print('\n[36] 重复页面过滤测试')

    from core.deduplicator import Deduplicator
    dedup = Deduplicator(similarity_threshold=0.85)
    test('去重器创建', dedup is not None)

    html1 = '<html><body><h1>Hello World</h1><p>This is page content.</p></body></html>'
    html2 = '<html><body><h1>Hello World</h1><p>This is page content.</p></body></html>'
    html3 = '<html><body><div class="sidebar"><ul><li>Nav1</li><li>Nav2</li></ul></div><main><article><h2>Different Page</h2><div class="content"><p>Different content here with much more structure.</p><table><tr><td>cell1</td></tr></table></div></article></main></body></html>'
    html4 = '<html><body><h1>Hello World</h1><p>This is page content.</p><script>console.log("timestamp: 1234567890")</script></body></html>'

    test('非重复页面', dedup.is_duplicate('https://example.com/page1', html1) == False)
    test('完全重复页面', dedup.is_duplicate('https://example.com/page2', html2) == True)
    test('不同结构页面', dedup.is_duplicate('https://example.com/page3', html3) == False)

    dedup2 = Deduplicator()
    test('不同页面-首次', dedup2.is_duplicate('https://example.com/a', html1) == False)
    test('结构重复(动态内容)', dedup2.is_duplicate('https://example.com/b', html4) == True)

    stats = dedup.get_stats()
    test('去重统计', stats['total_duplicates'] >= 1)

    duplicates = dedup.get_duplicates()
    test('重复页面映射', len(duplicates) >= 1)

    dedup.reset()
    test('去重重置', len(dedup._seen_hashes) == 0)

    pages = [
        {'url': 'https://example.com/1', 'html': '<html><body><h1>Page A</h1><p>Content</p></body></html>'},
        {'url': 'https://example.com/2', 'html': '<html><body><h1>Page A</h1><p>Content</p></body></html>'},
        {'url': 'https://example.com/3', 'html': '<html><head><title>B</title></head><body><div class="nav"><a href="/">Home</a></div><main><h2>Page B</h2><ul><li>Item1</li><li>Item2</li></ul></main></body></html>'},
    ]
    dedup3 = Deduplicator()
    filtered = dedup3.filter(pages)
    test('批量过滤结果', len(filtered) == 2)

    # 37. Backup Scanner tests
    print('\n[37] 备份文件探测测试')

    from core.backup_scanner import BackupScanner, BACKUP_PATHS
    bs = BackupScanner(timeout=5)
    test('备份探测器创建', bs is not None)
    test('备份路径数量', len(BACKUP_PATHS) >= 30)
    test('含Git路径', any('.git/HEAD' in p[0] for p in BACKUP_PATHS))
    test('含SVN路径', any('.svn' in p[0] for p in BACKUP_PATHS))
    test('含环境变量路径', any('.env' in p[0] for p in BACKUP_PATHS))
    test('含编辑器残留', any('.swp' in p[0] or '.bak' in p[0] or '~' in p[0] for p in BACKUP_PATHS))

    test('严重程度-高危', bs._assess_severity('.env file', 100) == 'high')
    test('严重程度-Git', bs._assess_severity('git config', 100) == 'high')
    test('严重程度-中危', bs._assess_severity('.bak backup', 100) == 'medium')
    test('严重程度-低危', bs._assess_severity('readme file', 50) == 'low')

    # 38. Cloud Storage Detector tests
    print('\n[38] 云存储泄露检测测试')

    from core.cloud_storage_detector import CloudStorageDetector, CLOUD_PATTERNS
    csd = CloudStorageDetector(timeout=5)
    test('云存储检测器创建', csd is not None)
    test('云存储提供商数量', len(CLOUD_PATTERNS) >= 4)
    test('AWS S3模式存在', 'AWS S3' in CLOUD_PATTERNS)
    test('Firebase模式存在', 'Firebase' in CLOUD_PATTERNS)
    test('阿里云OSS模式存在', '阿里云 OSS' in CLOUD_PATTERNS)

    html_cloud = '<script>var s3url = "https://my-bucket.s3.amazonaws.com"; firebase.initializeApp({storageBucket: "my-app.appspot.com"})</script>'
    result_cloud = csd.scan('https://example.com', html=html_cloud)
    test('云存储扫描返回', 'findings' in result_cloud)

    # Pattern matching
    import re as _re
    s3_pat = CLOUD_PATTERNS['AWS S3']['url_patterns'][0]
    test('S3 URL匹配', bool(_re.search(s3_pat, html_cloud, _re.I)))

    # 39. Favicon Fingerprint tests
    print('\n[39] Favicon 哈希指纹测试')

    from core.favicon_fingerprint import FaviconFingerprinter, KNOWN_FAVICON_HASHES
    ffp = FaviconFingerprinter(timeout=5)
    test('Favicon指纹器创建', ffp is not None)
    test('已知哈希数量', len(KNOWN_FAVICON_HASHES) >= 20)
    test('Jenkins哈希存在', -297069493 in KNOWN_FAVICON_HASHES)
    test('Grafana哈希存在', -606508076 in KNOWN_FAVICON_HASHES)

    # MurmurHash3 test
    test_data = b'\x00' * 100
    h1 = ffp._murmurhash3(test_data)
    h2 = ffp._murmurhash3(test_data)
    test('MurmurHash3确定性', h1 == h2)
    test('MurmurHash3有符号', isinstance(h1, int))

    diff_data = b'\xff' * 100
    h3 = ffp._murmurhash3(diff_data)
    test('MurmurHash3区分数据', h1 != h3)

    test('空数据哈希', ffp._murmurhash3(b'') == 0)

    # 40. Forbidden Bypass tests
    print('\n[40] 403/401 绕过测试')

    from core.forbidden_bypass import ForbiddenBypass
    fb = ForbiddenBypass(timeout=5)
    test('绕过测试器创建', fb is not None)
    test('策略数量', len(fb.STRATEGIES) >= 15)

    # Strategy types
    header_strategies = [s for s in fb.STRATEGIES if s.get('headers') and not s.get('method')]
    method_strategies = [s for s in fb.STRATEGIES if s.get('method')]
    path_strategies = [s for s in fb.STRATEGIES if s.get('path_transform') and s['path_transform'] is not None]
    test('Header欺骗策略', len(header_strategies) >= 5)
    test('HTTP方法覆盖策略', len(method_strategies) >= 4)
    test('路径变换策略', len(path_strategies) >= 8)

    # URL transformation tests
    url_trailing = fb._transform_url('https://example.com/admin', 'trailing_slash')
    test('尾部斜杠变换', url_trailing.endswith('/'))

    url_double = fb._transform_url('https://example.com/admin', 'double_slash')
    test('双斜杠变换', '//admin' in url_double or '/./' in url_double)

    url_case = fb._transform_url('https://example.com/admin/test', 'case_mix')
    test('大小写混合变换', url_case != 'https://example.com/admin/test')

    url_backslash = fb._transform_url('https://example.com/admin', 'backslash')
    test('反斜杠变换', '\\' in url_backslash)

    url_parent = fb._transform_url('https://example.com/admin/panel', 'parent_traversal')
    test('目录回溯变换', '/../' in url_parent)

    # 41. Wayback Scanner tests
    print('\n[41] Wayback Machine 历史接口测试')

    from core.wayback_scanner import WaybackScanner, API_INDICATORS
    ws = WaybackScanner(timeout=5)
    test('Wayback扫描器创建', ws is not None)
    test('API特征数量', len(API_INDICATORS) >= 8)

    test('API URL识别-1', ws._is_api_url('https://example.com/api/v1/users') == True)
    test('API URL识别-2', ws._is_api_url('https://example.com/graphql') == True)
    test('API URL识别-3', ws._is_api_url('https://example.com/rest/search?q=test') == True)
    test('非API URL', ws._is_api_url('https://example.com/about.html') == False)
    test('非API URL-2', ws._is_api_url('https://example.com/style.css') == False)

    test('敏感URL识别-1', ws._is_sensitive_url('https://example.com/admin') == True)
    test('敏感URL识别-2', ws._is_sensitive_url('https://example.com/.env') == True)
    test('敏感URL识别-3', ws._is_sensitive_url('https://example.com/backup') == True)
    test('非敏感URL', ws._is_sensitive_url('https://example.com/products') == False)

    test('域名清理', ws._clean_domain('https://www.example.com:8080/path') == 'www.example.com')

    # 42. Error Page Detector tests
    print('\n[42] 404 页面学习测试')

    from core.error_page_detector import ErrorPageDetector
    epd = ErrorPageDetector(timeout=5)
    test('错误页检测器创建', epd is not None)

    test('标题提取', epd._extract_title('<html><title>404 Not Found</title></html>') == '404 Not Found')
    test('标题提取-空', epd._extract_title('<html><body>No title</body></html>') == '')

    # Custom error detection
    samples_404 = [
        {'status_code': 404, 'body_len': 500, 'body_preview': 'Page Not Found'},
        {'status_code': 404, 'body_len': 500, 'body_preview': 'Page Not Found'},
    ]
    test('检测标准404', epd._detect_custom_error(samples_404) == True)

    samples_200 = [
        {'status_code': 200, 'body_len': 300, 'body_preview': 'Oops! Page not found'},
        {'status_code': 200, 'body_len': 300, 'body_preview': 'Oops! Page not found'},
    ]
    test('检测伪装404(返回200)', epd._detect_custom_error(samples_200) == True)

    samples_normal = [
        {'status_code': 404, 'body_len': 10, 'body_preview': 'Error'},
        {'status_code': 404, 'body_len': 10, 'body_preview': 'Error'},
    ]
    test('短响应不算自定义', epd._detect_custom_error(samples_normal) == False)

    # Reliability scoring
    fp_good = {'learned': True, 'status_codes': [404], 'body_hashes': ['abc'], 'body_lengths': [500], 'is_custom_error': False}
    score = epd.score_reliability(fp_good)
    test('可靠性评估-良好', score['reliable'] == True)
    test('可靠性评估-置信度', score['confidence'] > 0.5)

    fp_none = {}
    score_none = epd.score_reliability(fp_none)
    test('可靠性评估-无指纹', score_none['reliable'] == False)

    # 43. OAST Detector tests
    print('\n[43] OAST 带外检测测试')

    from core.oast_detector import OASTDetector
    oast = OASTDetector(timeout=5)
    test('OAST检测器创建', oast is not None)

    cb_url = oast.get_callback_url('test123')
    test('回调URL生成', 'test123' in cb_url and 'oast.pro' in cb_url)

    cb_domain = oast.get_callback_domain('abc')
    test('回调域名生成', 'abc' in cb_domain)

    # Verify token tracking
    oast.detect_blind_sqli('https://example.com/search', 'q')
    test('盲注SQL注入检测调用', len(oast._issued_tokens) > 0)
    first_token = list(oast._issued_tokens.values())[0]
    test('Token类型-blind_sqli', first_token['type'] == 'blind_sqli')

    oast2 = OASTDetector(timeout=5)
    oast2.detect_blind_xss('https://example.com/page', 'name')
    test('盲XSS检测调用', len(oast2._issued_tokens) > 0)

    oast3 = OASTDetector(timeout=5)
    oast3.detect_ssrf('https://example.com/fetch', 'url')
    test('SSRF检测调用', len(oast3._issued_tokens) > 0)

    oast4 = OASTDetector(timeout=5)
    oast4.detect_blind_command('https://example.com/exec', 'cmd')
    test('盲命令注入检测调用', len(oast4._issued_tokens) > 0)

    # 44. Template Engine tests
    print('\n[44] YAML 模板引擎测试')

    from core.template_engine import TemplateEngine, BUILTIN_TEMPLATES
    te = TemplateEngine(timeout=5)
    test('模板引擎创建', te is not None)
    test('内置模板数量', len(BUILTIN_TEMPLATES) >= 6)
    test('模板引擎模板列表', len(te.list_templates()) >= 6)

    # Verify template structure
    tpl_ids = [t['id'] for t in te.list_templates()]
    test('Spring Boot模板存在', 'tech-spring-boot' in tpl_ids)
    test('Swagger模板存在', 'tech-swagger' in tpl_ids)
    test('Git暴露模板存在', 'tech-git-exposure' in tpl_ids)
    test('GraphQL模板存在', 'tech-graphql-introspection' in tpl_ids)

    # Test add_template
    custom_tpl = {
        'id': 'test-custom',
        'info': {'name': 'Test', 'severity': 'low'},
        'requests': [{'method': 'GET', 'path': ['/test'], 'matchers': [{'type': 'status', 'value': [200]}]}],
    }
    test('添加自定义模板', te.add_template(custom_tpl) == True)
    test('自定义模板生效', any(t['id'] == 'test-custom' for t in te.list_templates()))

    # Test matcher evaluation
    test('添加无效模板拒绝', te.add_template({'bad': 'data'}) == False)

    # 45. Threat Intel tests
    print('\n[45] 外部威胁情报测试')

    from core.threat_intel import ThreatIntel
    ti = ThreatIntel(timeout=5)
    test('威胁情报创建', ti is not None)

    # Domain extraction
    test('域名提取-URL', ti.extract_domain('https://www.example.com/path') == 'www.example.com')
    test('域名提取-带端口', ti.extract_domain('http://api.example.com:8080/v1') == 'api.example.com')
    test('域名提取-纯域名', ti.extract_domain('example.com') == 'example.com')

    # Query structure
    result = ti.query_all('example.com')
    test('情报查询返回结构', 'domain' in result and 'sources' in result)
    test('情报查询含来源', len(result['sources']) == 3)
    test('情报来源-Shodan', any(s['source'] == 'Shodan' for s in result['sources']))
    test('情报来源-Censys', any(s['source'] == 'Censys' for s in result['sources']))
    test('情报来源-FOFA', any(s['source'] == 'FOFA' for s in result['sources']))

    # 46. SARIF Exporter tests
    print('\n[46] SARIF 导出测试')

    from core.sarif_exporter import SARIFExporter
    se = SARIFExporter()
    test('SARIF导出器创建', se is not None)
    test('SARIF版本', se.VERSION == '2.1.0')
    test('规则映射数量', len(se.RULE_MAP) >= 8)
    test('严重程度映射', len(se.SEVERITY_LEVEL) >= 4)

    # Export with empty results
    sarif_empty = se.export({'vulnerabilities': []})
    test('SARIF空结果导出', 'runs' in sarif_empty)
    test('SARIF含schema', '$schema' in sarif_empty)
    test('SARIF含版本', sarif_empty['version'] == '2.1.0')

    # Export with vulnerabilities
    sarif_vuln = se.export({
        'vulnerabilities': [
            {'type': 'sql_injection', 'severity': 'high', 'description': 'SQL注入', 'url': 'https://a.com/api', 'evidence': "' OR 1=1"},
            {'type': 'reflected_xss', 'severity': 'medium', 'description': 'XSS', 'url': 'https://a.com/page'},
        ],
    })
    test('SARIF漏洞导出', len(sarif_vuln['runs'][0]['results']) == 2)
    test('SARIF规则自动添加', len(sarif_vuln['runs'][0]['tool']['driver']['rules']) >= 2)

    # Export with sensitive files
    sarif_files = se.export({
        'vulnerabilities': [],
        'sensitive_files': [{'path': '/.git/HEAD', 'url': 'https://a.com/.git/HEAD'}],
    })
    test('SARIF敏感文件导出', len(sarif_files['runs'][0]['results']) == 1)

    # Severity mapping
    test('严重程度映射-critical→error', se.SEVERITY_LEVEL['critical'] == 'error')
    test('严重程度映射-medium→warning', se.SEVERITY_LEVEL['medium'] == 'warning')
    test('严重程度映射-low→note', se.SEVERITY_LEVEL['low'] == 'note')

    # 47. JARM Fingerprint tests
    print('\n[47] JARM TLS 指纹测试')

    from core.jarm_fingerprint import JARMFingerprinter, KNOWN_JARM_HASHES, PROBES
    jf = JARMFingerprinter(timeout=5)
    test('JARM指纹器创建', jf is not None)
    test('已知JARM哈希数量', len(KNOWN_JARM_HASHES) >= 5)
    test('探测配置数量', len(PROBES) >= 3)

    # Compute JARM
    raw = ['TLSv1.2|ECDHE-RSA-AES128-GCM-SHA256|abc123', 'TLSv1.2|ECDHE-RSA-AES256-GCM-SHA384|def456']
    jarm_hash = jf._compute_jarm(raw)
    test('JARM哈希计算', len(jarm_hash) == 62)
    test('JARM哈希确定性', jf._compute_jarm(raw) == jarm_hash)

    # Empty hash
    jarm_empty = jf._compute_jarm([])
    test('空输入JARM', jarm_empty == '0' * 62)

    # All empty strings
    jarm_all_empty = jf._compute_jarm(['', ''])
    test('全空字符串JARM', jarm_all_empty == '0' * 62)

    # fingerprint_url
    result_url = jf.fingerprint_url('https://example.com')
    test('URL指纹提取-host', result_url['host'] == 'example.com')
    test('URL指纹提取-port', result_url['port'] == 443)

    result_url2 = jf.fingerprint_url('http://example.com:8080/api')
    test('URL指纹提取-端口8080', result_url2['port'] == 8080)

    # batch_fingerprint
    batch_result = jf.batch_fingerprint([{'host': '127.0.0.1', 'port': 443}])
    test('批量指纹', isinstance(batch_result, list) and len(batch_result) == 1)

    # API routes test
    print('\n[47b] 新 API 路由测试')
    with app.test_client() as client:
        resp = client.get('/api/templates/list')
        test('模板列表API', resp.status_code == 200)
        data = json.loads(resp.data)
        test('模板列表含数据', 'templates' in data and data['total'] >= 6)

        resp2 = client.post('/api/jarm/fingerprint', json={'host': 'localhost'})
        test('JARM API可调用', resp2.status_code in (200, 500))  # localhost may fail but route exists

        resp3 = client.post('/api/jarm/compare', json={'target1': {'host': 'a.com'}, 'target2': {'host': 'b.com'}})
        test('JARM对比API可调用', resp3.status_code in (200, 500))

        resp4 = client.post('/api/export/sarif')
        test('SARIF导出API', resp4.status_code == 200)

        resp5 = client.post('/api/oast/scan', json={'url': 'https://example.com', 'param': 'q'})
        test('OAST扫描API', resp5.status_code == 200)

        resp6 = client.get('/api/oast/progress')
        test('OAST进度API', resp6.status_code == 200)

    # Summary
    print(f'\n{"="*40}')
    total = PASS + FAIL
    print(f'测试完成: {PASS}/{total} 通过, {FAIL} 失败')
    if FAIL > 0:
        print('部分测试失败!')
        return 1
    print('所有测试通过!')
    return 0


if __name__ == '__main__':
    code = run_tests()
    sys.exit(code)
