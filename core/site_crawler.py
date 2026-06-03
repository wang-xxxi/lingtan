"""Full site crawler with technology detection, asset inventory, SEO extraction"""
import re
import time
import random
import requests
from collections import defaultdict, deque
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

import urllib3
from core.page_classifier import classify as classify_page
from core.data_extractor import extract_all as extract_structured_data
from core.pagination_detector import detect as detect_pagination
from core.spa_adapter import analyze_page_for_spa
from core.tech_fingerprint import TechFingerprinter
from core.deduplicator import Deduplicator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.anti_detection import AntiDetection


class SiteCrawler:
    """Full site crawler - captures page structure, assets, and technology fingerprinting"""

    TECH_SIGNATURES = {
        'WordPress': {'category': 'CMS', 'headers': {'X-Pingback': '.'}, 'html': [r'wp-content/', r'wp-includes/', r'/wp-json/'], 'meta': [r'WordPress']},
        'Drupal': {'category': 'CMS', 'headers': {'X-Generator': '.'}, 'html': [r'sites/default/files/', r'Drupal\.settings'], 'meta': [r'Drupal']},
        'Joomla': {'category': 'CMS', 'html': [r'media/jui/', r'/components/com_'], 'meta': [r'Joomla']},
        'Shopify': {'category': 'CMS', 'html': [r'cdn\.shopify\.com', r'Shopify\.theme'], 'cookies': ['_shopify_']},
        'Magento': {'category': 'CMS', 'html': [r'mage/cookies\.js', r'Magento_Catalog'], 'cookies': ['mage-']},
        'Laravel': {'category': 'Framework', 'cookies': ['laravel_session', 'XSRF-TOKEN'], 'html': [r'mix\.manifest\.js']},
        'Django': {'category': 'Framework', 'cookies': ['csrftoken', 'sessionid'], 'html': [r'csrfmiddlewaretoken']},
        'Flask': {'category': 'Framework', 'cookies': ['session']},
        'Spring': {'category': 'Framework', 'cookies': ['JSESSIONID'], 'headers': {'X-Application-Context': '.'}},
        'Express': {'category': 'Framework', 'headers': {'X-Powered-By': r'Express'}},
        'React': {'category': 'Frontend', 'html': [r'data-reactroot', r'_reactRootContainer', r'__NEXT_DATA__']},
        'Vue.js': {'category': 'Frontend', 'html': [r'data-v-', r'__vue__', r'Vue\.createApp']},
        'Angular': {'category': 'Frontend', 'html': [r'ng-version', r'ng-app', r'_nghost']},
        'Svelte': {'category': 'Frontend', 'html': [r'class="svelte-']},
        'jQuery': {'category': 'Library', 'html': [r'jquery[.-]', r'jquery\.js', r'jquery\.min\.js']},
        'Bootstrap': {'category': 'CSS Framework', 'html': [r'bootstrap[.-]', r'bootstrap\.min\.(css|js)']},
        'Tailwind CSS': {'category': 'CSS Framework', 'html': [r'tailwind\.css', r'class="[^"]*(?:flex|grid|p-\d|m-\d)']},
        'Font Awesome': {'category': 'Icon', 'html': [r'font-awesome', r'fontawesome']},
        'Google Analytics': {'category': 'Analytics', 'html': [r'google-analytics\.com/analytics\.js', r'gtag\(', r'ga\(.*create']},
        'Google Tag Manager': {'category': 'Analytics', 'html': [r'googletagmanager\.com/gtm\.js', r'GTM-']},
        'Baidu Analytics': {'category': 'Analytics', 'html': [r'hm\.baidu\.com', r'_hmt']},
        'Cloudflare': {'category': 'CDN', 'headers': {'CF-Ray': '.', 'Server': r'cloudflare'}},
        'Nginx': {'category': 'Server', 'headers': {'Server': r'nginx'}},
        'Apache': {'category': 'Server', 'headers': {'Server': r'Apache'}},
        'IIS': {'category': 'Server', 'headers': {'Server': r'Microsoft-IIS'}},
        'LiteSpeed': {'category': 'Server', 'headers': {'Server': r'LiteSpeed'}},
        'GitHub Pages': {'category': 'Hosting', 'headers': {'Server': r'GitHub.com'}},
        'Netlify': {'category': 'Hosting', 'headers': {'Server': r'Netlify'}},
        'Vercel': {'category': 'Hosting', 'headers': {'x-vercel-id': r'.'}},
        'Next.js': {'category': 'Frontend', 'html': [r'__NEXT_DATA__', r'_next/static']},
        'Nuxt.js': {'category': 'Frontend', 'html': [r'__NUXT__', r'_nuxt/']},
        'webpack': {'category': 'Build Tool', 'html': [r'webpackChunk', r'webpackJsonp']},
        'Vite': {'category': 'Build Tool', 'html': [r'/@vite/', r'vite']},
        'TypeScript': {'category': 'Language', 'html': [r'\.ts']},
        'PHP': {'category': 'Language', 'headers': {'X-Powered-By': r'PHP'}},
        'ASP.NET': {'category': 'Framework', 'headers': {'X-AspNet-Version': r'.'}, 'cookies': ['ASP.NET_SessionId']},
        'GraphQL': {'category': 'API', 'html': [r'/graphql', r'__schema']},
        'WebSocket': {'category': 'Protocol', 'html': [r'new WebSocket\(', r'ws://', r'wss://']},
        'GSAP': {'category': 'Animation', 'html': [r'gsap\.', r'TweenMax', r'TweenLite']},
        'Swiper': {'category': 'Library', 'html': [r'swiper[.-]', r'new Swiper']},
        'AOS': {'category': 'Animation', 'html': [r'data-aos=', r'aos\.js']},
        'Lodash': {'category': 'Library', 'html': [r'lodash[.-]']},
        'Axios': {'category': 'Library', 'html': [r'axios[.-]', r'axios\.']},
        'Day.js': {'category': 'Library', 'html': [r'dayjs[.-]']},
        'Moment.js': {'category': 'Library', 'html': [r'moment[.-]']},
        'Three.js': {'category': '3D', 'html': [r'three[.-]', r'THREE\.']},
        'Chart.js': {'category': 'Visualization', 'html': [r'chart[.-]', r'Chart\(']},
        'ECharts': {'category': 'Visualization', 'html': [r'echarts[.-]', r'echarts\.init']},
        'Highcharts': {'category': 'Visualization', 'html': [r'highcharts[.-]']},
        'D3.js': {'category': 'Visualization', 'html': [r'd3[.-]', r'd3\.select']},
        'Prism': {'category': 'Code Highlight', 'html': [r'prism[.-]', r'language-']},
        'Highlight.js': {'category': 'Code Highlight', 'html': [r'highlight[.-]', r'hljs']},
        'MathJax': {'category': 'Math', 'html': [r'MathJax']},
        'KaTeX': {'category': 'Math', 'html': [r'katex']},
        'Mapbox': {'category': 'Map', 'html': [r'mapbox\.com']},
        'Leaflet': {'category': 'Map', 'html': [r'leaflet[.-]']},
        'Babel': {'category': 'Build Tool', 'html': [r'babel']},
        'Sass/SCSS': {'category': 'CSS Preprocessor', 'html': [r'\.scss']},
        'Less': {'category': 'CSS Preprocessor', 'html': [r'\.less']},
        'Element UI': {'category': 'UI Component', 'html': [r'element-ui', r'el-button']},
        'Ant Design': {'category': 'UI Component', 'html': [r'ant-design', r'ant-']},
        'Vuetify': {'category': 'UI Component', 'html': [r'v-app', r'v-btn']},
        'Material UI': {'category': 'UI Component', 'html': [r'MuiButton', r'@mui/']},
        'Taro': {'category': 'Mini Program', 'html': [r'taro']},
        'uni-app': {'category': 'Mini Program', 'html': [r'uni-', r'uni\.']},
        'WePY': {'category': 'Mini Program', 'html': [r'wepy']},
    }

    ASSET_EXTENSIONS = {
        '.css': 'css', '.js': 'js', '.json': 'js',
        '.png': 'image', '.jpg': 'image', '.jpeg': 'image', '.gif': 'image',
        '.svg': 'image', '.ico': 'image', '.webp': 'image', '.bmp': 'image',
        '.woff': 'font', '.woff2': 'font', '.ttf': 'font', '.eot': 'font', '.otf': 'font',
        '.mp4': 'media', '.mp3': 'media', '.webm': 'media', '.ogg': 'media', '.wav': 'media',
        '.pdf': 'document', '.doc': 'document', '.docx': 'document',
        '.zip': 'archive', '.rar': 'archive', '.tar': 'archive', '.gz': 'archive',
    }

    def __init__(self, timeout=12, max_pages=200):
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        # Anti-detection: UA rotation, randomized delays, modern browser headers
        self.anti_detect = AntiDetection(min_delay=0.5, max_delay=2.5, respect_robots=True)
        self.session.headers.update(self.anti_detect.get_headers())
        self.session.verify = False
        self._stop_flag = False
        self._progress_callback = None
        self._pages = []
        self._all_assets = []
        self._all_technologies = {}
        self._visited = set()
        self._last_page_url = ''
        self._crawl_rule = None
        self._fingerprinter = TechFingerprinter()
        self._deduplicator = Deduplicator()
        self._dup_stats = {'filtered': 0}

    def stop(self):
        self._stop_flag = True

    def set_crawl_rule(self, rule):
        """Set a crawl rule for filtering. Accepts CrawlRule or dict."""
        from core.crawl_rules import CrawlRule
        if isinstance(rule, dict):
            self._crawl_rule = CrawlRule.from_dict(rule)
        else:
            self._crawl_rule = rule

    def set_cookies(self, cookies):
        """Inject cookies into the session. Accepts dict {name: value} or list [{name, value}]"""
        if isinstance(cookies, dict):
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        elif isinstance(cookies, list):
            for ck in cookies:
                if isinstance(ck, dict) and ck.get('name'):
                    self.session.cookies.set(ck['name'], ck.get('value', ''))

    def set_progress_callback(self, callback):
        self._progress_callback = callback

    def _report(self, message, pct):
        if self._progress_callback:
            try:
                self._progress_callback(message, pct)
            except Exception:
                pass

    def _safe_get(self, url):
        """Safe GET with anti-detection: UA rotation, delays, backoff, robots.txt"""
        # Check robots.txt
        if self.anti_detect.should_skip_request(url):
            return None
        # Apply rate limiting delay with jitter
        self.anti_detect.wait(url)
        # Rotate headers for this request
        headers = self.anti_detect.get_headers(url, referer=self._last_page_url)
        self.session.headers.update(headers)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp is not None:
                self.anti_detect.handle_response(resp.status_code, url)
                # Update referer chain on successful HTML pages
                if resp.status_code == 200:
                    ct = resp.headers.get('content-type', '')
                    if 'html' in ct:
                        self.anti_detect.set_referer(url)
                        self._last_page_url = url
            return resp
        except Exception:
            return None

    def crawl(self, target_url):
        """Main crawl entry point - returns full site data"""
        self._stop_flag = False
        self._pages = []
        self._all_assets = []
        self._all_technologies = {}
        self._visited = set()

        parsed = urlparse(target_url)
        base = f'{parsed.scheme}://{parsed.netloc}'
        base_netloc = parsed.netloc

        # Phase 1: Fetch entry page
        self._report('正在获取首页...', 5)
        resp = self._safe_get(target_url)
        if not resp:
            return {'error': '无法访问目标网站', 'pages': [], 'assets': [], 'technologies': []}

        # Analyze entry page
        page_data = self._analyze_page(target_url, resp, 0, None)
        self._pages.append(page_data)
        self._visited.add(self._normalize_url(target_url))

        # Collect internal links from entry page
        queue = deque()
        entry_links = page_data.get('links') or []
        entry_links = self.anti_detect.randomize_request_order(entry_links)
        for link in entry_links:
            if link.get('type') == 'internal':
                href = link.get('href', '')
                nurl = self._normalize_url(href)
                if nurl and nurl not in self._visited:
                    queue.append((href, 1))

        # Phase 2: BFS crawl all pages
        total_estimate = min(self.max_pages, len(queue) + 1)
        crawled = 1
        while queue and crawled < self.max_pages and not self._stop_flag:
            url, depth = queue.popleft()
            nurl = self._normalize_url(url)
            if nurl in self._visited:
                continue
            self._visited.add(nurl)

            crawled += 1
            pct = 5 + int(60 * crawled / max(self.max_pages, 1))
            self._report(f'爬取页面 {crawled}/{self.max_pages}: {url[:60]}...', min(pct, 65))

            resp = self._safe_get(url)
            if not resp:
                continue

            # Deduplicate: skip pages with identical content
            if self._deduplicator.is_duplicate(url, resp.text or ''):
                self._dup_stats['filtered'] += 1
                continue

            page_data = self._analyze_page(url, resp, depth, None)
            self._pages.append(page_data)

            if depth < 4:
                page_links = page_data.get('links') or []
                # Randomize link order within each page to avoid predictable patterns
                page_links = self.anti_detect.randomize_request_order(page_links)
                for link in page_links:
                    if link.get('type') == 'internal':
                        href = link.get('href', '')
                        hnurl = self._normalize_url(href)
                        if hnurl and hnurl not in self._visited:
                            queue.append((href, depth + 1))

            time.sleep(random.uniform(0.3, 1.2))

        # Phase 3: Technology summary
        self._report('汇总技术栈信息...', 75)
        self._compile_technologies()

        # Phase 4: Build sitemap tree
        self._report('构建站点地图...', 85)
        sitemap = self._build_sitemap()

        # Phase 5: Final summary
        self._report('爬取完成', 100)

        return {
            'pages': self._pages,
            'assets': self._all_assets,
            'technologies': list(self._all_technologies.values()),
            'sitemap': sitemap,
            'dedup_stats': {'duplicate_pages_filtered': self._dup_stats['filtered']},
            'summary': {
                'total_pages': len(self._pages),
                'total_assets': len(self._all_assets),
                'total_technologies': len(self._all_technologies),
                'total_internal_links': sum(len([l for l in (p.get('links') or []) if l.get('type') == 'internal']) for p in self._pages),
                'total_external_links': sum(len([l for l in (p.get('links') or []) if l.get('type') == 'external']) for p in self._pages),
                'total_images': sum(len(p.get('images') or []) for p in self._pages),
                'total_forms': sum(len(p.get('forms') or []) for p in self._pages),
            },
        }

    def _normalize_url(self, url):
        try:
            parsed = urlparse(url)
            clean = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
            return clean.rstrip('/').lower()
        except Exception:
            return ''

    def _analyze_page(self, url, resp, depth, parent_url):
        """Analyze a single page - extract all structure, assets, tech, SEO"""
        start_time = time.time()

        page = {
            'url': url,
            'status_code': resp.status_code,
            'content_type': resp.headers.get('Content-Type', ''),
            'page_size': len(resp.content),
            'depth': depth,
            'parent_url': parent_url,
            'title': '',
            'meta_description': '',
            'headings': {},
            'links': [],
            'images': [],
            'forms': [],
            'scripts': [],
            'stylesheets': [],
            'assets': [],
            'technologies': [],
            'seo_data': {},
            'performance': {},
            'html_tags': {},
        }

        ct = resp.headers.get('Content-Type', '').lower()
        if 'html' not in ct and 'xhtml' not in ct:
            # Non-HTML page, just record basic info
            page['performance'] = {
                'response_time': round(time.time() - start_time, 3),
                'page_size': len(resp.content),
                'resource_count': 0,
            }
            return page

        try:
            soup = BeautifulSoup(resp.content, 'lxml')
        except Exception:
            try:
                soup = BeautifulSoup(resp.content, 'html.parser')
            except Exception:
                return page

        # Title
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            page['title'] = title_tag.string.strip()[:500]

        # Meta description
        meta_desc = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
        if meta_desc and meta_desc.get('content'):
            page['meta_description'] = meta_desc['content'].strip()[:1000]

        # Headings
        headings = {}
        for i in range(1, 7):
            h_tags = soup.find_all(f'h{i}')
            if h_tags:
                headings[f'h{i}'] = [t.get_text(strip=True)[:200] for t in h_tags[:20]]
        page['headings'] = headings

        # Links
        parsed_url = urlparse(url)
        base_netloc = parsed_url.netloc
        links = []
        seen_links = set()
        for a in soup.find_all('a', href=True):
            href = a.get('href', '').strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            full_url = urljoin(url, href)
            if full_url in seen_links:
                continue
            seen_links.add(full_url)
            link_parsed = urlparse(full_url)
            link_type = 'internal' if link_parsed.netloc == base_netloc else 'external'
            text = a.get_text(strip=True)[:200]
            links.append({'href': full_url, 'text': text, 'type': link_type})
        page['links'] = links

        # Images
        images = []
        for img in soup.find_all('img'):
            src = img.get('src') or img.get('data-src') or ''
            if src:
                images.append({'src': urljoin(url, src), 'alt': (img.get('alt') or '')[:200]})
        page['images'] = images

        # Forms
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = (form.get('method') or 'GET').upper()
            fields = []
            for inp in form.find_all(['input', 'select', 'textarea']):
                fname = inp.get('name', '')
                ftype = inp.get('type', inp.name)
                if fname:
                    fields.append({'name': fname, 'type': ftype or 'text'})
            forms.append({'action': urljoin(url, action), 'method': method, 'fields': fields})
        page['forms'] = forms

        # Scripts
        scripts = []
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src:
                scripts.append({'src': urljoin(url, src), 'inline': False})
            elif script.string and len(script.string) > 10:
                scripts.append({'src': '', 'inline': True})
        page['scripts'] = scripts

        # Stylesheets
        stylesheets = []
        for link in soup.find_all('link', rel='stylesheet'):
            href = link.get('href', '')
            if href:
                stylesheets.append({'href': urljoin(url, href)})
        for style in soup.find_all('link', attrs={'type': 'text/css'}):
            href = style.get('href', '')
            if href:
                stylesheets.append({'href': urljoin(url, href)})
        page['stylesheets'] = stylesheets

        # Asset classification
        assets = []
        all_urls = (
            [(i.get('src', ''), 'image') for i in images] +
            [(s.get('src', ''), 'js') for s in scripts if s.get('src')] +
            [(s.get('href', ''), 'css') for s in stylesheets]
        )
        seen_assets = set()
        for asset_url, default_type in all_urls:
            if not asset_url or asset_url in seen_assets:
                continue
            seen_assets.add(asset_url)
            ext = '.' + asset_url.split('?')[0].rsplit('.', 1)[-1].lower() if '.' in asset_url else ''
            asset_type = self.ASSET_EXTENSIONS.get(ext, default_type)
            assets.append({'url': asset_url, 'type': asset_type})
        page['assets'] = assets
        self._all_assets.extend(assets)

        # Technology detection
        techs = self._detect_technologies(resp, soup, resp.text if resp.text else '')
        page['technologies'] = techs

        # SEO data
        seo = {}
        # Open Graph
        og_tags = {}
        for meta in soup.find_all('meta', property=re.compile(r'^og:')):
            og_tags[meta.get('property', '')] = meta.get('content', '')[:500]
        seo['og_tags'] = og_tags
        # Twitter Card
        tw_tags = {}
        for meta in soup.find_all('meta', attrs={'name': re.compile(r'^twitter:')}):
            tw_tags[meta.get('name', '')] = meta.get('content', '')[:500]
        seo['twitter_tags'] = tw_tags
        # Canonical
        canonical = soup.find('link', rel='canonical')
        seo['canonical'] = canonical.get('href', '') if canonical else ''
        # Robots
        robots = soup.find('meta', attrs={'name': re.compile(r'robots', re.I)})
        seo['robots'] = robots.get('content', '') if robots else ''
        page['seo_data'] = seo

        # HTML tag distribution
        tag_counts = defaultdict(int)
        for tag in soup.find_all(True):
            tag_counts[tag.name] += 1
        page['html_tags'] = dict(tag_counts)

        # Performance
        page['performance'] = {
            'response_time': round(time.time() - start_time, 3),
            'page_size': len(resp.content),
            'resource_count': len(assets),
        }

        # Intelligent analysis
        try:
            html_text = resp.text if resp.text else ''
            # Page type classification
            page['page_type'] = classify_page(url, html_text=html_text, soup=soup)
            # Structured data extraction
            page['structured_data'] = extract_structured_data(html_text, url)
            # Pagination detection
            page['pagination'] = detect_pagination(url, html_text, soup)
            # SPA analysis (lightweight - only check if page seems empty)
            if len(html_text) < 5000 or html_text.count('<') < 50:
                page['spa_info'] = analyze_page_for_spa(html_text, url)
            else:
                page['spa_info'] = {'is_spa': False}
        except Exception:
            page['page_type'] = {'type': 'unknown', 'confidence': 0}
            page['structured_data'] = {'tables': [], 'lists': [], 'repeated_patterns': []}
            page['pagination'] = {'url_pagination': {'has_pagination': False}, 'next_urls': []}
            page['spa_info'] = {'is_spa': False}

        return page

    def _detect_technologies(self, resp, soup, html):
        """Detect technologies from response headers, HTML content"""
        detected = []
        headers = resp.headers or {}
        cookies = resp.cookies or {}

        header_dict = {}
        for k, v in headers.items():
            header_dict[k.lower()] = v

        for tech_name, sig in self.TECH_SIGNATURES.items():
            evidence = []
            confidence = 0

            # Check headers
            headers_sig = sig.get('headers', {})
            if isinstance(headers_sig, dict):
                for hk, hv in headers_sig.items():
                    val = header_dict.get(hk.lower(), '')
                    if val and (hv == '.' or re.search(hv, val, re.I)):
                        evidence.append(f'Header: {hk}: {val}')
                        confidence += 0.4

            # Check HTML patterns
            for pattern in sig.get('html', []):
                if re.search(pattern, html, re.I):
                    evidence.append(f'HTML: {pattern}')
                    confidence += 0.3
                    break

            # Check meta tags
            for pattern in sig.get('meta', []):
                meta_gen = soup.find('meta', attrs={'name': 'generator'})
                if meta_gen and re.search(pattern, meta_gen.get('content', ''), re.I):
                    evidence.append(f'Meta: generator={meta_gen["content"][:50]}')
                    confidence += 0.5

            # Check cookies
            for ck in sig.get('cookies', []):
                for cookie_name in cookies.keys():
                    if ck.lower() in cookie_name.lower():
                        evidence.append(f'Cookie: {cookie_name}')
                        confidence += 0.3
                        break

            if evidence:
                detected.append({
                    'name': tech_name,
                    'category': sig.get('category', 'Unknown'),
                    'confidence': round(min(confidence, 1.0), 2),
                    'evidence': '; '.join(evidence[:3]),
                })
                self._all_technologies[tech_name] = {
                    'name': tech_name,
                    'category': sig.get('category', 'Unknown'),
                    'confidence': round(min(confidence, 1.0), 2),
                    'evidence': '; '.join(evidence[:3]),
                }

        # Enhanced fingerprinting with version detection
        try:
            header_dict_for_fp = {k.lower(): v for k, v in (resp.headers or {}).items()}
            fp_result = self._fingerprinter.analyze(
                url=resp.url, html=html,
                headers=header_dict_for_fp,
                cookies={c.name: c.value for c in resp.cookies} if resp.cookies else {}
            )
            existing_names = {d['name'] for d in detected}
            for tech in fp_result.get('technologies', []):
                if tech['name'] not in existing_names:
                    detected.append(tech)
                    self._all_technologies[tech['name']] = tech
                elif tech.get('version'):
                    # Update existing detection with version info
                    for d in detected:
                        if d['name'] == tech['name'] and not d.get('version'):
                            d['version'] = tech['version']
                            d['evidence'] += f'; version: {tech["version"]}'
                            break
        except Exception:
            pass

        return detected

    def _compile_technologies(self):
        """Merge technology detections across all pages"""
        for page in self._pages:
            for tech in (page.get('technologies') or []):
                name = tech.get('name')
                if name and name not in self._all_technologies:
                    self._all_technologies[name] = tech

    def _build_sitemap(self):
        """Build a tree structure from crawled pages"""
        url_to_page = {}
        children = defaultdict(list)

        for page in self._pages:
            url = page.get('url', '')
            url_to_page[url] = page
            parent = page.get('parent_url')
            if parent:
                children[parent].append(url)

        # Find root
        root_url = None
        min_depth = 999
        for page in self._pages:
            if page.get('depth', 0) < min_depth:
                min_depth = page.get('depth', 0)
                root_url = page.get('url')

        def build_node(url):
            page = url_to_page.get(url, {})
            node = {
                'url': url,
                'title': page.get('title', ''),
                'status_code': page.get('status_code'),
                'content_type': (page.get('content_type') or '').split(';')[0].strip(),
                'children': [],
            }
            for child_url in sorted(children.get(url, [])):
                node['children'].append(build_node(child_url))
            return node

        if root_url:
            return build_node(root_url)
        return {'url': root_url or '', 'title': '', 'children': []}
