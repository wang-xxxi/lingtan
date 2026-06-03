import sqlite3
import json
import os
import time
import traceback
from threading import Lock
from urllib.parse import urlparse

from core.path_resolver import get_data_dir
DB_PATH = os.path.join(get_data_dir(), 'api_hunter.db')

class Database:
    _instance = None
    _lock = Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        try:
            c = self.conn.cursor()
            c.executescript('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    url TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at REAL,
                    updated_at REAL,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    url TEXT NOT NULL,
                    method TEXT DEFAULT 'GET',
                    status_code INTEGER,
                    content_type TEXT,
                    response_size INTEGER,
                    parameters TEXT,
                    headers TEXT,
                    response_headers TEXT,
                    request_body TEXT,
                    response_sample TEXT,
                    category TEXT,
                    description TEXT,
                    risk_level TEXT DEFAULT 'info',
                    source TEXT,
                    discovered_at REAL
                );

                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id INTEGER,
                    analysis_type TEXT,
                    result TEXT,
                    confidence REAL,
                    created_at REAL
                );

                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    target_url TEXT,
                    scan_type TEXT,
                    status TEXT DEFAULT 'running',
                    start_time REAL,
                    end_time REAL,
                    stats TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_endpoints_url ON api_endpoints(url);
                CREATE INDEX IF NOT EXISTS idx_endpoints_target ON api_endpoints(target_id);
                CREATE INDEX IF NOT EXISTS idx_endpoints_category ON api_endpoints(category);

                CREATE TABLE IF NOT EXISTS crawled_pages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    url TEXT NOT NULL,
                    status_code INTEGER,
                    content_type TEXT,
                    title TEXT,
                    meta_description TEXT,
                    headings TEXT,
                    links TEXT,
                    images TEXT,
                    forms TEXT,
                    scripts TEXT,
                    stylesheets TEXT,
                    assets TEXT,
                    technologies TEXT,
                    seo_data TEXT,
                    performance TEXT,
                    html_tags TEXT,
                    page_size INTEGER,
                    depth INTEGER DEFAULT 0,
                    parent_url TEXT,
                    crawled_at REAL
                );

                CREATE TABLE IF NOT EXISTS site_technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    name TEXT NOT NULL,
                    category TEXT,
                    version TEXT,
                    confidence REAL DEFAULT 0,
                    evidence TEXT,
                    detected_at REAL
                );

                CREATE INDEX IF NOT EXISTS idx_pages_target ON crawled_pages(target_id);
                CREATE INDEX IF NOT EXISTS idx_pages_url ON crawled_pages(url);
                CREATE INDEX IF NOT EXISTS idx_tech_target ON site_technologies(target_id);

                CREATE TABLE IF NOT EXISTS captured_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    method TEXT,
                    url TEXT,
                    host TEXT,
                    path TEXT,
                    request_headers TEXT,
                    request_body TEXT,
                    status_code INTEGER,
                    response_headers TEXT,
                    response_body TEXT,
                    content_type TEXT,
                    captured_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_traffic_host ON captured_traffic(host);
                CREATE INDEX IF NOT EXISTS idx_traffic_url ON captured_traffic(url);

                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    target TEXT,
                    params TEXT,
                    status TEXT DEFAULT 'pending',
                    progress INTEGER DEFAULT 0,
                    message TEXT,
                    result TEXT,
                    created_at REAL,
                    started_at REAL,
                    finished_at REAL
                );

                CREATE TABLE IF NOT EXISTS favorites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    method TEXT DEFAULT 'GET',
                    label TEXT,
                    created_at REAL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_fav_url_method ON favorites(url, method);

                CREATE TABLE IF NOT EXISTS request_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    method TEXT,
                    url TEXT,
                    headers TEXT,
                    body TEXT,
                    status_code INTEGER,
                    response_size INTEGER,
                    elapsed REAL,
                    created_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_history_url ON request_history(url);

                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    url TEXT,
                    cookies TEXT,
                    local_storage TEXT,
                    created_at REAL
                );

                CREATE TABLE IF NOT EXISTS scan_checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    checkpoint_id TEXT UNIQUE NOT NULL,
                    scan_type TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    state TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_checkpoints_type ON scan_checkpoints(scan_type);

                CREATE TABLE IF NOT EXISTS crawl_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url_pattern TEXT,
                    config TEXT,
                    created_at REAL
                );
            ''')
            self.conn.commit()
        except Exception as e:
            print(f'Database init error: {e}')

    def add_target(self, name, type_, url=None, metadata=None):
        if not name:
            name = 'unknown'
        if not type_:
            type_ = 'unknown'
        try:
            c = self.conn.cursor()
            now = time.time()
            c.execute('INSERT INTO targets (name, type, url, created_at, updated_at, metadata) VALUES (?,?,?,?,?,?)',
                      (str(name)[:500], str(type_)[:50], str(url)[:2000] if url else None,
                       now, now, json.dumps(metadata) if metadata else None))
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_target error: {e}')
            return 0

    def add_endpoint(self, target_id, url, method='GET', status_code=None,
                     content_type=None, response_size=None, parameters=None,
                     headers=None, response_headers=None, request_body=None,
                     response_sample=None, category=None, description=None,
                     risk_level='info', source=None):
        if not url or not isinstance(url, str):
            return 0
        url = str(url)[:2000]
        method = str(method or 'GET')[:10].upper()

        try:
            c = self.conn.cursor()
            now = time.time()

            # Check for duplicate
            c.execute('SELECT id FROM api_endpoints WHERE url=? AND method=? AND COALESCE(target_id,0)=?',
                      (url, method, target_id or 0))
            existing = c.fetchone()
            if existing:
                c.execute('''UPDATE api_endpoints SET status_code=?, content_type=?,
                            response_size=?, parameters=?, response_headers=?,
                            request_body=?, response_sample=?
                            WHERE id=?''',
                          (status_code, str(content_type)[:200] if content_type else None,
                           response_size,
                           json.dumps(parameters) if parameters else None,
                           json.dumps(response_headers) if response_headers else None,
                           str(request_body)[:2000] if request_body else None,
                           str(response_sample)[:2000] if response_sample else None,
                           existing['id']))
                self.conn.commit()
                return existing['id']

            c.execute('''INSERT INTO api_endpoints
                        (target_id, url, method, status_code, content_type, response_size,
                         parameters, headers, response_headers, request_body, response_sample,
                         category, description, risk_level, source, discovered_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                      (target_id, url, method, status_code,
                       str(content_type)[:200] if content_type else None,
                       response_size,
                       json.dumps(parameters) if parameters else None,
                       json.dumps(headers) if headers else None,
                       json.dumps(response_headers) if response_headers else None,
                       str(request_body)[:2000] if request_body else None,
                       str(response_sample)[:2000] if response_sample else None,
                       str(category)[:50] if category else None,
                       str(description)[:500] if description else None,
                       str(risk_level)[:20] if risk_level else 'info',
                       str(source)[:50] if source else None,
                       now))
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_endpoint error: {e}')
            return 0

    def get_all_endpoints(self, target_id=None, category=None, limit=1000):
        try:
            c = self.conn.cursor()
            query = 'SELECT * FROM api_endpoints WHERE 1=1'
            params = []
            if target_id:
                query += ' AND target_id=?'
                params.append(target_id)
            if category:
                query += ' AND category=?'
                params.append(category)
            query += ' ORDER BY discovered_at DESC LIMIT ?'
            params.append(limit)
            c.execute(query, params)
            return [dict(r) for r in c.fetchall()]
        except Exception as e:
            print(f'get_all_endpoints error: {e}')
            return []

    def get_targets(self):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM targets ORDER BY created_at DESC')
            return [dict(r) for r in c.fetchall()]
        except Exception:
            return []

    def get_endpoint_stats(self):
        stats = {
            'total_endpoints': 0,
            'total_targets': 0,
            'by_category': {},
            'by_method': {},
            'by_risk': {},
            'by_source': {},
        }
        try:
            c = self.conn.cursor()
            c.execute('SELECT COUNT(*) as cnt FROM api_endpoints')
            row = c.fetchone()
            stats['total_endpoints'] = row['cnt'] if row else 0

            c.execute('SELECT COUNT(*) as cnt FROM targets')
            row = c.fetchone()
            stats['total_targets'] = row['cnt'] if row else 0

            c.execute('SELECT category, COUNT(*) as cnt FROM api_endpoints GROUP BY category')
            stats['by_category'] = {(r['category'] or 'uncategorized'): r['cnt'] for r in c.fetchall()}

            c.execute('SELECT method, COUNT(*) as cnt FROM api_endpoints GROUP BY method')
            stats['by_method'] = {(r['method'] or 'UNKNOWN'): r['cnt'] for r in c.fetchall()}

            c.execute('SELECT risk_level, COUNT(*) as cnt FROM api_endpoints GROUP BY risk_level')
            stats['by_risk'] = {(r['risk_level'] or 'info'): r['cnt'] for r in c.fetchall()}

            c.execute('SELECT source, COUNT(*) as cnt FROM api_endpoints GROUP BY source')
            stats['by_source'] = {(r['source'] or 'unknown'): r['cnt'] for r in c.fetchall()}
        except Exception as e:
            print(f'get_endpoint_stats error: {e}')
        return stats

    def search_endpoints(self, keyword):
        if not keyword:
            return []
        try:
            c = self.conn.cursor()
            keyword_safe = str(keyword)[:200]
            c.execute('SELECT * FROM api_endpoints WHERE url LIKE ? OR description LIKE ? OR category LIKE ? ORDER BY discovered_at DESC',
                      (f'%{keyword_safe}%', f'%{keyword_safe}%', f'%{keyword_safe}%'))
            return [dict(r) for r in c.fetchall()]
        except Exception:
            return []

    def update_endpoint_analysis(self, endpoint_id, category, description, risk_level):
        try:
            c = self.conn.cursor()
            c.execute('UPDATE api_endpoints SET category=?, description=?, risk_level=? WHERE id=?',
                      (category, description, risk_level, endpoint_id))
            self.conn.commit()
        except Exception as e:
            print(f'update_endpoint_analysis error: {e}')

    def clear_all(self):
        try:
            with self._lock:
                c = self.conn.cursor()
                for table in [
                    'analysis_results', 'api_endpoints', 'targets',
                    'scan_sessions', 'crawled_pages', 'site_technologies',
                    'captured_traffic', 'tasks', 'favorites',
                    'request_history', 'scan_checkpoints',
                    'sessions', 'crawl_rules',
                ]:
                    c.execute(f'DELETE FROM {table}')
                self.conn.commit()
        except Exception as e:
            print(f'clear_all error: {e}')

    def execute(self, query, params=None):
        """Execute a SQL statement (INSERT/UPDATE/DELETE)"""
        try:
            c = self.conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            self.conn.commit()
        except Exception as e:
            print(f'execute error: {e}')

    def fetch_all(self, query, params=None):
        """Execute a SELECT query and return all rows as list of dicts"""
        try:
            c = self.conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            return [dict(r) for r in c.fetchall()]
        except Exception as e:
            print(f'fetch_all error: {e}')
            return []

    def export_all(self):
        try:
            c = self.conn.cursor()
            c.execute('''SELECT e.*, t.name as target_name, t.type as target_type
                        FROM api_endpoints e
                        LEFT JOIN targets t ON e.target_id = t.id
                        ORDER BY e.discovered_at DESC''')
            return [dict(r) for r in c.fetchall()]
        except Exception:
            return []

    # ─── Crawled Pages ───

    def add_crawled_page(self, target_id, url, status_code=None, content_type=None,
                         title=None, meta_description=None, headings=None, links=None,
                         images=None, forms=None, scripts=None, stylesheets=None,
                         assets=None, technologies=None, seo_data=None,
                         performance=None, html_tags=None, page_size=None,
                         depth=0, parent_url=None):
        if not url or not isinstance(url, str):
            return 0
        try:
            c = self.conn.cursor()
            now = time.time()
            c.execute('''INSERT INTO crawled_pages
                        (target_id, url, status_code, content_type, title, meta_description,
                         headings, links, images, forms, scripts, stylesheets, assets,
                         technologies, seo_data, performance, html_tags, page_size,
                         depth, parent_url, crawled_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                      (target_id, str(url)[:2000], status_code,
                       str(content_type)[:200] if content_type else None,
                       str(title)[:500] if title else None,
                       str(meta_description)[:1000] if meta_description else None,
                       json.dumps(headings) if headings else None,
                       json.dumps(links) if links else None,
                       json.dumps(images) if images else None,
                       json.dumps(forms) if forms else None,
                       json.dumps(scripts) if scripts else None,
                       json.dumps(stylesheets) if stylesheets else None,
                       json.dumps(assets) if assets else None,
                       json.dumps(technologies) if technologies else None,
                       json.dumps(seo_data) if seo_data else None,
                       json.dumps(performance) if performance else None,
                       json.dumps(html_tags) if html_tags else None,
                       page_size, depth, str(parent_url)[:2000] if parent_url else None, now))
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_crawled_page error: {e}')
            return 0

    def get_crawled_pages(self, target_id=None, limit=1000):
        try:
            c = self.conn.cursor()
            query = 'SELECT * FROM crawled_pages WHERE 1=1'
            params = []
            if target_id:
                query += ' AND target_id=?'
                params.append(target_id)
            query += ' ORDER BY crawled_at DESC LIMIT ?'
            params.append(limit)
            c.execute(query, params)
            rows = [dict(r) for r in c.fetchall()]
            for row in rows:
                for field in ('headings', 'links', 'images', 'forms', 'scripts',
                              'stylesheets', 'assets', 'technologies', 'seo_data',
                              'performance', 'html_tags'):
                    val = row.get(field)
                    if val and isinstance(val, str):
                        try:
                            row[field] = json.loads(val)
                        except Exception:
                            pass
            return rows
        except Exception as e:
            print(f'get_crawled_pages error: {e}')
            return []

    def get_crawled_page(self, page_id):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM crawled_pages WHERE id=?', (page_id,))
            row = c.fetchone()
            if not row:
                return None
            d = dict(row)
            for field in ('headings', 'links', 'images', 'forms', 'scripts',
                          'stylesheets', 'assets', 'technologies', 'seo_data',
                          'performance', 'html_tags'):
                val = d.get(field)
                if val and isinstance(val, str):
                    try:
                        d[field] = json.loads(val)
                    except Exception:
                        pass
            return d
        except Exception as e:
            print(f'get_crawled_page error: {e}')
            return None

    # ─── Site Technologies ───

    def add_site_technology(self, target_id, name, category=None, version=None,
                            confidence=0, evidence=None):
        if not name:
            return 0
        try:
            c = self.conn.cursor()
            now = time.time()
            c.execute('''INSERT INTO site_technologies
                        (target_id, name, category, version, confidence, evidence, detected_at)
                        VALUES (?,?,?,?,?,?,?)''',
                      (target_id, str(name)[:200], str(category)[:100] if category else None,
                       str(version)[:50] if version else None,
                       confidence, str(evidence)[:500] if evidence else None, now))
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_site_technology error: {e}')
            return 0

    def get_site_technologies(self, target_id=None):
        try:
            c = self.conn.cursor()
            if target_id:
                c.execute('SELECT * FROM site_technologies WHERE target_id=? ORDER BY confidence DESC', (target_id,))
            else:
                c.execute('SELECT * FROM site_technologies ORDER BY detected_at DESC LIMIT 200')
            return [dict(r) for r in c.fetchall()]
        except Exception as e:
            print(f'get_site_technologies error: {e}')
            return []

    def clear_site_data(self, target_id=None):
        try:
            c = self.conn.cursor()
            if target_id:
                c.execute('DELETE FROM crawled_pages WHERE target_id=?', (target_id,))
                c.execute('DELETE FROM site_technologies WHERE target_id=?', (target_id,))
            else:
                c.execute('DELETE FROM crawled_pages')
                c.execute('DELETE FROM site_technologies')
            self.conn.commit()
        except Exception as e:
            print(f'clear_site_data error: {e}')

    # ─── Captured Traffic ───

    def add_traffic(self, method=None, url=None, host=None, path=None,
                    request_headers=None, request_body=None, status_code=None,
                    response_headers=None, response_body=None, content_type=None):
        try:
            c = self.conn.cursor()
            now = time.time()
            c.execute('''INSERT INTO captured_traffic
                        (method, url, host, path, request_headers, request_body,
                         status_code, response_headers, response_body, content_type, captured_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                      (str(method)[:10] if method else None,
                       str(url)[:2000] if url else None,
                       str(host)[:500] if host else None,
                       str(path)[:2000] if path else None,
                       json.dumps(request_headers) if request_headers else None,
                       str(request_body)[:50000] if request_body else None,
                       status_code,
                       json.dumps(response_headers) if response_headers else None,
                       str(response_body)[:50000] if response_body else None,
                       str(content_type)[:200] if content_type else None,
                       now))
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_traffic error: {e}')
            return 0

    def get_traffic(self, host=None, method=None, keyword=None, limit=500):
        try:
            c = self.conn.cursor()
            query = 'SELECT * FROM captured_traffic WHERE 1=1'
            params = []
            if host:
                query += ' AND host LIKE ?'
                params.append(f'%{host}%')
            if method:
                query += ' AND method=?'
                params.append(method)
            if keyword:
                query += ' AND (url LIKE ? OR path LIKE ?)'
                params.extend([f'%{keyword}%', f'%{keyword}%'])
            query += ' ORDER BY captured_at DESC LIMIT ?'
            params.append(limit)
            c.execute(query, params)
            rows = [dict(r) for r in c.fetchall()]
            for row in rows:
                for field in ('request_headers', 'response_headers'):
                    val = row.get(field)
                    if val and isinstance(val, str):
                        try:
                            row[field] = json.loads(val)
                        except Exception:
                            pass
            return rows
        except Exception as e:
            print(f'get_traffic error: {e}')
            return []

    def get_traffic_detail(self, traffic_id):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM captured_traffic WHERE id=?', (traffic_id,))
            row = c.fetchone()
            if not row:
                return None
            d = dict(row)
            for field in ('request_headers', 'response_headers'):
                val = d.get(field)
                if val and isinstance(val, str):
                    try:
                        d[field] = json.loads(val)
                    except Exception:
                        pass
            return d
        except Exception as e:
            print(f'get_traffic_detail error: {e}')
            return None

    def clear_traffic(self):
        try:
            c = self.conn.cursor()
            c.execute('DELETE FROM captured_traffic')
            self.conn.commit()
        except Exception as e:
            print(f'clear_traffic error: {e}')

    # ─── Tasks ───

    def add_task(self, task_id, task_type, target=None, params=None):
        try:
            c = self.conn.cursor()
            now = time.time()
            c.execute('''INSERT INTO tasks (id, type, target, params, status, progress, created_at)
                        VALUES (?,?,?,?,?,?,?)''',
                      (task_id, str(task_type)[:50], str(target)[:2000] if target else None,
                       json.dumps(params) if params else None, 'pending', 0, now))
            self.conn.commit()
        except Exception as e:
            print(f'add_task error: {e}')

    def update_task(self, task_id, status, progress=0, message=None, result=None):
        try:
            c = self.conn.cursor()
            now = time.time()
            if status == 'running':
                c.execute('''UPDATE tasks SET status=?, progress=?, message=?, started_at=COALESCE(started_at,?)
                            WHERE id=?''',
                          (status, progress, message, now, task_id))
            elif status in ('completed', 'failed', 'stopped'):
                c.execute('''UPDATE tasks SET status=?, progress=?, message=?, result=?, finished_at=?
                            WHERE id=?''',
                          (status, progress, message, json.dumps(result) if result else None, now, task_id))
            else:
                c.execute('''UPDATE tasks SET status=?, progress=?, message=? WHERE id=?''',
                          (status, progress, message, task_id))
            self.conn.commit()
        except Exception as e:
            print(f'update_task error: {e}')

    def get_task(self, task_id):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM tasks WHERE id=?', (task_id,))
            row = c.fetchone()
            if not row:
                return None
            d = dict(row)
            for field in ('params', 'result'):
                val = d.get(field)
                if val and isinstance(val, str):
                    try:
                        d[field] = json.loads(val)
                    except Exception:
                        pass
            return d
        except Exception:
            return None

    def list_tasks(self, limit=50):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?', (limit,))
            rows = [dict(r) for r in c.fetchall()]
            for row in rows:
                for field in ('params', 'result'):
                    val = row.get(field)
                    if val and isinstance(val, str):
                        try:
                            row[field] = json.loads(val)
                        except Exception:
                            pass
            return rows
        except Exception:
            return []

    # ─── Favorites ───

    def add_favorite(self, url, method='GET', label=''):
        if not url:
            return 0
        try:
            c = self.conn.cursor()
            c.execute('INSERT OR REPLACE INTO favorites (url, method, label, created_at) VALUES (?,?,?,?)',
                      (str(url)[:2000], str(method or 'GET')[:10].upper(), str(label or '')[:200], time.time()))
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_favorite error: {e}')
            return 0

    def remove_favorite(self, url, method='GET'):
        try:
            c = self.conn.cursor()
            c.execute('DELETE FROM favorites WHERE url=? AND method=?',
                      (str(url)[:2000], str(method or 'GET')[:10].upper()))
            self.conn.commit()
            return c.rowcount > 0
        except Exception:
            return False

    def get_favorites(self, limit=200):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM favorites ORDER BY created_at DESC LIMIT ?', (limit,))
            return [dict(r) for r in c.fetchall()]
        except Exception:
            return []

    def get_favorite_set(self):
        """Return set of 'METHOD:url' strings for fast lookup"""
        try:
            c = self.conn.cursor()
            c.execute('SELECT method, url FROM favorites')
            return {f'{r["method"]}:{r["url"]}' for r in c.fetchall()}
        except Exception:
            return set()

    # ─── Request History ───

    def add_history(self, method, url, headers=None, body=None, status_code=None,
                    response_size=None, elapsed=None):
        try:
            c = self.conn.cursor()
            c.execute('''INSERT INTO request_history
                (method, url, headers, body, status_code, response_size, elapsed, created_at)
                VALUES (?,?,?,?,?,?,?,?)''',
                (str(method or 'GET')[:10], str(url)[:2000],
                 json.dumps(headers) if headers else None,
                 str(body)[:10000] if body else None,
                 status_code, response_size, elapsed, time.time()))
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_history error: {e}')
            return 0

    def get_history(self, limit=100):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM request_history ORDER BY created_at DESC LIMIT ?', (limit,))
            rows = [dict(r) for r in c.fetchall()]
            for row in rows:
                if row.get('headers') and isinstance(row['headers'], str):
                    try:
                        row['headers'] = json.loads(row['headers'])
                    except Exception:
                        pass
            return rows
        except Exception:
            return []

    def clear_history(self):
        try:
            c = self.conn.cursor()
            c.execute('DELETE FROM request_history')
            self.conn.commit()
            return True
        except Exception:
            return False

    # ─── Sessions ───

    def add_session(self, name, domain, url, cookies, local_storage=None):
        try:
            c = self.conn.cursor()
            c.execute(
                'INSERT INTO sessions (name, domain, url, cookies, local_storage, created_at) VALUES (?,?,?,?,?,?)',
                (name, domain, url, json.dumps(cookies) if isinstance(cookies, (list, dict)) else cookies,
                 json.dumps(local_storage) if local_storage else None, time.time())
            )
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_session error: {e}')
            return None

    def get_sessions(self):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM sessions ORDER BY created_at DESC')
            rows = [dict(r) for r in c.fetchall()]
            for row in rows:
                if row.get('cookies') and isinstance(row['cookies'], str):
                    try:
                        row['cookies'] = json.loads(row['cookies'])
                    except Exception:
                        pass
                if row.get('local_storage') and isinstance(row['local_storage'], str):
                    try:
                        row['local_storage'] = json.loads(row['local_storage'])
                    except Exception:
                        row['local_storage'] = {}
            return rows
        except Exception:
            return []

    def get_session(self, session_id):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM sessions WHERE id=?', (session_id,))
            row = c.fetchone()
            if not row:
                return None
            row = dict(row)
            if row.get('cookies') and isinstance(row['cookies'], str):
                try:
                    row['cookies'] = json.loads(row['cookies'])
                except Exception:
                    pass
            if row.get('local_storage') and isinstance(row['local_storage'], str):
                try:
                    row['local_storage'] = json.loads(row['local_storage'])
                except Exception:
                    row['local_storage'] = {}
            return row
        except Exception:
            return None

    def delete_session(self, session_id):
        try:
            c = self.conn.cursor()
            c.execute('DELETE FROM sessions WHERE id=?', (session_id,))
            self.conn.commit()
            return True
        except Exception:
            return False

    def get_cookies_for_url(self, url):
        """Get cookies from the most recent session matching the URL's domain"""
        try:
            domain = urlparse(url).netloc
            c = self.conn.cursor()
            c.execute(
                'SELECT cookies, local_storage FROM sessions WHERE domain=? ORDER BY created_at DESC LIMIT 1',
                (domain,)
            )
            row = c.fetchone()
            if not row:
                # Try matching without port
                base_domain = domain.split(':')[0]
                c.execute(
                    'SELECT cookies, local_storage FROM sessions WHERE domain LIKE ? ORDER BY created_at DESC LIMIT 1',
                    (f'%{base_domain}%',)
                )
                row = c.fetchone()
            if not row:
                return {}, {}
            cookies = {}
            raw = row['cookies']
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    raw = []
            if isinstance(raw, list):
                for ck in raw:
                    if isinstance(ck, dict) and ck.get('name'):
                        cookies[ck['name']] = ck.get('value', '')
            ls = {}
            raw_ls = row['local_storage']
            if isinstance(raw_ls, str):
                try:
                    ls = json.loads(raw_ls)
                except Exception:
                    pass
            elif isinstance(raw_ls, dict):
                ls = raw_ls
            return cookies, ls
        except Exception:
            return {}, {}

    # ─── Crawl Rules ───

    def add_crawl_rule(self, name, url_pattern, config):
        try:
            c = self.conn.cursor()
            c.execute(
                'INSERT INTO crawl_rules (name, url_pattern, config, created_at) VALUES (?,?,?,?)',
                (name, url_pattern, json.dumps(config) if isinstance(config, dict) else config, time.time())
            )
            self.conn.commit()
            return c.lastrowid
        except Exception as e:
            print(f'add_crawl_rule error: {e}')
            return None

    def get_crawl_rules(self):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM crawl_rules ORDER BY created_at DESC')
            rows = [dict(r) for r in c.fetchall()]
            for row in rows:
                if row.get('config') and isinstance(row['config'], str):
                    try:
                        row['config'] = json.loads(row['config'])
                    except Exception:
                        row['config'] = {}
            return rows
        except Exception:
            return []

    def get_crawl_rule(self, rule_id):
        try:
            c = self.conn.cursor()
            c.execute('SELECT * FROM crawl_rules WHERE id=?', (rule_id,))
            row = c.fetchone()
            if not row:
                return None
            row = dict(row)
            if row.get('config') and isinstance(row['config'], str):
                try:
                    row['config'] = json.loads(row['config'])
                except Exception:
                    row['config'] = {}
            return row
        except Exception:
            return None

    def delete_crawl_rule(self, rule_id):
        try:
            c = self.conn.cursor()
            c.execute('DELETE FROM crawl_rules WHERE id=?', (rule_id,))
            self.conn.commit()
            return True
        except Exception:
            return False