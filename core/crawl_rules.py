"""Configurable crawl rules - user-defined URL filters, field extraction, depth limits"""
import re
import json


# Built-in page type filters (user can select which types to crawl)
PAGE_TYPE_FILTERS = {
    'article_list': {'label': '文章列表', 'default': True},
    'article_detail': {'label': '文章详情', 'default': True},
    'product_list': {'label': '商品列表', 'default': True},
    'product_detail': {'label': '商品详情', 'default': True},
    'api_endpoint': {'label': 'API接口', 'default': True},
    'user_center': {'label': '用户中心', 'default': False},
    'login': {'label': '登录页', 'default': False},
    'search_result': {'label': '搜索结果', 'default': True},
    'data_table': {'label': '数据表格', 'default': True},
    'data_feed': {'label': '数据源', 'default': True},
    'static_resource': {'label': '静态资源', 'default': False},
    'home_page': {'label': '首页', 'default': True},
    'unknown': {'label': '未知类型', 'default': True},
}


class CrawlRule:
    """A single crawl rule configuration"""

    def __init__(self, name='', url_pattern='', include_patterns=None, exclude_patterns=None,
                 page_types=None, max_depth=3, max_pages=100, extract_fields=None,
                 follow_pagination=True, handle_spa=False, custom_headers=None):
        self.name = name
        self.url_pattern = url_pattern  # Target URL prefix/pattern
        self.include_patterns = include_patterns or []  # Regex patterns: only crawl matching URLs
        self.exclude_patterns = exclude_patterns or []  # Regex patterns: skip matching URLs
        self.page_types = page_types or list(PAGE_TYPE_FILTERS.keys())  # Which page types to crawl
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.extract_fields = extract_fields or []  # Fields to extract (CSS selectors)
        self.follow_pagination = follow_pagination
        self.handle_spa = handle_spa
        self.custom_headers = custom_headers or {}

    def should_crawl(self, url, page_type='unknown'):
        """Check if a URL should be crawled based on this rule"""
        # Check page type filter
        if page_type and self.page_types and page_type not in self.page_types:
            return False

        # Check include patterns
        if self.include_patterns:
            if not any(re.search(p, url) for p in self.include_patterns):
                return False

        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if re.search(pattern, url):
                return False

        return True

    def to_dict(self):
        return {
            'name': self.name,
            'url_pattern': self.url_pattern,
            'include_patterns': self.include_patterns,
            'exclude_patterns': self.exclude_patterns,
            'page_types': self.page_types,
            'max_depth': self.max_depth,
            'max_pages': self.max_pages,
            'extract_fields': self.extract_fields,
            'follow_pagination': self.follow_pagination,
            'handle_spa': self.handle_spa,
            'custom_headers': self.custom_headers,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            name=data.get('name', ''),
            url_pattern=data.get('url_pattern', ''),
            include_patterns=data.get('include_patterns', []),
            exclude_patterns=data.get('exclude_patterns', []),
            page_types=data.get('page_types', []),
            max_depth=data.get('max_depth', 3),
            max_pages=data.get('max_pages', 100),
            extract_fields=data.get('extract_fields', []),
            follow_pagination=data.get('follow_pagination', True),
            handle_spa=data.get('handle_spa', False),
            custom_headers=data.get('custom_headers', {}),
        )


def create_default_rule(url=''):
    """Create a default rule with sensible defaults"""
    return CrawlRule(
        name='默认规则',
        url_pattern=url,
        max_depth=3,
        max_pages=100,
        follow_pagination=True,
        handle_spa=True,
    )


def get_example_rules():
    """Return example rules for the UI"""
    return [
        CrawlRule(
            name='只爬文章',
            url_pattern='',
            include_patterns=[r'/blog/', r'/news/', r'/article/', r'/post/'],
            page_types=['article_list', 'article_detail'],
            extract_fields=['h1', '.title', '.content', '.author', '.date'],
            follow_pagination=True,
        ),
        CrawlRule(
            name='只爬商品',
            url_pattern='',
            include_patterns=[r'/product', r'/item/', r'/goods/', r'/shop/'],
            page_types=['product_list', 'product_detail'],
            extract_fields=['.title', '.price', '.description', '.image'],
            follow_pagination=True,
        ),
        CrawlRule(
            name='只爬API接口',
            url_pattern='',
            include_patterns=[r'/api/', r'/rest/', r'/v\d+/'],
            page_types=['api_endpoint', 'data_feed'],
            max_depth=1,
        ),
        CrawlRule(
            name='深度爬取(含SPA)',
            url_pattern='',
            max_depth=5,
            max_pages=500,
            follow_pagination=True,
            handle_spa=True,
        ),
    ]
