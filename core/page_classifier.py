"""Page type classifier - auto classify web pages by content pattern"""
import re
from urllib.parse import urlparse, parse_qs


# URL pattern rules: (compiled_regex, page_type, weight)
URL_RULES = [
    (re.compile(r'/page/\d+|/p/\d+|[?&]page=\d+|[?&]p=\d+|/list\b|/category\b|/tag\b|/archive\b', re.I), 'article_list', 6),
    (re.compile(r'/article/|/post/|/blog/|/news/\d|/post/\d+|/\d{4}/\d{2}/|/detail/\d+|/content/\d+', re.I), 'article_detail', 7),
    (re.compile(r'/product[s]?/\d+|/item/\d+|/goods/\d+|/sku/|/shop/\d+|/p/\d+[-_]', re.I), 'product_detail', 8),
    (re.compile(r'/product[s]?/?$|/shop/?$|/store/?$|/mall/?$|/goods/?$|/category/|/catalog/', re.I), 'product_list', 7),
    (re.compile(r'/api/|/rest/|/graphql|/v\d+/|\.json(\?|$)', re.I), 'api_endpoint', 9),
    (re.compile(r'/login|/signin|/sign-in|/register|/signup|/sign-up|/auth/', re.I), 'login', 8),
    (re.compile(r'/user/|/profile/|/account/|/member/|/my/|/dashboard/|/settings/', re.I), 'user_center', 7),
    (re.compile(r'/search\b|[?&]q=|[?&]keyword=|[?&]search=', re.I), 'search_result', 6),
    (re.compile(r'\.(json|xml|csv|rss|atom)(\?|$)', re.I), 'data_feed', 9),
]

# HTML keyword weights: (keyword_set, page_type, weight)
HTML_KEYWORD_RULES = [
    (frozenset(['article', 'post', 'blog', 'news', 'author', 'publish']), 'article_detail', 5),
    (frozenset(['pagination', 'page-numbers', 'next-page', 'prev-page', 'load-more']), 'article_list', 5),
    (frozenset(['product', 'price', 'add-to-cart', 'buy-now', 'shopping', 'sku']), 'product_detail', 6),
    (frozenset(['login', 'sign-in', 'signin', 'password', 'username', 'email']), 'login', 6),
    (frozenset(['profile', 'account', 'settings', 'dashboard', 'my-account']), 'user_center', 5),
    (frozenset(['search', 'results', 'query', 'filter']), 'search_result', 4),
]

# HTML structural patterns
STRUCTURAL_RULES = [
    # Many <article> tags = list page
    (lambda soup: len(soup.find_all('article')) >= 3, 'article_list', 6),
    # Single <article> with substantial text = detail page
    (lambda soup: len(soup.find_all('article')) == 1 and
     (soup.find('article').get_text(strip=True) if soup.find('article') else '') > 500,
     'article_detail', 7),
    # Many identical card-like divs = list page
    (lambda soup: _has_repeated_cards(soup), 'article_list', 5),
    # Price elements present = product page
    (lambda soup: bool(soup.find_all(class_=re.compile(r'price|amount|cost', re.I))) or
     bool(soup.find_all(string=re.compile(r'￥|\$|€|¥\s*\d+'))),
     'product_detail', 5),
    # Form with password field = login page
    (lambda soup: bool(soup.find('input', attrs={'type': 'password'})), 'login', 7),
    # Large table = data page
    (lambda soup: any(len(t.find_all('tr')) > 10 for t in soup.find_all('table')), 'data_table', 6),
]


def _has_repeated_cards(soup):
    """Check if page has repeated card-like structures (list indicator)"""
    # Check for repeated div/section patterns with similar class names
    containers = soup.find_all(['div', 'section', 'li'], class_=re.compile(
        r'card|item|entry|post|article|product|list-item|result', re.I))
    if len(containers) >= 5:
        # Check if they have similar structure (same child tags)
        class_groups = {}
        for c in containers:
            cls = ' '.join(sorted(c.get('class', [])))
            class_groups.setdefault(cls, 0)
            class_groups[cls] += 1
        return any(count >= 3 for count in class_groups.values())
    return False


# Human-readable labels
PAGE_TYPE_LABELS = {
    'article_list': '文章列表',
    'article_detail': '文章详情',
    'product_list': '商品列表',
    'product_detail': '商品详情',
    'api_endpoint': 'API接口',
    'user_center': '用户中心',
    'login': '登录页',
    'search_result': '搜索结果',
    'data_table': '数据表格',
    'data_feed': '数据源',
    'static_resource': '静态资源',
    'home_page': '首页',
    'unknown': '未知类型',
}


def classify(url, html_text='', soup=None, status_code=200):
    """Classify a page into a type category.

    Returns:
        dict: {'type': str, 'confidence': float, 'label': str, 'indicators': list}
    """
    scores = {}
    indicators = []

    # 1. Non-HTML content types
    ct = ''
    if hasattr(html_text, 'headers'):
        ct = html_text.headers.get('Content-Type', '')
    if not html_text or (isinstance(html_text, str) and not html_text.strip().startswith(('<', '!'))):
        ext = '.' + urlparse(url).path.rsplit('.', 1)[-1].lower() if '.' in urlparse(url).path else ''
        if ext in {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico', '.webp', '.mp4', '.mp3', '.pdf'}:
            return {'type': 'static_resource', 'confidence': 0.95, 'label': PAGE_TYPE_LABELS['static_resource'], 'indicators': [f'文件扩展名: {ext}']}

    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()

    # 2. URL pattern scoring
    for pattern, ptype, weight in URL_RULES:
        if pattern.search(url):
            scores[ptype] = scores.get(ptype, 0) + weight
            indicators.append(f'URL模式匹配: {ptype}')

    # 3. Root path = home page
    if path in ('', '/') and not query:
        scores['home_page'] = scores.get('home_page', 0) + 10
        indicators.append('根路径')

    # 4. HTML analysis (only if soup provided or text available)
    if soup is None and html_text and isinstance(html_text, str) and '<' in html_text:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_text[:50000], 'lxml')
        except Exception:
            soup = None

    if soup:
        # Keyword scoring
        text_lower = soup.get_text(' ', strip=True).lower()[:10000]
        html_str = str(soup)[:30000].lower()

        for keywords, ptype, weight in HTML_KEYWORD_RULES:
            hits = sum(1 for kw in keywords if kw in html_str)
            if hits >= 2:
                scores[ptype] = scores.get(ptype, 0) + weight
                indicators.append(f'HTML关键词: {ptype}({hits}个匹配)')

        # Structural scoring
        for check, ptype, weight in STRUCTURAL_RULES:
            try:
                if check(soup):
                    scores[ptype] = scores.get(ptype, 0) + weight
                    indicators.append(f'HTML结构: {ptype}')
            except Exception:
                pass

    # 5. Pick best
    if not scores:
        return {'type': 'unknown', 'confidence': 0.0, 'label': PAGE_TYPE_LABELS['unknown'], 'indicators': indicators}

    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best_type, best_score = sorted_scores[0]
    total = sum(s for _, s in sorted_scores) or 1
    confidence = round(best_score / total, 2)

    return {
        'type': best_type,
        'confidence': confidence,
        'label': PAGE_TYPE_LABELS.get(best_type, best_type),
        'indicators': indicators,
    }


# All known page types for user filtering
ALL_PAGE_TYPES = list(PAGE_TYPE_LABELS.keys())
