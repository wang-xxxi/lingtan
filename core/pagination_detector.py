"""Pagination detector - detect pagination patterns, load more buttons, infinite scroll"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup


# Common pagination URL patterns
PAGINATION_URL_PATTERNS = [
    re.compile(r'[?&](page|p|pn|pg|offset)=(\d+)', re.I),
    re.compile(r'/page/(\d+)', re.I),
    re.compile(r'/p(\d+)(?:\.html?)?$', re.I),
    re.compile(r'[?&]start=(\d+)', re.I),
    re.compile(r'[?&]from=(\d+)', re.I),
    re.compile(r'[?&]skip=(\d+)', re.I),
]

# Common "load more" / "next page" button text patterns
NEXT_PATTERNS = re.compile(
    r'下一页|下页|next\s*page|next|load\s*more|加载更多|查看更多|show\s*more|更多|older\s*posts|'
    r'后一页|后页|下翻|加载下一页', re.I
)

# Pagination CSS class/id patterns
PAGINATION_CSS = re.compile(
    r'pag(e|ination)|pager|page-nav|page-numbers|next-page|load-more|'
    r'more-btn|load-btn|show-more|has-more', re.I
)

# Infinite scroll indicators
SCROLL_INDICATORS = re.compile(
    r'infinite[-_]?scroll|lazy[-_]?load|load[-_]?on[-_]?scroll|'
    r'intersection[-_]?observer|scroll[-_]?load|inf[-_]?scroll', re.I
)


def detect(url, html='', soup=None):
    """Detect all pagination mechanisms on a page.

    Returns:
        dict with keys:
        - url_pagination: pagination info from URL params
        - html_pagination: pagination links found in HTML
        - load_more: load more button info
        - infinite_scroll: whether infinite scroll is likely used
        - next_urls: list of next page URLs to try
    """
    result = {
        'url_pagination': _detect_url_pagination(url),
        'html_pagination': [],
        'load_more': None,
        'infinite_scroll': False,
        'next_urls': [],
    }

    if not html:
        return result

    if soup is None and isinstance(html, str):
        try:
            soup = BeautifulSoup(html[:100000], 'lxml')
        except Exception:
            try:
                soup = BeautifulSoup(html[:100000], 'html.parser')
            except Exception:
                return result

    if not soup:
        return result

    result['html_pagination'] = _detect_html_pagination(soup, url)
    result['load_more'] = _detect_load_more(soup)
    result['infinite_scroll'] = _detect_infinite_scroll(soup, html)
    result['next_urls'] = _build_next_urls(result, url)

    return result


def _detect_url_pagination(url):
    """Analyze URL for pagination parameters"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    info = {'has_pagination': False, 'param': None, 'current': None, 'pattern': None}

    for name in ('page', 'p', 'pn', 'pg', 'offset', 'start', 'from', 'skip'):
        if name in params:
            val = params[name][0]
            if val.isdigit():
                info['has_pagination'] = True
                info['param'] = name
                info['current'] = int(val)
                info['pattern'] = f'{name}={{page}}'
                break

    # Check path-based pagination
    if not info['has_pagination']:
        m = re.search(r'/page/(\d+)', url, re.I)
        if m:
            info['has_pagination'] = True
            info['param'] = 'path'
            info['current'] = int(m.group(1))
            info['pattern'] = re.sub(r'/page/\d+', '/page/{page}', url, flags=re.I)

    return info


def _detect_html_pagination(soup, url):
    """Find pagination links in HTML"""
    results = []

    # Find pagination containers
    containers = soup.find_all(class_=PAGINATION_CSS) + soup.find_all(id=PAGINATION_CSS)
    containers = containers or soup.find_all('nav')  # Fallback to nav elements

    for container in containers[:5]:
        links = container.find_all('a', href=True)
        page_links = []
        for a in links:
            text = a.get_text(strip=True)
            href = a.get('href', '')
            # Check if this looks like a page number
            if text.isdigit() or NEXT_PATTERNS.search(text):
                full_url = url.rstrip('/') + href if href.startswith('/') else href
                page_links.append({
                    'text': text,
                    'href': full_url,
                    'is_next': bool(NEXT_PATTERNS.search(text)),
                    'page_num': int(text) if text.isdigit() else None,
                })

        if page_links:
            max_page = max((pl.get('page_num') or 0) for pl in page_links)
            results.append({
                'page_links': page_links,
                'max_page': max_page if max_page > 0 else None,
            })

    # Also find standalone "next" links anywhere
    for a in soup.find_all('a', href=True):
        text = a.get_text(strip=True).lower()
        if NEXT_PATTERNS.search(text) and len(text) < 30:
            href = a.get('href', '')
            if href and href not in ('#', 'javascript:'):
                full_url = url.rstrip('/') + href if href.startswith('/') else href
                results.append({
                    'page_links': [{'text': a.get_text(strip=True), 'href': full_url, 'is_next': True, 'page_num': None}],
                    'max_page': None,
                })
                break

    return results


def _detect_load_more(soup):
    """Find 'Load More' buttons"""
    # Check buttons
    for btn in soup.find_all(['button', 'a', 'div']):
        text = btn.get_text(strip=True).lower()
        classes = ' '.join(btn.get('class', []))
        btn_id = btn.get('id', '')

        if (NEXT_PATTERNS.search(text) and len(text) < 30) or PAGINATION_CSS.search(classes) or PAGINATION_CSS.search(btn_id):
            attrs = {
                'text': btn.get_text(strip=True),
                'tag': btn.name,
                'class': classes,
                'id': btn_id,
            }
            # Check for data attributes that might indicate load behavior
            for attr in btn.attrs:
                if attr.startswith('data-') and any(kw in attr.lower() for kw in ('page', 'offset', 'load', 'more', 'next')):
                    attrs[attr] = btn.get(attr, '')
            if attrs.get('text') or attrs.get('class'):
                return attrs

    return None


def _detect_infinite_scroll(soup, html):
    """Detect if page uses infinite scroll"""
    # Check for JS libraries/patterns
    html_lower = html.lower() if isinstance(html, str) else ''

    # Check script content
    for script in soup.find_all('script'):
        src = (script.get('src', '') or '').lower()
        content = (script.string or '').lower()

        if SCROLL_INDICATORS.search(src) or SCROLL_INDICATORS.search(content):
            return True

        # Check for Intersection Observer usage
        if 'intersectionobserver' in content and ('load' in content or 'fetch' in content or 'ajax' in content):
            return True

        # Check for scroll event + AJAX pattern
        if 'scroll' in content and ('ajax' in content or 'fetch(' in content or 'loadmore' in content or 'load_more' in content):
            return True

    return False


def _build_next_urls(detection_result, url):
    """Build list of next page URLs to try"""
    next_urls = []

    # From URL pagination
    url_pg = detection_result['url_pagination']
    if url_pg['has_pagination'] and url_pg['current'] is not None:
        if url_pg['param'] == 'path':
            pattern = url_pg['pattern']
            next_urls.append(pattern.format(page=url_pg['current'] + 1))
        else:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[url_pg['param']] = [str(url_pg['current'] + 1)]
            new_query = urlencode(params, doseq=True)
            next_urls.append(urlunparse(parsed._replace(query=new_query)))

    # From HTML pagination links
    for pg in detection_result['html_pagination']:
        for link in pg.get('page_links', []):
            if link.get('is_next') and link.get('href'):
                if link['href'] not in next_urls:
                    next_urls.append(link['href'])

    # From URL (add ?page=2 as fallback if no pagination detected)
    if not next_urls and not url_pg['has_pagination']:
        parsed = urlparse(url)
        if parsed.query:
            next_urls.append(url + '&page=2')
        else:
            next_urls.append(url + '?page=2')

    return next_urls[:3]  # Max 3 next URLs to try


def get_all_pages(base_url, max_page=None, max_pages=50):
    """Generate page URLs from a paginated base URL.

    Args:
        base_url: URL with pagination (e.g., https://example.com/list?page=1)
        max_page: maximum page number (detected from HTML)
        max_pages: safety limit
    """
    urls = []
    pg_info = _detect_url_pagination(base_url)

    if pg_info['has_pagination']:
        start = pg_info['current'] or 1
        end = min((max_page or start + max_pages - 1), start + max_pages - 1)
        if pg_info['param'] == 'path':
            pattern = pg_info['pattern']
            for p in range(start, end + 1):
                urls.append(pattern.format(page=p))
        else:
            parsed = urlparse(base_url)
            params = parse_qs(parsed.query)
            for p in range(start, end + 1):
                params[pg_info['param']] = [str(p)]
                new_query = urlencode(params, doseq=True)
                urls.append(urlunparse(parsed._replace(query=new_query)))
    else:
        urls.append(base_url)

    return urls
