"""Structured data extractor - extract tables, lists, repeated patterns, forms from HTML"""
import re
from collections import defaultdict
from bs4 import BeautifulSoup


def extract_all(html, url=''):
    """Extract all structured data from HTML.

    Returns:
        dict with keys: tables, lists, repeated_patterns, forms, metadata
    """
    if not html or not isinstance(html, str):
        return {'tables': [], 'lists': [], 'repeated_patterns': [], 'forms': [], 'metadata': {}}

    try:
        soup = BeautifulSoup(html[:200000], 'lxml')
    except Exception:
        try:
            soup = BeautifulSoup(html[:200000], 'html.parser')
        except Exception:
            return {'tables': [], 'lists': [], 'repeated_patterns': [], 'forms': [], 'metadata': {}}

    return {
        'tables': _extract_tables(soup),
        'lists': _extract_lists(soup),
        'repeated_patterns': _find_repeated_patterns(soup),
        'forms': _extract_forms(soup),
        'metadata': _extract_metadata(soup),
    }


def _extract_tables(soup):
    """Extract all HTML tables as structured data"""
    results = []
    for i, table in enumerate(soup.find_all('table')[:20]):
        rows = table.find_all('tr')
        if len(rows) < 2:
            continue

        # Extract headers
        headers = []
        header_row = table.find('thead')
        if header_row:
            headers = [th.get_text(strip=True)[:100] for th in header_row.find_all(['th', 'td'])]
        elif rows:
            first_cells = rows[0].find_all(['th', 'td'])
            if any(c.name == 'th' for c in first_cells):
                headers = [c.get_text(strip=True)[:100] for c in first_cells]

        # Extract data rows
        data_rows = []
        for row in rows:
            cells = row.find_all(['td', 'th'])
            if not cells:
                continue
            row_data = [c.get_text(strip=True)[:500] for c in cells]
            # Skip if this looks like a header row we already captured
            if row_data == headers:
                continue
            if len(row_data) == len(headers) and headers:
                data_rows.append(dict(zip(headers, row_data)))
            elif row_data:
                data_rows.append({'_values': row_data})

        if data_rows:
            results.append({
                'index': i,
                'headers': headers,
                'row_count': len(data_rows),
                'rows': data_rows[:50],  # Cap at 50 rows
            })
    return results


def _extract_lists(soup):
    """Extract structured list data (ul/ol with consistent items)"""
    results = []
    for tag_name in ['ul', 'ol']:
        for i, lst in enumerate(soup.find_all(tag_name)[:30]):
            items = lst.find_all('li', recursive=False)
            if len(items) < 3:
                continue

            # Check if items have a consistent structure
            item_data = []
            for li in items:
                entry = {}
                links = li.find_all('a')
                if links:
                    entry['links'] = [{'text': a.get_text(strip=True)[:200], 'href': a.get('href', '')} for a in links[:3]]
                text = li.get_text(strip=True)[:300]
                if text:
                    entry['text'] = text
                imgs = li.find_all('img')
                if imgs:
                    entry['images'] = [img.get('src', '') for img in imgs[:3]]
                if entry:
                    item_data.append(entry)

            if len(item_data) >= 3:
                results.append({
                    'type': tag_name,
                    'index': i,
                    'item_count': len(item_data),
                    'items': item_data[:30],
                })
    return results


def _find_repeated_patterns(soup):
    """Find repeated DOM structures that indicate list/detail patterns.

    Looks for containers with multiple child elements sharing the same class pattern.
    """
    results = []

    # Find containers with repeated child structures
    for container in soup.find_all(['div', 'section', 'ul', 'ol']):
        children = container.find_all(recursive=False)
        if len(children) < 3:
            continue

        # Group children by their CSS class
        class_groups = defaultdict(list)
        for child in children:
            cls = ' '.join(sorted(child.get('class', [])))
            if cls:
                class_groups[cls].append(child)

        # Find the largest group of similar elements
        for cls, group in class_groups.items():
            if len(group) < 3:
                continue

            # Extract pattern from first element
            first = group[0]
            pattern = _extract_element_pattern(first)

            # Extract data from each element
            items = []
            for elem in group[:30]:
                item = {}
                links = elem.find_all('a', limit=3)
                if links:
                    item['links'] = [{'text': a.get_text(strip=True)[:200], 'href': a.get('href', '')} for a in links]
                imgs = elem.find_all('img', limit=2)
                if imgs:
                    item['images'] = [img.get('src', '') for img in imgs]
                text = elem.get_text(strip=True)[:300]
                if text:
                    item['text'] = text
                # Extract any price-like content
                price_match = re.search(r'[￥$€¥]\s*[\d,]+\.?\d*|\d+\.?\d*\s*[元]', elem.get_text())
                if price_match:
                    item['price'] = price_match.group()
                if item:
                    items.append(item)

            if items:
                results.append({
                    'container_class': cls,
                    'item_count': len(group),
                    'pattern': pattern,
                    'items': items,
                })

    # Deduplicate by container class
    seen = set()
    deduped = []
    for r in results:
        key = r['container_class']
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return sorted(deduped, key=lambda x: x['item_count'], reverse=True)[:10]


def _extract_element_pattern(elem):
    """Extract a structural pattern from a DOM element"""
    parts = []
    for child in elem.find_all(recursive=False)[:5]:
        tag = child.name
        cls = '.'.join(child.get('class', []))[:30]
        parts.append(f'{tag}.{cls}' if cls else tag)
    return ' > '.join(parts)


def _extract_forms(soup):
    """Extract form structures with field details"""
    results = []
    for i, form in enumerate(soup.find_all('form')[:20]):
        action = form.get('action', '')
        method = (form.get('method') or 'GET').upper()
        fields = []
        for inp in form.find_all(['input', 'select', 'textarea']):
            field = {
                'name': inp.get('name', ''),
                'type': inp.get('type', inp.name) if inp.name != 'select' else 'select',
                'required': inp.has_attr('required'),
                'placeholder': inp.get('placeholder', '')[:100],
            }
            if inp.name == 'select':
                field['options'] = [opt.get('value', opt.get_text(strip=True))[:100] for opt in inp.find_all('option')[:20]]
            if field['name']:
                fields.append(field)

        if fields:
            results.append({
                'index': i,
                'action': action,
                'method': method,
                'field_count': len(fields),
                'fields': fields,
            })
    return results


def _extract_metadata(soup):
    """Extract structured metadata (JSON-LD, microdata, meta tags)"""
    meta = {}

    # JSON-LD
    jsonld_list = []
    for script in soup.find_all('script', type='application/ld+json'):
        if script.string:
            try:
                import json
                data = json.loads(script.string)
                jsonld_list.append(data)
            except Exception:
                pass
    if jsonld_list:
        meta['json_ld'] = jsonld_list

    # Open Graph
    og = {}
    for m in soup.find_all('meta', property=re.compile(r'^og:')):
        og[m.get('property', '')] = m.get('content', '')[:500]
    if og:
        meta['open_graph'] = og

    # Standard meta
    std = {}
    for m in soup.find_all('meta'):
        name = m.get('name', '') or m.get('property', '')
        content = m.get('content', '')
        if name and content and not name.startswith('og:'):
            std[name] = content[:500]
    if std:
        meta['meta_tags'] = std

    return meta
