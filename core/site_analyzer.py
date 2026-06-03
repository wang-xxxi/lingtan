"""SEO and Performance analysis for crawled pages"""


class SiteAnalyzer:
    """SEO scoring and performance analysis"""

    def analyze(self, pages):
        """Analyze all crawled pages for SEO and performance"""
        if not pages:
            return {'seo': {}, 'performance': {}, 'overall_score': 0}

        seo_results = []
        perf_results = []

        for page in pages:
            if not isinstance(page, dict):
                continue
            seo = self._score_seo(page)
            perf = self._score_performance(page)
            seo_results.append(seo)
            perf_results.append(perf)

        # Overall scores
        avg_seo = sum(r['score'] for r in seo_results) / max(len(seo_results), 1)
        avg_perf = sum(r['score'] for r in perf_results) / max(len(perf_results), 1)

        return {
            'seo': {
                'pages': seo_results,
                'average_score': round(avg_seo),
                'summary': self._seo_summary(seo_results),
            },
            'performance': {
                'pages': perf_results,
                'average_score': round(avg_perf),
                'summary': self._perf_summary(perf_results),
            },
            'overall_score': round((avg_seo + avg_perf) / 2),
        }

    def _score_seo(self, page):
        """Score a single page's SEO (0-100)"""
        score = 0
        issues = []
        url = page.get('url', '')

        # Title (20 points)
        title = page.get('title', '')
        if title:
            score += 10
            if 10 <= len(title) <= 70:
                score += 10
            elif len(title) > 70:
                score += 5
                issues.append(f'标题过长({len(title)}字符，建议30-70)')
            else:
                score += 3
                issues.append(f'标题过短({len(title)}字符)')
        else:
            issues.append('缺少页面标题')

        # Meta description (15 points)
        desc = page.get('meta_description', '')
        if desc:
            score += 8
            if 50 <= len(desc) <= 160:
                score += 7
            elif len(desc) > 160:
                score += 3
                issues.append(f'Meta描述过长({len(desc)}字符，建议50-160)')
            else:
                score += 2
                issues.append(f'Meta描述过短({len(desc)}字符)')
        else:
            issues.append('缺少Meta描述')

        # Headings (20 points)
        headings = page.get('headings') or {}
        h1s = headings.get('h1', [])
        if h1s:
            score += 10
            if len(h1s) == 1:
                score += 5
            else:
                issues.append(f'H1标签过多({len(h1s)}个，建议1个)')
                score += 2
        else:
            issues.append('缺少H1标签')

        # Heading hierarchy
        has_h2 = bool(headings.get('h2'))
        if has_h2:
            score += 5
        else:
            issues.append('缺少H2标签')

        # Open Graph (15 points)
        seo_data = page.get('seo_data') or {}
        og_tags = seo_data.get('og_tags') or {}
        og_keys = ['og:title', 'og:description', 'og:image', 'og:url']
        og_present = sum(1 for k in og_keys if k in og_tags)
        score += int(15 * og_present / len(og_keys))
        if og_present < len(og_keys):
            missing = [k for k in og_keys if k not in og_tags]
            issues.append(f'缺少OG标签: {", ".join(missing)}')

        # Canonical (10 points)
        canonical = seo_data.get('canonical', '')
        if canonical:
            score += 10
        else:
            issues.append('缺少canonical链接')
            score += 3

        # Image alt texts (10 points)
        images = page.get('images') or []
        if images:
            with_alt = sum(1 for i in images if i.get('alt'))
            alt_ratio = with_alt / len(images)
            score += int(10 * alt_ratio)
            if alt_ratio < 0.8:
                issues.append(f'图片alt覆盖率: {int(alt_ratio*100)}%({with_alt}/{len(images)})')
        else:
            score += 10  # No images = no issue

        # Robots (10 points)
        robots = seo_data.get('robots', '')
        if robots:
            if 'noindex' in robots.lower():
                issues.append('页面设置了noindex')
            else:
                score += 5
        score += 5  # Base points for robots

        return {
            'url': url,
            'title': title,
            'score': min(score, 100),
            'issues': issues,
            'issue_count': len(issues),
        }

    def _score_performance(self, page):
        """Score a single page's performance (0-100)"""
        score = 100
        perf = page.get('performance') or {}

        # Response time
        rt = perf.get('response_time', 0) or 0
        if rt > 5:
            score -= 30
            grade = 'slow'
        elif rt > 2:
            score -= 15
            grade = 'acceptable'
        elif rt > 1:
            score -= 5
            grade = 'good'
        else:
            grade = 'fast'

        # Page size
        size = page.get('page_size', 0) or 0
        if size > 5 * 1024 * 1024:
            score -= 25
            size_grade = 'very large'
        elif size > 1 * 1024 * 1024:
            score -= 15
            size_grade = 'large'
        elif size > 500 * 1024:
            score -= 5
            size_grade = 'medium'
        else:
            size_grade = 'small'

        # Resource count
        rc = perf.get('resource_count', 0) or 0
        if rc > 100:
            score -= 15
        elif rc > 50:
            score -= 8
        elif rc > 20:
            score -= 3

        return {
            'url': page.get('url', ''),
            'score': max(score, 0),
            'response_time': rt,
            'response_grade': grade,
            'page_size': size,
            'size_grade': size_grade,
            'resource_count': rc,
        }

    def _seo_summary(self, results):
        """Aggregate SEO summary across all pages"""
        if not results:
            return {}
        total = len(results)
        avg_score = sum(r['score'] for r in results) / total
        all_issues = {}
        for r in results:
            for issue in (r.get('issues') or []):
                key = issue.split('(')[0].strip() if '(' in issue else issue
                all_issues[key] = all_issues.get(key, 0) + 1

        top_issues = sorted(all_issues.items(), key=lambda x: -x[1])[:10]

        return {
            'total_pages': total,
            'average_score': round(avg_score),
            'pages_above_80': sum(1 for r in results if r['score'] >= 80),
            'pages_below_50': sum(1 for r in results if r['score'] < 50),
            'top_issues': [{'issue': k, 'count': v} for k, v in top_issues],
        }

    def _perf_summary(self, results):
        """Aggregate performance summary"""
        if not results:
            return {}
        total = len(results)
        avg_rt = sum(r['response_time'] for r in results) / total
        avg_size = sum(r['page_size'] for r in results) / total
        avg_rc = sum(r['resource_count'] for r in results) / total

        return {
            'total_pages': total,
            'avg_response_time': round(avg_rt, 3),
            'avg_page_size': round(avg_size),
            'avg_resource_count': round(avg_rc),
            'fast_pages': sum(1 for r in results if r['response_grade'] == 'fast'),
            'slow_pages': sum(1 for r in results if r['response_grade'] == 'slow'),
        }
