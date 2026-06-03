"""Anti-detection utilities for web crawling - evade common anti-scraping measures"""
import random
import time
import threading
import re
from urllib.parse import urlparse


class AntiDetection:
    """Provides anti-detection features for HTTP requests"""

    # Real browser User-Agent strings (Chrome, Firefox, Edge, Safari)
    USER_AGENTS = [
        # Chrome on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        # Chrome on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        # Chrome on Linux
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        # Firefox on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
        # Firefox on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0',
        # Firefox on Linux
        'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
        # Edge on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        # Safari on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
        # Chrome on Android
        'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
        # Safari on iOS
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    ]

    # Chrome version mapping for Sec-CH-UA header
    _CHROME_VERSIONS = {
        '131': '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        '130': '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="24"',
        '129': '"Chromium";v="129", "Google Chrome";v="129", "Not_A Brand";v="24"',
    }

    # Sec-CH-UA-Platform values matching UA strings
    _CH_PLATFORMS = {
        'Windows': '"Windows"',
        'Mac': '"macOS"',
        'Linux': '"Linux"',
        'Android': '"Android"',
        'iPhone': '"iOS"',
    }

    def __init__(self, min_delay=0.5, max_delay=2.0, respect_robots=True):
        """
        Args:
            min_delay: Minimum delay between requests in seconds
            max_delay: Maximum delay between requests in seconds
            respect_robots: Whether to parse and respect robots.txt
        """
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.respect_robots = respect_robots

        self._last_request_time = 0
        self._lock = threading.Lock()
        self._current_ua = random.choice(self.USER_AGENTS)
        self._current_referer = ''
        self._robots_rules = {}  # domain -> DisallowedPaths

        # Track per-domain backoff state
        self._backoff_until = {}  # domain -> timestamp
        self._backoff_counts = {}  # domain -> consecutive 429/503 count

    def get_headers(self, url='', referer=None):
        """Generate realistic browser headers for a request"""
        ua = self._rotate_ua()
        headers = {
            'User-Agent': ua,
            'Accept': self._get_accept_header(url),
            'Accept-Language': random.choice([
                'zh-CN,zh;q=0.9,en;q=0.8',
                'en-US,en;q=0.9,zh-CN;q=0.8',
                'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
                'en-GB,en;q=0.9',
            ]),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
        }

        # Add modern Chrome client hints if UA is Chrome
        if 'Chrome/' in ua and 'Edg/' not in ua:
            chrome_ver = re.search(r'Chrome/(\d+)', ua)
            if chrome_ver:
                ver = chrome_ver.group(1)
                headers['Sec-Ch-Ua'] = self._CHROME_VERSIONS.get(ver,
                    f'"Chromium";v="{ver}", "Google Chrome";v="{ver}"')
                headers['Sec-Ch-Ua-Mobile'] = '?1' if 'Mobile' in ua else '?0'
                # Detect platform
                for key, val in self._CH_PLATFORMS.items():
                    if key in ua:
                        headers['Sec-Ch-Ua-Platform'] = val
                        break

        # Sec-Fetch headers (modern browsers always send these)
        headers['Sec-Fetch-Site'] = 'none' if not referer else 'same-origin'
        headers['Sec-Fetch-Mode'] = 'navigate'
        headers['Sec-Fetch-Dest'] = 'document'
        headers['Sec-Fetch-User'] = '?1'

        # Referer chain
        if referer:
            headers['Referer'] = referer
        elif self._current_referer:
            # Occasionally drop referer to look natural
            if random.random() > 0.15:
                headers['Referer'] = self._current_referer

        return headers

    def _get_accept_header(self, url):
        """Return context-appropriate Accept header"""
        if not url:
            return 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        path = urlparse(url).path.lower()
        if path.endswith('.js') or path.endswith('.mjs'):
            return '*/*'
        if path.endswith('.css'):
            return 'text/css,*/*;q=0.1'
        if path.endswith('.json'):
            return 'application/json,*/*;q=0.5'
        if any(path.endswith(ext) for ext in ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico')):
            return 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8'
        return 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'

    def _rotate_ua(self):
        """Rotate UA string - change occasionally to mimic browser restart"""
        if random.random() < 0.05:
            self._current_ua = random.choice(self.USER_AGENTS)
        return self._current_ua

    def set_referer(self, referer):
        """Set the referer for the next request chain"""
        self._current_referer = referer or ''

    def wait(self, url=''):
        """Apply rate limiting delay before a request"""
        with self._lock:
            now = time.time()
            # Check per-domain backoff
            domain = urlparse(url).netloc if url else ''
            if domain and domain in self._backoff_until:
                if now < self._backoff_until[domain]:
                    sleep_time = self._backoff_until[domain] - now
                    time.sleep(sleep_time)
                    now = time.time()

            # Normal delay with jitter
            elapsed = now - self._last_request_time
            base_delay = random.uniform(self.min_delay, self.max_delay)
            # Add jitter: +/- 30%
            jitter = base_delay * random.uniform(-0.3, 0.3)
            target_delay = max(0.1, base_delay + jitter)

            if elapsed < target_delay:
                time.sleep(target_delay - elapsed)

            self._last_request_time = time.time()

    def handle_response(self, status_code, url=''):
        """Handle response status - manage backoff on rate limiting"""
        domain = urlparse(url).netloc if url else ''
        if not domain:
            return

        if status_code in (429, 503):
            with self._lock:
                count = self._backoff_counts.get(domain, 0) + 1
                self._backoff_counts[domain] = count
                # Exponential backoff: 2^count seconds, max 120s
                backoff = min(2 ** count, 120)
                # Add random jitter to backoff
                backoff += random.uniform(0, backoff * 0.3)
                self._backoff_until[domain] = time.time() + backoff
        elif status_code < 500:
            # Reset backoff on success or client error
            with self._lock:
                self._backoff_counts.pop(domain, None)
                self._backoff_until.pop(domain, None)

    def check_robots(self, url):
        """Check if URL is allowed by robots.txt (lazy-loaded per domain)"""
        if not self.respect_robots:
            return True
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if not domain:
                return True

            if domain not in self._robots_rules:
                self._load_robots(parsed.scheme + '://' + domain)

            rules = self._robots_rules.get(domain)
            if rules is None:
                return True  # No robots.txt or parse error = allow all

            path = parsed.path or '/'
            for pattern in rules:
                if path.startswith(pattern):
                    return False
            return True
        except Exception:
            return True

    def _load_robots(self, base_url):
        """Load and parse robots.txt for a domain"""
        import requests
        try:
            robots_url = base_url.rstrip('/') + '/robots.txt'
            resp = requests.get(robots_url, timeout=5, verify=False)
            if resp.status_code != 200:
                self._robots_rules[urlparse(base_url).netloc] = None
                return

            disallowed = []
            is_our_agent = True
            for line in resp.text.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                lower = line.lower()
                if lower.startswith('user-agent:'):
                    agent = line.split(':', 1)[1].strip()
                    is_our_agent = agent == '*' or 'bot' in agent.lower() or 'crawler' in agent.lower()
                elif lower.startswith('disallow:') and is_our_agent:
                    path = line.split(':', 1)[1].strip()
                    if path:
                        disallowed.append(path)

            self._robots_rules[urlparse(base_url).netloc] = disallowed if disallowed else []
        except Exception:
            self._robots_rules[urlparse(base_url).netloc] = None

    def randomize_request_order(self, items):
        """Randomize the order of a list of URLs/items to avoid predictable patterns"""
        shuffled = list(items)
        random.shuffle(shuffled)
        return shuffled

    def should_skip_request(self, url):
        """Pre-flight check: should this request be skipped?"""
        if not self.check_robots(url):
            return True
        return False
