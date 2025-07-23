import argparse
import collections
import json
import os
import requests
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


@dataclass
class Result:
    url: str
    status: Optional[int]
    size: int
    title: str
    login_form: bool = False
    security_headers: Dict[str, str] = field(default_factory=dict)


def allowed_domain(url, domains):
    if not domains:
        return True
    netloc = urlparse(url).netloc
    for domain in domains:
        if netloc.endswith(domain):
            return True
    return False


def extension_blacklisted(url, blacklist):
    path = urlparse(url).path
    for ext in blacklist:
        if path.lower().endswith(ext.lower()):
            return True
    return False


def extract_links(content, base_url):
    soup = BeautifulSoup(content, 'html.parser')
    links = set()
    for tag in soup.find_all('a', href=True):
        href = tag['href']
        href = urljoin(base_url, href)
        if href.startswith('http'):
            links.add(href.split('#')[0])
    return links


def extract_title(content):
    soup = BeautifulSoup(content, 'html.parser')
    title_tag = soup.find('title')
    if title_tag:
        return title_tag.get_text(strip=True)
    return ''


def has_login_form(content: bytes) -> bool:
    soup = BeautifulSoup(content, 'html.parser')
    for form in soup.find_all('form'):
        if form.find('input', {'type': 'password'}):
            return True
    return False


SECURITY_HEADERS = [
    'X-Frame-Options',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Strict-Transport-Security',
]


def get_security_headers(resp) -> Dict[str, str]:
    found = {}
    for h in SECURITY_HEADERS:
        if h in resp.headers:
            found[h] = resp.headers[h]
    return found


def crawl(start_url, max_depth, domains=None, blacklist=None, *, user_agent=None,
          save_html_dir=None):
    if domains is None:
        domains = []
    if blacklist is None:
        blacklist = []
    headers = {}
    if user_agent:
        headers['User-Agent'] = user_agent
    if save_html_dir:
        os.makedirs(save_html_dir, exist_ok=True)

    queue = collections.deque([(start_url, 0)])
    visited = set([start_url])
    results = []
    status_counts = collections.Counter()
    domain_counts = collections.Counter()
    error_count = 0
    login_form_count = 0
    missing_header_counts = collections.Counter()

    while queue:
        url, depth = queue.popleft()
        try:
            resp = requests.get(url, timeout=10, headers=headers)
            status = resp.status_code
            size = len(resp.content)
            title = ''
            login_form = False
            sec_headers = get_security_headers(resp)
            if 'text/html' in resp.headers.get('Content-Type', ''):
                title = extract_title(resp.content)
                login_form = has_login_form(resp.content)
                if save_html_dir:
                    fname = os.path.join(save_html_dir, f"page{len(results)}.html")
                    with open(fname, 'wb') as f:
                        f.write(resp.content)
            if login_form:
                login_form_count += 1
            for h in SECURITY_HEADERS:
                if h not in sec_headers:
                    missing_header_counts[h] += 1
            results.append(Result(url, status, size, title, login_form, sec_headers))
            status_counts[status] += 1
            domain_counts[urlparse(url).netloc] += 1
        except requests.RequestException:
            results.append(Result(url, None, 0, '', False, {}))
            error_count += 1
            continue

        if depth >= max_depth:
            continue
        if 'text/html' not in resp.headers.get('Content-Type', ''):
            continue

        links = extract_links(resp.content, url)
        for link in links:
            if link in visited:
                continue
            if not allowed_domain(link, domains):
                continue
            if extension_blacklisted(link, blacklist):
                continue
            visited.add(link)
            queue.append((link, depth + 1))

    return results, {
        'total_urls': len(results),
        'total_errors': error_count,
        'status_counts': dict(status_counts),
        'domain_counts': dict(domain_counts),
        'login_form_count': login_form_count,
        'missing_security_headers': dict(missing_header_counts),
    }


def parse_args():
    parser = argparse.ArgumentParser(description='Simple web crawler')
    parser.add_argument('url', help='Starting URL')
    parser.add_argument('--max-depth', type=int, default=1, help='Maximum crawl depth')
    parser.add_argument('--domains', help='Comma separated list of allowed domains')
    parser.add_argument('--blacklist', help='Comma separated list of extensions to ignore')
    parser.add_argument('--blacklist-file', help='File containing extensions to ignore, one per line')
    parser.add_argument('--user-agent', help='Custom User-Agent header')
    parser.add_argument('--save-json', help='Write crawl output to JSON file')
    parser.add_argument('--save-html-dir', help='Directory to save downloaded HTML')
    return parser.parse_args()


def main():
    args = parse_args()
    domains = args.domains.split(',') if args.domains else []
    blacklist = args.blacklist.split(',') if args.blacklist else []
    if args.blacklist_file:
        with open(args.blacklist_file) as f:
            blacklist.extend([line.strip() for line in f if line.strip()])

    results, stats = crawl(
        args.url,
        args.max_depth,
        domains,
        blacklist,
        user_agent=args.user_agent,
        save_html_dir=args.save_html_dir,
    )

    for res in results:
        print(f"{res.url}\t{res.status}\t{res.size}\t{res.title}")

    print('\nStatistics:')
    print(f"Total URLs crawled: {stats['total_urls']}")
    print(f"Total errors: {stats['total_errors']}")
    print('Status code counts:')
    for code, count in stats['status_counts'].items():
        print(f"  {code}: {count}")
    print('Domain counts:')
    for domain, count in stats['domain_counts'].items():
        print(f"  {domain}: {count}")
    print(f"Login forms found: {stats['login_form_count']}")
    if stats['missing_security_headers']:
        print('Missing security headers:')
        for h, c in stats['missing_security_headers'].items():
            print(f"  {h}: {c}")

    if args.save_json:
        with open(args.save_json, 'w') as f:
            json.dump({'results': [res.__dict__ for res in results], 'stats': stats}, f, indent=2)


if __name__ == '__main__':
    main()
