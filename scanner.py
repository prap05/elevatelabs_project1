import re
import json
import os
from urllib.parse import urljoin, urlparse, parse_qs
import requests
from bs4 import BeautifulSoup

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"sqlite3.OperationalError",
    r"syntax error",
]

XSS_PAYLOAD = "<scRiPt>qwerty_alert()</scRiPt>"
SQLI_PAYLOAD = "' OR '1'='1"

REPORT_DIR = 'reports'
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

session = requests.Session()
session.headers.update({'User-Agent': 'MinimalScanner/1.0'})


def is_same_domain(base, link):
    try:
        return urlparse(base).netloc == urlparse(link).netloc
    except Exception:
        return False


def get_forms(soup):
    return soup.find_all('form')


def find_inputs(form):
    inputs = []
    for i in form.find_all(['input', 'textarea', 'select']):
        name = i.get('name') or i.get('id') or ''
        t = i.get('type', 'text')
        inputs.append({'name': name, 'type': t})
    return inputs


def detect_sql_error(text):
    t = text.lower()
    for p in SQL_ERRORS:
        if re.search(p, t):
            return True
    return False


def scan_form(url, form, report, base_url):
    action = form.get('action') or ''
    method = (form.get('method') or 'get').lower()
    target = urljoin(url, action)
    inputs = find_inputs(form)

    # Prepare data dict
    data = {}
    for inp in inputs:
        if inp['type'] in ['submit', 'button', 'checkbox', 'radio']:
            continue
        # place payloads
        data[inp['name'] or 'payload'] = XSS_PAYLOAD

    try:
        if method == 'post':
            resp = session.post(target, data=data, timeout=10)
        else:
            resp = session.get(target, params=data, timeout=10)
    except Exception as e:
        report['errors'].append({'url': target, 'error': str(e)})
        return

    body = resp.text

    # XSS detection (reflected payload)
    if XSS_PAYLOAD.lower() in body.lower():
        report['vulns'].append(
            {'type': 'XSS', 'url': target, 'evidence': XSS_PAYLOAD})

    # SQL detection (error messages)
    if detect_sql_error(body):
        report['vulns'].append(
            {'type': 'SQLi', 'url': target, 'evidence': 'sql_error_pattern'})

    # CSRF check: look for hidden token-like inputs
    hidden_names = [i['name'].lower()
                    for i in inputs if i['type'] == 'hidden' and i['name']]
    if not any('csrf' in n or 'token' in n for n in hidden_names):
        report['vulns'].append(
            {'type': 'Missing-CSRF-Token', 'url': target, 'evidence': 'no-hidden-token'})


def test_url_params(url, report):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return

    for key in qs:
        # create test url with payload
        new_qs = qs.copy()
        new_qs[key] = [XSS_PAYLOAD]
        new_query = '&'.join(f"{k}={v[0]}" for k, v in new_qs.items())
        test_url = parsed._replace(query=new_query).geturl()
        try:
            resp = session.get(test_url, timeout=10)
            body = resp.text
            if XSS_PAYLOAD.lower() in body.lower():
                report['vulns'].append(
                    {'type': 'XSS', 'url': test_url, 'evidence': XSS_PAYLOAD})
            if detect_sql_error(body):
                report['vulns'].append(
                    {'type': 'SQLi', 'url': test_url, 'evidence': 'sql_error_pattern'})
        except Exception as e:
            report['errors'].append({'url': test_url, 'error': str(e)})


def crawl_and_scan(start_url, max_pages=10):
    visited = set()
    to_visit = [start_url]
    report = {'target': start_url, 'vulns': [], 'errors': [], 'scanned': []}

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        report['scanned'].append(url)

        try:
            r = session.get(url, timeout=10)
            soup = BeautifulSoup(r.text, 'lxml')
        except Exception as e:
            report['errors'].append({'url': url, 'error': str(e)})
            continue

        # scan forms on page
        forms = get_forms(soup)
        for f in forms:
            scan_form(url, f, report, start_url)

        # test query params
        test_url_params(url, report)

        # simple crawler: find same-domain links
        for a in soup.find_all('a', href=True):
            link = urljoin(url, a['href'])
            if is_same_domain(start_url, link) and link not in visited and link not in to_visit:
                to_visit.append(link)

    # save report
    fname = os.path.join(
        REPORT_DIR, f"report_{urlparse(start_url).netloc.replace(':', '_')}.json")
    with open(fname, 'w', encoding='utf-8') as fh:
        json.dump(report, fh, indent=2)

    return report


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        r = crawl_and_scan(target)
        print(json.dumps(r, indent=2))
    else:
        print('Usage: python scanner.py https://example.com')
