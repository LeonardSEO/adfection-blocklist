#!/usr/bin/env python3
"""Collect independent public observations and root-only measurements; no feed sync."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from research import (ROOT, DOMAIN_RE, read_json, write_json, utcnow, ensure_indicator,
                      observe, relate, validate_registry, indicator, timestamp, asset_supported)
from probe import probe

POLICY = read_json(ROOT / 'research/project.json', {})
FEEDS = POLICY.get('feeds', [])
SEED_LIMIT = 24
NETWORK_ERRORS = (urllib.error.URLError, OSError, TimeoutError)


def fetch(url, deadline, *, accept=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('research time budget reached')
    try:
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/transport.py'), url, str(remaining), accept or ''],
                                capture_output=True, timeout=remaining, check=True)
    except subprocess.TimeoutExpired as error:
        raise TimeoutError('Public-provider absolute deadline reached') from error
    except subprocess.CalledProcessError as error:
        raise OSError('Public-provider request failed') from error
    return result.stdout


def select_seeds(domains: list[str], day: dt.date) -> list[str]:
    if not domains:
        return []
    ordered = sorted(set(domains))
    start = (day.toordinal() * SEED_LIMIT) % len(ordered)
    return [ordered[(start + i) % len(ordered)] for i in range(min(SEED_LIMIT, len(ordered)))]


def certificate_names(rows: list[dict], seed: str) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for row in rows:
        names = set()
        for raw in (row.get('name_value', '') + '\n' + row.get('common_name', '')).splitlines():
            name = raw.strip().lower().removeprefix('*.').rstrip('.')
            if DOMAIN_RE.fullmatch(name):
                names.add(name)
        # A search hit alone is not evidence: require an explicit known name on the certificate.
        if not any(name == seed or name.endswith('.' + seed) for name in names):
            continue
        for name in sorted(names):
            found.setdefault(name, []).append({'kind': 'certificate-san', 'seed': seed,
                'certificate_id': row.get('id'), 'not_before': row.get('not_before'),
                'meaning': 'Co-occurring certificate name; ownership and attribution unverified.'})
    return found


def publications(data: bytes, feed: str) -> list[dict]:
    root = ET.fromstring(data)
    found = []
    for item in root.findall('.//item'):
        title, link = item.findtext('title', ''), item.findtext('link', '')
        text = title + ' ' + item.findtext('description', '')
        if not any(term in text.lower() for term in POLICY.get('news_terms', ['pegasus','nso group'])):
            continue
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme != 'https' or parsed.hostname != urllib.parse.urlsplit(feed).hostname:
            continue
        found.append({'title': title, 'url': link, 'published': item.findtext('pubDate', ''), 'feed': feed})
    return found


def enqueue(registry, key, tasks):
    for row in registry['queue']:
        if row['target'] == key:
            row['tasks'] = list(dict.fromkeys(row['tasks'] + list(tasks)))
            return
    registry['queue'].append({'target': key, 'tasks': list(tasks)})


def record_scans(registry, rows, url, at, allowed, anchor=None):
    for row in rows:
        page = row.get('page', {})
        domain = page.get('domain', '').lower().rstrip('.')
        if not DOMAIN_RE.fullmatch(domain) or domain in allowed:
            continue
        if anchor:
            host = registry['indicators'][anchor]['value']
            if not (domain == host or domain.endswith('.' + host)):
                continue  # Publishers loading a known resource are not infrastructure.
        child = ensure_indicator(registry, domain, 'existing-scan' if anchor else 'archive-query')
        data = {'domain': domain, 'ip': page.get('ip'), 'port': page.get('port'), 'reference': row.get('_id')}
        oid = observe(registry, child, 'scan-service', data, url, row.get('task', {}).get('time'), at)
        if anchor:
            relate(registry, anchor, domain, 'existing-scan', oid)
        if data['ip']:
            _, typ, address = indicator(data['ip'])
            if typ != 'ip':
                raise ValueError('Invalid scan IP')
            relate(registry, child, address, 'historical-scan-ip', oid)
        if registry['indicators'][child]['status'] == 'candidate':
            enqueue(registry, child, ['dns', 'measure'])



def discover_assets(registry, deadline, at, allowed):
    for path in POLICY.get('asset_paths', []):
        url = 'https://urlscan.io/api/v1/search/?' + urllib.parse.urlencode({'q': 'filename:"'+path.rsplit('/',1)[-1]+'"', 'size': 20})
        for hit in json.loads(fetch(url, deadline)).get('results', []):
            reference = hit.get('_id', '')
            import re
            if not re.fullmatch(r'[a-f0-9-]{36}', reference):
                continue
            detail = 'https://urlscan.io/api/v1/result/' + reference + '/'
            scan = json.loads(fetch(detail, deadline))
            observed = scan.get('task', {}).get('time')
            if not observed:
                continue
            for row in scan.get('data', {}).get('requests', []):
                request = row.get('request', {}).get('request', {})
                parsed = urllib.parse.urlsplit(request.get('url', ''))
                host = (parsed.hostname or '').lower().rstrip('.')
                if parsed.path != path or not DOMAIN_RE.fullmatch(host) or host in allowed:
                    continue
                response=row.get('response',{})
                http=response.get('response',{})
                served=urllib.parse.urlsplit(http.get('url',''))
                data={'path':path,'scan_id':reference,'status':http.get('status'),
                      'mime_type':http.get('mimeType',''),'body_sha256':response.get('hash','')}
                if served.hostname != host or served.path != path or not asset_supported(data,POLICY):
                    continue
                key = ensure_indicator(registry, host, 'asset-scan')
                observe(registry,key,'asset-scan',data,detail,observed,at)
                if registry['indicators'][key]['status']=='candidate':
                    enqueue(registry,key,['dns','measure'])

def task(registry, key, kind, deadline, at, allowed):
    at = utcnow()
    host = registry['indicators'][key]['value']
    if kind == 'ct':
        url = 'https://crt.sh/?' + urllib.parse.urlencode({'q': '%.' + host, 'output': 'json'})
        rows = json.loads(fetch(url, deadline))
        for name, evidence in certificate_names(rows, host).items():
            if name in allowed:
                continue
            for row in evidence:
                observed = row['not_before']
                if observed:
                    observed = observed.replace(' ', 'T')
                    if not observed.endswith('Z') and '+' not in observed:
                        observed += '+00:00'
                oid = observe(registry, key, 'certificate-log', row, url, observed, at)
                child = relate(registry, key, name, 'certificate-san', oid)
                if registry['indicators'][child]['status'] == 'candidate':
                    enqueue(registry, child, ['dns', 'measure'])
    elif kind == 'urlscan':
        url = 'https://urlscan.io/api/v1/search/?' + urllib.parse.urlencode({'q': 'page.domain:' + host, 'size': 100})
        record_scans(registry, json.loads(fetch(url, deadline)).get('results', []), url, at, allowed, key)
    elif kind == 'dns':
        for qtype in ('A', 'AAAA', 'CNAME', 'NS'):
            url = 'https://cloudflare-dns.com/dns-query?' + urllib.parse.urlencode({'name': host, 'type': qtype})
            data = json.loads(fetch(url, deadline, accept='application/dns-json'))
            if data.get('Status') not in (0, 3):
                raise ValueError('DNS resolver error')
            payload = {'query_type': qtype, 'status': data['Status'], 'answers': data.get('Answer', [])}
            if qtype == 'NS':
                payload['nameservers'] = sorted(a['data'].rstrip('.').lower() for a in data.get('Answer', []) if a.get('type') == 2)
            oid = observe(registry, key, 'dns', payload, url, at, at)
            for answer in data.get('Answer', []):
                if answer.get('type') in (1, 28, 5, 2):
                    value = answer['data'].rstrip('.')
                    try:
                        _, typ, normal = indicator(value)
                    except ValueError:
                        continue
                    if normal not in allowed:
                        relate(registry, key, normal, 'dns-' + qtype.lower(), oid)
    elif kind == 'measure':
        ports = []
        for oid in registry['indicators'][key]['evidence']:
            row = registry['observations'][oid]
            if row['kind'] == 'scan-service' and row['observed_at']:
                age = (timestamp(at) - timestamp(row['observed_at'])).total_seconds()
                port = row['data'].get('port')
                if 0 <= age <= 7 * 86400 and isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
                    ports.append(port)
        results, errors = probe(host, deadline, ports)
        for result in results:
            actual = ensure_indicator(registry, result['host'], 'redirect' if result['host'] != host else 'measurement')
            for channel in ('tls', 'http'):
                if result[channel]:
                    oid = observe(registry, actual, channel, result[channel], 'direct-root-probe', at, at)
                    relate(registry, actual, result['ip'], 'connected-ip', oid)
        for error in errors:
            observe(registry, key, 'measurement-error', error, 'direct-root-probe', None, at)
        if errors:
            raise ValueError('Some root probes failed; evidence and previous indicators retained')


def run(registry, deadline, at, allowed, rules=()):
    # Candidates only get bounded DNS/probe work, never independent graph expansion.
    for key, item in sorted(registry['indicators'].items()):
        if item['type'] == 'domain' and item['status'] == 'candidate' and item['origin'] in ('certificate-san', 'existing-scan', 'dns-cname', 'archive-query', 'legacy-lead', 'asset-scan') and item['value'] not in allowed and (not item.get('last_attempts', {}).get('measure') or (timestamp(at) - timestamp(item['last_attempts']['measure'])).total_seconds() >= 86400):
            enqueue(registry, key, ['dns', 'measure'])
    seeds = [r['value'] for r in registry['indicators'].values() if r['type'] == 'domain' and r['status'] in ('historical', 'accepted') and r['value'] not in allowed]
    for host in select_seeds(seeds, timestamp(at).date()):
        enqueue(registry, indicator(host)[0], ['ct', 'urlscan', 'dns', 'measure'])
    registry['queue'].sort(key=lambda row: (registry['indicators'][row['target']]['status'] != 'candidate', min((registry['indicators'][row['target']].get('last_attempts', {}).get(t, '') for t in row['tasks']), default='')))
    report = {'observed_at': at, 'status': 'completed', 'completed_queries': [], 'errors': [], 'publications': [],
              'limits': {'max_seed_domains': SEED_LIMIT, 'api_pages': 1, 'probe_path': '/', 'max_body_bytes': 65536}}
    # News is context only and never becomes an indicator automatically.
    for feed in FEEDS:
        try:
            report['publications'].extend(publications(fetch(feed, min(deadline, time.monotonic()+5)), feed))
            report['completed_queries'].append('news:' + feed)
        except (NETWORK_ERRORS + (ValueError, ET.ParseError)) as error:
            report['errors'].append({'query': 'news:' + feed, 'error': type(error).__name__})
    try:
        discover_assets(registry, min(deadline,time.monotonic()+30),at,allowed)
        if POLICY.get('asset_paths'): report['completed_queries'].append('specific-assets')
    except (NETWORK_ERRORS + (ValueError,)) as error:
        report['errors'].append({'query':'specific-assets','error':type(error).__name__})
    from research import qualified
    for rule in rules:
        if not qualified(rule, registry):
            continue
        for query in rule.get('archive_queries', []):
            if not isinstance(query, str) or not query.strip():
                raise ValueError('Invalid urlscan detector query')
            url = 'https://urlscan.io/api/v1/search/?' + urllib.parse.urlencode({'q': query, 'size': 100})
            try:
                record_scans(registry, json.loads(fetch(url, min(deadline, time.monotonic()+10))).get('results', []), url, at, allowed)
                report['completed_queries'].append('detector-archive:' + rule['id'])
            except (NETWORK_ERRORS + (ValueError,)) as error:
                report['errors'].append({'query': 'detector-archive:' + rule['id'], 'error': type(error).__name__})
    # Work present at run start is bounded; newly found candidates wait until next run.
    for row in list(registry['queue']):
        for kind in list(row['tasks']):
            if time.monotonic() >= deadline:
                break
            label = kind + ':' + row['target']
            succeeded = False
            try:
                task(registry, row['target'], kind, min(deadline, time.monotonic()+15), at, allowed)
                report['completed_queries'].append(label)
                succeeded = True
            except (NETWORK_ERRORS + (ValueError, ET.ParseError)) as error:
                report['errors'].append({'query': label, 'error': type(error).__name__})
            registry['indicators'][row['target']].setdefault('last_attempts', {})[kind] = at
            if time.monotonic() >= deadline:
                break  # Preserve interrupted work, including partially completed DNS/probe tasks.
            if succeeded:
                row['tasks'].remove(kind)
        if not row['tasks']:
            registry['queue'].remove(row)
    report['pending_tasks'] = sum(len(row['tasks']) for row in registry['queue'])
    if report['errors'] or report['pending_tasks']:
        report['status'] = 'partial'
    report['candidate_count'] = sum(r['status'] == 'candidate' for r in registry['indicators'].values())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--max-seconds', type=int, default=600)
    args = parser.parse_args()
    if not 1 <= args.max_seconds <= 600:
        parser.error('--max-seconds must be between 1 and 600')
    registry = read_json(ROOT / 'research/registry.json')
    rules = read_json(ROOT / 'research/detectors.json')['detectors']
    bootstrap = read_json(ROOT / 'sources/bootstrap.json')
    validate_registry(registry, rules, bootstrap)
    allowed = {line.strip() for line in (ROOT / 'allowlist.txt').read_text().splitlines() if line.strip() and not line.startswith('#')}
    report = run(registry, time.monotonic()+args.max_seconds, utcnow(), allowed, rules)
    validate_registry(registry, rules, bootstrap)
    write_json(ROOT / 'research/registry.json', registry)
    write_json(ROOT / 'candidates/latest.json', report)
    print(f'{report["status"]}: {len(report["completed_queries"])} completed queries; {report["pending_tasks"]} pending tasks')
    if report['status'] == 'partial':
        sys.exit(3)


if __name__ == '__main__':
    main()
