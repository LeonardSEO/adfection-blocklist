#!/usr/bin/env python3
"""One-time, offline import of pinned public files. Never run by scheduled research."""
import argparse
import hashlib
import ipaddress
import pathlib

from research import ROOT, empty_registry, ensure_indicator, indicator, read_json, write_json, observe, relate, utcnow


def parse_source(text, syntax):
    values, rejected = {}, []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.partition('#')[0].strip()
        if not line:
            continue
        fields = line.split()
        if syntax == 'hosts' and len(fields) > 1 and fields[0] in ('0.0.0.0', '127.0.0.1', '::'):
            fields = fields[1:]
        elif len(fields) != 1:
            rejected.append({'line': number, 'reason': 'Malformed record', 'text': line})
            continue
        for token in fields:
            try:
                key, kind, value = indicator(token)
                if syntax == 'domains' and kind != 'domain' or syntax == 'endpoints' and kind != 'endpoint':
                    raise ValueError('Unexpected indicator type')
                values[key] = (kind, value)
            except ValueError:
                rejected.append({'line': number, 'reason': 'Invalid indicator', 'text': token})
    if not values:
        raise ValueError('Refusing an empty bootstrap source')
    return values, rejected


def import_sources(specs, directory, excluded):
    manifest = {'version': 1, 'sources': {}, 'indicators': {}, 'rejected': []}
    registry = empty_registry()
    for source in specs:
        data = (directory / source['file']).read_bytes()
        values, rejected = parse_source(data.decode('utf-8'), source['syntax'])
        manifest['sources'][source['id']] = {**source, 'sha256': hashlib.sha256(data).hexdigest(), 'parsed_count': len(values)}
        manifest['rejected'].extend({'source': source['id'], **r} for r in rejected)
        for key, (kind, value) in values.items():
            if value in excluded:
                manifest['rejected'].append({'source': source['id'], 'text': value, 'reason': 'Exact allowlist exclusion'})
                continue
            ensure_indicator(registry, value, 'bootstrap')
            row = registry['indicators'][key]
            row['status'] = 'historical'
            row['sources'].append(source['id'])
            manifest['indicators'].setdefault(key, {'sources': []})['sources'].append(source['id'])
    for row in registry['indicators'].values():
        if row['value'] in {'176.223.111.131', '178.220.122.57', '185.86.148.174', '188.93.127.34', '195.178.51.251', '79.101.110.108', '94.140.125.174'}:
            row['families'] = ['NoviSpy']
    return manifest, registry


def migrate_report(registry, report):
    for host, entries in report.get('candidates', {}).items():
        for entry in entries:
            seed = entry.get('seed')
            if not seed:
                continue
            key = ensure_indicator(registry, seed, 'legacy-report')
            at = entry.get('not_before')
            if at and not at.endswith('Z') and '+' not in at:
                at += '+00:00'
            oid = observe(registry, key, 'certificate-log', entry, 'legacy-discovery-report', at,
                          report.get('observed_at') or utcnow())
            relate(registry, key, host, 'certificate-san', oid)
    return registry


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=pathlib.Path)
    args = parser.parse_args()
    if (ROOT / 'sources/bootstrap.json').exists():
        parser.error('Bootstrap is frozen; an explicit reviewed migration is required to replace it')
    specs = read_json(args.directory / 'catalog.json')
    excluded = {s.strip() for s in (ROOT / 'allowlist.txt').read_text().splitlines() if s.strip() and not s.startswith('#')}
    manifest, registry = import_sources(specs, args.directory, excluded)
    registry = migrate_report(registry, read_json(ROOT / 'candidates/latest.json', {}))
    write_json(ROOT / 'sources/bootstrap.json', manifest)
    write_json(ROOT / 'research/registry.json', registry)
