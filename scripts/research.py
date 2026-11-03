"""Persistent evidence, detector qualification and publication validation (offline)."""
from __future__ import annotations

import copy
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$')
NEGATIVE_CLASSES = {'cdn', 'shared-hosting', 'parking', 'reregistered', 'generic-server'}
TASKS = {'ct', 'urlscan', 'dns', 'measure'}


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(data):
    return hashlib.sha256(canonical(data).encode()).hexdigest()


def timestamp(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Evidence timestamps must include a timezone')
    return result


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def indicator(value, kind=None):
    value = value.strip().lower().replace('[.]', '.')
    try:
        ip = ipaddress.ip_address(value)
        inferred, value = 'ip', str(ip)
    except ValueError:
        match = re.fullmatch(r'(?:\[([^]]+)\]|([^:]+)):(\d+)', value)
        if match:
            host = str(ipaddress.ip_address(match[1] or match[2]))
            port = int(match[3])
            if not 1 <= port <= 65535:
                raise ValueError('Invalid endpoint port')
            inferred = 'endpoint'
            value = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        elif DOMAIN_RE.fullmatch(value.rstrip('.')):
            inferred, value = 'domain', value.rstrip('.')
        else:
            raise ValueError(f'Invalid indicator: {value!r}')
    if kind is not None and kind != inferred:
        raise ValueError('Indicator type does not match its value')
    return f'{inferred}:{value}', inferred, value


def empty_registry():
    return {'version': 1, 'indicators': {}, 'observations': {}, 'relationships': [], 'queue': []}


def read_json(path, default=None):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else copy.deepcopy(default)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')


def ensure_indicator(registry, value, origin='research'):
    key, kind, value = indicator(value)
    registry['indicators'].setdefault(key, {'type': kind, 'value': value, 'status': 'candidate',
        'origin': origin, 'sources': [], 'families': [], 'first_seen': None, 'last_seen': None,
        'evidence': [], 'admissions': []})
    return key


def observation_id(record):
    return digest({k: v for k, v in record.items() if k != 'recorded_at'})


def observe(registry, key, kind, data, source, observed_at=None, recorded_at=None):
    record = {'indicator': key, 'kind': kind, 'data': data, 'source': source,
              'observed_at': observed_at, 'recorded_at': recorded_at or utcnow()}
    oid = observation_id(record)
    registry['observations'].setdefault(oid, record)
    item = registry['indicators'][key]
    if oid not in item['evidence']:
        item['evidence'].append(oid)
    if observed_at is not None:
        seen = timestamp(observed_at)
        for field, choose in [('first_seen', min), ('last_seen', max)]:
            old = timestamp(item[field]) if item[field] else seen
            item[field] = choose(old, seen).isoformat()
    return oid


def relate(registry, source_key, value, relation, evidence_id):
    key = ensure_indicator(registry, value, relation)
    row = {'from': source_key, 'to': key, 'kind': relation, 'evidence': evidence_id}
    if row not in registry['relationships']:
        registry['relationships'].append(row)
    return key


def features(registry, ids, at):
    found = {}
    for oid in ids:
        record = registry['observations'][oid]
        if record['kind'] not in ('tls', 'http', 'dns') or not record['observed_at']:
            continue
        age = (timestamp(at) - timestamp(record['observed_at'])).total_seconds()
        if not 0 <= age <= 7 * 86400:
            continue
        # Distinct evidence channels; repeated observations cannot increase confidence.
        for name, value in record['data'].items():
            found[f'{record["kind"]}.{name}'] = value
    return found


def same_session(registry, ids):
    records = [registry['observations'][oid] for oid in ids if registry['observations'][oid]['kind'] in ('tls', 'http')]
    sessions = {r['data'].get('session') for r in records}
    return len(sessions) == 1 and None not in sessions and {'tls', 'http'}.issubset({r['kind'] for r in records})


def matches(registry, ids, rule, at):
    found = features(registry, ids, at)
    return all(found.get(name) == value for name, value in rule['match'].items())


def qualified(rule, registry):
    if not rule.get('enabled'):
        return False
    clauses = rule.get('match', {})
    if not clauses or not {'tls', 'http'}.issubset({k.split('.')[0] for k in clauses}):
        raise ValueError('Enabled detectors must combine TLS and HTTP features')
    allowed = {'tls.certificate_sha256', 'tls.cipher', 'tls.version', 'http.fingerprint', 'dns.nameservers'}
    if set(clauses) - allowed or not rule.get('id') or not rule.get('version'):
        raise ValueError('Unsupported detector definition')
    examples = rule.get('qualification', {})
    positives, negatives, shadow = (examples.get(k, []) for k in ('positives', 'negatives', 'shadow'))
    if not positives or not shadow or not NEGATIVE_CLASSES.issubset({e.get('class') for e in negatives}):
        raise ValueError('Detector requires attributed positives, negative classes and shadow evidence')
    used = set()
    for label, entries in [('positive', positives), ('negative', negatives), ('shadow', shadow)]:
        for example in entries:
            ids = example.get('evidence', [])
            if not ids or not example.get('reference') or set(ids) & used:
                raise ValueError('Qualification examples require distinct evidence and a reference')
            used.update(ids)
            keys = {registry['observations'][oid]['indicator'] for oid in ids}
            if len(keys) != 1 or not same_session(registry, ids):
                raise ValueError('Qualification requires measured TLS and HTTP from one target/session')
            if not example['reference'].startswith('https://'):
                raise ValueError('Qualification requires an attributable reference URL')
            if matches(registry, ids, rule, example['at']) != (label != 'negative'):
                raise ValueError('Detector does not pass its qualification examples')
    return True


def eligible(registry, key, rule, at):
    # Never combine TLS from one endpoint with HTTP from another endpoint/redirect.
    groups = {}
    for oid in registry['indicators'][key]['evidence']:
        record = registry['observations'][oid]
        session = record['data'].get('session')
        if session:
            groups.setdefault(session, []).append(oid)
    dns_ids = [oid for oid in registry['indicators'][key]['evidence'] if registry['observations'][oid]['kind'] == 'dns']
    for ids in groups.values():
        ids = ids + dns_ids
        if same_session(registry, ids) and matches(registry, ids, rule, at):
            return ids
    return None


def reconcile(registry, rules, at):
    enabled = {}
    for rule in rules:
        if qualified(rule, registry):
            name = (rule['id'], rule['version'])
            if name in enabled:
                raise ValueError('Duplicate detector version')
            enabled[name] = rule
    for key, item in list(registry['indicators'].items()):
        if item['origin'] == 'bootstrap':
            continue
        if item['status'] == 'accepted':
            admission = item['admissions'][-1]
            if (admission['detector'], admission['version']) not in enabled:
                item['status'] = 'withdrawn'
                observe(registry, key, 'decision', {'action': 'withdraw', 'reason': 'detector disabled or replaced'}, 'publisher', at)
                continue
        if item['status'] in ('candidate', 'withdrawn'):
            for rule in enabled.values():
                ids = eligible(registry, key, rule, at)
                if ids:
                    item['admissions'].append({'detector': rule['id'], 'version': rule['version'],
                                               'evidence': ids, 'decided_at': at})
                    item['status'] = 'accepted'
                    break
    return registry


def validate_registry(registry, rules, bootstrap):
    if registry['version'] != 1:
        raise ValueError('Unsupported registry version')
    enabled = {(r['id'], r['version']): r for r in rules if qualified(r, registry)}
    for oid, record in registry['observations'].items():
        if oid != observation_id(record) or record['indicator'] not in registry['indicators']:
            raise ValueError('Evidence integrity failure')
        timestamp(record['recorded_at'])
        if record['observed_at']:
            timestamp(record['observed_at'])
        if record['kind'] in ('tls', 'http'):
            data = record['data']
            if not record['observed_at'] or not re.fullmatch(r'[a-f0-9]{64}', data.get('session', '')):
                raise ValueError('Measurement requires a timestamp and session')
            if indicator(data['host'])[0] != record['indicator']:
                raise ValueError('Probe evidence target mismatch')
            import probe
            if not probe.public_ip(data['ip']) or not isinstance(data['port'], int) or not 1 <= data['port'] <= 65535:
                raise ValueError('Non-public probe evidence')
            if record['kind'] == 'tls':
                certificate = base64.b64decode(data['certificate_der_base64'], validate=True)
                if hashlib.sha256(certificate).hexdigest() != data['certificate_sha256']:
                    raise ValueError('Certificate digest mismatch')
            else:
                raw = {k: data[k] for k in ('status', 'server', 'content_type', 'body_sha256', 'truncated')}
                if digest(raw) != data['fingerprint']:
                    raise ValueError('HTTP fingerprint mismatch')
    for key, item in registry['indicators'].items():
        if indicator(item['value'], item['type'])[0] != key:
            raise ValueError('Invalid registry indicator key')
        if item['status'] not in ('candidate', 'accepted', 'historical', 'withdrawn'):
            raise ValueError('Invalid indicator status')
        if item['origin'] == 'bootstrap':
            if key not in bootstrap['indicators'] or item['sources'] != bootstrap['indicators'][key]['sources']:
                raise ValueError('Bootstrap provenance changed')
        elif item['sources'] or item['status'] == 'historical':
            raise ValueError('Research cannot introduce historical source indicators')
        for oid in item['evidence']:
            if registry['observations'][oid]['indicator'] != key:
                raise ValueError('Evidence belongs to a different indicator')
        if item['status'] == 'accepted':
            admission = item['admissions'][-1]
            rule = enabled.get((admission['detector'], admission['version']))
            if not rule or eligible(registry, key, rule, admission['decided_at']) is None:
                raise ValueError('Accepted indicator lacks qualified current evidence')
            if not set(admission['evidence']).issubset(item['evidence']) or not same_session(registry, admission['evidence']) or not matches(registry, admission['evidence'], rule, admission['decided_at']):
                raise ValueError('Admission evidence does not support detector')
    if not set(bootstrap['indicators']).issubset(registry['indicators']):
        raise ValueError('Historical indicators must not disappear')
    for row in registry['relationships']:
        if row['from'] not in registry['indicators'] or row['to'] not in registry['indicators'] or row['evidence'] not in registry['observations']:
            raise ValueError('Invalid relationship evidence')
    for row in registry['queue']:
        if row['target'] not in registry['indicators'] or not set(row['tasks']).issubset(TASKS):
            raise ValueError('Invalid research queue')
        if registry['indicators'][row['target']]['status'] not in ('historical', 'accepted') and set(row['tasks']) - {'dns', 'measure'}:
            raise ValueError('Unconfirmed candidates cannot expand the research graph')
    return True


def merge_measurements(current, incoming):
    """Import evidence only; the unprivileged artifact cannot authorize publication."""
    merged = copy.deepcopy(current)
    for key, item in incoming['indicators'].items():
        if key not in merged['indicators']:
            if item['origin'] == 'bootstrap' or item['sources'] or item['status'] != 'candidate':
                raise ValueError('Artifact tried to introduce trusted indicators')
            ensure_indicator(merged, item['value'], item['origin'])
            if indicator(item['value'], item['type'])[0] != key:
                raise ValueError('Invalid artifact indicator')
    for oid, record in incoming['observations'].items():
        if oid != observation_id(record) or record['kind'] == 'decision' and oid not in current['observations']:
            raise ValueError('Invalid artifact evidence')
        if oid in current['observations']:
            if observation_id(current['observations'][oid]) != observation_id(record):
                raise ValueError('Artifact overwrote prior evidence')
            continue
        observed = timestamp(record['observed_at']) if record['observed_at'] else None
        if observed and observed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            raise ValueError('Future evidence is invalid')
        observe(merged, record['indicator'], record['kind'], record['data'], record['source'], record['observed_at'], record['recorded_at'])
    for row in incoming['relationships']:
        if row not in merged['relationships']:
            merged['relationships'].append(row)
    for key, item in incoming['indicators'].items():
        for kind, at in item.get('last_attempts', {}).items():
            if kind not in TASKS:
                raise ValueError('Invalid attempted task')
            timestamp(at)
            merged['indicators'][key].setdefault('last_attempts', {})[kind] = at
    merged['queue'] = incoming['queue']
    return merged


def publication_values(registry, kind, discovered=False):
    return sorted({item['value'] for item in registry['indicators'].values()
                   if item['type'] == kind and (item['status'] == 'accepted' or
                   not discovered and item['origin'] == 'bootstrap')})


def asset_supported(data, policy):
    status=data.get('status',0)
    return (data.get('path') in policy.get('asset_paths',[]) and isinstance(status,int) and 200<=status<300
            and 'javascript' in data.get('mime_type','').lower()
            and re.fullmatch(r'[a-f0-9]{64}',data.get('body_sha256','')) is not None)
