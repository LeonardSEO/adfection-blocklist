import base64
import copy
import hashlib
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import research as r
from bootstrap import parse_source, import_sources

AT = '2026-11-03T12:00:00+00:00'


def measurement(registry, host, same=True, at=AT, session=None):
    key = r.ensure_indicator(registry, host)
    session = session or r.digest({'host': host, 'at': at})
    common = {'host': host, 'ip': '1.1.1.1', 'port': 443, 'session': session}
    cert = b'CONTROLLED TEST CERTIFICATE' if same else host.encode()
    tls = {**common, 'certificate_sha256': hashlib.sha256(cert).hexdigest(),
           'certificate_der_base64': base64.b64encode(cert).decode(), 'version': 'TLSv1.3', 'cipher': 'control', 'authenticated': False}
    raw = {'status': 200, 'server': 'controlled' if same else host, 'content_type': 'text/plain',
           'body_sha256': hashlib.sha256(b'controlled root page').hexdigest(), 'truncated': False}
    http = {**raw, **common, 'fingerprint': r.digest(raw)}
    ids = [r.observe(registry, key, kind, data, 'direct-root-probe', at, at) for kind, data in [('tls', tls), ('http', http)]]
    return key, ids


def qualified_fixture():
    """Synthetic engine regression data; never install as a production detector."""
    registry = r.empty_registry()
    positive, pos = measurement(registry, 'positive.example.org')
    shadow, sha = measurement(registry, 'shadow.example.org')
    negatives = []
    for category in sorted(r.NEGATIVE_CLASSES):
        key, ids = measurement(registry, category + '.example.net', same=False)
        negatives.append({'evidence': ids, 'at': AT, 'reference': 'https://example.org/CONTROLLED-FIXTURE', 'class': category})
    features = r.features(registry, pos, AT)
    rule = {'id': 'CONTROLLED-FIXTURE-NOT-PEGASUS', 'version': '1', 'enabled': True,
            'match': {k: features[k] for k in ('tls.certificate_sha256', 'http.fingerprint')},
            'qualification': {'positives': [{'evidence': pos, 'at': AT, 'reference': 'https://example.org/CONTROLLED-FIXTURE'}],
                              'negatives': negatives,
                              'shadow': [{'evidence': sha, 'at': AT, 'reference': 'https://example.org/CONTROLLED-SHADOW'}]}}
    return registry, rule


class BootstrapTests(unittest.TestCase):
    def test_hosts_domain_ip_and_endpoint_formats_are_distinct(self):
        values, rejected = parse_source('0.0.0.0 EXAMPLE.org\n1.1.1.1\nexample.org\niusacell-movil. com.mx\n', 'hosts')
        self.assertEqual(set(values), {'domain:example.org', 'ip:1.1.1.1'})
        self.assertEqual(len(rejected), 1)
        self.assertNotIn('domain:com.mx', values)
        values, rejected = parse_source('1.1.1.1:443\n[2606:4700:4700::1111]:443\n1.1.1.1:70000\n', 'endpoints')
        self.assertEqual(len(values), 2)
        self.assertEqual(len(rejected), 1)

    def test_import_preserves_multiple_sources_and_exclusions(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root/'a').write_text('example.org\ncloudfront.net\nx.cloudfront.net\n')
            specs = [{'id': 'a', 'file': 'a', 'syntax': 'hosts'}, {'id': 'b', 'file': 'a', 'syntax': 'hosts'}]
            manifest, registry = import_sources(specs, root, {'cloudfront.net'})
        self.assertEqual(registry['indicators']['domain:example.org']['sources'], ['a', 'b'])
        self.assertIn('domain:x.cloudfront.net', registry['indicators'])
        self.assertNotIn('domain:cloudfront.net', registry['indicators'])
        self.assertTrue(r.validate_registry(registry, [], manifest))

    def test_empty_sources_fail(self):
        with self.assertRaises(ValueError):
            parse_source('# empty\n', 'domains')


class EvidenceTests(unittest.TestCase):
    def test_repeated_observation_is_preserved_without_overwrite(self):
        registry = r.empty_registry()
        key = r.ensure_indicator(registry, 'example.org')
        a = r.observe(registry, key, 'certificate-log', {'id': 1}, 'https://crt.sh', '2020-01-01T00:00:00+00:00', AT)
        before = copy.deepcopy(registry['observations'][a])
        b = r.observe(registry, key, 'certificate-log', {'id': 1}, 'https://crt.sh', '2020-01-01T00:00:00+00:00', '2026-11-04T00:00:00+00:00')
        self.assertEqual(a, b)
        self.assertEqual(registry['observations'][a], before)
        self.assertEqual(registry['indicators'][key]['last_seen'], '2020-01-01T00:00:00+00:00')

    def test_empty_detector_set_never_admits_candidates(self):
        registry = r.empty_registry()
        key, _ = measurement(registry, 'candidate.example.org')
        r.reconcile(registry, [], AT)
        self.assertEqual(registry['indicators'][key]['status'], 'candidate')

    def test_qualified_rule_admits_and_disabled_rule_withdraws_only_own_findings(self):
        registry, rule = qualified_fixture()
        key, ids = measurement(registry, 'new.example.org')
        historical = r.ensure_indicator(registry, 'historical.example.org', 'bootstrap')
        registry['indicators'][historical]['status'] = 'historical'
        r.reconcile(registry, [rule], AT)
        self.assertEqual(registry['indicators'][key]['status'], 'accepted')
        self.assertIn('new.example.org', r.publication_values(registry, 'domain', True))
        r.validate_registry(registry, [rule], {'indicators': {historical: {'sources': []}}})
        rule['enabled'] = False
        r.reconcile(registry, [rule], AT)
        self.assertEqual(registry['indicators'][key]['status'], 'withdrawn')
        self.assertEqual(registry['indicators'][historical]['status'], 'historical')
        self.assertNotIn('new.example.org', r.publication_values(registry, 'domain'))
        self.assertEqual(len(registry['indicators'][key]['admissions']), 1)
        self.assertTrue(all(oid in registry['observations'] for oid in ids))

    def test_stale_evidence_cannot_authorize_a_new_indicator(self):
        registry, rule = qualified_fixture()
        key, _ = measurement(registry, 'stale.example.org', at='2020-01-01T00:00:00+00:00')
        r.reconcile(registry, [rule], AT)
        self.assertEqual(registry['indicators'][key]['status'], 'candidate')

    def test_tls_and_http_from_different_sessions_do_not_correlate(self):
        registry, rule = qualified_fixture()
        key, ids = measurement(registry, 'cross.example.org')
        old = registry['observations'].pop(ids[1])
        old['data']['session'] = 'f'*64
        oid = r.observation_id(old)
        registry['observations'][oid] = old
        registry['indicators'][key]['evidence'][1] = oid
        r.reconcile(registry, [rule], AT)
        self.assertEqual(registry['indicators'][key]['status'], 'candidate')

    def test_negative_classes_and_distinct_shadow_evidence_are_required(self):
        registry, rule = qualified_fixture()
        rule['qualification']['negatives'].pop()
        with self.assertRaises(ValueError): r.qualified(rule, registry)
        registry, rule = qualified_fixture()
        rule['qualification']['shadow'] = rule['qualification']['positives']
        with self.assertRaises(ValueError): r.qualified(rule, registry)

    def test_shared_ip_or_certificate_alone_is_not_a_detector(self):
        registry, rule = qualified_fixture()
        rule['match'] = {'tls.certificate_sha256': 'a'*64}
        with self.assertRaises(ValueError): r.qualified(rule, registry)

    def test_artifact_cannot_authorize_or_overwrite_publication(self):
        original = r.empty_registry()
        key, _ = measurement(original, 'candidate.example.org')
        incoming = copy.deepcopy(original)
        incoming['indicators'][key]['status'] = 'accepted'
        incoming['indicators'][key]['admissions'] = [{'fake': True}]
        merged = r.merge_measurements(original, incoming)
        self.assertEqual(merged['indicators'][key]['status'], 'candidate')
        self.assertEqual(merged['indicators'][key]['admissions'], [])
        incoming['observations'][next(iter(incoming['observations']))]['data']['ip'] = '127.0.0.1'
        with self.assertRaises(ValueError): r.merge_measurements(original, incoming)

    def test_public_ip_redirect_measurement_has_consistent_indicator_type(self):
        registry = r.empty_registry()
        key, ids = measurement(registry, '1.1.1.1')
        self.assertEqual(key, 'ip:1.1.1.1')
        self.assertTrue(r.validate_registry(registry, [], {'indicators': {}}))

    def test_forged_accepted_indicator_fails_ci(self):
        registry = r.empty_registry()
        key, _ = measurement(registry, 'forged.example.org')
        registry['indicators'][key]['status'] = 'accepted'
        registry['indicators'][key]['admissions'] = [{'detector': 'unknown', 'version': '1', 'decided_at': AT, 'evidence': []}]
        with self.assertRaises(ValueError): r.validate_registry(registry, [], {'indicators': {}})
