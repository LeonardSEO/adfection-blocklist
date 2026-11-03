import datetime as dt
import pathlib
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import refresh
import research


class DiscoveryTests(unittest.TestCase):
    def test_san_finds_new_root_and_subdomain_but_requires_a_known_anchor(self):
        rows = [{'id': 1, 'name_value': 'known.example.org\nchild.known.example.org\nnew.example.net'}, {'id': 2, 'name_value': 'unrelated.example.com'}]
        found = refresh.certificate_names(rows, 'known.example.org')
        self.assertIn('new.example.net', found)
        self.assertIn('child.known.example.org', found)
        self.assertNotIn('unrelated.example.com', found)

    def test_publications_do_not_import_domains_from_text(self):
        xml = b'<rss><channel><item><title>Pegasus research evil.example.org</title><link>https://citizenlab.ca/report/</link></item><item><title>NSO Group</title><link>https://evil.example.org/</link></item></channel></rss>'
        with patch.object(refresh, 'POLICY', {'news_terms':['pegasus','nso group']}):
            self.assertEqual(len(refresh.publications(xml, 'https://citizenlab.ca/feed/')), 1)

    def test_rotation_visits_full_seed_set(self):
        names = [f'd{i}.example.org' for i in range(50)]
        day = dt.date(2026, 11, 3)
        found = set()
        for offset in range(3): found.update(refresh.select_seeds(names, day+dt.timedelta(days=offset)))
        self.assertEqual(found, set(names))

    def test_deadline_preserves_unfinished_queue_and_prior_evidence(self):
        registry = research.empty_registry()
        key = research.ensure_indicator(registry, 'known.example.org', 'bootstrap')
        registry['indicators'][key]['status'] = 'historical'
        oid = research.observe(registry, key, 'dns', {}, 'control', '2026-11-03T00:00:00+00:00')
        with patch.object(refresh, 'fetch', side_effect=TimeoutError('deadline')):
            report = refresh.run(registry, time.monotonic()-1, '2026-11-03T12:00:00+00:00', set())
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(registry['queue'])
        self.assertIn(oid, registry['observations'])
        self.assertEqual(registry['indicators'][key]['status'], 'historical')

    def test_candidates_cannot_expand_graph_via_ct(self):
        registry = research.empty_registry()
        key = research.ensure_indicator(registry, 'new.example.org', 'certificate-san')
        with patch.object(refresh, 'fetch', return_value=b'<rss/>'), patch.object(refresh, 'task') as task:
            refresh.run(registry, time.monotonic()+10, '2026-11-03T12:00:00+00:00', set())
        self.assertEqual([call.args[2] for call in task.call_args_list], ['dns', 'measure'])

    def test_fingerprint_archive_search_can_find_a_new_root_without_seed_match(self):
        registry = research.empty_registry()
        refresh.record_scans(registry, [{'page': {'domain': 'new-root.example.net', 'ip': '1.1.1.1', 'port': 443},
                                         'task': {'time': '2026-11-03T00:00:00+00:00'}}],
                             'https://urlscan.io/api/v1/search/?q=controlled-fingerprint',
                             '2026-11-03T12:00:00+00:00', set())
        key = 'domain:new-root.example.net'
        self.assertIn(key, registry['indicators'])
        self.assertEqual(registry['indicators'][key]['status'], 'candidate')
        self.assertEqual(registry['queue'][0]['tasks'], ['dns', 'measure'])

    def test_existing_scan_publisher_is_not_imported_as_infrastructure(self):
        registry = research.empty_registry()
        key = research.ensure_indicator(registry, 'known.example.org')
        refresh.record_scans(registry, [{'page': {'domain': 'publisher.example.net'}}],
                             'https://urlscan.io/api/v1/search/', '2026-11-03T12:00:00+00:00', set(), key)
        self.assertNotIn('domain:publisher.example.net', registry['indicators'])

    def test_service_failure_retains_prior_state_and_allows_other_tasks(self):
        registry = research.empty_registry()
        key = research.ensure_indicator(registry, 'known.example.org', 'bootstrap')
        registry['indicators'][key]['status'] = 'historical'
        def action(registry, key, kind, *args):
            if kind == 'ct': raise TimeoutError('offline')
        with patch.object(refresh, 'fetch', return_value=b'<rss/>'), patch.object(refresh, 'task', side_effect=action):
            report = refresh.run(registry, time.monotonic()+10, '2026-11-03T12:00:00+00:00', set())
        self.assertTrue(any(q.startswith('measure:') for q in report['completed_queries']))
        self.assertEqual(registry['indicators'][key]['status'], 'historical')
        self.assertEqual(report['status'], 'partial')


class BoundaryRegressionTests(unittest.TestCase):
    def test_public_provider_drip_has_a_wall_clock_limit(self):
        import subprocess
        with patch.object(refresh.subprocess, 'run', side_effect=subprocess.TimeoutExpired('control', 1)):
            with self.assertRaises(TimeoutError): refresh.fetch('https://crt.sh/', time.monotonic()+1)

    def test_failed_ct_work_remains_queued_while_other_work_completes(self):
        registry = research.empty_registry()
        key = research.ensure_indicator(registry, 'known.example.org', 'bootstrap')
        registry['indicators'][key]['status'] = 'historical'
        def action(registry, key, kind, *args):
            if kind == 'ct': raise TimeoutError('offline')
        with patch.object(refresh, 'fetch', return_value=b'<rss/>'), patch.object(refresh, 'task', side_effect=action):
            refresh.run(registry, time.monotonic()+10, '2026-11-03T12:00:00+00:00', set())
        self.assertEqual(registry['queue'], [{'target': key, 'tasks': ['ct']}])
