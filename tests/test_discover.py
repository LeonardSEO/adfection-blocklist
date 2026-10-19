import json
import pathlib
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import discover


class DiscoveryTests(unittest.TestCase):
    def test_shared_ip_is_a_lead_not_confirmation(self):
        answers = {('infra.example.org', 'A'): ['192.0.2.10'],
                   (discover.ALB, 'A'): ['192.0.2.10']}
        found = {}
        with patch.object(discover, 'doh', side_effect=lambda n, t: answers.get((n, t), [])), patch.object(discover.time, 'sleep'):
            discover.dns(found, {'infra.example.org'})
        self.assertNotIn('bevestigd', found['infra.example.org'])

    def test_urlscan_does_not_block_publishers(self):
        data = {'results': [{'page': {'domain': 'innocent.example.org', 'apexDomain': 'example.org'}},
                            {'page': {'domain': 'new.mtrtb.com', 'apexDomain': 'mtrtb.com'}}]}
        found = {}
        with patch.object(discover, 'get_json', return_value=data), patch.object(discover.time, 'sleep'):
            discover.urlscan(found)
        self.assertEqual(set(found), {'mtrtb.com', 'new.mtrtb.com'})

    def test_clean_only_accepts_actual_domain_names(self):
        self.assertEqual(discover.clean('*.EXAMPLE.org.'), 'example.org')
        self.assertIsNone(discover.clean('https://example.org/'))
        self.assertIsNone(discover.clean('192.0.2.1'))
        self.assertIsNone(discover.clean('...example.org'))

    def test_http_failures_are_recorded(self):
        discover.ERRORS.clear()
        with patch.object(discover.urllib.request, 'urlopen', side_effect=discover.urllib.error.URLError('offline')), patch.object(discover.time, 'sleep'):
            self.assertIsNone(discover.get_json('https://example.org', retries=1))
        self.assertEqual(len(discover.ERRORS), 1)

    def test_timed_out_source_does_not_skip_other_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'candidates').mkdir()
            with patch.object(discover, 'ROOT', root), \
                 patch.object(sys, 'argv', ['discover.py', '--max-seconds', '5']), \
                 patch.object(discover, 'crtsh', side_effect=discover.DiscoveryDeadline('timeout')), \
                 patch.object(discover, 'urlscan') as urlscan, \
                 patch.object(discover, 'dns'), \
                 patch.dict(discover.os.environ, {'CENSYS_API_ID': '', 'CENSYS_API_SECRET': ''}):
                with self.assertRaises(SystemExit) as error:
                    discover.main()
                self.assertEqual(error.exception.code, 1)
                urlscan.assert_called_once()
            report = json.loads(next((root / 'candidates').glob('*.json')).read_text())
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(report['candidate_count'], 0)
            self.assertIn('urlscan', report['completed_sources'])


if __name__ == '__main__':
    unittest.main()
