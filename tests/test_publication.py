"""Offline end-to-end publication; synthetic qualification is never shipped."""
import copy
import pathlib
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import build
import publish
import research as r
from test_research import AT, measurement, qualified_fixture


class PublicationTests(unittest.TestCase):
    def test_artifact_admission_build_and_targeted_withdrawal(self):
        registry, rule = qualified_fixture()
        historical = r.ensure_indicator(registry, 'historical.example.org', 'bootstrap')
        registry['indicators'][historical]['status'] = 'historical'
        incoming = copy.deepcopy(registry)
        key, _ = measurement(incoming, 'independent.example.org')
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            artifact = root / 'artifact'
            r.write_json(root / 'research/registry.json', registry)
            r.write_json(root / 'research/detectors.json', {'detectors': [rule]})
            r.write_json(root / 'sources/bootstrap.json', {'indicators': {historical: {'sources': []}}})
            r.write_json(artifact / 'research/registry.json', incoming)
            r.write_json(artifact / 'candidates/latest.json', {'fixture': True})
            (root / 'README.md').write_text('Fixture\n')
            with patch.object(publish, 'ROOT', root), patch.object(publish, 'utcnow', return_value=AT), patch.multiple(
                    build, ROOT=root, SOURCES=root / 'sources', OUT=root / 'lists',
                    APPROVED=root / 'approved.txt', ALLOWLIST=root / 'allowlist.txt'):
                with patch('sys.argv', ['publish.py', '--measurements', str(artifact)]):
                    publish.main()
                self.assertEqual(r.read_json(root / 'research/registry.json')['indicators'][key]['status'], 'accepted')
                domains = build.load_domains()
                build.write_all(sorted(domains), domains)
                self.assertIn('independent.example.org', (root / 'lists/domains/adfection-discovered.txt').read_text())
                rule['enabled'] = False
                r.write_json(root / 'research/detectors.json', {'detectors': [rule]})
                with patch('sys.argv', ['publish.py']):
                    publish.main()
                domains = build.load_domains()
                build.write_all(sorted(domains), domains)
                self.assertNotIn('independent.example.org', (root / 'lists/domains/adfection.txt').read_text())
                self.assertIn('historical.example.org', (root / 'lists/domains/adfection.txt').read_text())
                self.assertTrue(r.read_json(root / 'research/registry.json')['indicators'][key]['admissions'])
