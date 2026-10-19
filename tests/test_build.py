import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import build


class BuildTests(unittest.TestCase):
    def test_compression_preserves_dns_coverage(self):
        domains = ['a.example.org', 'example.org', 'other.org', 'x.other.org']
        compressed = build.compress(domains)
        self.assertEqual(compressed, ['example.org', 'other.org'])
        for domain in domains:
            self.assertTrue(any(domain == root or domain.endswith('.' + root) for root in compressed))

    def test_parse_rejects_invalid_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'source.txt'
            path.write_text('https://example.org/path # candiru: invalid\n')
            with self.assertRaises(SystemExit):
                build.parse(path)

    def test_hyphens_cannot_start_any_label(self):
        self.assertIsNone(build.DOMAIN_RE.fullmatch('valid.-invalid.org'))

    def test_unknown_category_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources').mkdir()
            (root / 'sources' / 'bad.txt').write_text('bad.example.org # candiruu: typo\n')
            with patch.multiple(build, SOURCES=root / 'sources', APPROVED=root / 'approved.txt', ALLOWLIST=root / 'allowlist.txt'):
                with self.assertRaisesRegex(ValueError, 'categor'):
                    build.load_domains()

    def test_allowlist_prevents_shared_platform_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources').mkdir()
            (root / 'sources' / 'source.txt').write_text('cloudfront.net # candiru: shared\nd123.cloudfront.net # candiru: specific\n')
            (root / 'allowlist.txt').write_text('cloudfront.net\n')
            with patch.multiple(build, SOURCES=root / 'sources', APPROVED=root / 'approved.txt', ALLOWLIST=root / 'allowlist.txt'):
                with contextlib.redirect_stdout(io.StringIO()):
                    domains = build.load_domains()
            self.assertEqual(set(domains), {'d123.cloudfront.net'})

    def test_published_appendix_c_hosts_are_in_exact_lists(self):
        domains = build.load_domains()
        for domain in ['noas.adtimizer.co', 'noas.impchkdsp.com', 'noas.trakking.co',
                       'checkmyimp.com', 'ads-impressions.com', 'nutralove.co']:
            self.assertIn(domain, domains)

    def test_generated_formats_have_equivalent_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'README.md').write_text('<!-- LISTS:START -->\n<!-- LISTS:END -->\n')
            with patch.multiple(build, ROOT=root, OUT=root / 'lists'):
                build.write_all(['example.org', 'sub.example.org'], {'example.org': 'candiru', 'sub.example.org': 'candiru'})
            out = root / 'lists'
            self.assertIn('sub.example.org\n', (out / 'domains/adfection.txt').read_text())
            self.assertIn('0.0.0.0 sub.example.org', (out / 'hosts/adfection.txt').read_text())
            self.assertIn('||example.org^', (out / 'adblock/adfection.txt').read_text())
            self.assertNotIn('||sub.example.org^', (out / 'adblock/adfection.txt').read_text())
            rpz = (out / 'rpz/adfection.txt').read_text()
            self.assertIn('example.org CNAME .', rpz)
            self.assertIn('*.example.org CNAME .', rpz)
            serial = int(next(line for line in rpz.splitlines() if ' IN SOA ' in line).split()[5])
            self.assertLessEqual(serial, 2**32 - 1)
            self.assertGreater(serial, 1_000_000_000)
            self.assertIn('local-zone: "example.org." always_nxdomain', (out / 'unbound/adfection.txt').read_text())
            asterisk = (out / 'wildcard/adfection.txt').read_text().splitlines()
            self.assertIn('example.org', asterisk)
            self.assertIn('*.example.org', asterisk)

    def test_check_detects_stale_output_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'README.md').write_text('<!-- LISTS:START -->\n<!-- LISTS:END -->\n')
            domains = {'example.org': 'candiru'}
            with patch.multiple(build, ROOT=root, OUT=root / 'lists'):
                build.write_all(sorted(domains), domains)
                build.check_output(domains)
                path = root / 'lists/domains/adfection.txt'
                path.write_text(path.read_text().replace('example.org', 'stale.org'))
                before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError, 'stale'):
                    build.check_output(domains)
                after = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
                self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main()
