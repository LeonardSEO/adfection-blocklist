import json
import pathlib
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import probe


class ProbeTests(unittest.TestCase):
    def test_public_ip_rejects_internal_reserved_metadata_and_mapped_addresses(self):
        for address in ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.100.100.200', '192.0.2.1', '224.0.0.1', '::1', 'fd00::1', '::ffff:127.0.0.1']:
            with self.subTest(address=address): self.assertFalse(probe.public_ip(address))
        self.assertTrue(probe.public_ip('1.1.1.1'))
        self.assertTrue(probe.public_ip('2606:4700:4700::1111'))

    def test_mixed_public_private_dns_response_is_rejected(self):
        with patch.object(probe.subprocess, 'run', return_value=Mock(stdout=json.dumps(['1.1.1.1', '10.0.0.1']))):
            with self.assertRaises(ValueError): probe.resolve_public('example.org', 443, time.monotonic()+10)

    def test_connection_is_pinned_and_does_not_re_resolve_host(self):
        response = Mock(status=200)
        response.getheader.side_effect = lambda name, default=None: default
        response.read1.return_value = b''
        connection = Mock()
        connection.getresponse.return_value = response
        sock = Mock()
        with patch.object(probe, 'resolve_public', return_value=['1.1.1.1']) as resolve, \
             patch.object(probe, 'dial', return_value=sock) as dial, \
             patch.object(probe.http.client, 'HTTPConnection', return_value=connection):
            result = probe.request_root('http://example.org/', time.monotonic()+10)
        resolve.assert_called_once()
        self.assertEqual(dial.call_args.args[:2], ('1.1.1.1', 80))
        self.assertEqual(result['ip'], '1.1.1.1')
        self.assertEqual(connection.sock, sock)

    def test_infection_paths_credentials_and_queries_are_never_requested(self):
        for url in ['http://example.org/infect/token', 'https://example.org/?id=secret', 'http://user:pass@example.org/', 'file:///etc/passwd']:
            with self.subTest(url=url), self.assertRaises(ValueError): probe.root_url(url)

    def test_redirect_is_checked_before_following(self):
        record = {'host': 'example.org', 'ip': '1.1.1.1', 'port': 80, 'http': {}, 'tls': None, 'redirect': 'http://169.254.169.254/'}
        with patch.object(probe, 'request_root', side_effect=[record, ValueError('private target'), ValueError('end')]) as request:
            _, errors = probe._probe('example.org', time.monotonic()+10)
        self.assertTrue(errors)
        self.assertEqual(request.call_args_list[1].args[0], 'http://169.254.169.254/')
        # request_root must resolve/reject a private literal before dial.
        with patch.object(probe, 'resolve_public', side_effect=ValueError('private')) as resolve, patch.object(probe, 'dial') as dial:
            with self.assertRaises(ValueError): probe.request_root('http://169.254.169.254/', time.monotonic()+10)
        dial.assert_not_called()

    def test_redirect_to_unobserved_port_is_not_followed(self):
        record = {'redirect': 'http://example.org:22/'}
        with patch.object(probe, 'request_root', return_value=record) as request:
            _, errors = probe._probe('example.org', time.monotonic()+10)
        self.assertEqual(request.call_count, 2)
        self.assertTrue(errors)

    def test_real_http_response_is_bounded_even_when_connection_closes(self):
        import http.server
        import socket
        import threading
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'x' * (probe.MAX_BODY + 10))
            def log_message(self, *args): pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            local = socket.create_connection(server.server_address, timeout=2)
            with patch.object(probe, 'resolve_public', return_value=['1.1.1.1']), patch.object(probe, 'dial', return_value=local):
                result = probe.request_root('http://controlled.example.org/', time.monotonic()+5)
            self.assertTrue(result['http']['truncated'])
            self.assertEqual(result['http']['status'], 200)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_worker_deadline_preserves_completed_records(self):
        import subprocess
        result = {'host': 'controlled.example.org', 'http': {'status': 200}}
        partial = (json.dumps({'record': result}) + '\n').encode() + b'{"record":'
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('control', 1, output=partial)) as worker:
            records, errors = probe.probe('controlled.example.org', time.monotonic()+1)
        self.assertEqual(records, [result])
        self.assertEqual(errors[0]['error'], 'AbsoluteDeadline')
        self.assertLessEqual(worker.call_args.kwargs['timeout'], 1)

    def test_expired_budget_never_opens_socket(self):
        with self.assertRaises(TimeoutError): probe.timeout(time.monotonic()-1)
