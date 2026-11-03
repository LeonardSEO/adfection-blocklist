"""Trusted-provider fetch worker; parent enforces an absolute process deadline."""
import http.client
import ssl
import sys
import time
import urllib.parse

from probe import resolve_public, dial, timeout

PROVIDERS = {'crt.sh', 'urlscan.io', 'cloudflare-dns.com', 'securitylab.amnesty.org', 'citizenlab.ca', 'raw.githubusercontent.com'}
MAX_BYTES = 4 * 1024 * 1024


def fetch(url, deadline, accept=''):
    for hop in range(4):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in PROVIDERS or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise ValueError('Unapproved provider URL/redirect')
        ip = resolve_public(parsed.hostname, 443, deadline)[0]
        sock = dial(ip, 443, deadline)
        connection = http.client.HTTPConnection(parsed.hostname, 443, timeout=timeout(deadline))
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
            connection.sock = sock
            path = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
            headers = {'User-Agent': 'pegasus-blocklist/2.0 (independent defensive research)', 'Accept-Encoding': 'identity', 'Connection': 'close'}
            if accept:
                headers['Accept'] = accept
            connection.request('GET', path, headers=headers)
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                if hop == 3 or not response.getheader('Location'):
                    raise ValueError('Provider redirect limit')
                url = urllib.parse.urljoin(url, response.getheader('Location'))
                continue
            if response.status != 200:
                raise OSError(f'Provider status {response.status}')
            body = response.read(MAX_BYTES+1)
            if len(body) > MAX_BYTES:
                raise ValueError('Provider response exceeds bound')
            return body
        finally:
            connection.close()
            sock.close()
    raise ValueError('No provider response')


if __name__ == '__main__':
    sys.stdout.buffer.write(fetch(sys.argv[1], time.monotonic()+float(sys.argv[2]), sys.argv[3]))
