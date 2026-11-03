"""Bounded root-only probes. Every connection pins a freshly checked public IP."""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

from research import DOMAIN_RE, digest

MAX_BODY = 65536
REDIRECTS = {301, 302, 303, 307, 308}


def public_ip(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not (address.is_multicast or address.is_reserved or address.is_unspecified)


def timeout(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Research deadline reached')
    return min(5, remaining)


def resolve_public(host, port, deadline):
    # A subprocess bounds libc DNS resolution too, unlike socket timeout alone.
    program = 'import socket,json,sys; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)})))'
    result = subprocess.run([sys.executable, '-c', program, host, str(port)], capture_output=True,
                            text=True, check=True, timeout=timeout(deadline))
    addresses = json.loads(result.stdout)
    if not addresses or any(not public_ip(ip) for ip in addresses):
        raise ValueError('Blocked non-public or mixed public/private DNS resolution')
    return addresses


def dial(ip, port, deadline):
    if not public_ip(ip):
        raise ValueError('Non-public connection denied')
    sock = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout(deadline))
        sock.connect((ip, port))
        return sock
    except Exception:
        sock.close()
        raise


def root_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Unsupported probe URL')
    if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Only root pages without query/fragment may be probed')
    host = parsed.hostname.rstrip('.').lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not DOMAIN_RE.fullmatch(host):
            raise ValueError('Invalid probe hostname')
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid probe port')
    return parsed.scheme, host, port


def request_root(url, deadline):
    scheme, host, port = root_url(url)
    addresses = resolve_public(host, port, deadline)
    ip = addresses[0]
    sock = dial(ip, port, deadline)
    tls = None
    connection = http.client.HTTPConnection(host, port, timeout=timeout(deadline))
    try:
        if scheme == 'https':
            # Inspect untrusted certificates as evidence, never as authenticated content.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['http/1.1'])
            sock = context.wrap_socket(sock, server_hostname=host)
            cert = sock.getpeercert(binary_form=True)
            tls = {'certificate_sha256': hashlib.sha256(cert).hexdigest(),
                   'certificate_der_base64': base64.b64encode(cert).decode(),
                   'version': sock.version(), 'cipher': sock.cipher()[0],
                   'authenticated': False}
        session = digest({'url': url, 'ip': ip, 'port': port, 'started': time.time_ns()})
        connection.sock = sock
        connection.request('GET', '/', headers={'Host': f'[{host}]:{port}' if ':' in host else f'{host}:{port}',
                           'User-Agent': 'pegasus-blocklist/2.0 (defensive root-only research)',
                           'Connection': 'close', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        body = bytearray()
        while len(body) <= MAX_BODY:
            timeout(deadline)
            part = response.read1(min(4096, MAX_BODY + 1 - len(body)))
            if not part:
                break
            body.extend(part)
        http_data = {'status': response.status, 'server': response.getheader('Server', ''),
                'content_type': response.getheader('Content-Type', ''),
                'body_sha256': hashlib.sha256(body[:MAX_BODY]).hexdigest(),
                'truncated': len(body) > MAX_BODY}
        http_data['fingerprint'] = digest(http_data)
        lower = bytes(body).lower()
        http_data['body_bytes'] = len(body[:MAX_BODY])
        http_data['generic'] = any(token in lower for token in (b'domain for sale', b'buy this domain', b'parkingcrew', b'sedo parking', b'just a moment', b'welcome to nginx', b'apache2 default page', b'domain has expired'))
        for record in (tls, http_data):
            if record is not None:
                record.update({'session': session, 'ip': ip, 'port': port, 'host': host})
        return {'host': host, 'ip': ip, 'port': port, 'tls': tls, 'http': http_data,
                'redirect': response.getheader('Location') if response.status in REDIRECTS else None}
    finally:
        connection.close()
        sock.close()


def _probe(host, deadline, extra_ports=(), emit=None):
    records, errors = [], []
    targets = [f'http://{host}/', f'https://{host}/']
    for port in sorted(set(extra_ports) - {80, 443}):
        targets.append(f'https://{host}:{port}/')
    for target in targets:
        url = target
        for hop in range(4):
            try:
                result = request_root(url, deadline)
                clean = {k: v for k, v in result.items() if k != 'redirect'}
                records.append(clean)
                if emit:
                    emit(clean)
                if not result['redirect']:
                    break
                redirect = urllib.parse.urljoin(url, result['redirect'])
                _, _, redirect_port = root_url(redirect)
                if redirect_port not in {80, 443, *extra_ports}:
                    raise ValueError('Redirect to an unobserved port denied')
                if hop == 3:
                    raise ValueError('Redirect limit reached')
                # No cookies, Authorization or incoming headers are forwarded.
                url = redirect
            except (OSError, ValueError, subprocess.SubprocessError, http.client.HTTPException) as error:
                errors.append({'target': target, 'error': type(error).__name__})
                break
    return records, errors


def probe(host, deadline, extra_ports=()):
    """A worker process enforces a wall-clock limit even during slow headers."""
    import pathlib
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return [], [{'target': host, 'error': 'Deadline'}]
    request = json.dumps({'host': host, 'seconds': remaining, 'ports': list(extra_ports)})
    try:
        result = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()), request],
                                capture_output=True, timeout=remaining, check=True)
        output, errors = result.stdout, []
    except subprocess.TimeoutExpired as error:
        output, errors = error.stdout or b'', [{'target': host, 'error': 'AbsoluteDeadline'}]
    records = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue  # A killed worker may leave a truncated final JSON line.
        if 'record' in row:
            records.append(row['record'])
        errors.extend(row.get('errors', []))
    return records, errors


if __name__ == '__main__':
    request = json.loads(sys.argv[1])
    _, errors = _probe(request['host'], time.monotonic()+request['seconds'], request['ports'],
                       emit=lambda row: print(json.dumps({'record': row}), flush=True))
    print(json.dumps({'errors': errors}), flush=True)
