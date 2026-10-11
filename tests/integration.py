#!/usr/bin/env python3
"""One-shot, stdlib-only black-box tests. Outbound transport is a Pascal mock.
No Discord/API credentials and no external targets are used.
"""
import ctypes
import ctypes.util
import http.client
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SODIUM = ctypes.CDLL(ctypes.util.find_library('sodium'))
SODIUM.sodium_init()
SODIUM.crypto_sign_detached.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p]
PK = ctypes.create_string_buffer(32)
SK = ctypes.create_string_buffer(64)
SEED = ctypes.create_string_buffer(bytes(range(32)), 32)  # test key, never a real Discord secret
assert SODIUM.crypto_sign_seed_keypair(PK, SK, SEED) == 0
TOKEN = 'TEST_TOKEN_NOT_FOR_LOGS_' + 'x' * 160
GUILD, ROLE, PENTEST, APP = [str(n) * 18 for n in (1, 2, 3, 4)]


def sign(body, ts):
    message = str(ts).encode() + body
    signature = ctypes.create_string_buffer(64)
    assert SODIUM.crypto_sign_detached(signature, None, message, len(message), SK) == 0
    return signature.raw.hex()


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'build').mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=ROOT / 'build')
        cls.record = pathlib.Path(cls.temp.name) / 'calls.jsonl'
        cls.log_path = pathlib.Path(cls.temp.name) / 'server.log'
        cls.log = cls.log_path.open('wb')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        env = dict(os.environ, TEST_PUBLIC_KEY=PK.raw.hex(), TEST_PORT=str(cls.port), TEST_RECORD_PATH=str(cls.record))
        cls.proc = subprocess.Popen([str(ROOT / 'bin/test_server')], cwd=ROOT, env=env,
                                    stdout=cls.log, stderr=subprocess.STDOUT)
        # This bounded startup wait belongs to the one-shot test harness, not a daemon.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if cls.proc.poll() is not None:
                raise RuntimeError(cls.log_path.read_text())
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            cls.proc.kill()
            raise RuntimeError('Test server did not start')
        cls.serial = 100000000000000000

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
            cls.proc.wait()
        cls.log.close()
        logs = cls.log_path.read_text()
        assert TOKEN not in logs, 'Interaction tokens must never appear in audit logs'
        assert cls.proc.returncode == 0, f'Test server failed: {logs}'
        cls.temp.cleanup()

    def payload(self, group='help', sub=None, arg=None, user=None, roles=None, guild=GUILD):
        type(self).serial += 1
        serial = str(type(self).serial)
        data = {'name': group, 'type': 1}
        if sub:
            option = {'name': sub, 'type': 1}
            if arg:
                option['options'] = [{'name': arg[0], 'value': arg[1], 'type': 3}]
            data['options'] = [option]
        return {'id': serial, 'type': 2, 'application_id': APP, 'guild_id': guild,
                'token': TOKEN + serial, 'member': {'user': {'id': user or serial},
                                                  'roles': [ROLE] if roles is None else roles}, 'data': data}

    def request(self, payload=None, *, raw=None, ts=None, valid=True, path='/interactions', method='POST', extra=None):
        body = raw if raw is not None else json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
        ts = int(time.time()) if ts is None else ts
        headers = {'Content-Type': 'application/json'}
        if valid:
            headers.update({'X-Signature-Timestamp': str(ts), 'X-Signature-Ed25519': sign(body, ts)})
        if extra:
            headers.update(extra)
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        try:
            start = time.monotonic()
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            contents = response.read()
            return response.status, json.loads(contents) if contents else {}, time.monotonic() - start
        finally:
            connection.close()

    def records(self):
        if not self.record.exists():
            return []
        # Writes are one short locked append; ignore a temporarily incomplete final line.
        return [json.loads(line) for line in self.record.read_text().splitlines() if line.endswith('}')]

    def wait_edit(self, payload):
        expected = '/'+payload['token']+'/messages/@original'
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            for record in self.records():
                if record['url'].endswith(expected):
                    return json.loads(record['body'])
            time.sleep(0.01)
        self.fail('Deferred result was not delivered to mock transport')

    def test_health(self):
        status, data, _ = self.request(raw=b'', method='GET', path='/healthz', valid=False)
        self.assertEqual((status, data['status']), (200, 'ok'))

    def test_unsigned_rejected(self):
        self.assertEqual(self.request({'type': 1}, valid=False)[0], 401)

    def test_bad_signature_rejected(self):
        self.assertEqual(self.request({'type': 1}, extra={'X-Signature-Ed25519': '00'*64})[0], 401)

    def test_signed_ping(self):
        status, data, elapsed = self.request({'type': 1, 'unicode': '日本語 / café'})
        self.assertEqual((status, data), (200, {'type': 1}))
        self.assertLess(elapsed, 1)

    def test_stale_signature(self):
        self.assertEqual(self.request({'type': 1}, ts=int(time.time())-301)[0], 401)

    def test_future_signature(self):
        self.assertEqual(self.request({'type': 1}, ts=int(time.time())+90)[0], 401)

    def test_raw_body_integrity(self):
        ts = int(time.time())
        self.assertEqual(self.request(raw=b'{"type": 1}', ts=ts,
                         extra={'X-Signature-Ed25519': sign(b'{"type":1}', ts)})[0], 401)

    def test_wrong_application(self):
        p = self.payload()
        p['application_id'] = '9'*18
        self.assertEqual(self.request(p)[0], 401)

    def test_wrong_guild(self):
        _, data, _ = self.request(self.payload(guild='9'*18))
        self.assertEqual((data['type'], data['data']['flags']), (4, 64))
        self.assertIn('Access denied', data['data']['content'])

    def test_missing_role(self):
        _, data, _ = self.request(self.payload(roles=[]))
        self.assertIn('Access denied', data['data']['content'])

    def test_admin_permission_no_bypass(self):
        p = self.payload(roles=[])
        p['member']['permissions'] = '8'
        self.assertIn('Access denied', self.request(p)[1]['data']['content'])

    def test_pentest_extra_role(self):
        _, data, _ = self.request(self.payload('pentest', 'scope'))
        self.assertIn('Access denied', data['data']['content'])

    def test_pentest_role_alone_rejected(self):
        _, data, _ = self.request(self.payload('pentest', 'scope', roles=[PENTEST]))
        self.assertIn('Access denied', data['data']['content'])

    def test_direct_message_rejected(self):
        p = self.payload()
        del p['guild_id']
        self.assertIn('Guild-only', self.request(p)[1]['data']['content'])

    def test_deferred_private_reply(self):
        p = self.payload()
        status, data, elapsed = self.request(p)
        self.assertEqual((status, data), (200, {'type': 5, 'data': {'flags': 64}}))
        self.assertLess(elapsed, 1)
        reply = self.wait_edit(p)
        self.assertIn('SENTINEL', reply['content'])
        self.assertEqual(reply['allowed_mentions'], {'parse': []})
        self.assertLess(len(reply['content']), 2000)

    def test_replay_deduplicated(self):
        p = self.payload()
        self.request(p)
        self.wait_edit(p)
        self.assertEqual(self.request(p)[1]['type'], 5)
        time.sleep(0.08)
        matching = [r for r in self.records() if p['token'] in r['url']]
        self.assertEqual(len(matching), 1)

    def test_ffraud_roundtrip(self):
        p = self.payload('ffraud', 'ip', ('address', '1.1.1.1'))
        self.assertEqual(self.request(p)[1]['type'], 5)
        reply = self.wait_edit(p)
        self.assertIn('0/100', reply['content'])
        self.assertIn('FFraud', reply['content'])

    def test_scope_requires_no_network(self):
        p = self.payload('pentest', 'scope', roles=[ROLE, PENTEST])
        self.request(p)
        self.assertIn('Authorized targets', self.wait_edit(p)['content'])

    def test_unknown_target_fails_closed(self):
        p = self.payload('pentest', 'ports', ('target', 'not-approved'), roles=[ROLE, PENTEST])
        self.request(p)
        self.assertIn('Unknown target alias', self.wait_edit(p)['content'])

    def test_user_rate_limit(self):
        for _ in range(5):
            p = self.payload(user='8'*18)
            self.assertEqual(self.request(p)[1]['type'], 5)
            self.wait_edit(p)
        denied = self.request(self.payload(user='8'*18))[1]
        self.assertEqual(denied['type'], 4)
        self.assertIn('Rate limit', denied['data']['content'])

    def test_unknown_command(self):
        data = self.request(self.payload('shell'))[1]
        self.assertEqual(data['type'], 4)
        self.assertIn('Expected exactly one subcommand', data['data']['content'])

    def test_body_rejected_before_reading(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        try:
            conn.putrequest('POST', '/interactions')
            conn.putheader('Content-Length', '70000')
            conn.endheaders()  # deliberately send no oversized body
            self.assertEqual(conn.getresponse().status, 413)
        finally:
            conn.close()

    def test_chunked_rejected(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        try:
            conn.putrequest('POST', '/interactions')
            conn.putheader('Transfer-Encoding', 'chunked')
            conn.endheaders()
            self.assertEqual(conn.getresponse().status, 413)
        finally:
            conn.close()

    def test_exact_route_and_method(self):
        self.assertEqual(self.request({'type': 1}, path='/interactions/other')[0], 404)
        self.assertEqual(self.request(raw=b'', method='GET')[0], 405)


if __name__ == '__main__':
    unittest.main(verbosity=2)
