"""Pure restricted staging template and relay protocol acceptance."""
from pathlib import Path
import unittest

from aegis_staging_execution import validate_template
from aegis_staging_protocol import decode_frame, encode_frame
from aegis_staging_sandbox import parse_proxy_request
from aegis_supervisor import ExecutionDenied

TEMPLATE = Path(__file__).parent/"fixtures"/"scanner-exports"/"nuclei-fixture.yaml"

class StagingBoundaryUnitTests(unittest.TestCase):
    def request(self, method="GET", route="http://127.0.0.1:1234/fixture", headers=(), suffix=b""):
        return (f"{method} {route} HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n" + "".join(h+"\r\n" for h in headers) + "\r\n").encode()+suffix

    def test_relay_rejects_credentials_bodies_duplicates_and_pipelining(self):
        self.assertEqual(parse_proxy_request(self.request())["method"], "GET")
        cases = [self.request(method="CONNECT"), self.request(method="POST"),
                 self.request(headers=["Authorization: Bearer SECRET"]), self.request(headers=["Proxy-Authorization: Basic SECRET"]),
                 self.request(headers=["Cookie: SECRET"]), self.request(headers=["Content-Length: 1"]),
                 self.request(headers=["Transfer-Encoding: chunked"]), self.request(headers=["Host: 127.0.0.1:1234"]),
                 self.request(headers=[" folded: unsafe"]), self.request(route="http://user:pass@127.0.0.1:1234/fixture"),
                 self.request(suffix=self.request()), self.request(route="https://127.0.0.1:1234/fixture"),
                 self.request(headers=["Content-Length: 0", "content-length: 0"])]
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                parse_proxy_request(raw)

    def test_template_extensions_and_code_fail_closed(self):
        profile = {"methods":["GET"],"rule_id":"aegis-fixture-marker"}
        raw = TEMPLATE.read_bytes(); validate_template(raw, profile)
        for altered in (raw+b"\ncode: []\n", raw.replace(b'type: word', b'type: dsl'),
                        raw.replace(b'{{BaseURL}}', b'http://outside.invalid'), raw.replace(b'method: GET', b'method: POST'),
                        raw+b"\nid: duplicate\n", raw.replace(b'AEGIS_SYNTHETIC_MARKER', b'{{interactsh-url}}'),
                        b'id: &alias [*alias]', b'['*1000+b']'*1000):
            with self.assertRaises((ExecutionDenied, ValueError)):
                validate_template(altered, profile)

    def test_frame_bounds_duplicates_and_roundtrip(self):
        body = {"kind":"request","method":"GET","url":"http://example.invalid/fixture"}
        self.assertEqual(decode_frame(encode_frame(body)[4:]), body)
        for raw in (b'{"kind":"request","kind":"ready"}', b'{}' * 100000, b'[]', b'{"exit_code":1e400}',
                    b'{"exit_code":'+b'9'*10000+b'}', b'{"nested":[]}', b'{"nested":'+b'['*1000+b']'*1000+b'}'):
            with self.assertRaises(ValueError):
                decode_frame(raw)



if __name__ == "__main__":
    unittest.main()
