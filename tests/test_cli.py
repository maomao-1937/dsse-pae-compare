import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "dsse_pae_compare.py"
sys.path.insert(0, str(ROOT))
import dsse_pae_compare as app


def document(kind, body):
    return json.dumps({"payloadType": kind, "payload": body}).encode()


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.left = Path(self.temp.name) / "PRIVATE-left.json"
        self.right = Path(self.temp.name) / "PRIVATE-right.json"

    def invoke(self, left, right, code):
        self.left.write_bytes(left)
        self.right.write_bytes(right)
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.left), str(self.right)],
                                capture_output=True, timeout=15)
        self.assertEqual((result.returncode, result.stderr), (code, b""))
        self.assertNotIn(b"PRIVATE", result.stdout)
        return json.loads(result.stdout)

    def test_normative_pae_vectors(self):
        self.assertEqual(app.pae(b"http://example.com/HelloWorld", b"hello world"),
                         b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")
        self.assertEqual(app.pae("猫😀".encode(), b"\x00 \xff"), b"DSSEv1 7 " + "猫😀".encode() + b" 3 \x00 \xff")
        self.assertEqual(app.pae(b"", b""), b"DSSEv1 0  0 ")

    def test_alphabets_padding_and_ignored_metadata(self):
        left = b'{"payloadType":"PRIVATE","payload":"+/8=","signatures":[{"sig":"not inspected"}]}'
        right = b'{"signatures":[],"payload":"-_8","payloadType":"PRIVATE","extra":123}'
        self.assertEqual(self.invoke(left, right, 0), {"status": "same", "type_same": True,
            "payload_same": True, "legacy_collision": False, "type_utf8_bytes": [7, 7]})
        self.assertEqual(self.invoke(document("", ""), document("", ""), 0)["type_utf8_bytes"], [0, 0])

    def test_legacy_low_bytes_bmp_and_astral(self):
        for left, right, sizes in [("test", "ŴťųŴ", [4, 8]), ("=A", "🙁", [2, 4])]:
            result = self.invoke(document(left, "AA"), document(right, "AA=="), 1)
            self.assertEqual(result, {"status": "different", "type_same": False, "payload_same": True,
                             "legacy_collision": True, "type_utf8_bytes": sizes})
        result = self.invoke(document("a", "QQ=="), document("b", "QQ=="), 1)
        self.assertFalse(result["legacy_collision"])
        result = self.invoke(document("=A", "QQ=="), document("🙁", "Qg=="), 1)
        self.assertFalse(result["legacy_collision"])
        self.assertFalse(result["payload_same"])

    def test_strict_base64_and_unicode(self):
        good = document("PRIVATE", "QQ==")
        for value in ["QR==", "QR", "Q", "QQ=", "QQ===", "Q Q==", "QQ==\n", "+_8=", "你好"]:
            with self.subTest(value=value):
                self.assertEqual(self.invoke(good, document("PRIVATE", value), 2), {"status": "invalid"})
        for malformed in [b'\xef\xbb\xbf' + good, b'{"payloadType":"x","payload":"","extra":"\\ud800"}',
                          b'{"payloadType":"x","payload":"","extra":{"a":1,"a":2}}',
                          b'{"payloadType":"x","payload":"","extra":NaN}', b'{"payloadType":9,"payload":""}',
                          b'{"payloadType":"x","payload":9}', b'[]', b'\xff']:
            with self.subTest(malformed=malformed):
                self.assertEqual(self.invoke(good, malformed, 2), {"status": "invalid"})

    def test_exact_bounds(self):
        maximum = document("猫" * 1365 + "a", base64.b64encode(b"X" * 131072).decode())
        self.assertEqual(self.invoke(maximum, maximum, 0)["type_utf8_bytes"], [4096, 4096])
        for too_big in [document("猫" * 1366, ""), document("", base64.b64encode(b"X" * 131073).decode())]:
            self.assertEqual(self.invoke(maximum, too_big, 2), {"status": "invalid"})
        good = document("a", "AA")
        self.assertEqual(self.invoke(good.ljust(262144), good, 0)["status"], "same")
        self.assertEqual(self.invoke(good.ljust(262145), good, 2), {"status": "invalid"})

    def test_unsafe_path_rejected_before_any_access(self):
        with patch.object(app.os, "stat", side_effect=AssertionError("unexpected stat")):
            with patch.object(app, "emit", return_value=2):
                for unsafe in ("https://invalid.test/file", r"/\host\share", r"\x\..\Device\secret",
                               "C:drive-relative", "f:stream", "dir/NUL .json", "x/file.", "-"):
                    self.assertEqual(app.main(["placeholder", unsafe]), 2)
                    self.assertEqual(app.main([unsafe, "placeholder"]), 2)

    def test_descriptor_revalidated_and_closed(self):
        self.left.write_bytes(b"{}")
        with patch.object(app.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR, st_size=0)) as fstat:
            with patch.object(app.os, "fdopen", side_effect=AssertionError("unexpected read")):
                with self.assertRaises(ValueError):
                    app.read_fixture(self.left)
        with self.assertRaises(OSError):
            os.fstat(fstat.call_args.args[0])

    def test_closed_stdout_is_quiet_for_help_and_reports(self):
        good = document("a", "")
        self.left.write_bytes(good)
        self.right.write_bytes(good)
        for args in ([str(self.left), str(self.right)], ["--help"], []):
            reader, writer = os.pipe()
            os.close(reader)
            with os.fdopen(writer, "wb") as pipe:
                result = subprocess.run([sys.executable, str(SCRIPT), *args], stdout=pipe,
                                        stderr=subprocess.PIPE, timeout=10)
            self.assertEqual((result.returncode, result.stderr), (2, b""))


if __name__ == "__main__":
    unittest.main()
