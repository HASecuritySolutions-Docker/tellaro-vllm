#!/usr/bin/env python3
"""tellaro-gpu-bootstrap against a fake backend: redeem, renew and the seal_v2 raw-key format.

Run: python3 tests/bootstrap_test.py   (needs only `cryptography`; no network, no Docker).
tests/image-smoke.sh also runs it inside the image, against the image's own Python.
"""

from __future__ import annotations

import base64
import datetime
import http.server
import importlib.machinery
import importlib.util
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.environ.get("BOOTSTRAP", os.path.join(HERE, "..", "rootfs", "usr", "local", "bin", "tellaro-gpu-bootstrap"))
_loader = importlib.machinery.SourceFileLoader("tgb", SCRIPT)
_spec = importlib.util.spec_from_loader("tgb", _loader)
assert _spec is not None
tgb = importlib.util.module_from_spec(_spec)
_loader.exec_module(tgb)

RUN_ID = "6f1c2a3b-4d5e-4f60-a1b2-c3d4e5f60718"
RUN_HEX = uuid.UUID(RUN_ID).hex
SERVER_NAME = f"{RUN_HEX}.gpu.tellaro.internal"
UTC = datetime.timezone.utc


# ---------------------------------------------------------------------------
# A test CA and the backend side of the contract (mirrors tellaro-backend B3).
# ---------------------------------------------------------------------------
def make_ca(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def sign_leaf(ca: tuple, public_key, names: list[x509.GeneralName], days: float = 7) -> x509.Certificate:
    ca_key, ca_cert = ca
    now = datetime.datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def seal_to_key(plaintext: str, public_key, binding: str) -> str:
    """Test copy of backend seal_v2.seal_to_key; test_backend_vector pins the opener to the real one."""
    eph = ec.generate_private_key(type(public_key.curve)())
    point = lambda k: k.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)  # noqa: E731
    e_point = point(eph.public_key())
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=e_point + point(public_key), info=b"tellaro-seal-v2").derive(
        eph.exchange(ec.ECDH(), public_key)
    )
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), b"tellaro-seal-v2/raw" + binding.replace("-", "").lower().encode())
    return "s2$" + base64.b64encode(e_point + iv + ct).decode()


GPU_CA = make_ca("GPU pool CA (test)")
TLS_CA = make_ca("public TLS CA (test)")


class FakeBackend(http.server.BaseHTTPRequestHandler):
    """POST /api/v1/gpu_pool/bootstrap. ``script`` is a list of callables, one per request."""

    script: list = []
    requests: list = []

    def log_message(self, *a):  # noqa: D102
        pass

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeBackend.requests.append((self.path, body))
        step = FakeBackend.script.pop(0) if len(FakeBackend.script) > 1 else FakeBackend.script[0]
        code, payload, headers = step(body)
        data = json.dumps(payload).encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def good_answer(body: dict, *, sign_key=None, **override) -> tuple[int, dict, None]:
    csr = x509.load_pem_x509_csr(body["csr"].encode())
    leaf = sign_leaf(GPU_CA, sign_key or csr.public_key(), [x509.DNSName(SERVER_NAME)])
    answer = {
        "run_id": RUN_HEX,
        "server_name": SERVER_NAME,
        "certificate_chain": pem(leaf) + pem(GPU_CA[1]),
        "client_ca_bundle": pem(GPU_CA[1]),
        "sealed": {"vllm_api_key": seal_to_key("tgp_secret-api-key", csr.public_key(), RUN_HEX)},
        "model": {
            "model_id": "Qwen/Qwen3-32B",
            "launch_profile": {"tp": 2, "max_model_len": 32768, "gpu_memory_utilization": 0.9, "weights_gb": 64},
        },
        "terminator_port": 8443,
    }
    answer.update(override)
    return 200, answer, None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="tgb-test-")
        ca_file = os.path.join(cls.tmp.name, "public-ca.pem")
        with open(ca_file, "w") as f:
            f.write(pem(TLS_CA[1]))
        os.environ["SSL_CERT_FILE"] = ca_file
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = sign_leaf(TLS_CA, key.public_key(), [x509.DNSName("localhost")])
        cert_file = os.path.join(cls.tmp.name, "backend.pem")
        with open(cert_file, "wb") as f:
            f.write(pem(leaf).encode())
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file)
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeBackend)
        cls.httpd.socket = ctx.wrap_socket(cls.httpd.socket, server_side=True)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.url = f"https://localhost:{cls.httpd.server_address[1]}/api/v1/gpu_pool/bootstrap"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=self.tmp.name)
        self.tls, self.secrets, self.launch = (os.path.join(self.dir, d) for d in ("tls", "secrets", "launch"))
        for d in (self.tls, self.secrets, self.launch):
            os.mkdir(d)
        FakeBackend.requests = []
        os.environ.update(TELLARO_BOOTSTRAP_URL=self.url, TELLARO_RUN_ID=RUN_ID, TELLARO_BOOTSTRAP_TOKEN="tok-123")
        self.assertEqual(tgb.main(["keygen", "--out", self.tls]), 0)

    def redeem(self, *script, deadline: float = 20) -> int:
        FakeBackend.script = list(script)
        return tgb.main(
            [
                "redeem",
                "--tls-dir",
                self.tls,
                "--secrets-dir",
                self.secrets,
                "--launch-dir",
                self.launch,
                "--deadline",
                str(deadline),
            ]
        )

    def assert_nothing_written(self):
        self.assertEqual(os.listdir(self.secrets), [])
        self.assertEqual(os.listdir(self.launch), [])
        self.assertFalse(os.path.exists(os.path.join(self.tls, "server.crt")))


# ---------------------------------------------------------------------------
class SealTest(unittest.TestCase):
    def test_backend_vector(self):
        """Pinned to tellaro-backend seal_v2.seal_to_key output (tests/fixtures/seal_v2_raw_p256.json)."""
        with open(os.path.join(HERE, "fixtures", "seal_v2_raw_p256.json")) as f:
            v = json.load(f)
        key = ec.derive_private_key(int(v["private_scalar_hex"], 16), ec.SECP256R1())
        self.assertEqual(tgb.open_sealed(v["sealed"], key, v["binding"]), v["plaintext"])
        # The binding is the run: a value for another run does not open.
        with self.assertRaises(InvalidTag):
            tgb.open_sealed(v["sealed"], key, "0" * 32)
        with self.assertRaises(InvalidTag):
            tgb.open_sealed(v["sealed"], ec.generate_private_key(ec.SECP256R1()), v["binding"])


class ProfileTest(unittest.TestCase):
    def test_full_profile(self):
        args = tgb.profile_to_args(
            {
                "model_id": "org/m",
                "launch_profile": {
                    "tp": 4,
                    "max_model_len": 8192,
                    "gpu_memory_utilization": 0.85,
                    "quantization": "fp8",
                    "weights_gb": 10,
                    "future": "x",
                },
            }
        )
        self.assertEqual(
            args,
            [
                "org/m",
                "--tensor-parallel-size",
                "4",
                "--max-model-len",
                "8192",
                "--gpu-memory-utilization",
                "0.85",
                "--quantization",
                "fp8",
            ],
        )

    def test_checkpoint_served_under_model_id(self):
        args = tgb.profile_to_args({"model_id": "org/m", "launch_profile": {"checkpoint": "org/m-AWQ"}})
        self.assertEqual(args, ["org/m-AWQ", "--served-model-name", "org/m"])

    def test_rejects_flag_injection_and_bad_types(self):
        for model in (
            {"model_id": "--host=0.0.0.0"},
            {"model_id": "org/m --api-key x"},
            {"model_id": ""},
            {"model_id": "org/m", "launch_profile": {"checkpoint": "-x"}},
            {"model_id": "org/m", "launch_profile": {"quantization": "--enable-log-requests"}},
            {"model_id": "org/m", "launch_profile": {"tp": True}},
            {"model_id": "org/m", "launch_profile": {"tp": "2"}},
            {"model_id": "org/m", "launch_profile": {"gpu_memory_utilization": 1.5}},
            {"model_id": "org/m", "launch_profile": []},
            None,
        ):
            with self.subTest(model=model), self.assertRaises(ValueError):
                tgb.profile_to_args(model)


class RedeemTest(Base):
    def test_retries_425_then_writes_files(self):
        not_ready = lambda b: (425, {"code": "not_ready"}, {"Retry-After": "1"})  # noqa: E731
        self.assertEqual(self.redeem(not_ready, good_answer), 0)
        self.assertEqual(len(FakeBackend.requests), 2)
        path, body = FakeBackend.requests[0]
        self.assertEqual(path, "/api/v1/gpu_pool/bootstrap")
        self.assertEqual(set(body), {"run_id", "token", "csr"})
        self.assertEqual((body["run_id"], body["token"]), (RUN_ID, "tok-123"))
        with open(os.path.join(self.secrets, "vllm-api-key")) as f:
            self.assertEqual(f.read(), "tgp_secret-api-key")
        self.assertFalse(os.path.exists(os.path.join(self.secrets, "hf-token")))
        with open(os.path.join(self.launch, "vllm-args.json")) as f:
            self.assertEqual(
                json.load(f),
                [
                    "Qwen/Qwen3-32B",
                    "--tensor-parallel-size",
                    "2",
                    "--max-model-len",
                    "32768",
                    "--gpu-memory-utilization",
                    "0.9",
                ],
            )
        for p in (
            "tls/server.crt",
            "tls/client-ca.pem",
            "tls/server.key",
            "secrets/vllm-api-key",
            "launch/vllm-args.json",
        ):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dir, p)).st_mode), 0o600, p)
        crt = x509.load_pem_x509_certificates(read(os.path.join(self.tls, "server.crt")))
        key = tgb.load_key(os.path.join(self.tls, "server.key"))
        self.assertEqual(tgb._spki(crt[0].public_key()), tgb._spki(key.public_key()))

    def test_hf_token_when_sealed(self):
        def answer(body):
            code, a, _ = good_answer(body)
            pub = x509.load_pem_x509_csr(body["csr"].encode()).public_key()
            a["sealed"]["hf_token"] = seal_to_key("hf_abc", pub, RUN_HEX)
            return code, a, None

        self.assertEqual(self.redeem(answer), 0)
        with open(os.path.join(self.secrets, "hf-token")) as f:
            self.assertEqual(f.read(), "hf_abc")

    def test_refusal_is_final(self):
        self.assertEqual(self.redeem(lambda b: (409, {"code": "refused"}, None)), tgb.EX_CONFIG)
        self.assertEqual(len(FakeBackend.requests), 1)
        self.assert_nothing_written()

    def test_gives_up_at_the_deadline(self):
        self.assertEqual(
            self.redeem(lambda b: (425, {"code": "not_ready"}, {"Retry-After": "5"}), deadline=2), tgb.EX_CONFIG
        )
        self.assert_nothing_written()

    def test_plain_http_refused(self):
        os.environ["TELLARO_BOOTSTRAP_URL"] = self.url.replace("https:", "http:")
        started = time.monotonic()
        self.assertEqual(self.redeem(good_answer, deadline=30), tgb.EX_CONFIG)
        # Refused up front, never tried (and never retried) over plain HTTP.
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(FakeBackend.requests, [])

    def test_untrusted_backend_cert_not_used(self):
        os.environ["SSL_CERT_FILE"] = os.path.join(self.dir, "nothing.pem")
        try:
            self.assertEqual(self.redeem(good_answer, deadline=2), tgb.EX_CONFIG)
        finally:
            os.environ["SSL_CERT_FILE"] = os.path.join(self.tmp.name, "public-ca.pem")
        self.assertEqual(FakeBackend.requests, [])
        self.assert_nothing_written()

    def test_rejects_answers_not_for_this_pod(self):
        other = ec.generate_private_key(ec.SECP256R1()).public_key()
        cases = {
            "leaf for another key": lambda b: good_answer(b, sign_key=other),
            "another run": lambda b: good_answer(b, run_id="0" * 32),
            "another server name": lambda b: good_answer(b, server_name="x.gpu.tellaro.internal"),
            "another port": lambda b: good_answer(b, terminator_port=9443),
            "no sealed key": lambda b: good_answer(b, sealed={}),
            "key sealed to another run": lambda b: good_answer(
                b,
                sealed={
                    "vllm_api_key": seal_to_key("k", x509.load_pem_x509_csr(b["csr"].encode()).public_key(), "1" * 32)
                },
            ),
            "injected profile": lambda b: good_answer(b, model={"model_id": "--host=0.0.0.0"}),
            "no client CA": lambda b: good_answer(b, client_ca_bundle=""),
        }
        for name, step in cases.items():
            with self.subTest(name):
                self.setUp()
                self.assertEqual(self.redeem(step), 1)
                self.assert_nothing_written()


class RenewTest(Base):
    def start_helper(self, caddy_rc: int = 0):
        marker = os.path.join(self.dir, "caddy-calls")
        stub = os.path.join(self.dir, "caddy")
        with open(stub, "w") as f:
            f.write(f'#!/bin/sh\necho "$@" >> {marker}\nexit {caddy_rc}\n')
        os.chmod(stub, 0o700)
        port = free_port()
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "serve", "--listen", f"127.0.0.1:{port}", "--tls-dir", self.tls, "--caddy", stub],
            env={**os.environ, "TELLARO_RUN_ID": RUN_ID},
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: self.proc.poll() is None and (self.proc.terminate(), self.proc.wait()))
        self.base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        return marker

    def post(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else b""
        req = urllib.request.Request(
            self.base + path, data=data, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def push_for(self, public_key, ca=GPU_CA) -> dict:
        leaf = sign_leaf(ca, public_key, [x509.DNSName(SERVER_NAME)])
        return {"certificate_chain": pem(leaf) + pem(ca[1]), "client_ca_bundle": pem(ca[1]) + pem(GPU_CA[1])}

    def test_renew_swaps_key_and_chain_and_reloads(self):
        marker = self.start_helper()
        old_key = read(os.path.join(self.tls, "server.key"))
        code, body = self.post("/_tellaro/renew")
        self.assertEqual(code, 200)
        csr = x509.load_pem_x509_csr(body["csr"].encode())
        new_ca = make_ca("GPU pool CA (next)")
        self.assertEqual(self.post("/_tellaro/renew/certificate", self.push_for(csr.public_key(), new_ca))[0], 200)
        for _ in range(100):
            if os.path.exists(marker):
                break
            time.sleep(0.05)
        with open(marker) as f:
            self.assertIn(
                "reload --config /etc/tellaro/Caddyfile --adapter caddyfile "
                "--address unix//run/tellaro/caddy-admin.sock --force",
                f.read(),
            )
        key = tgb.load_key(os.path.join(self.tls, "server.key"))
        self.assertNotEqual(read(os.path.join(self.tls, "server.key")), old_key)
        self.assertEqual(tgb._spki(key.public_key()), tgb._spki(csr.public_key()))
        bundle = x509.load_pem_x509_certificates(read(os.path.join(self.tls, "client-ca.pem")))
        self.assertEqual(len(bundle), 2)
        for p in ("server.key", "server.crt", "client-ca.pem"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tls, p)).st_mode), 0o600, p)
        # The pending key is spent: a replay of the push is refused.
        self.assertEqual(self.post("/_tellaro/renew/certificate", self.push_for(csr.public_key()))[0], 409)

    def test_push_for_another_key_refused(self):
        marker = self.start_helper()
        self.assertEqual(
            self.post(
                "/_tellaro/renew/certificate", self.push_for(ec.generate_private_key(ec.SECP256R1()).public_key())
            )[0],
            409,
        )
        before = {p: read(os.path.join(self.tls, p)) for p in ("server.key",)}
        self.assertEqual(self.post("/_tellaro/renew")[0], 200)
        other = ec.generate_private_key(ec.SECP256R1()).public_key()
        self.assertEqual(self.post("/_tellaro/renew/certificate", self.push_for(other))[0], 409)
        self.assertEqual(read(os.path.join(self.tls, "server.key")), before["server.key"])
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(self.post("/_tellaro/renew/certificate", {"x": 1})[0], 409)

    def test_failed_reload_exits_helper(self):
        self.start_helper(caddy_rc=1)
        _code, body = self.post("/_tellaro/renew")
        csr = x509.load_pem_x509_csr(body["csr"].encode())
        self.assertEqual(self.post("/_tellaro/renew/certificate", self.push_for(csr.public_key()))[0], 200)
        self.assertEqual(self.proc.wait(timeout=10), 1)


if __name__ == "__main__":
    unittest.main(verbosity=1)
