import http.client
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from icheck import agent_worker_completion_loss_test as completion_loss


def test_completion_loss_probe_has_no_application_database_fallback(monkeypatch, capsys):
    monkeypatch.delenv(completion_loss.DATABASE_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://application/production")
    monkeypatch.setattr(
        sys, "argv",
        ["agent-completion-loss-probe", "--acknowledge-dedicated-database"],
    )
    with pytest.raises(SystemExit) as failure:
        completion_loss.main()
    assert failure.value.code == 2
    assert completion_loss.DATABASE_URL_ENV in capsys.readouterr().err


def test_completion_loss_probe_requires_explicit_acknowledgement(monkeypatch, capsys):
    monkeypatch.setenv(completion_loss.DATABASE_URL_ENV, "postgresql://private/test")
    monkeypatch.setattr(sys, "argv", ["agent-completion-loss-probe"])
    with pytest.raises(SystemExit) as failure:
        completion_loss.main()
    assert failure.value.code == 2
    assert "--acknowledge-dedicated-database" in capsys.readouterr().err


def test_fault_proxy_drops_only_first_committed_completion_response():
    requests = []

    class UpstreamHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, body))
            response = json.dumps({"status": "succeeded"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream.daemon_threads = True
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    proxy = completion_loss._CompletionLossProxy(upstream.server_address[1])
    upstream_thread.start()
    proxy.start()
    try:
        path = "/api/v1/agent/executions/test-execution/complete"
        document = b'{"lease_token":"test-token","status":"succeeded"}'
        first = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
        first.request("POST", path, document, {"Content-Type": "application/json"})
        with pytest.raises((http.client.RemoteDisconnected, ConnectionResetError)):
            first.getresponse()
        first.close()

        second = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
        second.request("POST", path, document, {"Content-Type": "application/json"})
        response = second.getresponse()
        assert response.status == 200
        assert json.loads(response.read()) == {"status": "succeeded"}
        second.close()

        assert requests == [(path, document), (path, document)]
        assert proxy.dropped_responses == 1
        assert len(proxy.completion_request_hashes) == 2
        assert len(set(proxy.completion_request_hashes)) == 1
        assert proxy.completion_upstream_statuses == [200, 200]
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=5)


def test_local_mtls_proxy_requires_cert_and_replaces_forged_identity(tmp_path):
    observed = []

    class UpstreamHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            observed.append(dict(self.headers.items()))
            response = b'{}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream.daemon_threads = True
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    material = completion_loss._local_mtls_material(tmp_path)
    proxy = completion_loss._CompletionLossProxy(
        upstream.server_address[1],
        tls_context=completion_loss._local_mtls_context(material),
    )
    upstream_thread.start()
    proxy.start()
    try:
        assert completion_loss._missing_client_certificate_rejected(
            proxy.port, material.ca_file
        )
        context = ssl.create_default_context(cafile=str(material.ca_file))
        context.load_cert_chain(
            certfile=str(material.worker_cert_file),
            keyfile=str(material.worker_key_file),
        )
        client = http.client.HTTPSConnection(
            "127.0.0.1", proxy.port, context=context, timeout=5
        )
        client.request(
            "GET", "/inspect",
            headers={
                "X-iCheck-Client-Cert-Verified": "FAILURE",
                "X-iCheck-Client-Cert-SHA256": "0" * 64,
                "X-Forwarded-For": "203.0.113.99",
            },
        )
        response = client.getresponse()
        assert response.status == 200
        assert response.read() == b"{}"
        client.close()
        assert len(observed) == 1
        assert observed[0]["X-iCheck-Client-Cert-Verified"] == "SUCCESS"
        assert observed[0]["X-iCheck-Client-Cert-SHA256"] == (
            material.worker_fingerprint_sha256
        )
        assert "X-Forwarded-For" not in observed[0]
        assert proxy.peer_fingerprints == [material.worker_fingerprint_sha256]
        assert set(proxy.tls_versions) <= {"TLSv1.2", "TLSv1.3"}
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=5)
