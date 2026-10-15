from __future__ import annotations

import base64
import json
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization

from icheck.services.artifact_portability import trusted_digest_signature_message
from icheck.services.mib_ingestion import extract_mib_collector_input
from icheck.services.snmp_exporter_attestations import canonical_hash
from icheck.snmp_attestation_schemas import (
    SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
    SignedSNMPExporterAttestation,
)
from icheck.snmp_attestor import (
    AttestorProposal,
    build_signed_attestation,
    collect_live_evidence,
    compile_and_verify_module,
    _private_key,
    _write_document,
)
from icheck.snmp_generator import GeneratorRuntime
from test_mib_ingestion import ACME_MIB
from test_snmp_exporter_attestations import _attestor_key, _proposal


RUNTIME_MODULE = {
    "walk": [{"oid": "1.3.6.1.4.1.424242.1.1"}],
    "metrics": [
        {
            "name": "acme_temperature_celsius",
            "oid": "1.3.6.1.4.1.424242.1.1",
            "type": "gauge",
            "help": "ACME sensor temperature",
        }
    ],
}
METRICS = b"""# HELP acme_temperature_celsius ACME sensor temperature
# TYPE acme_temperature_celsius gauge
acme_temperature_celsius{sensor=\"1\"} 21
"""


class FakeRunner:
    def __init__(self, runtime_module=None):
        self.runtime_module = runtime_module or RUNTIME_MODULE
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), kwargs))
        assert kwargs["check"] is False
        assert kwargs["start_new_session"] is True
        assert kwargs["env"] == {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        }
        if command[-1] == "--version":
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"{Path(command[0]).name}, version 0.30.1\n",
                stderr="",
            )
        output = Path(command[command.index("-o") + 1])
        module_name = next(
            iter(yaml.safe_load(Path(command[command.index("-g") + 1]).read_text())["modules"])
        )
        output.write_text(
            yaml.safe_dump({"modules": {module_name: self.runtime_module}}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return METRICS


class FakeOpener:
    def __init__(self):
        self.urls: list[str] = []

    def open(self, request, **_kwargs):
        self.urls.append(request.full_url)
        return FakeResponse()


def _files(tmp_path: Path):
    mib_file = tmp_path / "ACME-SENSORS-MIB.txt"
    mib_file.write_text(ACME_MIB, encoding="utf-8")
    generator = tmp_path / "generator"
    exporter = tmp_path / "snmp_exporter"
    generator.write_bytes(b"test generator binary")
    exporter.write_bytes(b"test exporter binary")
    generator.chmod(0o755)
    exporter.chmod(0o755)
    installed = tmp_path / "snmp.yml"
    installed.write_text(
        yaml.safe_dump({"modules": {"acme_sensors": RUNTIME_MODULE}}),
        encoding="utf-8",
    )
    return mib_file, generator, exporter, installed


def _proposal_input(**overrides) -> AttestorProposal:
    mib = extract_mib_collector_input(ACME_MIB)
    generator_module = {
        "walk": [
            "1.3.6.1.4.1.424242.1.1",
            "1.3.6.1.4.1.424242.1.2",
        ],
        "max_repetitions": 20,
        "retries": 2,
        "timeout": "10s",
    }
    values = {
        "proposal_artifact_id": "11111111-1111-1111-1111-111111111111",
        "proposal_version_id": "22222222-2222-2222-2222-222222222222",
        "proposal_version": 1,
        "proposal_content_hash": "3" * 64,
        "mib_document_sha256": mib.provenance["document_sha256"],
        "generator_module_sha256": canonical_hash(generator_module),
        "exporter_module_name": "acme_sensors",
        "generator_module": generator_module,
    }
    values.update(overrides)
    return AttestorProposal.model_validate(values)


def _key_file(tmp_path: Path, private_key) -> Path:
    path = tmp_path / "attestor-key.pem"
    path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path


def test_generator_without_version_flag_uses_a_binary_bound_manifest(tmp_path, monkeypatch):
    import hashlib
    mib_file, generator, exporter, installed = _files(tmp_path)
    manifest = GeneratorRuntime(generator,exporter,"0.30.1",hashlib.sha256(generator.read_bytes()).hexdigest())
    monkeypatch.setattr(GeneratorRuntime,"from_manifest",classmethod(lambda cls,path:manifest))
    runner = FakeRunner()
    version, digest, module_hash = compile_and_verify_module(_proposal_input(),mib_file=mib_file,
        shared_mib_dirs=[],generator_binary=generator,installed_config=installed,
        generator_manifest=tmp_path/"protected-manifest.json",runner=runner)
    assert version == "0.30.1" and digest == manifest.binary_sha256
    assert not any(command[-1] == "--version" for command,kwargs in runner.calls)
    assert module_hash == canonical_hash(RUNTIME_MODULE)


def test_attestor_compiles_scrapes_and_signs_minimized_evidence(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    key_file = _key_file(tmp_path, private_key)
    mib_file, generator, exporter, installed = _files(tmp_path)
    runner = FakeRunner()
    opener = FakeOpener()

    document = build_signed_attestation(
        _proposal_input(),
        mib_file=mib_file,
        shared_mib_dirs=[],
        generator_binary=generator,
        exporter_binary=exporter,
        installed_config=installed,
        exporter_url="http://127.0.0.1:9116",
        target="192.0.2.55",
        auth_module="lab_v3",
        exporter_allowed_hosts=["127.0.0.1"],
        target_allowed_hosts=["192.0.2.0/24"],
        installation_id="lab-snmp-exporter-01",
        private_key_file=str(key_file),
        runner=runner,
        opener=opener,
    )

    signed = SignedSNMPExporterAttestation.model_validate(document)
    assert signed.statement.successful_scrapes == 3
    assert signed.statement.sample_count == 3
    assert signed.statement.series_count == 1
    assert signed.statement.label_name_count == 1
    assert len(opener.urls) == 3
    serialized = json.dumps(document)
    assert "192.0.2.55" not in serialized
    assert "lab_v3" not in serialized
    assert METRICS.decode() not in serialized
    generate = runner.calls[1]
    assert generate[0][1:3] == ["--fail-on-parse-errors", "generate"]
    assert "shell" not in generate[1]
    private_key.public_key().verify(
        base64.b64decode(signed.signature.signature_base64),
        trusted_digest_signature_message(
            SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
            signed.digest_sha256,
        ),
    )


def test_attestor_rejects_installed_drift_and_non_allowlisted_targets(tmp_path):
    mib_file, generator, _exporter, installed = _files(tmp_path)
    installed.write_text(
        yaml.safe_dump({"modules": {"acme_sensors": {"walk": []}}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="does not match generated output"):
        compile_and_verify_module(
            _proposal_input(),
            mib_file=mib_file,
            shared_mib_dirs=[],
            generator_binary=generator,
            installed_config=installed,
            runner=FakeRunner(),
        )
    with pytest.raises(ValueError, match="target is not allowlisted"):
        collect_live_evidence(
            exporter_url="http://127.0.0.1:9116",
            target="198.51.100.9",
            auth_module="lab_v3",
            exporter_module_name="acme_sensors",
            exporter_allowed_hosts=["127.0.0.1"],
            target_allowed_hosts=["192.0.2.0/24"],
            opener=FakeOpener(),
        )


def test_attestor_output_is_atomic_private_and_key_permissions_fail_closed(tmp_path):
    destination = tmp_path / "signed.json"
    destination.write_text("long stale content that must disappear", encoding="utf-8")
    _write_document({"ok": True}, str(destination))
    assert json.loads(destination.read_text(encoding="utf-8")) == {"ok": True}
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".signed.json.*"))

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_file = _key_file(tmp_path, Ed25519PrivateKey.generate())
    key_file.chmod(0o640)
    with pytest.raises(ValueError, match="group/world accessible"):
        _private_key(str(key_file))


def test_platform_attestor_input_round_trips_to_accepted_attestation(
    client,
    monkeypatch,
    tmp_path,
):
    _artifact, proposal = _proposal(client, monkeypatch)
    private_key, _registered, _fingerprint = _attestor_key(client)
    response = client.get(
        f"/api/v1/snmp-exporter-attestations/proposal-inputs/{proposal['id']}"
    )
    assert response.status_code == 200, response.text
    attestor_input = AttestorProposal.model_validate(response.json())
    mib_file, generator, exporter, installed = _files(tmp_path)
    document = build_signed_attestation(
        attestor_input,
        mib_file=mib_file,
        shared_mib_dirs=[],
        generator_binary=generator,
        exporter_binary=exporter,
        installed_config=installed,
        exporter_url="http://127.0.0.1:9116",
        target="192.0.2.55",
        auth_module="lab_v3",
        exporter_allowed_hosts=["127.0.0.1"],
        target_allowed_hosts=["192.0.2.0/24"],
        installation_id="lab-snmp-exporter-01",
        private_key_file=str(_key_file(tmp_path, private_key)),
        runner=FakeRunner(),
        opener=FakeOpener(),
    )
    accepted = client.post(
        "/api/v1/snmp-exporter-attestations",
        json={
            "signed_attestation": document,
            "actor": "capability.attestation_reviewer",
        },
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["proposal_version_id"] == proposal["id"]
