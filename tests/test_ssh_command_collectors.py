from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from icheck import collector_worker
from icheck.collectors.ssh_command_sandbox import (
    _target_host,
    collect_ssh_command_sandbox,
)
from icheck.ssh_executor import AsyncSSHCommandExecutor


class PassthroughSandbox:
    def transform(self, implementation, records, configuration, output_kinds):
        assert implementation["adapter"] == "ssh_command_sandbox"
        assert configuration["command_profile"] == "linux.ip_address_json"
        assert output_kinds == ["observation"]
        return records


class RecordingCommandExecutor:
    def __init__(self, output: str | bytes):
        self.output = output
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.output


def assignment(executor=None):
    executor = executor or RecordingCommandExecutor(
        '[{"ifname":"eth0","address":"52:54:00:12:34:56"}]'
    )
    return {
        "artifact_name": "linux-interface-inventory",
        "implementation": {
            "runtime": "python_sandbox_v1",
            "adapter": "ssh_command_sandbox",
            "entrypoint": "transform",
            "source": "def transform(records, configuration):\n    return records\n",
        },
        "output_kinds": ["observation"],
        "credential_profile_ref": "linux-readonly",
        "target": {"host": "192.0.2.10", "port": 22},
        "defaults": {
            "command_profile": "linux.ip_address_json",
            "record_type": "linux.interface",
            "source": "linux.ssh",
            "subject_field": "ifname",
            "idempotency_field": "ifname",
            "max_records": 100,
            "max_response_bytes": 2_000_000,
            "timeout_seconds": 15,
        },
        "configuration": {},
        "_runtime": {
            "credential": {"username": "readonly", "password": "secret"},
            "ssh_allowed_targets": ["192.0.2.0/24"],
            "ssh_command_executor": executor,
            "sandbox_executor": PassthroughSandbox(),
            "lease_seconds": 60,
        },
    }, executor


def test_ssh_collector_executes_only_the_registered_command_profile():
    payload, executor = assignment()

    envelopes = collect_ssh_command_sandbox(payload)

    assert envelopes[0]["type"] == "linux.interface"
    assert envelopes[0]["subject"] == "eth0"
    assert envelopes[0]["payload"]["address"] == "52:54:00:12:34:56"
    assert executor.calls == [
        {
            "host": "192.0.2.10",
            "port": 22,
            "credential_profile_ref": "linux-readonly",
            "credential": {"username": "readonly", "password": "secret"},
            "command_profile": "linux.ip_address_json",
            "command": "ip -json address show",
            "timeout_seconds": 15,
        }
    ]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda item: item["defaults"].update(
                {"command_profile": "linux.arbitrary_shell"}
            ),
            "Unsupported fixed SSH command profile",
        ),
        (
            lambda item: item.update({"credential_profile_ref": None}),
            "requires a credential profile reference",
        ),
        (
            lambda item: item["_runtime"].update(
                {"ssh_allowed_targets": ["198.51.100.0/24"]}
            ),
            "is not allowlisted",
        ),
        (
            lambda item: item["_runtime"].update({"credential": None}),
            "credential was not resolved",
        ),
    ],
)
def test_ssh_collector_fails_closed_before_execution(mutate, message):
    payload, executor = assignment()
    mutate(payload)

    with pytest.raises((ValueError, RuntimeError), match=message):
        collect_ssh_command_sandbox(payload)

    assert executor.calls == []


@pytest.mark.parametrize(
    ("output", "message"),
    [
        ("not-json", "valid JSON"),
        ('{"item":1,"item":2}', "duplicate key"),
        ("NaN", "non-finite value"),
        ('"scalar"', "object or array"),
    ],
)
def test_ssh_collector_rejects_ambiguous_or_unstructured_output(output, message):
    payload, _ = assignment(RecordingCommandExecutor(output))

    with pytest.raises(ValueError, match=message):
        collect_ssh_command_sandbox(payload)


def test_ssh_collector_enforces_response_and_lease_budgets():
    payload, _ = assignment(RecordingCommandExecutor("{}"))
    payload["defaults"]["max_response_bytes"] = 1
    with pytest.raises(ValueError, match="max_response_bytes"):
        collect_ssh_command_sandbox(payload)

    payload, executor = assignment()
    payload["_runtime"]["lease_seconds"] = 20
    with pytest.raises(ValueError, match="run lease"):
        collect_ssh_command_sandbox(payload)
    assert executor.calls == []


class FakeConnection:
    def __init__(self, result):
        self.result = result
        self.commands = []
        self.closed = False

    async def run(self, command, *, check):
        self.commands.append((command, check))
        return self.result

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class FakeAsyncSSH:
    def __init__(self, result):
        self.connection = FakeConnection(result)
        self.connect_calls = []

    async def connect(self, host, **kwargs):
        self.connect_calls.append((host, kwargs))
        return self.connection

    def import_private_key(self, *_args, **_kwargs):
        raise AssertionError("password authentication must not import a key")


def test_asyncssh_executor_pins_known_hosts_and_disables_implicit_credentials(
    tmp_path,
    monkeypatch,
):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "edge.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
        encoding="utf-8",
    )
    fake = FakeAsyncSSH(SimpleNamespace(exit_status=0, stdout='{"ok":true}'))
    monkeypatch.setattr(
        "icheck.ssh_executor.importlib.import_module",
        lambda name: fake if name == "asyncssh" else None,
    )
    executor = AsyncSSHCommandExecutor(str(known_hosts))

    output = executor(
        host="edge.example.test",
        port=22,
        credential_profile_ref="linux-readonly",
        credential={"username": "readonly", "password": "secret"},
        command_profile="linux.ip_address_json",
        command="ip -json address show",
        timeout_seconds=15,
    )

    assert output == '{"ok":true}'
    host, options = fake.connect_calls[0]
    assert host == "edge.example.test"
    assert options["known_hosts"] == str(known_hosts)
    assert options["agent_path"] is None
    assert options["client_keys"] == []
    assert options["kbdint_auth"] is False
    assert fake.connection.commands == [("ip -json address show", False)]
    assert fake.connection.closed is True


def test_asyncssh_executor_requires_an_existing_absolute_known_hosts(tmp_path):
    with pytest.raises(ValueError, match="absolute"):
        AsyncSSHCommandExecutor("relative/known_hosts")
    with pytest.raises(ValueError, match="does not exist"):
        AsyncSSHCommandExecutor(str(tmp_path / "missing"))


def test_ssh_target_accepts_literal_ipv6_without_a_url_wrapper():
    assert _target_host("2001:db8::10") == "2001:db8::10"


def test_worker_ssh_capability_fails_fast_without_runtime_boundaries():
    base = [
        "--capability",
        "ssh_command_sandbox",
        "--sandbox-enabled",
        "--tenant-id",
        "00000000-0000-0000-0000-000000000001",
        "--region-id",
        "00000000-0000-0000-0000-000000000002",
        "--once",
    ]
    with pytest.raises(SystemExit, match="SSH_ALLOWED_TARGETS"):
        collector_worker.main(base)
    with pytest.raises(SystemExit, match="SSH_KNOWN_HOSTS_FILE"):
        collector_worker.main(
            [*base, "--ssh-allowed-target", "192.0.2.0/24"]
        )


def test_hand_authored_ssh_artifact_cannot_omit_profile_pinning(client):
    created = client.post(
        "/api/v1/artifacts",
        json={
            "name": "unsafe-unpinned-ssh-command",
            "kind": "collector",
            "description": "Attempt to omit immutable command pinning.",
            "owner": "platform-team",
            "initial_version": {
                "definition": {"purpose": "Negative contract test"},
                "implementation": {
                    "runtime": "python_sandbox_v1",
                    "adapter": "ssh_command_sandbox",
                    "entrypoint": "transform",
                    "source": (
                        "def transform(records, configuration):\n"
                        "    return records\n"
                    ),
                },
                "tests": [],
                "created_by": "capability.author",
                "collector_definition": {
                    "adapter_type": "ssh_command_sandbox",
                    "mode": "poll",
                    "output_kinds": ["observation"],
                    "target_schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["host"],
                        "properties": {
                            "host": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 255,
                            }
                        },
                    },
                    "config_schema": {"type": "object"},
                    "defaults": {
                        "command_profile": "linux.ip_address_json"
                    },
                },
            },
        },
    )
    assert created.status_code == 201, created.text
    version_id = created.json()["versions"][0]["id"]

    validated = client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "capability.reviewer"},
    )

    assert validated.status_code == 422, validated.text
    assert "must require and pin" in validated.text
