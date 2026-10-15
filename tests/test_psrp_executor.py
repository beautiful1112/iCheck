from __future__ import annotations

import time

import pytest

from icheck import collector_worker
from icheck.collectors.psrp_cim import CIM_OPERATIONS
from icheck.psrp_executor import PSRPCIMTransportExecutor


class FakeClient:
    def __init__(self, server, calls, execution, **options):
        self.server = server
        self.calls = calls
        self.execution = execution
        self.options = options

    def __enter__(self):
        self.calls.append(("connect", self.server, self.options))
        return self

    def __exit__(self, *_args):
        self.calls.append(("close",))

    def execute_ps(self, script, *, configuration_name):
        self.calls.append(("execute", script, configuration_name))
        return self.execution


def make_executor(execution, *, ca_file=None):
    calls = []

    def factory(server, **options):
        return FakeClient(server, calls, execution, **options)

    executor = PSRPCIMTransportExecutor(
        allowed_targets=("*.example.test",),
        allowed_ports=(5986,),
        auth="ntlm",
        ca_file=ca_file,
        configuration_name="iCheck.ReadOnly",
        client_factory=factory,
    )
    return executor, calls


def execute(executor, **overrides):
    values = {
        "host": "win-app-01.example.test",
        "port": 5986,
        "use_ssl": True,
        "credential_profile_ref": "windows-readonly",
        "credential": {"username": "readonly", "password": "secret"},
        "operation": "operating_system",
        "script": CIM_OPERATIONS["operating_system"],
        "timeout_seconds": 15,
        "max_response_bytes": 100_000,
    }
    values.update(overrides)
    return executor(**values)


def test_psrp_executor_pins_tls_auth_ca_timeouts_and_endpoint(tmp_path):
    ca_file = tmp_path / "winrm-ca.pem"
    ca_file.write_text("test CA", encoding="utf-8")
    executor, calls = make_executor(
        (
            '{"Caption":"Windows Server 2025","BuildNumber":"26100"}',
            None,
            False,
        ),
        ca_file=str(ca_file),
    )

    result = execute(executor)

    assert result == {
        "Caption": "Windows Server 2025",
        "BuildNumber": "26100",
    }
    _, server, options = calls[0]
    assert server == "win-app-01.example.test"
    assert options["ssl"] is True
    assert options["auth"] == "ntlm"
    assert options["cert_validation"] == str(ca_file)
    assert options["no_proxy"] is True
    assert options["reconnection_retries"] == 0
    assert options["connection_timeout"] == 15
    assert options["operation_timeout"] < options["read_timeout"] < 15
    assert calls[1] == (
        "execute",
        CIM_OPERATIONS["operating_system"],
        "iCheck.ReadOnly",
    )
    assert calls[2] == ("close",)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"host": "169.254.169.254"}, "not allowlisted"),
        ({"port": 5985}, "port 5985.*not allowlisted"),
        ({"use_ssl": False}, "requires WinRM over TLS"),
        ({"script": "Get-Process"}, "unregistered script"),
        ({"credential": {"username": "readonly"}}, "requires a password"),
    ],
)
def test_psrp_executor_fails_closed_before_opening_a_connection(
    overrides,
    message,
):
    executor, calls = make_executor(("{}", None, False))

    with pytest.raises(ValueError, match=message):
        execute(executor, **overrides)

    assert calls == []


@pytest.mark.parametrize(
    ("output", "message"),
    [
        ("not-json", "valid JSON"),
        ('{"item":1,"item":2}', "duplicate key"),
        ("NaN", "non-finite value"),
        ('{"TotalPhysicalMemory":1e999}', "non-finite value"),
        ('{"private-output-key":1,"private-output-key":2}', "duplicate key"),
        ("[1,2]", "array of objects"),
    ],
)
def test_psrp_executor_rejects_ambiguous_or_unstructured_output(output, message):
    executor, _calls = make_executor((output, None, False))

    with pytest.raises(ValueError, match=message):
        execute(executor)


def test_duplicate_remote_field_name_is_not_echoed_in_diagnostics():
    executor, _ = make_executor(('{"private-output-key":1,"private-output-key":2}', None, False))
    with pytest.raises(ValueError) as error:
        execute(executor)
    assert "private-output-key" not in str(error.value)


def test_psrp_executor_does_not_relay_remote_error_details():
    executor, _calls = make_executor(("secret echoed by remote", None, True))

    with pytest.raises(RuntimeError, match="remote execution failed") as error:
        execute(executor)

    assert "secret echoed" not in str(error.value)


def test_psrp_executor_enforces_the_response_budget_before_parsing():
    executor, _calls = make_executor(('{"item":"large"}', None, False))

    with pytest.raises(ValueError, match="max_response_bytes"):
        execute(executor, max_response_bytes=4)


def _slow_child(connection, _request):
    time.sleep(2)
    connection.close()


def test_psrp_executor_hard_timeout_terminates_the_transport_process(monkeypatch):
    executor = PSRPCIMTransportExecutor(
        allowed_targets=("*.example.test",),
        allowed_ports=(5986,),
    )
    monkeypatch.setattr("icheck.psrp_executor._execute_child", _slow_child)
    started = time.monotonic()

    with pytest.raises(RuntimeError, match="timed out"):
        execute(executor, timeout_seconds=1)

    assert time.monotonic() - started < 1.8


def test_worker_builds_psrp_executor_only_with_explicit_boundaries(monkeypatch):
    args = collector_worker.parse_args([])
    monkeypatch.setattr(
        PSRPCIMTransportExecutor,
        "require_dependency",
        staticmethod(lambda: None),
    )

    with pytest.raises(SystemExit, match="WINDOWS_ALLOWED_TARGETS"):
        collector_worker.build_psrp_cim_executor(
            args,
            ["psrp_cim"],
            allowed_targets=[],
            allowed_ports=[5986],
        )

    executor = collector_worker.build_psrp_cim_executor(
        args,
        ["psrp_cim"],
        allowed_targets=["10.20.0.0/16"],
        allowed_ports=[5986],
    )
    assert executor is not None
    assert executor.allowed_targets == ("10.20.0.0/16",)
    assert executor.allowed_ports == (5986,)
    assert executor.auth == "ntlm"


def test_worker_rejects_invalid_psrp_port_policy(monkeypatch):
    args = collector_worker.parse_args([])
    monkeypatch.setattr(
        PSRPCIMTransportExecutor,
        "require_dependency",
        staticmethod(lambda: None),
    )

    with pytest.raises(SystemExit, match="allowed ports"):
        collector_worker.build_psrp_cim_executor(
            args,
            ["psrp_cim"],
            allowed_targets=["10.20.0.0/16"],
            allowed_ports=[0],
        )
