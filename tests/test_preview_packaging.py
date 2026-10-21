"""Reusable packaging contract tests; no historical release/hash matrix."""
from pathlib import Path
import json
import shutil
from zipfile import ZipFile

import pytest

from deploy import build_engineering_preview as preview
from deploy import verify_native_backend_bundle as verifier

ROOT=Path(__file__).resolve().parents[1]








@pytest.mark.parametrize("extras", [["windows"], ["extensions", "windows"]])
def test_reviewed_native_dependency_selections(extras):
    assert verifier.selected_backend_extras({"extras": extras, "unselected_extras": ["action", "dev"]}) == extras


@pytest.mark.parametrize("extras", [[], ["extensions"], ["windows", "dev"], ["action", "windows"], ["windows", "windows"], ["unreviewed", "windows"]])
def test_native_dependency_selection_does_not_enable_other_runtimes(extras):
    with pytest.raises(ValueError, match="reviewed native runtime"):
        verifier.selected_backend_extras({"extras": extras, "unselected_extras": ["action"]})




def test_direct_preview_uses_one_assembly_and_includes_current_guides(tmp_path,monkeypatch):
    from deploy import assemble_native_application as assembler
    calls=[]
    def assemble(**kwargs):
        calls.append(kwargs)
        target=kwargs["destination"]; target.mkdir()
        with ZipFile(target/"icheck.whl","w") as wheel: wheel.writestr("migrations/versions/current.py","# fixture")
        (target/"release.json").write_text(json.dumps({"backend_wheel":"icheck.whl","frontend_build_id":"fixture-build"}))
        return {"release_ready":False,"installed_host_changed":False}
    monkeypatch.setattr(assembler,"assemble_application",assemble)
    monkeypatch.setattr(preview,"build_release",lambda *_a,**_k:pytest.fail("Direct packaging must not recopy an intermediate application tree"))
    destination=tmp_path/"icheck-preview-fixture"
    result=preview.package_preview(None,destination,ROOT,artifacts={name:tmp_path/name for name in ("wheel","runtime","wheelhouse","frontend")})
    assert len(calls)==1 and calls[0]["include_operator"] is True
    assert result["release_ready"] is False and result["installed_host_changed"] is False
    for name in ("metric-alerts","grafana-access","http-monitoring","system-exporter-monitoring","workflow-templates"):
        assert (destination/"docs"/(name+".md")).is_file()
    assert (destination/"config/alertmanager/alertmanager.yml.example").is_file()
    assert (destination/"docs/development-plan.md").is_file()
    qualification_path=(destination/"acceptance/public-preview-qualification.json")
    qualification=json.loads(qualification_path.read_text())
    assert qualification["private_runtime_state_included"] is False
    assert qualification["qualification"]["live_lab_acceptance"] == "pending"
    manifest=json.loads((destination/"preview.json").read_text())
    assert manifest["native_host_installation_verified"] is False
    assert (destination/manifest["candidate_qualification"]).is_file()
    assert manifest["feedback_url"] == "https://github.com/beautiful1112/iCheck/issues"


def test_direct_preview_failure_removes_only_new_claim(tmp_path,monkeypatch):
    from deploy import assemble_native_application as assembler
    target=tmp_path/"icheck-preview-fixture"
    def assemble(**kwargs):
        target.mkdir(); (target/"release.json").write_text("broken")
        return {}
    monkeypatch.setattr(assembler,"assemble_application",assemble)
    with pytest.raises(ValueError): preview.package_preview(None,target,ROOT,artifacts={})
    assert not target.exists()
    target.mkdir(); (target/"retained").write_text("keep")
    with pytest.raises(ValueError,match="already exists"): preview.package_preview(None,target,ROOT,artifacts={})
    assert (target/"retained").read_text()=="keep"


def bundle_fixture(tmp_path,monkeypatch):
    bundle=tmp_path/"icheck-fixture"; bundle.mkdir()
    (bundle/"backend-runtime").mkdir(); (bundle/"backend-wheelhouse").mkdir(); (bundle/"frontend/.next").mkdir(parents=True)
    import platform,sys
    environment={"implementation_name":sys.implementation.name,"implementation_version":platform.python_version(),"platform_machine":platform.machine(),
        "platform_system":platform.system(),"python_full_version":platform.python_version(),"sys_platform":sys.platform,"platform_python_implementation":platform.python_implementation()}
    runtime={"format_version":"icheck.native-runtime-constraints/v1","environment":environment,"extras":["windows"],"unselected_extras":["action"],
        "project":"icheck","version":"0.1.0","wheel":"icheck-0.1.0-py3-none-any.whl","dependencies":{}}
    (bundle/"backend-runtime/backend-runtime.json").write_text(json.dumps(runtime)); (bundle/"backend-runtime/backend-constraints.txt").write_text("")
    (bundle/"frontend/.next/BUILD_ID").write_text("fixture")
    (bundle/"frontend/native-release.json").write_text(json.dumps({"format_version":"icheck.native-frontend/v1","build_id":"fixture"}))
    (bundle/"release.json").write_text(json.dumps({"format_version":"icheck.native-test-release-bundle/v1","name":bundle.name,"backend_wheel":runtime["wheel"],
        "backend_runtime_manifest":"backend-runtime/backend-runtime.json","backend_constraints":"backend-runtime/backend-constraints.txt","backend_wheelhouse":"backend-wheelhouse",
        "frontend_package":"frontend","frontend_build_id":"fixture","selected_backend_extras":["windows"],"selected_runtime":f"{platform.python_implementation()} {platform.python_version()} on {platform.system()} {platform.machine()}",
        "cryptographic_release_signature":False,"backend_wheel_count":2}))
    with ZipFile(bundle/runtime["wheel"],"w") as wheel:
        for module in ("snmp_install_broker", "integration_sync_worker", "integration_alert_worker"):
            wheel.writestr(f"icheck/{module}.py", "# fixture module")
    (bundle/"backend-wheelhouse/packaging-26.3-py3-none-any.whl").write_text("fixture")
    (bundle/"backend-wheelhouse/uvicorn-0.34.0-py3-none-any.whl").write_text("fixture")
    from packaging.version import Version
    monkeypatch.setattr(verifier,"_constraints",lambda _: {"packaging":Version("26.3"),"uvicorn":Version("0.34.0")})
    runtime["dependencies"]={"packaging":"26.3","uvicorn":"0.34.0"}; (bundle/"backend-runtime/backend-runtime.json").write_text(json.dumps(runtime))
    monkeypatch.setattr(verifier,"_wheel_metadata",lambda path:("icheck",Version("0.1.0")) if path.name.startswith("icheck") else
        ("uvicorn",Version("0.34.0")) if path.name.startswith("uvicorn") else ("packaging",Version("26.3")))
    scripts={Path(line.split("=",1)[1].split()[0]).name for file in (ROOT/"deploy/systemd").glob("*.service") for line in file.read_text().splitlines()
        if line.startswith("ExecStart=/opt/icheck/.venv/bin/")}
    monkeypatch.setattr(verifier,"_product_scripts",lambda _:scripts)
    units=tmp_path/"units"; units.mkdir()
    for name in verifier.REQUIRED_PYTHON_UNITS|set(verifier.EXTERNAL_UNITS)|set(verifier.OPTIONAL_NATIVE_UNITS):
        shutil.copy2(ROOT/"deploy/systemd"/name,units/name)
    return bundle,units


def test_optional_native_templates_are_verified_but_not_required(tmp_path,monkeypatch):
    bundle,units=bundle_fixture(tmp_path,monkeypatch)
    checked=verifier.verify_bundle(bundle,units)
    assert set(checked["optional_native_unit_templates"])==set(verifier.OPTIONAL_NATIVE_UNITS)
    for name in verifier.OPTIONAL_NATIVE_UNITS:(units/name).unlink()
    assert verifier.verify_bundle(bundle,units)["optional_native_unit_templates"]==[]


def test_optional_broker_cannot_substitute_python_code_or_drop_isolation(tmp_path,monkeypatch):
    bundle,units=bundle_fixture(tmp_path,monkeypatch)
    target=units/"icheck-snmp-module-installer.service"
    target.write_text(target.read_text().replace("python -I -m icheck.snmp_install_broker","python -m icheck.snmp_install_broker"))
    with pytest.raises(ValueError,match="fixed native"): verifier.verify_bundle(bundle,units)


@pytest.mark.parametrize("kind", ("sync", "alert"))
def test_native_integration_workers_have_isolated_accounts_and_exact_commands(tmp_path, monkeypatch, kind):
    from deploy import stage_native_backend as stage
    from deploy import switch_native_backend as switch
    account = "icheck-integration-" + kind
    unit = account + "-worker.service"
    assert stage.SERVICE_ACCOUNTS[account] == ()
    assert unit in switch.PLAIN_UNITS
    bundle, units = bundle_fixture(tmp_path, monkeypatch)
    target = units / unit
    original = target.read_text()
    assert "LoadCredential=integration-key:" in original
    target.write_text(original.replace(" -m icheck.", " -m unreviewed."))
    with pytest.raises(ValueError, match="fixed native"):
        verifier.verify_bundle(bundle, units)


@pytest.mark.parametrize('fault',(None,'broker_running','wrong_external_command','unknown_unit'))
def test_switch_drain_tracks_broker_and_private_external_alertmanager(monkeypatch,fault):
    from deploy import switch_native_backend as switch
    broker='icheck-snmp-module-installer.service';external='icheck-alertmanager.service'
    entries=[{'unit':broker},{'unit':external}]
    if fault=='unknown_unit':entries.append({'unit':'icheck-unreviewed.service'})
    def systemctl(*args):
        if args[0]=='list-units':return json.dumps(entries)
        name=args[1]
        command='/opt/icheck/.venv/bin/python' if name==broker else '/opt/icheck/bin/alertmanager'
        if fault=='wrong_external_command' and name==external:command='/unreviewed/alertmanager'
        running=name==external or fault=='broker_running'
        return '\n'.join((f'Id={name}','LoadState=loaded',f'ActiveState={"active" if running else "inactive"}',
            f'MainPID={12 if running else 0}','ControlPID=0',f'ExecStart={{ path={command} ; argv[]=fixed ; }}'))
    monkeypatch.setattr(switch,'_systemctl',systemctl)
    assert switch.stopped_backend_units() is (fault is None)
