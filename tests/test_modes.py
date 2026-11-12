"""Smoke tests that EXECUTE the mode entry points (apply/plan/sweep/audit)
with the external CLIs (aws / git / terraform) stubbed out.

py_compile only checks syntax and the unit tests never enter the modes, so a
runtime NameError (the missing `import tempfile`, #1) shipped green. These
tests run the real mode functions end-to-end against fakes so the module's
own code paths — imports included — actually execute.
"""

import argparse
import json
from subprocess import CompletedProcess

import pytest

import addons_cli


# ----------------------------------------------------------------- helpers --

def stub_cli(monkeypatch, tmp_path):
    """Replace every external-CLI seam with in-memory fakes. Returns a dict
    recording what was called and provides a fake S3 bucket."""

    calls = {"run": [], "objects": {}, "deleted": [], "cloned": []}

    def fake_run(cmd, *, silent=False):
        calls["run"].append(cmd)
        return CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(addons_cli, "run", fake_run)
    monkeypatch.setattr(addons_cli, "aws", fake_run)

    def fake_list_state_keys(bucket, prefix="tenants/"):
        return sorted(calls["objects"])

    def fake_key_exists(bucket, key):
        return key in calls["objects"]

    def fake_get_object(bucket, key, dest):
        if key in calls["objects"]:
            with open(dest, "w", encoding="utf-8") as fh:
                json.dump(calls["objects"][key], fh)
            return True
        return False

    def fake_delete_key(bucket, key):
        for k in (key, key + ".tflock"):
            calls["deleted"].append(k)

    def fake_clone_repo(repo, ref, dest, token, attempts=3):
        # tests pre-materialize the addon root at dest; just record the clone
        calls["cloned"].append((repo, ref))

    monkeypatch.setattr(addons_cli, "list_state_keys", fake_list_state_keys)
    monkeypatch.setattr(addons_cli, "key_exists", fake_key_exists)
    monkeypatch.setattr(addons_cli, "get_object", fake_get_object)
    monkeypatch.setattr(addons_cli, "delete_key", fake_delete_key)
    monkeypatch.setattr(addons_cli, "clone_repo", fake_clone_repo)
    return calls


def write_state(key, outputs):
    """Register a fake tfstate (values.outputs shape) in the stub bucket."""
    return {"values": {"outputs": outputs}}


def make_args(**kw):
    argv = ["--mode", kw.pop("mode"), "--region", "us-east-1",
            "--bucket", "bkt", "--organization-id", "org123"]
    for key, val in kw.items():
        argv += [f"--{key.replace('_', '-')}", str(val)]
    return addons_cli.parse_args(argv)


def put_addon(addon_root, manifest_yaml):
    import os
    os.makedirs(addon_root, exist_ok=True)
    with open(os.path.join(addon_root, "manifest.yaml"), "w") as fh:
        fh.write(manifest_yaml)


# -------------------------------------------------------------------- apply --

def test_apply_skips_when_tenant_baseline_missing(monkeypatch):
    calls = stub_cli(monkeypatch, None)
    args = make_args(mode="apply", repo="NamazuStudios/namazu-cloud-addon-waf",
                     ref="a" * 40, instance="inst-1")
    # no baseline state registered -> clause 9 skip, exit 0, no terraform
    addons_cli.mode_apply_or_plan(args)
    assert calls["run"] == []  # terraform never ran


def test_apply_executes_end_to_end(monkeypatch, tmp_path):
    """The regression test for #1: the output-menu block (tempfile use) runs,
    tfvars are emitted, and terraform init+apply execute."""
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = write_state(
        "tenants/instances/inst-1/terraform.tfstate",
        {"namespace_name": {"value": "inst-1", "sensitive": False}})
    calls["objects"]["tenants/instances/inst-1/addon_waf.tfstate"] = write_state(
        "tenants/instances/inst-1/addon_waf.tfstate",
        {"web_acl_arn": {"value": "arn:waf", "sensitive": False}})

    repo = "NamazuStudios/namazu-cloud-addon-waf"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), """
description: test addon
visibility: shared
input:
  ns: $instance.namespace_name
  acl: $addon.waf.web_acl_arn
""")

    args = make_args(mode="apply", repo=repo, ref="a" * 40, instance="inst-1",
                     work_dir=str(tmp_path))
    # fake_clone_repo leaves only a placeholder manifest; point the module's
    # checkout dir at our prepared root instead
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)
    addons_cli.mode_apply_or_plan(args)

    cmds = calls["run"]
    assert any(c[:3] == ["terraform", "-chdir=" + str(root), "init"] for c in cmds)
    assert ["terraform", "-chdir=" + str(root), "apply", "-auto-approve",
            "-input=false", "-no-color"] == [c for c in cmds
                                             if c[0] == "terraform" and c[2] == "apply"][0][:6]
    # tfvars deleted after the run (never left on disk)
    assert not (root / "terraform.tfvars.json").exists()


def test_apply_loud_fails_on_missing_instance_output(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = write_state(
        "tenants/instances/inst-1/terraform.tfstate", {})
    repo = "NamazuStudios/namazu-cloud-addon-waf"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), """
description: test addon
visibility: shared
input:
  ns: $instance.namespace_name
""")
    args = make_args(mode="apply", repo=repo, ref="a" * 40, instance="inst-1",
                     work_dir=str(tmp_path))
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)
    with pytest.raises(addons_cli.ContractError, match="namespace_name"):
        addons_cli.mode_apply_or_plan(args)


def test_apply_rejects_unpinned_external_ref(monkeypatch):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = {}
    args = make_args(mode="apply", repo="NamazuStudios/namazu-cloud-addon-waf",
                     ref="main", instance="inst-1")
    with pytest.raises(addons_cli.ContractError, match="is rejected"):
        addons_cli.mode_apply_or_plan(args)


def test_contract_vars_parses_contract_flags(monkeypatch, tmp_path):
    stub_cli(monkeypatch, None)
    args = make_args(mode="plan", repo="NamazuStudios/namazu-cloud-addon-waf",
                     ref="a" * 40, instance="inst-1")
    args.contract = ["billable=true", 'gpu={"g5_limit": 1}', "bad-pair"]
    with pytest.raises(addons_cli.ContractError, match="bad-pair"):
        addons_cli.contract_vars(args)
    args.contract = ["billable=true", 'gpu={"g5_limit": 1}']
    vars_ = addons_cli.contract_vars(args)
    assert vars_["billable"] is True
    assert vars_["gpu"] == {"g5_limit": 1}
    assert vars_["instance_id"] == "inst-1"


# -------------------------------------------------------------------- sweep --

def test_sweep_converges_with_no_state(monkeypatch, tmp_path):
    stub_cli(monkeypatch, None)
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-waf", "ref": "a" * 40,
          "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", index_file=str(index))
    addons_cli.mode_sweep(args)  # nothing to destroy -> returns quietly


def test_sweep_destroys_orphans_and_tidy_deletes(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    key = "tenants/instances/gone/addon_waf.tfstate"
    calls["objects"][key] = {}
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-waf", "ref": "a" * 40,
          "instance": "inst-1", "workspace": ""}]))  # 'gone' tenant not named
    args = make_args(mode="sweep", index_file=str(index), tidy="true")
    # stub destroy_one (it clones the addon root; the clone seam is faked but
    # terraform destroy execution is what real CI exercises elsewhere)
    destroyed = []
    monkeypatch.setattr(addons_cli, "destroy_one",
                        lambda a, aid, meta, kind, tenant, k: destroyed.append(k))
    addons_cli.mode_sweep(args)
    assert destroyed == [key]
    assert calls["deleted"] == [key, key + ".tflock"]


def test_sweep_refuses_ids_it_never_named(monkeypatch, tmp_path):
    """A foreign addon id absent from the index AND not the fork suffix is
    never touched."""
    calls = stub_cli(monkeypatch, None)
    key = "tenants/instances/gone/addon_foreign.tfstate"
    calls["objects"][key] = {}
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-waf", "ref": "a" * 40,
          "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", index_file=str(index), tidy="true")
    addons_cli.mode_sweep(args)
    assert calls["deleted"] == []  # foreign id ignored entirely


# -------------------------------------------------------------------- audit --

def test_audit_lists_inventory(monkeypatch, capsys):
    stub_cli(monkeypatch, None)
    import addons_cli as m
    m.list_state_keys = lambda bucket, prefix="tenants/": [
        "tenants/instances/i1/addon_b.tfstate",
        "tenants/sandboxes/w1/addon_a.tfstate",
        "unrelated/key.tfstate",
    ]
    args = make_args(mode="audit")
    assert addons_cli.main(["--mode", "audit", "--region", "r",
                            "--bucket", "bkt", "--organization-id", "org"]) == 0
    out = capsys.readouterr().out
    assert "addon_b" in out and "addon_a" in out
    assert "unrelated" not in out


# ------------------------------------------------------------- exit codes --

def test_exit_code_2_on_contract_error(monkeypatch):
    monkeypatch.setattr(addons_cli, "mode_audit",
                        lambda a: (_ for _ in ()).throw(
                            addons_cli.ContractError("bad")))
    assert addons_cli.main(["--mode", "audit", "--region", "r",
                            "--bucket", "bkt", "--organization-id", "org"]) == 2


def test_exit_code_3_on_external_error(monkeypatch):
    monkeypatch.setattr(addons_cli, "mode_audit",
                        lambda a: (_ for _ in ()).throw(
                            addons_cli.ExternalError("boom")))
    assert addons_cli.main(["--mode", "audit", "--region", "r",
                            "--bucket", "bkt", "--organization-id", "org"]) == 3
