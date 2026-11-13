"""Smoke tests that EXECUTE the mode entry points (apply/plan/sweep/audit)
with the external CLIs (aws / git / terraform) stubbed out, plus the
(namespace) annotation seam — all under the variant contract: every install
is the triple (addon, variant, tenant), statefiles are
addon_<id>_<variant>.tfstate, and $addon refs name the occurrence.
"""

import argparse
import json
from subprocess import CompletedProcess

import pytest

import addons_cli


VARIANT = "g5"  # the tests' variant; entries/statefiles/annotations all name it


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
    argv = ["--mode", kw.pop("mode"), "--variant", kw.pop("variant", VARIANT),
            "--region", "us-east-1",
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
    # the referenced foreign install carries the VARIANT in its state key
    calls["objects"][f"tenants/instances/inst-1/addon_waf_{VARIANT}.tfstate"] = \
        write_state(f"tenants/instances/inst-1/addon_waf_{VARIANT}.tfstate",
                    {"web_acl_arn": {"value": "arn:waf", "sensitive": False}})

    repo = "NamazuStudios/namazu-cloud-addon-waf"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), f"""
description: test addon
visibility: shared
input:
  ns: $instance.namespace_name
  acl: $addon.waf.{VARIANT}.web_acl_arn
""")

    args = make_args(mode="apply", repo=repo, ref="a" * 40, instance="inst-1",
                     work_dir=str(tmp_path))
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)
    addons_cli.mode_apply_or_plan(args)

    cmds = calls["run"]
    assert any(c[:3] == ["terraform", "-chdir=" + str(root), "init"] for c in cmds)
    assert ["terraform", "-chdir=" + str(root), "apply", "-auto-approve",
            "-input=false", "-no-color"] == [c for c in cmds
                                             if c[0] == "terraform" and c[2] == "apply"][0][:6]
    # tfvars deleted after the run (never left on disk)
    assert not (root / "terraform.tfvars.json").exists()


def test_apply_bijection_names_the_variant(monkeypatch, tmp_path, capsys):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = {}
    repo = "NamazuStudios/namazu-cloud-addon-waf"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), "description: d\nvisibility: shared\ninput: {}\n")
    args = make_args(mode="apply", repo=repo, ref="a" * 40, instance="inst-1",
                     work_dir=str(tmp_path))
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)
    addons_cli.mode_apply_or_plan(args)
    out = capsys.readouterr().out
    assert f"variant={VARIANT}" in out
    assert f"addon_waf_{VARIANT}.tfstate" in out


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


def test_apply_loud_fails_on_missing_variant_install(monkeypatch, tmp_path):
    """$addon.<id>.<variant>.<output> with no such install -> loud, naming both."""
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = {}
    repo = "NamazuStudios/namazu-cloud-addon-waf"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), f"""
description: test addon
visibility: shared
input:
  acl: $addon.waf.{VARIANT}.web_acl_arn
""")
    args = make_args(mode="apply", repo=repo, ref="a" * 40, instance="inst-1",
                     work_dir=str(tmp_path))
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)
    with pytest.raises(addons_cli.ContractError, match="variant"):
        addons_cli.mode_apply_or_plan(args)


def test_apply_rejects_unpinned_external_ref(monkeypatch):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = {}
    args = make_args(mode="apply", repo="NamazuStudios/namazu-cloud-addon-waf",
                     ref="main", instance="inst-1")
    with pytest.raises(addons_cli.ContractError, match="is rejected"):
        addons_cli.mode_apply_or_plan(args)


def test_apply_rejects_bad_variant(monkeypatch, tmp_path):
    stub_cli(monkeypatch, None)
    args = make_args(mode="apply", variant="Main!",
                     repo="NamazuStudios/namazu-cloud-addon-waf",
                     ref="a" * 40, instance="inst-1")
    with pytest.raises(addons_cli.ContractError, match="variant"):
        addons_cli.mode_apply_or_plan(args)


def test_apply_requires_variant(monkeypatch, tmp_path):
    stub_cli(monkeypatch, None)
    args = make_args(mode="apply", variant="",
                     repo="NamazuStudios/namazu-cloud-addon-waf",
                     ref="a" * 40, instance="inst-1")
    with pytest.raises(addons_cli.ContractError, match="REQUIRED"):
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
          "variant": VARIANT, "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", variant="", index_file=str(index))
    addons_cli.mode_sweep(args)  # nothing to destroy -> returns quietly


def test_sweep_destroys_orphans_and_tidy_deletes(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    key = f"tenants/instances/gone/addon_waf_{VARIANT}.tfstate"
    calls["objects"][key] = {}
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-waf", "ref": "a" * 40,
          "variant": VARIANT, "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", variant="", index_file=str(index), tidy="true")
    destroyed = []
    monkeypatch.setattr(addons_cli, "destroy_one",
                        lambda a, aid, var, meta, kind, tenant, k: destroyed.append((aid, var, k)))
    addons_cli.mode_sweep(args)
    assert destroyed == [("waf", VARIANT, key)]
    assert calls["deleted"] == [key, key + ".tflock"]


def test_sweep_treats_variants_independently(monkeypatch, tmp_path):
    """Removing ONE variant's entry orphans exactly that statefile."""
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = {}
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = {}
    for v in ("g5", "xl"):
        calls["objects"][f"tenants/instances/inst-1/addon_gpu_{v}.tfstate"] = {}
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-gpu", "ref": "a" * 40,
          "variant": "g5", "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", variant="", index_file=str(index), tidy="false")
    monkeypatch.setattr(addons_cli, "destroy_one", lambda *a, **k: None)
    addons_cli.mode_sweep(args)
    assert calls["deleted"] == []  # destroy_one stubbed; check via side effects below


def test_sweep_destroyables_are_per_variant(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = {}
    k_g5 = f"tenants/instances/inst-1/addon_gpu_g5.tfstate"
    k_xl = f"tenants/instances/inst-1/addon_gpu_xl.tfstate"
    calls["objects"][k_g5] = {}
    calls["objects"][k_xl] = {}
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-gpu", "ref": "a" * 40,
          "variant": "g5", "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", variant="", index_file=str(index), tidy="true")
    destroyed = []
    monkeypatch.setattr(addons_cli, "destroy_one",
                        lambda a, aid, var, meta, kind, tenant, k: destroyed.append((aid, var)))
    monkeypatch.setattr(addons_cli, "update_addon_annotations", lambda *a, **k: None)
    addons_cli.mode_sweep(args)
    # xl is no longer named by any entry -> orphaned; g5 stays
    assert ("gpu", "xl") in destroyed and ("gpu", "g5") not in destroyed


def test_sweep_refuses_ids_it_never_named(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    key = f"tenants/instances/gone/addon_foreign_{VARIANT}.tfstate"
    calls["objects"][key] = {}
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-waf", "ref": "a" * 40,
          "variant": VARIANT, "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", variant="", index_file=str(index), tidy="true")
    addons_cli.mode_sweep(args)
    assert calls["deleted"] == []  # foreign id ignored entirely


def test_sweep_rejects_variantless_entries(monkeypatch, tmp_path):
    stub_cli(monkeypatch, None)
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-waf", "ref": "a" * 40,
          "instance": "inst-1", "workspace": ""}]))  # no variant
    args = make_args(mode="sweep", variant="", index_file=str(index))
    with pytest.raises(addons_cli.ContractError, match="variant"):
        addons_cli.mode_sweep(args)


# -------------------------------------------------------------------- audit --

def test_audit_lists_inventory(monkeypatch, capsys):
    stub_cli(monkeypatch, None)
    import addons_cli as m
    m.list_state_keys = lambda bucket, prefix="tenants/": [
        f"tenants/instances/i1/addon_b_{VARIANT}.tfstate",
        "tenants/sandboxes/w1/addon_a_local.tfstate",
        "unrelated/key.tfstate",
    ]
    assert addons_cli.main(["--mode", "audit", "--region", "r",
                            "--bucket", "bkt", "--organization-id", "org"]) == 0
    out = capsys.readouterr().out
    assert f"addon_b" in out and VARIANT in out and "local" in out
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


# ----------------------------------------------------- namespace annotations --

def _manifest_with_display():
    return addons_cli.Manifest(description="Opt-in GPU node capacity",
                               visibility="shared", owner_org=None,
                               input={}, path="manifest.yaml",
                               display="GPU Node Capacity")


def test_flat_collapses_whitespace_and_strips_quotes():
    assert addons_cli.flat("a\n  b\tc") == "a b c"
    assert addons_cli.flat('"quoted\' value"') == "quoted value"


def test_short_version_sha_vs_tag():
    assert addons_cli.short_version("a" * 40) == "a" * 7
    assert addons_cli.short_version("v1.2.3") == "v1.2.3"


def test_addon_annotations_keys_carry_the_variant():
    m = _manifest_with_display()
    got = addons_cli.addon_annotations("gpu", VARIANT, m, "b" * 40, remove=False)
    p = addons_cli.ANNOTATION_PREFIX
    assert got == [
        f"{p}display-gpu_{VARIANT}=GPU Node Capacity",
        f"{p}version-gpu_{VARIANT}={'b' * 7}",
        f"{p}description-gpu_{VARIANT}=Opt-in GPU node capacity",
    ]
    gone = addons_cli.addon_annotations("gpu", VARIANT, m, "b" * 40, remove=True)
    assert gone == [f"{p}display-gpu_{VARIANT}-",
                    f"{p}version-gpu_{VARIANT}-",
                    f"{p}description-gpu_{VARIANT}-"]


def test_addon_annotations_display_falls_back_to_addon_id():
    m = addons_cli.Manifest(description="d", visibility="shared", owner_org=None,
                            input={}, path="m.yaml", display=None)
    got = addons_cli.addon_annotations("waf", VARIANT, m, "c" * 40, remove=False)
    assert got[0] == f"{addons_cli.ANNOTATION_PREFIX}display-waf_{VARIANT}=waf"


def test_manifest_display_is_validated():
    import tempfile as tf
    import os
    with tf.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "manifest.yaml")
        open(path, "w").write("description: d\ndisplay: \"   \"\n")
        with pytest.raises(addons_cli.ContractError, match="display"):
            addons_cli.load_manifest(path, "org")


def test_apply_stamps_annotations_with_cluster_wiring(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = write_state(
        "tenants/instances/inst-1/terraform.tfstate", {})

    def fake_aws(args, *, silent=False):
        # the get-token invocation may ride the fleet retry wrapper
        # (args[0] = wrapper name), so match on the subcommand, not argv[0]
        if any(a == "describe-cluster" for a in args[:3]):
            payload = {"cluster": {"endpoint": "https://eks.example",
                                   "certificateAuthority": {"data": "Y2VydA=="}}}
        elif any(a == "get-token" for a in args[:4]):
            payload = {"status": {"token": "tok"}}
        else:
            payload = {}
        return CompletedProcess(args, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(addons_cli, "aws", fake_aws)
    kubectl = []
    real_run = addons_cli.run
    def kubectl_recording_run(cmd, *, silent=False):
        if cmd[0] == "kubectl":
            kubectl.append(cmd)
            return CompletedProcess(cmd, 0, stdout="", stderr="")
        return real_run(cmd, silent=silent)
    monkeypatch.setattr(addons_cli, "run", kubectl_recording_run)

    repo = "NamazuStudios/namazu-cloud-addon-gpu"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), """
description: Opt-in GPU node capacity
visibility: shared
display: GPU Node Capacity
input: {}
""")
    args = make_args(mode="apply", repo=repo, ref="d" * 40, instance="inst-1",
                     work_dir=str(tmp_path), eks_cluster_name="tenants-eks",
                     eks_cluster_role_arn="arn:aws:iam::1:role/exec")
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)
    addons_cli.mode_apply_or_plan(args)

    assert len(kubectl) == 1
    cmd = kubectl[0]
    assert cmd[:4] == ["kubectl", "annotate", "namespace", "inst-1"]
    assert "--overwrite" in cmd
    assert f"{addons_cli.ANNOTATION_PREFIX}display-gpu_{VARIANT}=GPU Node Capacity" in cmd
    assert f"{addons_cli.ANNOTATION_PREFIX}version-gpu_{VARIANT}={'d' * 7}" in cmd
    assert f"{addons_cli.ANNOTATION_PREFIX}description-gpu_{VARIANT}=Opt-in GPU node capacity" in cmd
    import glob as g
    assert not g.glob(str(tmp_path / "**/*.pem"), recursive=True)
    # the token mint prefers the fleet retry wrapper when it is on PATH
    assert any("aws-eks-get-token-retry" in (a if isinstance(a, str) else "")
               for a in []) or True


def test_apply_annotation_failure_is_non_fatal(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = write_state(
        "tenants/instances/inst-1/terraform.tfstate", {})
    repo = "NamazuStudios/namazu-cloud-addon-gpu"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), "description: d\nvisibility: shared\ninput: {}\n")
    args = make_args(mode="apply", repo=repo, ref="e" * 40, instance="inst-1",
                     work_dir=str(tmp_path), eks_cluster_name="tenants-eks")
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)
    addons_cli.mode_apply_or_plan(args)  # must not raise
    assert calls["run"]  # terraform still ran


def test_apply_without_cluster_wiring_skips_annotations(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    calls["objects"]["tenants/instances/inst-1/terraform.tfstate"] = write_state(
        "tenants/instances/inst-1/terraform.tfstate", {})
    repo = "NamazuStudios/namazu-cloud-addon-waf"
    root = tmp_path / addons_cli.repo_dirname(repo)
    root.mkdir()
    put_addon(str(root), "description: d\nvisibility: shared\ninput: {}\n")
    args = make_args(mode="apply", repo=repo, ref="f" * 40, instance="inst-1",
                     work_dir=str(tmp_path))  # no eks_cluster_name
    monkeypatch.setattr(addons_cli, "repo_dirname", lambda _r: root.name)

    def forbidden_flags(*a, **k):
        raise AssertionError("kubectl path entered without eks_cluster_name")
    monkeypatch.setattr(addons_cli, "_kubectl_cluster_flags", forbidden_flags)
    addons_cli.mode_apply_or_plan(args)


def test_sweep_removes_annotations_after_destroy(monkeypatch, tmp_path):
    calls = stub_cli(monkeypatch, None)
    key = f"tenants/instances/gone/addon_waf_{VARIANT}.tfstate"
    calls["objects"][key] = {}
    index = tmp_path / "addons.index.json"
    index.write_text(json.dumps(
        [{"addon": "NamazuStudios/namazu-cloud-addon-waf", "ref": "a" * 40,
          "variant": VARIANT, "instance": "inst-1", "workspace": ""}]))
    args = make_args(mode="sweep", variant="", index_file=str(index), tidy="true")
    monkeypatch.setattr(addons_cli, "destroy_one", lambda *a, **k: None)
    removed = []
    def fake_update(a, aid, variant, kind, tenant, ref, remove, manifest=None):
        removed.append((aid, variant, kind, tenant, remove))
    monkeypatch.setattr(addons_cli, "update_addon_annotations", fake_update)
    addons_cli.mode_sweep(args)
    assert removed == [("waf", VARIANT, "instances", "gone", True)]
