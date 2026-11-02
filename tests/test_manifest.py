import os

import pytest

from addons_cli import ContractError, Manifest, load_manifest


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


GOOD = """
description: WAF Rules For Tenants
visibility: shared
input:
  foo: $instance.cdn.dns_name
"""


def test_shared_is_the_default(tmp_path):
    p = write(tmp_path / "manifest.yaml",
              "description: some addon\ninput:\n  foo: 42\n")
    m = load_manifest(str(p), organization_id="8471")
    assert isinstance(m, Manifest)
    assert m.visibility == "shared" and m.owner_org is None
    assert m.input == {"foo": 42}


def test_private_requires_owner_org(tmp_path):
    p = write(tmp_path / "manifest.yaml",
              "description: x\nvisibility: private\ninput: {}\n")
    with pytest.raises(ContractError, match="owner_org"):
        load_manifest(str(p), organization_id="8471")


def test_private_owner_mismatch_fails(tmp_path):
    p = write(tmp_path / "manifest.yaml",
              "description: x\nvisibility: private\nowner_org: 9999\ninput: {}\n")
    with pytest.raises(ContractError, match="visibility violation"):
        load_manifest(str(p), organization_id="8471")


def test_private_owner_match_passes(tmp_path):
    p = write(tmp_path / "manifest.yaml",
              "description: x\nvisibility: private\nowner_org: 8471\ninput: {}\n")
    m = load_manifest(str(p), organization_id="8471")
    assert m.visibility == "private"


def test_bad_variable_name_rejected(tmp_path):
    p = write(tmp_path / "manifest.yaml",
              "description: x\ninput:\n  not-a-var: 1\n")
    with pytest.raises(ContractError, match="valid Terraform variable name"):
        load_manifest(str(p), organization_id=None)


def test_missing_manifest_is_a_contract_error(tmp_path):
    with pytest.raises(ContractError, match="missing"):
        load_manifest(str(tmp_path / "nope.yaml"), organization_id=None)
