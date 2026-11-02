import pytest

from addons_cli import (ContractError, validate_org, validate_ref,
                        validate_repo, validate_slug, REPO_PREFIX)


def test_repo_bijection_happy():
    owner, aid = validate_repo(f"NamazuStudios/{REPO_PREFIX}waf")
    assert (owner, aid) == ("NamazuStudios", "waf")


def test_repo_rejects_foreign_owner():
    with pytest.raises(ContractError, match="outside the addon family"):
        validate_repo("OtherOrg/namazu-cloud-addon-waf")


def test_repo_rejects_missing_family_prefix():
    with pytest.raises(ContractError, match="must start with"):
        validate_repo("NamazuStudios/waf")


def test_slug_rejects_bad_grammar():
    with pytest.raises(ContractError):
        validate_slug("-bad", "x")          # leading hyphen
    with pytest.raises(ContractError):
        validate_slug("UPPER", "x")         # case
    assert validate_slug("acme-corp-2", "x") == "acme-corp-2"


def test_ref_grammar():
    sha = "a" * 40
    assert validate_ref(sha) == sha
    assert validate_ref("v1.2.0") == "v1.2.0"
    assert validate_ref(None) is None
    for bad in ("main", "feature/x", "v1", "1.2.3", "a" * 39, "A" * 40):
        with pytest.raises(ContractError, match="rejected"):
            validate_ref(bad)


def test_org_id_is_machine_field_not_name():
    assert validate_org("8471") == "8471"
    assert validate_org("org_db_9") == "org_db_9"
    with pytest.raises(ContractError, match="database unique id"):
        validate_org("")
