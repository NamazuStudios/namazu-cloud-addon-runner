import json

import pytest

from addons_cli import ContractError, OutputMenu, resolve_binding


MENU = OutputMenu(values={
    "cdn":        {"value": {"dns_name": "acme.example.com"}, "sensitive": False},
    "waf_out":    {"value": {"rules": ["r1", "r2"]}, "sensitive": False},
    "mongo_ca":   {"value": "PEM-BODY", "sensitive": True},
    "plain":      {"value": "hello", "sensitive": False},
})


def test_literal_passthrough():
    assert resolve_binding(42, {}, "x") == (42, False)
    assert resolve_binding("'quoted'", {}, "x") == ("'quoted'", False)
    # a leading `$`/`!` without a recognized unit token is a literal
    assert resolve_binding("$foo", {}, "x") == ("$foo", False)


def test_instance_ref_resolves(tmp_path):
    v, sens = resolve_binding("$instance.cdn.dns_name", {"instance": MENU}, "x")
    assert (v, sens) == ("acme.example.com", False)


def test_addon_ref_resolves(tmp_path):
    menus = {"instance": MENU, "waf": MENU}
    v, _ = resolve_binding("$addon.waf.waf_out", menus, "x")
    assert v == {"rules": ["r1", "r2"]}  # structured values wire wholesale


def test_traversal_must_end_at_leaf():
    menu = OutputMenu(values={"deep": {"value": {"a": {"b": 1}}, "sensitive": False}})
    with pytest.raises(ContractError, match="leaf"):
        resolve_binding("$instance.deep.a", {"instance": menu}, "x")


def test_missing_menu_is_a_loud_named_failure():
    with pytest.raises(ContractError, match="install"):
        resolve_binding("$addon.waf.waf_out", {}, "x")


def test_sensitive_gate():
    with pytest.raises(ContractError, match="SENSITIVE"):
        resolve_binding("$instance.mongo_ca", {"instance": MENU}, "x")


def test_bang_overrides_and_flags():
    v, flag = resolve_binding("!instance.mongo_ca", {"instance": MENU}, "x")
    assert (v, flag) == ("PEM-BODY", True)


def test_menu_from_statefile(tmp_path):
    state = {"values": {"outputs": {"plain": {"value": "hello", "type": "string",
                                              "sensitive": False}}}}
    p = tmp_path / "s.tfstate"
    p.write_text(json.dumps(state))
    menu = OutputMenu.from_statefile(str(p))
    assert menu.values["plain"] == {"value": "hello", "sensitive": False}
