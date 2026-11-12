#!/usr/bin/env python3
"""
namazu-cloud-addon-runner — the enforcer of the namazu-cloud-addon contract.

Shared CODE, not shared authority: this CLI carries no trust of its own; it
runs as a composite GitHub Action step under the calling org fork's OIDC role
and exercises only the S3/EKS/git access that role confers.

Modes:
  apply   — resolve one addon repo @ ref against one tenant, honor
            manifest.yaml bindings, terraform init with the bijection
            backend key, apply.
  plan    — same, minus mutation.
  sweep   — enumerate the org fork's installed addon state keys from the
            state bucket listing; destroy-from-state anything whose tenant
            baseline is gone or whose workflow entry no longer names it.
  audit   — read-only listing of every addon_*.tfstate key in the bucket.

Contract implemented here (see namazu-cloud-instance/tenant-addons-plan.md):
  - bijection:  repo suffix = addon id = statefile addon_<id>.tfstate
                = sweep key  = $addon.<id> reference token
  - ref grammar: full 40-hex SHA or protected v<semver> tag; never a branch
  - references:  $instance.<output>[.<key>...] / $addon.<id>.<output>[...]
                 / `!` sensitive-override (env channel only, never on disk)
  - visibility:  manifest visibility: shared|private + owner_org (db id);
                 private is consumable only by a fork whose organization_id
                 equals owner_org (lint + audit + belt-and-suspenders here).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - action.sh installs PyYAML first
    yaml = None

GIT_OWNER_DEFAULT = os.environ.get("ELEMENTS_ADDON_GIT_OWNER", "NamazuStudios")
REPO_PREFIX = "namazu-cloud-addon-"
SLUG_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
ORG_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# addon_<id>_<variant>.tfstate: addon ids never contain '_' (slug grammar is
# [a-z0-9-]), so the single underscore always splits id | variant.
STATE_KEY_RE = re.compile(
    r"^tenants/(?P<kind>instances|sandboxes)/(?P<tenant>[^/]+)/"
    r"addon_(?P<aid>[^_/]+)_(?P<variant>[^/]+)\.tfstate$"
)
REF_RE = re.compile(r"^(?P<prefix>[$!])(?P<unit>instance|addon)\.(?P<rest>.+)$")

# Namespace annotation scheme (design: "Namespace Tagging") — the visibility
# seam between org-fork CI and the control plane. The conductor's per-scope
# read-out (namazu-conductor#109) surfaces these keys.
ANNOTATION_PREFIX = "addon.cloud.namazustudios.com/"


class ContractError(Exception):
    """A violation of the namazu-cloud-addon contract — loud, named, fatal."""


class ExternalError(Exception):
    """An infrastructure/tooling failure (aws, git, terraform)."""


def log(msg: str) -> None:
    print(f"[addon-runner] {msg}", flush=True)


def loud(msg: str) -> None:
    print(f"[addon-runner] ############ {msg} ############", flush=True)


# --------------------------------------------------------------------------- #
# validation — the contract's grammar layer
# --------------------------------------------------------------------------- #


def validate_slug(slug: str, what: str) -> str:
    if not isinstance(slug, str) or len(slug) < 2 or not SLUG_RE.match(slug):
        raise ContractError(
            f"{what}: '{slug}' violates the slug grammar "
            "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ (min length 2)"
        )
    return slug


def validate_repo(repo: str, git_owner: str = GIT_OWNER_DEFAULT) -> Tuple[str, str]:
    """'<owner>/<name>' -> (owner, addon_id), via the bijection."""
    if not isinstance(repo, str) or "/" not in repo:
        raise ContractError(f"repo '{repo}' must look like '<owner>/<name>'")
    owner, name = repo.split("/", 1)
    if owner != git_owner:
        raise ContractError(
            f"repo '{repo}': owner '{owner}' is outside the addon family "
            f"(expected namespace '{git_owner}')"
        )
    if not name.startswith(REPO_PREFIX):
        raise ContractError(
            f"repo '{repo}': name must start with '{REPO_PREFIX}' "
            "(the family naming grammar — contract clause 2)"
        )
    addon_id = validate_slug(name[len(REPO_PREFIX):], "addon id (repo suffix)")
    return owner, addon_id


def validate_variant(variant: Optional[str]) -> str:
    """REQUIRED: every install is the triple (addon, variant, tenant). The
    variant is the name WE specify in the matrix entry; no variant, no valid
    entry (loud at prepare-index)."""
    if not isinstance(variant, str) or len(variant) < 2 or not SLUG_RE.match(variant):
        raise ContractError(
            f"variant '{variant}' is REQUIRED and must match the slug grammar "
            "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ (min length 2)"
        )
    return variant


def validate_ref(ref: Optional[str]) -> Optional[str]:
    if ref in (None, ""):
        return None
    if SHA_RE.match(ref) or TAG_RE.match(ref):
        return ref
    raise ContractError(
        f"ref '{ref}' is rejected: pins are a full 40-hex commit SHA or a "
        "protected tag v<MAJOR>.<MINOR>.<PATCH>; branches (including 'main') "
        "are mutable and can never be a pin."
    )


def validate_org(org_id: str) -> str:
    if not isinstance(org_id, str) or not ORG_ID_RE.match(org_id):
        raise ContractError(
            f"organization_id '{org_id}' must be the org's database unique id "
            "(1-64 chars of [A-Za-z0-9_-])"
        )
    return org_id


def tenant_of(instance: Optional[str], workspace: Optional[str]) -> Tuple[str, str]:
    if bool(instance) == bool(workspace):
        raise ContractError(
            "exactly one of instance|workspace is required (the other stays empty)"
        )
    return ("instances", instance) if instance else ("sandboxes", workspace)


def tenant_prefix(kind: str, tenant: str) -> str:
    return f"tenants/{kind}/{tenant}/"


# --------------------------------------------------------------------------- #
# namespace annotations — the visibility seam (design: "Namespace Tagging")
# --------------------------------------------------------------------------- #


def flat(value: Any) -> str:
    """Single-line, quote-free annotation value (kubectl-annotate safe)."""
    return " ".join(str(value).split()).replace('"', "").replace("'", "")


def short_version(ref: str) -> str:
    """40-hex SHA -> short sha; a v<semver> tag rides as-is."""
    return ref[:7] if SHA_RE.match(ref) else ref


def addon_annotations(addon_id: str, variant: str, manifest: Optional[Manifest],
                      ref: str, remove: bool) -> List[str]:
    """Annotation args for ONE install (addon + variant) on ONE tenant
    namespace — keys carry the variant so multiple instances of one addon on
    one namespace never collide. Removal uses kubectl's trailing-dash syntax
    (`key-`); display/description never matter there."""
    p = ANNOTATION_PREFIX
    inst = f"{addon_id}_{variant}"
    if remove:
        return [f"{p}display-{inst}-", f"{p}version-{inst}-",
                f"{p}description-{inst}-"]
    return [
        f"{p}display-{inst}={flat((manifest.display if manifest else None) or addon_id)}",
        f"{p}version-{inst}={flat(short_version(ref))}",
        f"{p}description-{inst}={flat(manifest.description if manifest else '')}",
    ]


def _kubectl_cluster_flags(region: str, cluster: str, role_arn: str
                           ) -> Tuple[List[str], str]:
    """One-off kubectl auth flags against the tenant cluster: real endpoint +
    CA + a cloud-issued token. The token rides argv for the duration of the
    single call only; the CA file is public cert material and unlinked by the
    caller. With a role_arn the token mint self-assumes the executor role
    (the bootstrap trust allows role -> itself); without one it uses the
    ambient identity, which IS the executor role in CI."""
    info = json.loads(aws(["eks", "describe-cluster", "--name", cluster,
                           "--region", region, "--output", "json"],
                          silent=True).stdout or "{}").get("cluster") or {}
    if not info.get("endpoint") or not (info.get("certificateAuthority") or {}).get("data"):
        raise ExternalError(
            f"eks describe-cluster for '{cluster}' returned no endpoint/CA — "
            "cannot wire kubectl for namespace annotations")
    token_doc = json.loads(aws(["eks", "get-token", "--cluster-name", cluster,
                                "--region", region]
                               + (["--role-arn", role_arn] if role_arn else []),
                               silent=True).stdout or "{}")
    token = (token_doc.get("status") or {}).get("token")
    if not token:
        raise ExternalError(
            f"aws eks get-token returned no token for cluster '{cluster}' "
            "(ambient identity or role-arn lacks eks access)")
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(base64.b64decode(info["certificateAuthority"]["data"]).decode())
        ca_path = fh.name
    return (["--server", info["endpoint"], "--token", token,
             "--certificate-authority", ca_path], ca_path)


def update_addon_annotations(args, addon_id: str, variant: str, kind: str,
                             tenant: str, ref: str, remove: bool,
                             manifest: Optional[Manifest] = None) -> None:
    """Stamp (apply) or remove (sweep destroy) ONE addon's namespace
    annotations on its tenant namespace. Best-effort by design: a failed
    annotate never undoes a successful terraform apply/destroy — it warns
    loudly (visibility may go stale) and moves on. Skips entirely when the
    invocation carries no EKS cluster wiring."""
    cluster = getattr(args, "eks_cluster_name", "") or ""
    if not cluster:
        return
    ca_path = None
    try:
        flags, ca_path = _kubectl_cluster_flags(args.region, cluster,
                                                getattr(args, "eks_cluster_role_arn", "") or "")
        run(["kubectl", "annotate", "namespace", tenant, "--overwrite",
             *addon_annotations(addon_id, variant, manifest, ref, remove), *flags],
            silent=True)
        log(f"namespace annotations {'removed from' if remove else 'stamped on'} "
            f"{tenant} ({kind}): addon '{addon_id}' variant '{variant}'")
    except ExternalError as err:
        loud(f"namespace annotation {'removal' if remove else 'stamp'} failed for "
             f"{tenant} ({kind}), addon '{addon_id}' variant '{variant}' — the "
             f"terraform outcome stands; control-plane visibility for this "
             f"addon may be stale: {err}")
    finally:
        if ca_path:
            try:
                os.remove(ca_path)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# subprocess helpers — aws / git / terraform stay external CLIs
# --------------------------------------------------------------------------- #


def run(cmd: List[str], *, silent: bool = False) -> "subprocess.CompletedProcess":
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    except FileNotFoundError as e:
        raise ExternalError(f"'{cmd[0]}' is not on PATH: {e}") from e
    if proc.returncode != 0:
        raise ExternalError(
            f"command failed (rc={proc.returncode}): {' '.join(cmd[:8])}…\n"
            f"stdout:\n{proc.stdout[-4000:]}\nstderr:\n{proc.stderr[-4000:]}"
        )
    if not silent:
        log(f"$ {' '.join(cmd[:6])}{' …' if len(cmd) > 6 else ''}")
    return proc


def aws(args: List[str], *, silent: bool = False) -> "subprocess.CompletedProcess":
    return run(["aws"] + args, silent=silent)


# --------------------------------------------------------------------------- #
# S3 state access
# --------------------------------------------------------------------------- #


def list_state_keys(bucket: str, prefix: str = "tenants/") -> List[str]:
    keys: List[str] = []
    token = None
    while True:
        args = ["s3api", "list-objects-v2", "--bucket", bucket, "--prefix",
                prefix, "--output", "json"]
        if token:
            args += ["--continuation-token", token]
        page = json.loads(aws(args, silent=True).stdout or "{}")
        keys += [o["Key"] for o in (page.get("Contents") or [])]
        token = page.get("NextContinuationToken")
        if not token:
            return keys


def key_exists(bucket: str, key: str) -> bool:
    out = aws(["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", key,
               "--output", "json"], silent=True).stdout
    return key in [o["Key"] for o in (json.loads(out or "{}").get("Contents") or [])]


def get_object(bucket: str, key: str, dest: str) -> bool:
    try:
        aws(["s3api", "get-object", "--bucket", bucket, "--key", key, dest],
            silent=True)
        return True
    except ExternalError:
        return False


def delete_key(bucket: str, key: str) -> None:
    log(f"tidy: removing leftover state key(s) for {key}")
    for k in (key, key + ".tflock"):
        try:
            aws(["s3api", "delete-object", "--bucket", bucket, "--key", k],
                silent=True)
        except ExternalError as e:
            loud(f"tidy delete failed for {k} (continuing): {e}")


# --------------------------------------------------------------------------- #
# clone — repo @ ref (SHA or tag; shallow; retried).  Bundle usage-limits of
# the pin grammar: call sites guarantee ref is present and valid.
# --------------------------------------------------------------------------- #


def clone_repo(repo: str, ref: str, dest: str, token: Optional[str],
               attempts: int = 3) -> None:
    url = f"https://github.com/{repo}.git"
    if token:
        url = f"https://x-access-token:{token}@github.com/{repo}.git"
    for attempt in range(1, attempts + 1):
        try:
            if os.path.exists(dest):
                shutil.rmtree(dest)
            run(["git", "init", "-q", dest])
            run(["git", "-C", dest, "remote", "add", "origin", url])
            run(["git", "-C", dest, "config", "advice.detachedHead", "false"])
            log(f"shallow fetch {repo} @ {ref} (attempt {attempt})")
            run(["git", "-C", dest, "fetch", "-q", "--depth", "1", "origin", ref])
            run(["git", "-C", dest, "checkout", "-q", "FETCH_HEAD"])
            return
        except ExternalError as err:
            if attempt == attempts:
                raise
            log(f"clone attempt {attempt} failed: {err}; retrying in 5s")
            time.sleep(5)


# --------------------------------------------------------------------------- #
# manifest.yaml — the addon's input declaration + visibility contract
# --------------------------------------------------------------------------- #


@dataclass
class Manifest:
    description: str
    visibility: str
    owner_org: Optional[str]
    input: Dict[str, Any]
    path: str
    display: Optional[str] = None


def load_manifest(path: str, organization_id: Optional[str]) -> Manifest:
    if yaml is None:
        raise ExternalError("PyYAML is required but not installed")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except FileNotFoundError as e:
        raise ContractError(
            f"manifest.yaml missing at addon repo root ({path}) — every addon "
            "carries its input declaration (contract clause 10)"
        ) from e
    except yaml.YAMLError as e:
        raise ContractError(f"manifest.yaml at {path} is not valid YAML: {e}") from e
    if not isinstance(doc, dict):
        raise ContractError(f"manifest.yaml at {path} must be a mapping")

    description = doc.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ContractError("manifest.yaml requires a non-empty 'description'")
    visibility = doc.get("visibility", "shared")
    if visibility not in ("shared", "private"):
        raise ContractError(
            f"manifest 'visibility' must be 'shared' or 'private' (got {visibility!r})"
        )
    owner_org = doc.get("owner_org")
    display = doc.get("display")
    if display is not None:
        if not isinstance(display, str) or not display.strip():
            raise ContractError("manifest 'display' must be a non-empty string "
                                "(the human-readable addon name; omit to use the addon id)")
        display = display.strip()
    inp = doc.get("input") or {}
    if not isinstance(inp, dict):
        raise ContractError("manifest 'input' must be a mapping "
                            "(variable-name -> binding)")
    for var in inp:
        if not VAR_RE.match(var):
            raise ContractError(f"manifest 'input' key '{var}' is not a valid "
                                "Terraform variable name")
    if visibility == "private":
        if owner_org in (None, ""):
            raise ContractError(
                "visibility: private requires 'owner_org' (the org's database "
                "unique id) in manifest.yaml"
            )
        owner_org = validate_org(str(owner_org))
        if organization_id and owner_org != str(organization_id):
            raise ContractError(
                f"visibility violation: this addon is private to org '{owner_org}' "
                f"but the consuming fork declares organization_id='{organization_id}' "
                "(the fork's validate-lint should have failed its PR first)"
            )
    m = Manifest(description=description.strip(), visibility=visibility,
                 owner_org=owner_org, input=inp, path=path, display=display)
    log(f"manifest: '{m.description}' visibility={m.visibility}")
    return m


# --------------------------------------------------------------------------- #
# output menus — parsed straight from statefiles (the output surface redacts
# sensitive values, so we read state ourselves and honor the `!` gate here)
# --------------------------------------------------------------------------- #


@dataclass
class OutputMenu:
    values: Dict[str, Dict[str, Any]]  # name -> {value, sensitive}

    @classmethod
    def from_statefile(cls, path: str) -> "OutputMenu":
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
        outputs = (((state.get("values") or {}).get("outputs")) or {})
        menu: Dict[str, Dict[str, Any]] = {}
        for name, meta in (outputs or {}).items():
            menu[name] = {"value": meta.get("value"),
                          "sensitive": bool(meta.get("sensitive"))}
        return cls(values=menu)

    def value(self, output: str, path: Tuple[str, ...]) -> Tuple[Any, bool]:
        meta = self.values.get(output)
        if meta is None:
            raise ContractError(
                f"output '{output}' does not exist in the referenced statefile"
            )
        cur: Any = meta["value"]
        for part in path:
            if isinstance(cur, dict):
                if part not in cur:
                    raise ContractError(
                        f"output '{output}': key '{part}' missing in traversed value"
                    )
                cur = cur[part]
            elif isinstance(cur, list):
                try:
                    idx = int(part)
                    cur = cur[idx]
                except (ValueError, IndexError):
                    raise ContractError(
                        f"output '{output}': cannot index '{part}' while traversing"
                    )
            else:
                raise ContractError(
                    f"output '{output}': cannot traverse past a scalar at '{part}'"
                )
        if path and isinstance(cur, (dict, list)):
            raise ContractError(
                f"output '{output}': traversal must end at a scalar/leaf; wire "
                "structured values wholesale by naming variables that accept them"
            )
        return cur, bool(meta["sensitive"])


# --------------------------------------------------------------------------- #
# binding resolution — declared, never inferred; `!` = acknowledged override
# --------------------------------------------------------------------------- #


def _split_ref(raw: str) -> Optional[Tuple[bool, str, Tuple[str, ...]]]:
    m = REF_RE.match(raw)
    if not m:
        return None
    bang, unit, rest = m["prefix"] == "!", m["unit"], m["rest"]
    if unit == "addon":
        seg = rest.split(".")
        # $addon.<id>.<variant>.<output>... — variant REQUIRED (entries always
        # carry one, so the parse is always unambiguous)
        if len(seg) < 3 or not seg[0] or not seg[1]:
            return bang, unit, (rest,)
        aid, variant, out_path = seg[0], seg[1], ".".join(seg[2:])
        parts = (aid, variant, *[p for p in out_path.split(".") if p != ""])
        return bang, unit, parts
    return bang, unit, tuple(p for p in rest.split(".") if p != "")


def resolve_binding(raw: Any, menus: Dict[str, OutputMenu], where: str
                    ) -> Tuple[Any, bool]:
    """Returns (value, was_sensitive). A value is a reference only when it
    starts with a recognized unit token; anything else is a literal literal
    (`$$` escaping does not exist by design)."""
    if not isinstance(raw, str):
        return raw, False
    split = _split_ref(raw)
    if split is None:
        return raw, False  # literal (incl. stray `$`/`!` prefixes)
    bang, unit, parts = split
    if unit == "addon" and (len(parts) < 3 or not parts[0] or not parts[1]):
        raise ContractError(
            f"{where}: '{raw}' must reference "
            "$addon.<addon_id>.<variant>.<output> — the variant names WHICH "
            "install of that addon on this tenant"
        )
    menu_key = "instance" if unit == "instance" else f"{parts[0]}_{parts[1]}"
    menu = menus.get(menu_key)
    if menu is None:
        raise ContractError(
            f"{where}: reference '{raw}' names the variant install "
            f"'{menu_key}', whose statefile is not available on this tenant — "
            "install that (addon, variant) first (loud failure by contract "
            "clause 4; the error names the ref and owner), or correct the "
            "binding"
        )
    path = parts[2:] if unit == "addon" else parts
    if not path or not path[0]:
        raise ContractError(f"{where}: '{raw}' must name an output")
    out = path[0]
    value, sensitive = menu.value(out, tuple(path[1:]))
    if sensitive and not bang:
        raise ContractError(
            f"{where}: output '{out}' is SENSITIVE — a `$` reference is "
            "rejected; use `!` to acknowledge the sensitive gate"
        )
    if bang and sensitive:
        log(f"{where}: `!` authorized SENSITIVE wiring (the fact is logged; "
            "the value travels via env only)")
    return value, bang and sensitive


# --------------------------------------------------------------------------- #
# terraform execution — init on the bijection key, plan/apply, env channel
# --------------------------------------------------------------------------- #


DEFAULT_CONTRACT_VARS = (
    "instance_id", "workspace_id", "organization_id", "billable", "state",
    "product_sku", "app_dns_name", "architecture", "tags",
    "eks_cluster_name", "eks_cluster_role_arn",
)


def build_backend_config(workdir: str, region: str, bucket: str, key: str) -> str:
    path = os.path.join(workdir, "backend.hcl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"region = {json.dumps(region)}\n"
                 f"bucket = {json.dumps(bucket)}\n"
                 f"key    = {json.dumps(key)}\n"
                 "encrypt = true\n")
    return path


def emit_tfvars(workdir: str, tfvars: Dict[str, Any]) -> str:
    """Write the resolved (non-sensitive) vars to tfvars.json (0600); return
    its path. Sensitive values ride the env channel only (see
    write_sensitive_env) and are never written to disk."""
    path = os.path.join(workdir, "terraform.tfvars.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(tfvars, fh, indent=2, sort_keys=True)
    return path


def tf_exec(root: str, backend_args: List[str], tfvars_path: str,
            sensitive_env: Dict[str, str], cmd: List[str]) -> None:
    env: Dict[str, str] = dict(os.environ)
    env.update({"TF_IN_AUTOMATION": "1", **sensitive_env})
    if sensitive_env:
        log(f"env channel: {len(sensitive_env)} sensitive var(s) set via "
            "TF_VAR_* (values withheld)")
    run(["terraform", "-chdir=" + root, "init", "-input=false", "-no-color",
         "-reconfigure"] + backend_args)
    run(["terraform", "-chdir=" + root] + cmd +
        ["-input=false", "-no-color", f"-var-file={tfvars_path}"],
        silent=True)


# --------------------------------------------------------------------------- #
# apply / plan — one addon × one tenant
# --------------------------------------------------------------------------- #


def prepare_bindings(menus: Dict[str, OutputMenu], manifest: Manifest,
                     contract_vars: Dict[str, Any]) -> Tuple[Dict[str, Any],
                                                             Dict[str, str]]:
    """Resolve manifest bindings; contract vars are base inputs (they lose to
    explicit manifest bindings, which bind > terraform default per clause 10)."""
    resolved: Dict[str, Any] = {**contract_vars}
    sensitive_env: Dict[str, str] = {}
    for var, raw in manifest.input.items():
        value, is_sensitive = resolve_binding(raw, menus, f"manifest input '{var}'")
        if is_sensitive:
            sensitive_env[f"TF_VAR_{var}"] = value if isinstance(value, str) else json.dumps(value)
        else:
            resolved[var] = value
    return resolved, sensitive_env


def write_sensitive_env(env: Dict[str, str]) -> None:
    """Sensitive values ride the environment ONLY (contract: never on disk,
    never logged)."""
    for name, value in env.items():
        os.environ[name] = value


def mode_apply_or_plan(args) -> None:
    variant = validate_variant(args.variant)
    kind, tenant = tenant_of(args.instance, args.workspace)
    prefix = tenant_prefix(kind, tenant)
    baseline_key = prefix + "terraform.tfstate"

    # tenant existence: judged by the baseline statefile's presence
    if not key_exists(args.bucket, baseline_key):
        log(f"tenant '{tenant}' ({kind}) has no baseline state — skipping "
            "(per contract clause 9)")
        return

    # repo-less entries apply the fork's own root (the job's own checkout);
    # external entries require a pin and clone at it.
    if args.repo:
        owner, addon_id = validate_repo(args.repo)
        ref = validate_ref(args.ref)
        if not ref:
            raise ContractError(
                "external addon entries must carry a pinned ref (full SHA or "
                "protected v<semver> tag) — a ref can never default off-fork"
            )
        root = os.path.join(args.work_dir, repo_dirname(args.repo))
        token = os.environ.get("ELEMENTS_GIT_TOKEN")
        clone_repo(args.repo, ref, root, token)
        ref_log = ref
    else:
        addon_id = gh_suffix()
        ref = os.environ.get("GITHUB_SHA") or "(local)"
        root = args.caller_root
        ref_log = ref
        if addon_id == "__fork__":
            raise ContractError(
                "repo-less entries require GITHUB_REPOSITORY (the fork's own "
                "name) so the local root's id can be derived"
            )
        log(f"repo-less entry: applying this fork's local root (id={addon_id})")

    state_key = prefix + f"addon_{addon_id}_{variant}.tfstate"
    log(f"bijection: {args.repo or '<fork-local>'} → addon_id={addon_id} "
        f"variant={variant} → state key {state_key}")

    manifest = load_manifest(os.path.join(root, "manifest.yaml"),
                             args.organization_id)

    # output menus: baseline (once) + foreign addons (via the bijection)
    menus: Dict[str, OutputMenu] = {}
    with tempfile.TemporaryDirectory() as tmp:
        baseline_path = os.path.join(tmp, "baseline.tfstate")
        if get_object(args.bucket, baseline_key, baseline_path):
            menus["instance"] = OutputMenu.from_statefile(baseline_path)

        # foreign addon installs referenced by this manifest — keyed AND
        # fetched per (id, variant)
        for var, raw in manifest.input.items():
            split = _split_ref(raw) if isinstance(raw, str) else None
            if split and split[1] == "addon":
                foreign_id, foreign_variant = split[2][0], split[2][1]
                menu_key = f"{foreign_id}_{foreign_variant}"
                if not menus.get(menu_key):
                    foreign_path = os.path.join(
                        tmp, f"{foreign_id}_{foreign_variant}.tfstate")
                    if get_object(args.bucket,
                                  prefix + f"addon_{foreign_id}_{foreign_variant}.tfstate",
                                  foreign_path):
                        menus[menu_key] = OutputMenu.from_statefile(foreign_path)
                    # else: leave the menu ABSENT — resolve_binding then raises
                    # the loud install-first error naming ref + (id, variant)

    tfvars, sensitive_env = prepare_bindings(menus, manifest, contract_vars(args))
    tfvars_path = emit_tfvars(os.path.join(root, "."), tfvars)
    backend = build_backend_config(root, args.region, args.bucket, state_key)
    write_sensitive_env(sensitive_env)
    cmd = ["plan"] if args.mode == "plan" else ["apply", "-auto-approve"]
    try:
        tf_exec(root, ["-backend-config=" + backend], tfvars_path,
                sensitive_env, cmd)
    finally:
        for name in sensitive_env:
            os.environ.pop(name, None)
        try:
            os.remove(tfvars_path)
        except OSError:
            pass
    log(f"✓ mode={args.mode} finished: addon={addon_id} tenant={tenant} "
        f"(kind={kind}) ref={ref_log}")
    if args.mode == "apply":
        update_addon_annotations(args, addon_id, variant, kind, tenant, ref_log,
                                 remove=False, manifest=manifest)


def contract_vars(args) -> Dict[str, Any]:
    vars: Dict[str, Any] = {"organization_id": args.organization_id}
    kind, tenant = tenant_of(args.instance, args.workspace)
    if kind == "instances":
        vars["instance_id"] = tenant
    else:
        vars["workspace_id"] = tenant
    for key in ("billable", "state", "product_sku", "app_dns_name",
                "architecture", "tags", "eks_cluster_name",
                "eks_cluster_role_arn"):
        val = getattr(args, key.replace("-", "_"), None)
        if val not in (None, ""):
            vars[key] = val
    for pair in (args.contract or []):
        if "=" not in pair:
            raise ContractError(f"--contract expects key=json-or-scalar (got '{pair}')")
        k, raw = pair.split("=", 1)
        if not VAR_RE.match(k):
            raise ContractError(f"--contract key '{k}' is not a valid variable name")
        try:
            vars[k] = json.loads(raw)
        except json.JSONDecodeError:
            vars[k] = raw
    return vars


def repo_dirname(repo: str) -> str:
    return repo.replace("/", "__")


# --------------------------------------------------------------------------- #
# sweep — the org fork's own cleanup; destroy-from-state
# --------------------------------------------------------------------------- #


def mode_sweep(args) -> None:
    # coerce here too (main() coerces, but call sites/tests may not)
    args.tidy = str(getattr(args, "tidy", "false")).lower() in ("1", "true", "yes")
    if not args.index_file:
        raise ContractError("mode=sweep requires --index-file (addons.index.json "
                            "— the materialized workflow entries from this fork)")
    with open(args.index_file, encoding="utf-8") as fh:
        index = json.load(fh)
    if not isinstance(index, list):
        raise ContractError("addons.index.json must be a list of entries "
                            "{addon, ref, instance, workspace}")

    # entries: (addon_id, variant) -> {repo, ref};
    # pairs: (addon_id, variant, kind, tenant) -> ref
    known: Dict[Tuple[str, str], Dict[str, str]] = {}
    pairs: Dict[Tuple[str, str, str, str], str] = {}
    gh_repo = os.environ.get("GITHUB_REPOSITORY") or ""
    for entry in index:
        repo = entry.get("addon") or gh_repo
        owner, aid = validate_repo(repo)
        ref = entry.get("ref") or ""
        variant = validate_variant(entry.get("variant"))
        kind, tenant = tenant_of(entry.get("instance"), entry.get("workspace"))
        known[(aid, variant)] = {"repo": repo, "ref": ref}
        pairs[(aid, variant, kind, tenant)] = ref
    log(f"index: {len(known)} (addon, variant) id(s), {len(pairs)} install entries")

    destroyable: List[Tuple[str, str, str, str, str]] = []  # (aid, variant, kind, tenant, key)
    for key in list_state_keys(args.bucket):
        m = STATE_KEY_RE.match(key)
        if not m:
            continue
        aid, variant = m["aid"], m["variant"]
        if aid not in {a for (a, _) in known} and aid != gh_suffix():
            continue  # never touch addon ids our workflows never named
        cls = ("instances", m["tenant"]) if m["kind"] == "instances" else \
              ("sandboxes", m["tenant"])
        baseline_key = f"tenants/{m['kind']}/{m['tenant']}/terraform.tfstate"
        baseline_gone = not key_exists(args.bucket, baseline_key)
        pair_present = (aid, variant, *cls) in pairs
        if baseline_gone:
            log(f"orphan: {key} — tenant {m['tenant']} is gone")
            destroyable.append((aid, variant, m["kind"], m["tenant"], key))
        elif not pair_present:
            log(f"orphan: {key} — no workflow entry names addon '{aid}' "
                f"variant '{variant}' on tenant {m['tenant']} anymore")
            destroyable.append((aid, variant, m["kind"], m["tenant"], key))

    if not destroyable:
        log("sweep: nothing to destroy — converged")
        return

    failures = 0
    for aid, variant, kind, tenant, key in destroyable:
        try:
            destroy_one(args, aid, variant, known.get((aid, variant), {}), kind, tenant, key)
            update_addon_annotations(args, aid, variant, kind, tenant, "", remove=True)
            if args.tidy:
                delete_key(args.bucket, key)
        except (ContractError, ExternalError) as err:
            failures += 1
            loud(f"ADDON SWEEP FAILURE (retry next cron): {key} → {err}")
    if failures:
        # the sweep itself is best-effort (warn-and-continue per addon), but
        # the JOB ends failed so the lag is observable, never silent; the
        # remaining orphans retry on the next cron.
        raise ExternalError(
            f"sweep finished with {failures} failure(s) — the failed keys "
            "stay installed until the next sweep; two consecutive misses "
            "demand attention"
        )


def gh_suffix() -> str:
    gh_repo = os.environ.get("GITHUB_REPOSITORY") or ""
    if "/" in gh_repo:
        name = gh_repo.split("/", 1)[1]
        if name.startswith(REPO_PREFIX):
            return validate_slug(name[len(REPO_PREFIX):], "fork suffix")
    return "__fork__"


def destroy_one(args, aid: str, variant: str, meta: Dict[str, str], kind: str,
                tenant: str, key: str) -> None:
    state_key = key
    root = args.caller_root
    gh_repo = os.environ.get("GITHUB_REPOSITORY") or ""
    if meta.get("repo") and meta["repo"] != gh_repo:
        # foreign addon: destroy with the provider shell of ITS pinned ref
        owner_name = meta["repo"]
        ref = meta.get("ref") or ""
        if ref:
            validate_ref(ref)
        token = os.environ.get("ELEMENTS_GIT_TOKEN")
        root = os.path.join(args.work_dir, repo_dirname(owner_name))
        clone_repo(owner_name, ref, root, token)
    else:
        # fork-local root (index entry with no /addon: → this fork's repo):
        # use the sweep job's own checkout — never re-clone against the fork.
        if aid != gh_suffix():
            raise ContractError(
                f"sweep refuses to destroy state for addon '{aid}' without a "
                "pinned checkout source (not this fork's local root)"
            )
        log(f"destroy: fork-local root {aid} from the job's own checkout")
    # destroy needs the provider shell only: contract vars satisfy the root's
    # variable references; manifest BINDINGS are deliberately not resolved —
    # teardown must never depend on wiring still resolving.
    manifest = load_manifest(os.path.join(root, "manifest.yaml"),
                             args.organization_id)
    tfvars = contract_vars(args)
    tfvars_path = emit_tfvars(os.path.join(root, "."), tfvars)
    backend = build_backend_config(root, args.region, args.bucket, state_key)
    tf_exec(root, ["-backend-config=" + backend], tfvars_path, {},
            ["destroy", "-auto-approve"])
    try:
        os.remove(tfvars_path)
    except OSError:
        pass
    log(f"✓ destroyed {key} (tenant '{tenant}', kind {kind})")


# --------------------------------------------------------------------------- #
# audit — read-only inventory
# --------------------------------------------------------------------------- #


def mode_audit(args) -> None:
    rows = []
    for key in list_state_keys(args.bucket):
        m = STATE_KEY_RE.match(key)
        if m:
            rows.append((m["aid"], m["variant"], m["kind"], m["tenant"], key))
    rows.sort()
    log(f"inventory: {len(rows)} addon statefile(s)")
    for aid, variant, kind, tenant, key in rows:
        print(f"  {aid:26} {variant:12} {kind:9} {tenant:20} {key}")
    print("[addon-runner] audit is read-only (per contract clause 8)")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="namazu-cloud-addon runner")
    p.add_argument("--mode", required=True,
                   choices=["apply", "plan", "sweep", "audit"])
    p.add_argument("--region", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--organization-id", required=True)
    p.add_argument("--variant", default="",
                   help="REQUIRED for apply/plan: the install's variant slug "
                        "(the matrix entry's name for this install)")
    p.add_argument("--repo", default="")
    p.add_argument("--ref", default="")
    p.add_argument("--instance", default="")
    p.add_argument("--workspace", default="")
    p.add_argument("--eks-cluster-name", default="")
    p.add_argument("--eks-cluster-role-arn", default="")
    p.add_argument("--index-file", default="")
    p.add_argument("--tidy", default="false")
    p.add_argument("--work-dir", default=".addons-work")
    p.add_argument("--caller-root", default=os.getcwd(),
                   help="the calling fork's checkout root (repo-less entries)")
    p.add_argument("--contract", action="append", default=[],
                   metavar="KEY=JSON", help="extra contract variable, e.g. "
                   "--contract billable=true --contract app_dns_name=...")
    args = p.parse_args(argv)
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        validate_org(args.organization_id)
        args.tidy = str(args.tidy).lower() in ("1", "true", "yes")
        if args.mode == "audit":
            mode_audit(args)
        elif args.mode == "sweep":
            mode_sweep(args)
        else:
            mode_apply_or_plan(args)
        return 0
    except ContractError as err:
        loud(f"CONTRACT VIOLATION: {err}")
        return 2
    except ExternalError as err:
        loud(f"EXTERNAL FAILURE: {err}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
