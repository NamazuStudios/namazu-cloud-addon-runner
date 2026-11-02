# namazu-cloud-addon-runner

The contract-enforcement GitHub Action for the per-tenant addon ecosystem.
Shared **code, not shared authority**: the OIDC token belongs to the calling
org fork's workflow; this action carries no credentials of its own and can
never grant anything. Contract: [`namazu-cloud-instance` → `tenant-addons-plan.md`](https://github.com/NamazuStudios/namazu-cloud-instance/blob/main/tenant-addons-plan.md).

## What it enforces (mechanically)

| Contract element | Enforcement |
|---|---|
| Naming grammar | repo must be `NamazuStudios/namazu-cloud-addon-<id>`, `<id>` DNS-1123-ish; `<id>` becomes the addon id via the bijection |
| Ref grammar | full 40-hex SHA **or** protected `v<MAJOR>.<MINOR>.<PATCH>` tag; branches (incl. `main`) always rejected |
| Bijection | statefile = `addon_<id>.tfstate` under the tenant prefix; backend key per invocation |
| Tenant existence | baseline `terraform.tfstate` presence decides skip/apply (clause 9) |
| References | `$instance.<out>[.<key>…]` / `$addon.<id>.<out>…` resolved from statefiles; missing ⇒ loud failure naming ref + owner |
| Sensitivity gate | `$` on a sensitive output = hard error; `!` = acknowledged override, value rides `TF_VAR_*` env only (never on disk, never logged) |
| Visibility | private addons consumable only by the fork whose `organization_id` = `owner_org` |
| Sweep | destroy-from-state: provider shell + statefile suffice; no resource configs needed |

## Modes

- `apply` / `plan` — one addon × one tenant. Input contract:
  `mode, region, bucket, instance|workspace, organization_id` +
  (`repo`, `ref` for foreign addons; omitted ⇒ the fork's own local root) +
  optional `eks_cluster_name`, `eks_cluster_role_arn`, `index_file`, `tidy`.
- `sweep` — needs `index_file` (`addons.index.json`, the materialized
  workflow entries). Enumerates `tenants/*/*/addon_<id>.tfstate` from the
  bucket listing and destroys: vanished tenants, entries no longer named.
- `audit` — read-only inventory of every `addon_*.tfstate` key.

## Local usage

```bash
python3 -m pip install 'PyYAML>=6'
python3 src/addons_cli.py \
  --mode plan \
  --region us-east-1 --bucket namazu-cloud-instance \
  --organization-id 8471 \
  --repo NamazuStudios/namazu-cloud-addon-waf --ref v1.2.0 \
  --instance acme-prod \
  --eks-cluster-name dev-eks \
  --contract billable=false
```

Environment: AWS credentials in env (OIDC/job role), optional
`ELEMENTS_GIT_TOKEN` for private addon clones, `TF_PLUGIN_CACHE_DIR` for
fast repeated inits, `ELEMENTS_ADDON_GIT_OWNER` to override the family
namespace (default `NamazuStudios`).

## Trust model

- The action NEVER assumes a role itself; run
  `aws-actions/configure-aws-credentials` in the caller job first.
- Sensitive (`!`) wiring never touches disk — it is passed through
  `TF_VAR_<name>` environment to the terraform subprocess and scrubbed
  after.
- `terraform.tfvars.json` (all non-sensitive values) is written with 0600
  and deleted after the run.

## Development

```bash
python3 -m pip install 'PyYAML>=6' pytest
python3 -m pytest tests -q
```
