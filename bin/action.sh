#!/usr/bin/env bash
# Composite-action shim: python deps are declared by requirement minimalism
# (PyYAML only) and the CLI does everything else through the `aws` and
# `terraform` CLIs that GitHub runners already ship.
set -euo pipefail
ACTION_PATH="${1:?action path missing}"
python3 -m pip install --quiet --disable-pip-version-check 'PyYAML>=6' >/dev/null

# Optional contract variables (INPUT_CONTRACT): one KEY=JSON pair per line
# -> repeatable --contract flags. Empty/unset forwards nothing (backwards
# compatible); manifest bindings take precedence over these (clause 10).
contract_args=()
if [ -n "${INPUT_CONTRACT:-}" ]; then
  while IFS= read -r pair; do
    pair="${pair#"${pair%%[![:space:]]*}"}"   # trim leading whitespace
    pair="${pair%"${pair##*[![:space:]]}"}"   # trim trailing whitespace
    [ -n "$pair" ] || continue
    contract_args+=(--contract "$pair")
  done <<<"$INPUT_CONTRACT"
fi

exec python3 "${ACTION_PATH}/src/addons_cli.py" \
  --mode "${INPUT_MODE:?}" \
  --region "${INPUT_REGION:?}" \
  --bucket "${INPUT_BUCKET:?}" \
  --organization-id "${INPUT_ORGANIZATION_ID:?}" \
  --repo "${INPUT_REPO:-}" \
  --ref "${INPUT_REF:-}" \
  --instance "${INPUT_INSTANCE:-}" \
  --workspace "${INPUT_WORKSPACE:-}" \
  --eks-cluster-name "${INPUT_EKS_CLUSTER_NAME:-}" \
  --eks-cluster-role-arn "${INPUT_EKS_CLUSTER_ROLE_ARN:-}" \
  --index-file "${INPUT_INDEX_FILE:-}" \
  --tidy "${INPUT_TIDY:-false}" \
  --work-dir "${INPUT_WORK_DIR:-.addons-work}" \
  "${contract_args[@]}"
