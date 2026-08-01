#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: build-delivery.sh RUNTIME.pyz build-delivery-args..." >&2
  exit 64
fi

runtime_bundle="$1"
shift
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
skill_root="$(dirname -- "$script_dir")"
deployment_manifest="$skill_root/deployment-manifest.json"
skill_name="$(basename -- "$skill_root")"

python "$script_dir/verify-runtime-binding.py" \
  "$deployment_manifest" "$runtime_bundle" "$skill_name" >/dev/null
python "$runtime_bundle" "$@"
