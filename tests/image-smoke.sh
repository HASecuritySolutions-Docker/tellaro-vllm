#!/usr/bin/env bash
# Image smoke test (needs the vLLM base pulled, ~10 GB: run on a build host,
# not a laptop). Checks the entrypoint's fail-closed paths and the pinned tools.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
img="${IMAGE:-tellaro-vllm:smoke}"
[[ -n "${SKIP_BUILD:-}" ]] || docker build -q -t "$img" . >/dev/null
fail=0
# `vllm serve --help` needs a GPU to infer the device, so check the installed
# source instead: the flags the entrypoint passes exist, and request/output
# logging stays opt-in.
# shellcheck disable=SC2016  # expanded inside the container, not here
vllm_flags_sh='d=$(python3 -c "import os,vllm; print(os.path.dirname(vllm.__file__))" 2>/dev/null) || exit 3
for pat in "disable_uvicorn_access_log" "disable_log_stats" "enable_log_requests: bool = False" "enable_log_outputs: bool = False"; do
	grep -rqsF -- "$pat" "$d" || { echo "missing: $pat"; exit 1; }
done
echo ok'
expect() { # label want-rc want-pattern cmd...
	local label=$1 want=$2 pat=$3; shift 3
	local out rc=0
	out="$("$@" 2>&1)" || rc=$?
	if [[ $rc == "$want" ]] && grep -qE -- "$pat" <<<"$out"; then echo "ok   $label"
	else echo "FAIL $label (rc=$rc)"; tail -5 <<<"$out"; fail=1; fi
}
env=(-e TELLARO_BOOTSTRAP_URL=https://example.invalid -e TELLARO_RUN_ID=00000000-0000-4000-8000-000000000001 -e TELLARO_BOOTSTRAP_TOKEN=x)
expect "no env: refuses to start"      1  'TELLARO_BOOTSTRAP_URL is not set' docker run --rm "$img"
expect "stub redeem stops the start"   78 'STUB: bootstrap redemption'       docker run --rm "${env[@]}" "$img"
expect "keygen writes a 0600 key"      0  '^600 10001'                        docker run --rm "${env[@]}" --entrypoint bash "$img" -c \
	'tellaro-gpu-bootstrap keygen --out /run/tellaro >/dev/null 2>&1 && stat -c "%a %u" /run/tellaro/server.key'
expect "runs as 10001"                 0  '^uid=10001'                        docker run --rm --entrypoint id "$img"
expect "caddy pinned"                  0  '^v2\.11\.9'                        docker run --rm --entrypoint caddy "$img" version
# Full `caddy validate` (needs certs) runs in tests/mtls-guard.sh.
expect "caddy config adapts in image"  0  'require_and_verify'                docker run --rm --entrypoint caddy "$img" adapt --config /etc/tellaro/Caddyfile --adapter caddyfile
expect "vllm logging defaults"        0  '^ok$'                              docker run --rm --entrypoint bash "$img" -c "$vllm_flags_sh"
expect "only 8443 exposed"             0  '^\{"8443/tcp":\{\}\}$'             docker image inspect -f '{{json .Config.ExposedPorts}}' "$img"
if [[ $fail == 0 ]]; then echo "PASS image-smoke"; else echo "FAIL image-smoke"; exit 1; fi
