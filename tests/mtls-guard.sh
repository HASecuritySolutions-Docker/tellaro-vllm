#!/usr/bin/env bash
# Guard: the Caddy front refuses any client that does not present a cert
# chaining to the GPU pool client CA, and admits one that does.
#
#   tests/mtls-guard.sh                 run the guard (expect: PASS)
#   MUTATE=1 tests/mtls-guard.sh        weaken client_auth to `request` (expect: FAIL)
#
# Needs docker, openssl and curl. Uses the same Caddy image the Dockerfile pins.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

CADDY_IMAGE="$(sed -n 's/^FROM \(caddy:[^ ]*\) AS caddy$/\1/p' Dockerfile)"
[[ -n "$CADDY_IMAGE" ]] || { echo "could not read the Caddy image from Dockerfile" >&2; exit 2; }
PORT="${PORT:-18443}"
RUN_ID=00000000-0000-4000-8000-000000000001
SNI="$RUN_ID.gpu.tellaro.internal"

work="$(mktemp -d)"
name="tellaro-vllm-mtls-guard-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

pki="$work/pki"; state="$work/run"; mkdir -p "$pki" "$state/tls"
ossl() { openssl "$@" >/dev/null 2>&1; }
mkca() { # name
	ossl ecparam -name prime256v1 -genkey -noout -out "$pki/$1.key"
	ossl req -x509 -new -key "$pki/$1.key" -sha256 -days 2 -subj "/CN=$1" -out "$pki/$1.pem"
}
mkleaf() { # name ca subject ext
	ossl ecparam -name prime256v1 -genkey -noout -out "$pki/$1.key"
	ossl req -new -key "$pki/$1.key" -subj "/CN=$3" -out "$pki/$1.csr"
	printf '%s\n' "$4" >"$pki/$1.ext"
	ossl x509 -req -in "$pki/$1.csr" -CA "$pki/$2.pem" -CAkey "$pki/$2.key" -CAcreateserial \
		-days 1 -sha256 -extfile "$pki/$1.ext" -out "$pki/$1.pem"
}
mkca gpu-pool-ca
mkca rogue-ca
mkleaf server gpu-pool-ca "$RUN_ID" "subjectAltName=DNS:$SNI
extendedKeyUsage=serverAuth"
mkleaf client gpu-pool-ca "tellaro-backend.gpu-client.test" "extendedKeyUsage=clientAuth"
mkleaf rogue rogue-ca "tellaro-backend.gpu-client.test" "extendedKeyUsage=clientAuth"

cp "$pki/server.pem" "$state/tls/server.crt"
cp "$pki/server.key" "$state/tls/server.key"
cp "$pki/gpu-pool-ca.pem" "$state/tls/client-ca.pem"
cp rootfs/etc/tellaro/Caddyfile "$work/Caddyfile"
if [[ "${MUTATE:-0}" == 1 ]]; then
	sed -i 's/mode require_and_verify/mode request/' "$work/Caddyfile"
	echo "MUTATION: client_auth mode -> request"
fi
chmod -R a+rX "$work"; chmod 0777 "$state"

docker_caddy() {
	docker run --rm --user 10001:10001 -e HOME=/tmp \
		-v "$state:/run/tellaro" -v "$work/Caddyfile:/etc/tellaro/Caddyfile:ro" \
		"$@"
}
echo "== caddy validate"
docker_caddy "$CADDY_IMAGE" caddy validate --config /etc/tellaro/Caddyfile --adapter caddyfile 2>&1 | tail -3

docker_caddy -d --name "$name" -p "127.0.0.1:$PORT:8443" \
	"$CADDY_IMAGE" caddy run --config /etc/tellaro/Caddyfile --adapter caddyfile >/dev/null
for _ in $(seq 1 50); do
	(exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
	sleep 0.2
done

# Prints the HTTP status, or "tls-refused" if no HTTP exchange happened.
probe() { # extra curl args...
	local code
	code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
		--resolve "$SNI:$PORT:127.0.0.1" --cacert "$pki/gpu-pool-ca.pem" \
		"$@" "https://$SNI:$PORT/v1/models" 2>/dev/null)" || code=""
	[[ -n "$code" && "$code" != 000 ]] && echo "$code" || echo tls-refused
}

fail=0
check() { # label want got
	if [[ "$2" == "$3" || ( "$2" == http && "$3" =~ ^[0-9]{3}$ ) ]]; then
		echo "ok   $1: $3"
	else
		echo "FAIL $1: want $2, got $3"; fail=1
	fi
}
check "no client cert"        tls-refused "$(probe)"
check "cert from another CA"  tls-refused "$(probe --cert "$pki/rogue.pem" --key "$pki/rogue.key")"
check "GPU pool CA client"    http        "$(probe --cert "$pki/client.pem" --key "$pki/client.key")"

if [[ $fail == 0 ]]; then echo "PASS mtls-guard"; else echo "FAIL mtls-guard"; exit 1; fi
