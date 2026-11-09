# tellaro-vllm

`hasecuritysolutions/tellaro-vllm`: the image Tellaro runs on RunPod GPU pods.
Design: tellaro-docs `internal/platform/runpod-gpu-pools.md` (sections 2, 3.3, 3.4).

```
backend ── mTLS ──► :8443 Caddy ──► 127.0.0.1:8000  vLLM (--api-key, no request logging)
                         └─ /_tellaro/* ──► 127.0.0.1:8001  tellaro-gpu-bootstrap (renew, health)
```

- Base: `vllm/vllm-openai` and `caddy`, both pinned by tag and digest in the `Dockerfile`.
- Only 8443/tcp is exposed. Every request needs a client cert from the GPU pool CA.
- The pod's `env` carries only `TELLARO_BOOTSTRAP_URL`, `TELLARO_RUN_ID` and
  `TELLARO_BOOTSTRAP_TOKEN`. Certs, the vLLM API key, the HF token and the launch
  profile come from the sealed bootstrap answer.
- Runs as uid 10001. The Dockerfile has no `RUN` step, so CI never unpacks the base.

**Bootstrap:** `tellaro-gpu-bootstrap redeem` follows the wire contract of
tellaro-backend#3047 (B3). It retries `425`/`429`/`5xx` until the token's 30-minute
TTL, checks that the answer's run, server name, port and leaf key are this pod's,
opens the `seal_v2` raw-key values with the pod key, and turns the launch profile
into `vllm serve` arguments (a `checkpoint` is served under the model id). A
refusal exits 78 and a bad answer exits 1, both before anything listens.
Renewal: `POST /_tellaro/renew` returns `{"csr"}` for a fresh key, and
`POST /_tellaro/renew/certificate` takes `{"certificate_chain", "client_ca_bundle"}`
for that key only, swaps the files and reloads Caddy over its admin socket (a
failed reload exits the pod, so the run is replaced).

## Tests

```sh
docker run --rm -i hadolint/hadolint:v2.12.0 < Dockerfile
python3 tests/bootstrap_test.py # redeem/renew/seal against a fake backend (needs `cryptography`)
tests/mtls-guard.sh             # Caddy validate + mTLS refusal guard (pulls only the Caddy image)
MUTATE=1 tests/mtls-guard.sh    # must FAIL: client_auth weakened to `request`
tests/image-smoke.sh            # builds the full image (~10 GB base): build host only
```

## Publishing

`.github/workflows/docker-image.yml` builds linux/amd64 on PRs, and on pushes to
`main`/`dev` and tags it pushes to Docker Hub and writes the digest to the job
summary. Runs are pinned to that digest, never to a tag.
