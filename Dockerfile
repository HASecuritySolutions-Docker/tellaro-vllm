# tellaro-vllm: vLLM behind a Caddy mTLS front, for Tellaro RunPod GPU pools.
# Design: tellaro-docs internal/platform/runpod-gpu-pools.md (sections 2, 3.3, 3.4).
#
# Only the Caddy port (8443) is exposed. vLLM listens on 127.0.0.1:8000 and the
# bootstrap helper on 127.0.0.1:8001; neither is reachable from outside the pod.
#
# The image is COPY-only on top of the vLLM base on purpose: with no RUN step,
# BuildKit never has to unpack the ~20 GB base on the CI runner, and the push
# cross-repo-mounts the base layers on Docker Hub instead of re-uploading them.

# Both bases are pinned by tag and index digest. Bump them together with a
# test run; the bot does not track these.
FROM caddy:2.11.9@sha256:0c2243efcf437ab7f7a978f1027fcf0d4f9be8a75df27b1b3fbc5dbe0ffa8cf0 AS caddy

FROM vllm/vllm-openai:v0.33.0@sha256:d825baf9ce4b1b6bfc5ecc7b79880c7e6748c65a72d697ce3d47607aafa84c6e

LABEL org.opencontainers.image.title="tellaro-vllm" \
      org.opencontainers.image.description="vLLM behind a Caddy mTLS terminator for Tellaro GPU pools" \
      org.opencontainers.image.source="https://github.com/HASecuritySolutions-Docker/tellaro-vllm" \
      org.opencontainers.image.vendor="H&A Security Solutions"

COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
# Whole directory: BuildKit gives a parent dir it creates the same --chmod.
COPY --chmod=0555 rootfs/etc/tellaro/ /etc/tellaro/
COPY --chmod=0555 rootfs/usr/local/bin/tellaro-entrypoint /usr/local/bin/tellaro-entrypoint
COPY --chmod=0555 rootfs/usr/local/bin/tellaro-gpu-bootstrap /usr/local/bin/tellaro-gpu-bootstrap
# Writable state for the unprivileged user: /run/tellaro (keys, certs, sockets)
# and /var/lib/tellaro (HOME, HF cache). Created by COPY so no RUN is needed.
COPY --chown=10001:10001 --chmod=0700 rootfs/run/tellaro/ /run/tellaro/
COPY --chown=10001:10001 --chmod=0700 rootfs/var/lib/tellaro/ /var/lib/tellaro/

# No passwd entry exists for 10001 (that would need a RUN step); USER/LOGNAME
# let getpass.getuser() and friends resolve a name without one.
ENV HOME=/var/lib/tellaro \
    USER=tellaro \
    LOGNAME=tellaro \
    HF_HOME=/var/lib/tellaro/hf \
    XDG_CONFIG_HOME=/var/lib/tellaro/.config \
    XDG_DATA_HOME=/var/lib/tellaro/.local/share \
    VLLM_NO_USAGE_STATS=1 \
    DO_NOT_TRACK=1 \
    VLLM_LOGGING_LEVEL=WARNING \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
WORKDIR /var/lib/tellaro
EXPOSE 8443/tcp

ENTRYPOINT ["/usr/local/bin/tellaro-entrypoint"]
