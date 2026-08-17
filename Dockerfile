# janus-mcp container image.
#
# Dependency resolution honors uv.lock exactly: the builder exports it as a
# hash-pinned requirements file, and the runtime stage installs with
# --require-hashes plus the project wheel with --no-deps. Base images are
# pinned by digest (Dependabot proposes updates).
#
# Runs as a non-root user; the entrypoint is the janus-mcp CLI, defaulting to
# `serve` on stdio. Mount a kubeconfig and config read-only, and the state
# directory read-write if you use out-of-band approvals or want the audit log
# on the host:
#
#   docker run -i --rm \
#     -v ~/.kube/config:/home/janus/.kube/config:ro \
#     -v ~/.config/janus-mcp:/home/janus/.config/janus-mcp:ro \
#     -v ~/.local/state/janus-mcp:/home/janus/.local/state/janus-mcp \
#     ghcr.io/tonylchang/janus-mcp:latest

FROM ghcr.io/astral-sh/uv@sha256:531f855bda2c73cd6ef67d56b733b357cea384185b3022bd09f05e002cd144ca AS builder
# ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt \
        -o /requirements.txt \
    && uv build --wheel -o /dist

FROM python@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1
# python:3.13-slim-bookworm
COPY --from=builder /requirements.txt /tmp/requirements.txt
COPY --from=builder /dist /tmp/dist
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && pip install --no-cache-dir --no-deps /tmp/dist/*.whl \
    && rm -rf /tmp/dist /tmp/requirements.txt \
    && useradd --create-home --uid 10001 janus
USER janus
WORKDIR /home/janus
# stdio transport: stdout is the MCP channel, logs go to stderr
ENTRYPOINT ["janus-mcp"]
CMD ["serve"]
