# Build: podman build --format docker -t localhost/arialog-mcp:0.1.0 .
FROM docker.io/library/python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    ARIALOG_TRANSPORT=http \
    ARIALOG_HTTP_HOST=0.0.0.0 \
    ARIALOG_HTTP_PORT=8000

RUN pip install --no-cache-dir uv==0.10.9 \
 && useradd --system --uid 10001 --home-dir /app app
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --python 3.12 --no-managed-python \
 && chown -R app:app /app
USER app

EXPOSE 8000
# Liveness only (never calls VRLI). ProxyHandler({}) ignores any proxy env passed in by Podman.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request as u; u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:%s/healthz' % os.environ['ARIALOG_HTTP_PORT'], timeout=3)"]
ENTRYPOINT ["arialog-mcp"]
