# Two images from one source tree.
#   docker build -f sandbox/Dockerfile --target proxy   .   the egress proxy (tiny, no browser)
#   docker build -f sandbox/Dockerfile --target sandbox .   the tracer, with Chromium for browser mode

FROM python:3.12-slim AS proxy
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY sandbox/pyproject.toml ./
COPY sandbox/unhook_sandbox ./unhook_sandbox
# The proxy only needs the standard library, so skip the web dependencies.
RUN pip install --no-deps . && useradd --system --uid 10002 egress
USER egress
EXPOSE 3128
CMD ["unhook-proxy", "--host", "0.0.0.0", "--port", "3128"]

# Keep this tag in step with the playwright version in sandbox/pyproject.toml.
FROM mcr.microsoft.com/playwright/python:v1.56.0-noble AS sandbox
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_BREAK_SYSTEM_PACKAGES=1 HOME=/tmp
WORKDIR /src
COPY sandbox/pyproject.toml ./
COPY sandbox/unhook_sandbox ./unhook_sandbox
RUN pip install ".[browser]"
USER pwuser
EXPOSE 8080
CMD ["unhook-sandbox"]
