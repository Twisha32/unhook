# Build from the repository root: docker build -f backend/Dockerfile .
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set to "llm" to include the Anthropic client for LLM-written case notes.
ARG EXTRAS=""

WORKDIR /app
COPY backend /src/backend
RUN pip install "/src/backend${EXTRAS:+[$EXTRAS]}" && rm -rf /src/backend/build

# The sample messages double as a smoke test: `unhook samples`.
COPY samples /app/samples

RUN useradd --system --uid 10001 --home-dir /app unhook \
    && mkdir -p /app/data /app/eval /app/model \
    && chown -R unhook /app
USER unhook

ENV UNHOOK_MODEL_PATH=/app/model/model.json
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --start-period=20s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["uvicorn", "unhook.main:app", "--host", "0.0.0.0", "--port", "8000"]
