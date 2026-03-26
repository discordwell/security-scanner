FROM python:3.12-slim AS builder

RUN pip install uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ src/
COPY scripts/ scripts/
COPY data/yara_rules/ data/yara_rules/
COPY alembic.ini ./
RUN uv sync --frozen --no-dev


FROM python:3.12-slim

RUN groupadd -r scanner && useradd -r -g scanner scanner

WORKDIR /app
COPY --from=builder /app /app

RUN mkdir -p data/artifacts data/runtime && chown -R scanner:scanner data/

USER scanner

ENV PATH="/app/.venv/bin:$PATH"
ENV SCANNER_DATA_DIR=/app/data
ENV SCANNER_ARTIFACT_DIR=/app/data/artifacts
ENV SCANNER_RUNTIME_DIR=/app/data/runtime

EXPOSE 8000

CMD ["uvicorn", "security_scanner.api:app", "--host", "0.0.0.0", "--port", "8000"]
