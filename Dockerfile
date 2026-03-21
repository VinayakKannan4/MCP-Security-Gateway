FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# --- Step 1: install dependencies only (cached layer) ---
# --no-install-project skips building the local package so we don't need
# README.md / LICENSE yet. Layer is invalidated only when lockfile changes.
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-dev --frozen --no-install-project

# --- Step 2: copy source + metadata, then install the project itself ---
COPY LICENSE README.md alembic.ini ./
COPY gateway/ ./gateway/
COPY policies/ ./policies/
RUN uv sync --no-dev --frozen

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
