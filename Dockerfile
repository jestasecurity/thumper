# ── Stage 1: build the React UI ──────────────────────────────────────────────
FROM node:26-alpine AS ui
WORKDIR /ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# ── Stage 2: the monolith (FastAPI + bundled UI) ─────────────────────────────
FROM python:3.14-slim
WORKDIR /app

COPY pyproject.toml README.md ./
COPY server/ ./server/
COPY plugins/ ./plugins/
COPY agent/ ./agent/
RUN pip install --no-cache-dir ".[postgres,mysql]"

COPY --from=ui /ui/dist ./ui/dist

ENV PYTHONPATH=/app/server \
    THUMPER_BASE_URL=http://localhost:8000 \
    THUMPER_DB=/app/data/thumper.db
RUN mkdir -p /app/data

EXPOSE 8000
CMD ["uvicorn", "thumper.main:app", "--host", "0.0.0.0", "--port", "8000"]
