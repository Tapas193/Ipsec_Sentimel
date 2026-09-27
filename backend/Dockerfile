# IPsec Sentinel — backend image (Phase 1)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install the package (pulls all runtime dependencies from pyproject.toml).
COPY pyproject.toml ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app

RUN pip install .

EXPOSE 8000

# Migrations are run by docker-compose before the server starts.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]