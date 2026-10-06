FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    APP_HOST=0.0.0.0 \
    APP_ENV=production \
    CAPTURE_ENABLED=false \
    DATABASE_PATH=/app/data/network_analyzer.db

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY backend/app /app/backend/app
COPY frontend /app/frontend
RUN mkdir -p /app/data

EXPOSE 8000

# Railway supplies PORT at runtime. Shell form expands it before Uvicorn starts.
CMD ["sh", "-c", "exec uvicorn app.main:app --app-dir /app/backend --host 0.0.0.0 --port ${PORT:-8000}"]
