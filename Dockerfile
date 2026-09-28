FROM python:3.11-slim

WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY backend/ ./backend/
COPY datasets/ ./datasets/
COPY models/ ./models/

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    SENTINEL_MODE=cloud \
    PORT=8000

EXPOSE 8000

# Start Uvicorn on 0.0.0.0 with dynamic $PORT support
CMD ["sh", "-c", "uvicorn backend.api.server:app --host 0.0.0.0 --port ${PORT:-8000}"]
