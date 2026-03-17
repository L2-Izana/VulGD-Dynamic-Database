# ---------------------------
# FastAPI Backend
# ---------------------------
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY app ./app

# Expose port
EXPOSE 8000

# Run FastAPI (production-ready)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]