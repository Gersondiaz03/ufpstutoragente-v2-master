# Dockerfile for Azure AI Foundry Agent Backend
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements-v2.txt requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY agent_v2_simple.py .

# Expose port
EXPOSE 8100

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=8100
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8100/health || exit 1

# Run the application (use --workers 1 for better stability with Azure SDK)
CMD ["uvicorn", "agent_v2_simple:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "1"]
