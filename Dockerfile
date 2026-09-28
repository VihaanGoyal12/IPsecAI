FROM python:3.11-slim

# Install system dependencies (including optional tshark and network utilities)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose Streamlit and FastAPI ports
EXPOSE 8501 8000

# Default command starts Streamlit UI
CMD ["streamlit", "run", "app/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
