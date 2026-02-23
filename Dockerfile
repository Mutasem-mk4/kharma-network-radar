# Dockerfile for Kharma Network Radar
FROM python:3.12-slim

# Install system dependencies required for packet capture and networking utilities
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libpcap-dev \
    iproute2 \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirement files first for layer caching
COPY requirements.txt .

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the default web dashboard port
EXPOSE 8085

# Define the entry point
ENTRYPOINT ["python", "-m", "kharma"]

# Default command specifies starting the web dashboard
CMD ["web", "--host", "0.0.0.0", "--port", "8085"]
