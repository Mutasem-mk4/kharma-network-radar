# Kharma Evolution - Docker Containerization
# Optimized for high-performance network monitoring

FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive

# Install system dependencies for psutil and scapy
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Install the package in editable mode or as a library
RUN pip install -e .

# Expose the default Kharma Web port
EXPOSE 8085

# Healthcheck to ensure the backend is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8085/api/radar || exit 1

# Default command: launch the web dashboard
# NOTE: Needs --net=host to monitor the host's actual network traffic
CMD ["kharma", "web", "--port", "8085", "--host", "0.0.0.0"]
