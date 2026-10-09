FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# System dependencies for pentest tools, Playwright, and WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    git \
    unzip \
    whatweb \
    sqlmap \
    nikto \
    ffuf \
    exploitdb \
    ca-certificates \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based recon tools (optional — build continues if download fails)
COPY docker/install-tools.sh /tmp/install-tools.sh
RUN sed -i 's/\r$//' /tmp/install-tools.sh && bash /tmp/install-tools.sh

# Install gobuster
RUN apt-get update && apt-get install -y --no-install-recommends gobuster \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Bounded content-discovery and command-injection adapters. Pin dirsearch and
# Commix revisions so image rebuilds do not silently change scanner behavior.
RUN pip install --no-cache-dir dirsearch==0.4.3 \
    && git clone --depth 1 --branch v4.1 https://github.com/commixproject/commix.git /opt/commix \
    && chmod 0755 /opt/commix/commix.py \
    && ln -s /opt/commix/commix.py /usr/local/bin/commix

# Install Playwright Chromium
RUN playwright install chromium --with-deps

# Copy application code
COPY backend/ /app/backend/
COPY templates/ /app/templates/

# Create volume mount directories
RUN mkdir -p /app/reports /app/db /app/config /app/screenshots

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--limit-max-requests", "10485760", "--limit-concurrency", "100"]
