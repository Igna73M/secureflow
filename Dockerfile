FROM node:22-bookworm-slim

ENV NODE_ENV=production
ENV SECUREFLOW_HOST=0.0.0.0
ENV SECUREFLOW_PYTHON=/opt/secureflow-venv/bin/python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/secureflow-venv/bin:${PATH}"

WORKDIR /app

# Python scanners and native Node modules may require build tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python scanner dependencies into an isolated environment.
COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/secureflow-venv \
    && /opt/secureflow-venv/bin/pip install --no-cache-dir -r requirements.txt

# Install and build the React dashboard.
COPY dashboard/package.json dashboard/package-lock.json /app/dashboard/
WORKDIR /app/dashboard
RUN npm ci
COPY dashboard/ /app/dashboard/
RUN npm run build

# Install API runtime dependencies.
WORKDIR /app/api
COPY api/package.json api/package-lock.json /app/api/
RUN npm ci --omit=dev

# Copy the application, scanner engine, and local Semgrep rules.
WORKDIR /app
COPY api/ /app/api/
COPY engine/ /app/engine/
COPY rules/ /app/rules/
COPY fixtures/ /app/fixtures/

EXPOSE 10000

CMD ["node", "api/src/server.js"]
