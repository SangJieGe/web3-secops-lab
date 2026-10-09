FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for better layer caching
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY contracts ./contracts
COPY config ./config

RUN mkdir -p /app/logs /app/data

# Read-only workload: no privileged capabilities needed
USER nobody

ENTRYPOINT ["web3-secops"]
CMD ["--chain", "ethereum"]
