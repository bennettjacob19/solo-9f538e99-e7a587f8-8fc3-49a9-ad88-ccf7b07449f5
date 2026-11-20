FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APT_REPO_DATA_DIR=/data

# `zstd` is only needed to validate packages whose control/data archives use
# zstd compression when the Python `zstandard` wheel is unavailable. `curl` is
# used by the documented smoke test. `gnupg` provides the `gpg` executable
# that produces the clearsigned InRelease files.
RUN apt-get update \
    && apt-get install -y --no-install-recommends zstd curl gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd --system --uid 10001 --home-dir /srv --shell /usr/sbin/nologin aptrepo \
    && mkdir -p /data \
    && chown -R aptrepo:aptrepo /data /srv

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/status', timeout=2).status == 200 else 1)"]

# A single worker is required: publications serialise through a process lock
# and crash recovery assumes one writer. Reads are async and cheap.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "1", "--proxy-headers", "--no-server-header", "--timeout-keep-alive", "15"]
