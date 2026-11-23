FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRAIL_HOST=0.0.0.0 \
    TRAIL_PORT=8080 \
    TRAIL_DB_PATH=/app/data/trail.db \
    TRAIL_SEEDS_PATH=/app/config/seeds.txt

WORKDIR /app

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends util-linux parted e2fsprogs git ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 trailgroup && \
    useradd --uid 10001 --gid trailgroup --shell /usr/sbin/nologin --no-create-home trailuser && \
    mkdir -p /app/data /app/config && \
    chown -R trailuser:trailgroup /app

COPY --chown=trailuser:trailgroup trail /app/trail
COPY --chown=trailuser:trailgroup config/seeds.txt /app/config/seeds.txt
COPY --chown=trailuser:trailgroup openapi.yaml /app/openapi.yaml

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import sys, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3); sys.exit(0 if r.status == 200 else 1)"

CMD ["python", "-m", "trail.main"]
