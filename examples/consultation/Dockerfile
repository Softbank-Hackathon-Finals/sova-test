# Same multi-platform base and locked dependencies for source and destination.
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && groupadd --gid 10001 consultation \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin consultation \
    && mkdir -p /data/objects \
    && chown -R 10001:10001 /data \
    && chmod 700 /data /data/objects
COPY --chown=10001:10001 __init__.py storage.py objects.py telemetry.py private_files.py service.py /app/consultation/
COPY --chown=10001:10001 web/index.html web/app.js web/style.css /app/consultation/web/
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import os,urllib.request,urllib.parse; origin=os.environ['CONSULTATION_ORIGIN']; request=urllib.request.Request('http://127.0.0.1:8080/health',headers={'Host':urllib.parse.urlsplit(origin).netloc}); urllib.request.urlopen(request,timeout=3).read(4096)"]
CMD ["python", "-m", "uvicorn", "consultation.service:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--no-proxy-headers", "--limit-concurrency", "32", "--backlog", "128", "--timeout-keep-alive", "5", "--timeout-graceful-shutdown", "8", "--ws-max-size", "16384", "--ws-max-queue", "8"]
