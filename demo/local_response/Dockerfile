FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
WORKDIR /app
COPY requirements.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
ARG RELEASE=v1
ENV RELEASE=$RELEASE PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY workload.py /app/workload.py
USER 10001:10001
EXPOSE 8080
CMD ["python", "/app/workload.py"]
