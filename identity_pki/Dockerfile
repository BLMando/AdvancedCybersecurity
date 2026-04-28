FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IDENTITY_APP_HOST=0.0.0.0 \
    IDENTITY_APP_PORT=8080 \
    ZTA_PKI_DATA_DIR=/data/certs

COPY identity_pki/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY identity_pki /app/identity_pki

RUN mkdir -p /data/certs

WORKDIR /app

EXPOSE 8080

CMD ["python", "-m", "identity_pki.app"]
