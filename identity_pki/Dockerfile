FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app/identity_pki

RUN mkdir -p /data/certs

WORKDIR /app

EXPOSE 8080

CMD ["python", "-m", "identity_pki.app"]
