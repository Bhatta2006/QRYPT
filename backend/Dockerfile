# SVT System Backend - Stage 4 & 5 Compliance Build
FROM python:3.10-slim

WORKDIR /app

# Stage 4 Requirement: GeoIP Build-Time Download
RUN mkdir -p /app/data && \
    apt-get update && apt-get install -y curl tar && \
    curl -L "https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz" \
    | tar -xz --strip-components=1 -C /app/data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
