# NirapodNet — single-server LAN deployment (Phase 3).
# Build: docker build -t nirapodnet .
# Run (plain HTTP, trusted LAN only):
#   docker run -p 8000:8000 -v nirapodnet-data:/app/data nirapodnet
# Run with TLS and a persistent database:
#   docker run -p 8000:8000 -v nirapodnet-data:/app/data \
#     -v /path/to/cert.pem:/app/cert.pem:ro \
#     -v /path/to/key.pem:/app/key.pem:ro \
#     -e NIRAPODNET_DB=sqlite:////app/data/nirapodnet.db \
#     -e NIRAPODNET_HTTPS=1 \
#     -e NIRAPODNET_SIGNING_KEY=<a-long-random-secret> \
#     nirapodnet \
#     uvicorn app.main:app --host 0.0.0.0 --port 8000 \
#       --ssl-certfile /app/cert.pem --ssl-keyfile /app/key.pem
# The admin bootstrap needs NIRAPODNET_ADMIN_USERNAME and
# NIRAPODNET_ADMIN_PASSWORD on first start. Never bake
# secrets, certificates or a database file into the image.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]