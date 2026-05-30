FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn iproute2 iptables procps curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8080

# 容器启动时需要 --cap-add=NET_ADMIN --device=/dev/net/tun
CMD ["python", "app/app.py"]
