FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn iproute2 iptables procps curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8080

CMD ["python", "app/app.py"]
