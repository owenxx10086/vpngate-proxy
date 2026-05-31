FROM python:3.10-slim

# 接收构建参数（默认值用于本地构建）
ARG IMAGE_VERSION=本地构建

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn iproute2 iptables procps curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# 将版本信息写入文件
RUN echo "$IMAGE_VERSION" > /app/version.txt

EXPOSE 8080

CMD ["python", "app/app.py"]
