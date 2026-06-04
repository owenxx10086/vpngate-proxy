FROM python:3.10-slim

ARG IMAGE_VERSION=本地构建

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn iproute2 iptables procps curl iputils-ping tzdata \
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN echo "$IMAGE_VERSION" > /app/version.txt

LABEL org.opencontainers.image.description "1、修复SOCKS5资源不释放导致连接失败 \n 2、优化SOCKS5资源释放 \n 3、新增自定义SOCKS5最大并发量"


EXPOSE 8080

CMD ["python", "app/app.py"]
