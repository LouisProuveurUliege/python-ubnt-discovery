FROM python:3.12.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install scapy libpcap

COPY ubnt_discovery.py LICENSE /app/

EXPOSE 10001/udp 34053/udp

ENTRYPOINT [ "python3", "/app/ubnt_discovery.py" ]
