FROM python:3.11-slim
RUN groupadd -r mesh && useradd -r -g mesh mesh
RUN for i in 1 2 3 4 5; do apt-get update && apt-get install -y procps && break || sleep 3; done && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/worker/requirements.txt .
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ && pip install --no-cache-dir -r requirements.txt
COPY services/worker/ .
ENV PYTHONPATH=/app
USER mesh
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=15s \
    CMD pgrep -f 'app.worker' || exit 1
CMD ["python", "-u", "app/worker.py"]
