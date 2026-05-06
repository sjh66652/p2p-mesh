FROM python:3.11-slim
RUN groupadd -r mesh && useradd -r -g mesh mesh
RUN for i in 1 2 3 4 5; do apt-get update && apt-get install -y curl procps && break || sleep 3; done && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/auth-service/requirements.txt .
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ && pip install --no-cache-dir -r requirements.txt
COPY services/shared/app /app/shared/app
ENV PYTHONPATH=/app
COPY services/auth-service/ .
USER mesh
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=10s --retries=10 --start-period=30s \
    CMD curl -f http://localhost:8000/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
