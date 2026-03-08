FROM python:3.11-slim AS base

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 scanner

COPY xgboost_model.pkl .
COPY src/ src/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:3100/health')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "-m", "src.server"]
