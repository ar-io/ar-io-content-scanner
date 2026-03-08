FROM python:3.11-slim AS base

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -u 1000 scanner && mkdir -p /app/data && chown scanner:scanner /app/data

COPY xgboost_model.pkl .
COPY src/ src/

USER scanner

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:3100/health')" || exit 1

CMD ["python", "-m", "src.server"]
