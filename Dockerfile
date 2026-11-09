FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 OLFA_DB=/data/olfa_intel.db
# Pinned versions: create requirements.lock on the PC where the model works (see DEPLOY.md).
# The saved models are pickles, so scikit-learn and xgboost must match the training versions.
COPY requirements.txt requirements.lock* ./
RUN if [ -f requirements.lock ]; then pip install --no-cache-dir -r requirements.lock; \
    else pip install --no-cache-dir fastapi "uvicorn[standard]" requests cryptography tldextract numpy xgboost scikit-learn joblib; fi
COPY . .
RUN useradd -m olfa && mkdir -p /data && cp -n olfa_intel.db /data/olfa_intel.db; chown -R olfa /data /app
USER olfa
EXPOSE 8790
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
  CMD python -c "import urllib.request,json;assert json.load(urllib.request.urlopen('http://127.0.0.1:8790/health'))['ok']" || exit 1
# One worker: the rate limiter is in memory and the community database is SQLite.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8790", "--proxy-headers", "--forwarded-allow-ips", "*"]
