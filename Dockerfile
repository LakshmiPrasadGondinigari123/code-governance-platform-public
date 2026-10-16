FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# local language-model NER agent (no API key, no network at run time)
RUN pip install --no-cache-dir "spacy==3.7.5" \
    "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl"

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts
# release gate 1: every Python file must compile, otherwise this build fails and the running version stays up
RUN python -m compileall -q app
# release gate 2: the automated tests must pass, otherwise this build fails and the running version stays up
RUN pip install --no-cache-dir pytest==8.0.0 \
    && python -m pytest -q tests

RUN useradd --create-home --uid 10001 appuser && mkdir -p /data && chown -R appuser /data
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/liveness' % os.getenv('PORT','8000'))" || exit 1

# Railway injects $PORT; default 8000 locally.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
