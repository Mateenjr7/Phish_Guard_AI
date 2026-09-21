FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY ml/__init__.py ./ml/__init__.py
COPY ml/src/__init__.py ./ml/src/__init__.py
COPY ml/src/features ./ml/src/features

RUN useradd --create-home --uid 10001 appuser \
    && getent passwd appuser

RUN mkdir -p /app/ml/models/sms /app/ml/models/email \
    && python - <<'PY'
import os
import tempfile
import urllib.request

base_url = "https://github.com/Mateenjr7/Phish_Guard_AI/releases/download/models-v1"
artifacts = {
    "url_phishing_model_clean_v3.joblib": "/app/ml/models/url_phishing_model_clean_v3.joblib",
    "sms_phishing_model.joblib": "/app/ml/models/sms/sms_phishing_model.joblib",
    "sms_tfidf_vectorizer.joblib": "/app/ml/models/sms/sms_tfidf_vectorizer.joblib",
    "email_phishing_model.joblib": "/app/ml/models/email/email_phishing_model.joblib",
    "email_tfidf_vectorizer.joblib": "/app/ml/models/email/email_tfidf_vectorizer.joblib",
}
minimum_sizes = {
    "url_phishing_model_clean_v3.joblib": 100 * 1024 * 1024,
    "sms_phishing_model.joblib": 10 * 1024,
    "sms_tfidf_vectorizer.joblib": 100 * 1024,
    "email_phishing_model.joblib": 100 * 1024,
    "email_tfidf_vectorizer.joblib": 1024 * 1024,
}

for filename, destination in artifacts.items():
    url = f"{base_url}/{filename}"
    directory = os.path.dirname(destination)
    file_descriptor, temporary_path = tempfile.mkstemp(dir=directory)
    os.close(file_descriptor)

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "PhishGuard-Docker-Build"},
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is None:
                raise RuntimeError(f"Missing Content-Length for {url}")
            expected_size = int(content_length)
            minimum_size = minimum_sizes[filename]
            if expected_size < minimum_size:
                raise RuntimeError(
                    f"Downloaded artifact is too small: {filename} "
                    f"({expected_size} bytes, expected at least {minimum_size})"
                )

            downloaded_size = 0
            with open(temporary_path, "wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
                    downloaded_size += len(chunk)

        if downloaded_size != expected_size:
            raise RuntimeError(
                f"Incomplete download for {filename}: "
                f"{downloaded_size} of {expected_size} bytes"
            )
        if not os.path.isfile(temporary_path) or downloaded_size <= 0:
            raise RuntimeError(f"Downloaded artifact is empty: {url}")

        os.replace(temporary_path, destination)
        if not os.path.isfile(destination) or os.path.getsize(destination) != downloaded_size:
            raise RuntimeError(f"Downloaded artifact verification failed: {destination}")
        print(f"Downloaded {filename}: {downloaded_size} bytes", flush=True)
    except Exception:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise
PY

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '8000') + '/health')"

CMD ["sh", "-c", "exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]