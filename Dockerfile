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
COPY ml/models/url_phishing_model_clean_v3.joblib ./ml/models/url_phishing_model_clean_v3.joblib
COPY ml/models/sms/sms_phishing_model.joblib ./ml/models/sms/sms_phishing_model.joblib
COPY ml/models/sms/sms_tfidf_vectorizer.joblib ./ml/models/sms/sms_tfidf_vectorizer.joblib
COPY ml/models/email/email_phishing_model.joblib ./ml/models/email/email_phishing_model.joblib
COPY ml/models/email/email_tfidf_vectorizer.joblib ./ml/models/email/email_tfidf_vectorizer.joblib

RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '8000') + '/health')"

CMD ["sh", "-c", "exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]