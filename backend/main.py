from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ml_service import predict_url
from sms_risk import calculate_sms_risk
from email_risk import calculate_email_risk
from risk_engine import analyze_rules, calculate_risk


# =========================================================
# App
# =========================================================

app = FastAPI(
    title="PhishGuard AI API",
    version="1.0.0",
    description=(
        "Phishing and scam detection API using "
        "machine learning + rule-based analysis."
    ),
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# Request schemas
# =========================================================


class URLAnalysisRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=3,
        max_length=4096,
    )


class SMSAnalysisRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
    )


class EmailAnalysisRequest(BaseModel):
    subject: str = Field(
        default="",
        max_length=1000,
    )
    body: str = Field(
        default="",
        max_length=100000,
    )


# =========================================================
# Health endpoint
# =========================================================


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "PhishGuard AI",
        "ml_models": [
            "Clean V3 structural URL model",
            "TF-IDF + Logistic Regression SMS model",
            "TF-IDF + Logistic Regression Email model",
        ],
    }


# =========================================================
# URL analysis
# =========================================================


@app.post("/api/analyze/url")
def analyze_url(request: URLAnalysisRequest):

    url = request.url.strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty.",
        )

    try:
        # ML prediction
        ml_result = predict_url(url)

        # Rule analysis
        rule_result = analyze_rules(url)

        # Combined risk
        risk_result = calculate_risk(
            ml_probability=ml_result["phishing_probability"],
            rule_result=rule_result,
        )

        return {
            "url": url,
            "prediction": {
                "ml_probability": ml_result[
                    "phishing_probability"
                ],
                "ml_label": (
                    "phishing"
                    if ml_result["prediction"] == 1
                    else "legitimate"
                ),
            },
            "risk": risk_result,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


# =========================================================
# SMS analysis
# =========================================================


@app.post("/api/analyze/sms")
def analyze_sms(request: SMSAnalysisRequest):

    text = request.text.strip()

    if not text:
        raise HTTPException(
            status_code=400,
            detail="SMS text cannot be empty.",
        )

    try:
        result = calculate_sms_risk(text)

        return {
            "text": text,
            "prediction": {
                "ml_probability": result[
                    "ml_probability"
                ],
                "ml_label": result["ml_label"],
            },
            "risk": {
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "ml_probability": result[
                    "ml_probability"
                ],
                "rule_score": result["rule_score"],
                "indicators": result["indicators"],
            },
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


# =========================================================
# Email analysis
# =========================================================


@app.post("/api/analyze/email")
def analyze_email(request: EmailAnalysisRequest):

    subject = request.subject.strip()
    body = request.body.strip()

    if not subject and not body:
        raise HTTPException(
            status_code=400,
            detail="Email subject or body cannot be empty.",
        )

    try:
        result = calculate_email_risk(
            subject,
            body,
        )

        return {
            "subject": subject,
            "body": body,
            "prediction": {
                "ml_probability": result[
                    "ml_probability"
                ],
                "ml_label": result["ml_label"],
            },
            "risk": {
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "ml_probability": result[
                    "ml_probability"
                ],
                "rule_score": result["rule_score"],
                "indicators": result["indicators"],
            },
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


# =========================================================
# Root
# =========================================================


@app.get("/")
def root():
    return {
        "message": "PhishGuard AI API",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "url_analysis": "/api/analyze/url",
            "sms_analysis": "/api/analyze/sms",
            "email_analysis": "/api/analyze/email",
        },
    }