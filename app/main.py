
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.url_analyzer import analyze_url, calculate_risk

app = FastAPI(
    title="LinkGuard API",
    description="API for analyzing URL structure and potential risk indicators.",
    version="1.0.0",
)


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.get("/")
def home():
    return {
        "message": "Welcome to LinkGuard API!",
        "docs": "/docs",
    }


@app.post("/analyze")
def analyze(request: URLRequest):
    try:
        analysis = analyze_url(request.url)
        risk = calculate_risk(analysis)

        return {
            "analysis": analysis,
            "risk": risk,
        }
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
