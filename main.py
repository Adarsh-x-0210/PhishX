"""
PhishX - FastAPI Application Backend
Serves RESTful endpoints for multi-vector phishing detection (URL, Email, QR Code)
with interactive OpenAPI / Swagger documentation at /docs.
"""

from typing import Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from lib.detector import analyze_url
from lib.email_detector import analyze_email
from lib.qr_detector import analyze_qr_code

app = FastAPI(
    title="PhishX API",
    description="Multi-Vector Phishing Detection System using Heuristics, Typosquatting String Matching, and Machine Learning.",
    version="1.0.0"
)

# Enable CORS for Next.js frontend or external integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UrlRequest(BaseModel):
    url: str = Field(..., example="https://paypal.com.verify-login.xyz")


class EmailRequest(BaseModel):
    from_header: Optional[str] = Field(None, example="PayPal Support <service@paypa1-security.xyz>")
    reply_to: Optional[str] = Field(None, example="attacker@gmail.com")
    return_path: Optional[str] = Field(None, example="bounce@paypa1-security.xyz")
    subject: Optional[str] = Field(None, example="URGENT: Your account has been suspended")
    body: Optional[str] = Field(None, example="Please confirm your login immediately: http://paypal.com.verify-login.xyz")
    raw_email: Optional[str] = Field(None, description="Optional raw RFC 822 email format")


class QRBase64Request(BaseModel):
    image: str = Field(..., description="Base64 encoded image string (or data URI)")


@app.get("/")
@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "system": "PhishX Multi-Vector Phishing Detection System",
        "version": "1.0.0",
        "vectors": ["URL", "Email", "QR Code"],
        "ml_engine": "Random Forest + TF-IDF Naive Bayes"
    }


@app.post("/api/url")
def scan_url(req: UrlRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL is required.")
    return analyze_url(req.url)


@app.post("/api/email")
def scan_email(req: EmailRequest):
    return analyze_email(
        from_header=req.from_header or "",
        reply_to=req.reply_to or "",
        return_path=req.return_path or "",
        subject=req.subject or "",
        body=req.body or "",
        raw_email=req.raw_email
    )


@app.post("/api/qr")
async def scan_qr_upload(file: Optional[UploadFile] = File(None)):
    if not file:
        raise HTTPException(status_code=400, detail="Image file is required.")
    contents = await file.read()
    res = analyze_qr_code(image_bytes=contents)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to decode QR code."))
    return res


@app.post("/api/qr/base64")
def scan_qr_base64(req: QRBase64Request):
    res = analyze_qr_code(base64_str=req.image)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to decode QR code."))
    return res


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
