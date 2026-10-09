"""
FastAPI backend for Aadhaar verification.

Zero-retention: uploaded images are written to a temp file, processed,
and immediately deleted. No PII is logged or persisted.
"""
from __future__ import annotations

import tempfile
import os
import json
from datetime import datetime

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aadhar_verify.main import run_pipeline

app = FastAPI(
    title="Aadhaar Verify API",
    description="Upload an Aadhaar card photo and verify it against registration details.",
    version="1.0.0",
)

# Allow React dev server (localhost:5173) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

CERT_PATH = os.path.join(os.path.dirname(__file__), "keys", "uidai_qr_signing_cert.cer")


@app.post("/api/verify")
async def verify(
    aadhaar_image: UploadFile = File(...),
    expected_name: str = Form(""),
    expected_dob: str = Form(""),
):
    """
    Verify an Aadhaar card image.

    - **aadhaar_image**: PNG or JPEG photo of the Aadhaar card.
    - **expected_name**: Name from registration (for cross-check). Optional.
    - **expected_dob**: DOB from registration as DD-MM-YYYY (for cross-check). Optional.
    """
    # Validate file type
    content_type = aadhaar_image.content_type or ""
    if content_type not in ("image/jpeg", "image/png", "image/jpg"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{content_type}'. Only JPEG and PNG are accepted.",
        )

    # Read file into memory
    image_bytes = await aadhaar_image.read()
    if len(image_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(image_bytes) > 10 * 1024 * 1024:  # 10 MB limit
        raise HTTPException(status_code=400, detail="File too large. Max 10 MB.")

    # Write to temp file, process, then delete
    suffix = ".jpg" if "jpeg" in content_type or "jpg" in content_type else ".png"
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    try:
        tmp.write(image_bytes)
        tmp.flush()
        tmp.close()

        # Run the existing pipeline
        result = run_pipeline(
            image_path=tmp.name,
            cert_path=CERT_PATH,
            expected_name=expected_name.strip() or None,
            expected_dob=expected_dob.strip() or None,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")
    finally:
        # Zero-retention: always delete the temp file
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    return JSONResponse(content=json.loads(json.dumps(result, default=str)))


@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}
