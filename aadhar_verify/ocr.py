"""
OCR text extraction and pattern matching for Aadhaar card images.

Extracts printed text, card numbers, dates of birth, and names from Aadhaar cards,
and provides fuzzy cross-matching against registration data and Secure QR data.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
import cv2
import pytesseract

# Configure Tesseract path on Windows
TESSERACT_EXE = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(TESSERACT_EXE):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_EXE

AADHAAR_NUMBER_RE = re.compile(r"\b(\d{4})\s?(\d{4})\s?(\d{4})\b")
DOB_RE = re.compile(r"\b(\d{2}[/\-.]\d{2}[/\-.]\d{4})\b")
YOB_RE = re.compile(r"\b(19\d{2}|20\d{2})\b")
GENDER_RE = re.compile(r"\b(MALE|FEMALE|TRANSGENDER|\u092a\u0941\u0930\u0941\u0937|\u092e\u0939\u093f\u0932\u093e)\b", re.IGNORECASE)

GOV_HEADER_RE = re.compile(
    r"government\s+of\s+india"
    r"|gov[\w.]*\s*of\s*[il!|1]ndia"
    r"|\u092d\u093e\u0930\u0924\s*\u0938\u0930\u0915\u093e\u0930"
    r"|Government",
    re.IGNORECASE,
)
UIDAI_RE = re.compile(
    r"\bUIDAI\b"
    r"|un[il!|1]que\s+[il!|1]dent[il!|1]f[il!|1]cat[il!|1]on"
    r"|uidai\.gov\.in"
    r"|\u0906\u0927\u093e\u0930",
    re.IGNORECASE,
)


@dataclass
class OcrResult:
    text: str
    detected_name: str | None
    detected_dob: str | None
    detected_gender: str | None
    masked_aadhaar_number: str | None
    has_aadhaar_markers: bool

    def to_dict(self) -> dict:
        return {
            "detected_name": self.detected_name,
            "detected_dob": self.detected_dob,
            "detected_gender": self.detected_gender,
            "masked_aadhaar_number": self.masked_aadhaar_number,
            "has_aadhaar_markers": self.has_aadhaar_markers,
            "text_snippet": self.text[:200] if self.text else "",
        }


def extract_ocr(image_path: str) -> OcrResult:
    """Run OCR on the image and extract structured card fields."""
    raw = cv2.imread(image_path)
    if raw is None:
        return OcrResult("", None, None, None, None, False)

    # 1. Raw OCR
    try:
        text_raw = pytesseract.image_to_string(raw)
    except Exception:
        text_raw = ""

    # 2. Adaptive threshold preprocessing
    try:
        gray = cv2.cvtColor(raw, cv2.COLOR_BGR2GRAY)
        gray = cv2.bilateralFilter(gray, 9, 75, 75)
        thresh = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 11
        )
        text_thresh = pytesseract.image_to_string(thresh)
    except Exception:
        text_thresh = ""

    # 3. Hindi + English attempt
    try:
        text_hin = pytesseract.image_to_string(raw, lang="hin+eng")
    except Exception:
        text_hin = ""

    combined_text = "\n".join([text_raw, text_thresh, text_hin])

    # Extract masked Aadhaar number
    masked_num = None
    num_match = AADHAAR_NUMBER_RE.search(combined_text)
    if num_match:
        last4 = num_match.group(3)
        masked_num = f"XXXX XXXX {last4}"

    # Extract DOB
    detected_dob = None
    dob_match = DOB_RE.search(combined_text)
    if dob_match:
        detected_dob = dob_match.group(1).replace("/", "-").replace(".", "-")

    # Extract Gender
    detected_gender = None
    gender_match = GENDER_RE.search(combined_text)
    if gender_match:
        g = gender_match.group(1).upper()
        if g in ("MALE", "पुरुष"):
            detected_gender = "MALE"
        elif g in ("FEMALE", "महिला"):
            detected_gender = "FEMALE"
        else:
            detected_gender = g

    # Extract Name candidate if possible (line before DOB)
    detected_name = _extract_name_candidate(combined_text)

    has_markers = bool(GOV_HEADER_RE.search(combined_text) or UIDAI_RE.search(combined_text))

    return OcrResult(
        text=combined_text,
        detected_name=detected_name,
        detected_dob=detected_dob,
        detected_gender=detected_gender,
        masked_aadhaar_number=masked_num,
        has_aadhaar_markers=has_markers,
    )


def _extract_name_candidate(text: str) -> str | None:
    """Attempt to parse the English name line that usually precedes DOB."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for i, line in enumerate(lines):
        if re.search(r"\b(DOB|Date of Birth|\d{2}[/\-.]\d{2}[/\-.]\d{4})\b", line, re.IGNORECASE):
            # Look at previous line
            if i > 0:
                prev = lines[i - 1].strip()
                # Ignore common headers
                if not re.search(r"Government|India|भारत|सरकार", prev, re.IGNORECASE):
                    # Clean punctuation
                    cleaned = re.sub(r"[^A-Za-z\s]", "", prev).strip()
                    words = cleaned.split()
                    if len(cleaned) >= 3 and 1 <= len(words) <= 6:
                        return cleaned

    return None


def fuzzy_match_name(expected_name: str | None, ocr_text: str) -> bool:
    """Check if expected name matches text found in OCR using sliding window fuzzy ratio."""
    if not expected_name or not ocr_text:
        return False

    expected_clean = expected_name.strip().lower()
    text_clean = ocr_text.lower()

    # Exact token / substring check
    if expected_clean in text_clean:
        return True

    # Check all tokens (e.g. "Rahul", "Kumar")
    tokens = [t for t in expected_clean.split() if len(t) > 2]
    if tokens and all(t in text_clean for t in tokens):
        return True

    # Sliding-window SequenceMatcher (handles 1-2 char OCR errors)
    window = len(expected_clean)
    if window < 3 or len(text_clean) < window:
        return False

    best_ratio = 0.0
    for i in range(len(text_clean) - window + 1):
        chunk = text_clean[i : i + window]
        ratio = SequenceMatcher(None, expected_clean, chunk).ratio()
        if ratio > best_ratio:
            best_ratio = ratio

    return best_ratio >= 0.75


def match_dob(expected_dob: str | None, ocr_text: str) -> bool:
    """Check if expected DOB matches text found in OCR."""
    if not expected_dob or not ocr_text:
        return False

    clean_dob = expected_dob.strip().lower()
    # Normalize variants: 10-04-2007, 10/04/2007, 10.04.2007
    variants = [
        clean_dob,
        clean_dob.replace("-", "/"),
        clean_dob.replace("-", "."),
    ]
    text_lower = ocr_text.lower()
    return any(v in text_lower for v in variants)
