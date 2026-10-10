"""
Tier 1 — Check D: UIDAI Secure QR decode + digital signature verification.

This is the strongest signal in the pipeline: the QR printed on a genuine
Aadhaar letter / e-Aadhaar / PVC card / mAadhaar screen contains a zlib-
compressed, delimited data block followed by a 256-byte RSA-SHA256
signature over that block, signed by UIDAI's private key. If we can
verify that signature against UIDAI's published public key certificate,
we've cryptographically proven the printed data hasn't been altered
since UIDAI issued it — no network call to UIDAI required.

What this does NOT prove: that the person presenting the document is the
person named on it. That's what the live face-match step at the hostel
desk is for (see moodi_security_pipeline doc, stage 7).

Cert setup (one-time):
  Download the "Secure QR Code" / "Offline e-KYC" public key certificate
  from UIDAI's certificate page and save it as:
      keys/uidai_qr_signing_cert.cer
  https://uidai.gov.in/en/916-developer-section/data-and-downloads-section/19388-uidai-certificate-details-2.html
  (Both .cer forms — DER and PEM — are handled below.)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import datetime
import re
import zlib
import cv2
from pyzbar.pyzbar import decode as zbar_decode
import defusedxml.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from .ocr import dobs_match


# ── Field order for each known Secure QR version ────────────────────────
# Versioned QRs (V2, V3, V4, V5, …) start with a version tag + 0xFF,
# then email_mobile_status + 0xFF, then the demographic fields.
# The original (un-versioned) Secure QR has no version tag at all.

_VERSIONED_FIELDS = [
    "version", "email_mobile_status", "referenceid", "name", "dob",
    "gender", "careof", "district", "landmark", "house", "location",
    "pincode", "postoffice", "state", "street", "subdistrict", "vtc",
    "last_4_digits_mobile_no",
]

_UNVERSIONED_FIELDS = [
    "email_mobile_status", "referenceid", "name", "dob", "gender",
    "careof", "district", "landmark", "house", "location", "pincode",
    "postoffice", "state", "street", "subdistrict", "vtc",
]


@dataclass
class QrResult:
    score: float  # 0 (worst) - 1 (best)
    qr_found: bool
    decoded: bool
    signature_verified: Optional[bool]  # None = couldn't attempt (no cert / no QR)
    fields: dict
    cross_check: dict
    notes: list[str] = field(default_factory=list)

    def to_dict(self):
        return self.__dict__


def _locate_qr_payload(image_path: str) -> Optional[str]:
    img = cv2.imread(image_path)
    if img is None:
        return None

    results = zbar_decode(img)
    if not results:
        # zbar can struggle with glare/skew on phone photos — retry on a
        # grayscale + upscaled version before giving up.
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        gray = cv2.resize(gray, None, fx=1.6, fy=1.6, interpolation=cv2.INTER_CUBIC)
        results = zbar_decode(gray)

    if not results:
        # Fall back to OpenCV's own QR detector (different algorithm, catches
        # some cases pyzbar misses).
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        return data or None

    return results[0].data.decode("utf-8", errors="ignore")


def _qr_format(payload: str) -> str:
    """Classify a raw QR payload string."""
    s = payload.strip()
    if s.isdigit():
        return "secure"
    if s.startswith("<"):
        return "old_xml"
    return "unknown"


_OLD_XML_ROOT = "PrintLetterBarcodeData"

# Attribute map: XML attr -> our internal field name
_XML_ATTR_MAP = {
    "name":         "name",
    "gender":       "gender",
    "dob":          "dob",
    "yob":          "yob",          # older cards have year-of-birth only
    "careOf":       "careof",
    "co":           "careof",       # alternate spelling
    "house":        "house",
    "street":       "street",
    "lm":           "landmark",
    "loc":          "location",
    "vtcName":      "vtc",
    "vtc":          "vtc",
    "po":           "postoffice",
    "dist":         "district",
    "districtName": "district",
    "subdist":      "subdistrict",
    "stateName":    "state",
    "state":        "state",
    "pc":           "pincode",
    "pincode":      "pincode",
    "locality":     "location",
}


def _parse_old_xml_qr(payload: str) -> dict:
    """Parse an old-format Aadhaar XML QR (PrintLetterBarcodeData).

    The ``uid`` attribute holds the full 12-digit Aadhaar number — it is
    masked immediately; only the last 4 digits are kept.
    Raises ValueError if the XML is invalid or the root tag doesn't match.
    """
    try:
        root = ET.fromstring(payload.strip())
    except Exception as exc:
        raise ValueError(f"XML parse error: {exc}") from exc

    # Only trust recognised UIDAI root tags
    tag = root.tag.split("}")[-1]  # strip namespace if present
    if tag != _OLD_XML_ROOT:
        raise ValueError(
            f"Unexpected XML root tag '{tag}' — expected '{_OLD_XML_ROOT}'"
        )

    # Mask UID immediately — never put full UID in fields, notes, or logs
    raw_uid = root.get("uid", "")
    # Keep only the last 4 digits; redact the rest
    uid_digits = re.sub(r"\D", "", raw_uid)
    aadhaar_last_4 = uid_digits[-4:] if len(uid_digits) >= 4 else uid_digits

    data: dict = {"aadhaar_last_4_digit": aadhaar_last_4}

    for xml_attr, field_name in _XML_ATTR_MAP.items():
        val = root.get(xml_attr)
        if val is not None and field_name not in data:
            data[field_name] = val.strip()

    # Normalise dob: if only yob present, use it as dob for cross-checks
    if "dob" not in data and "yob" in data:
        data["dob"] = data["yob"]

    return data


def _load_uidai_cert(cert_path: str):
    """Load the certificate and return (public_key, cert) tuple."""
    with open(cert_path, "rb") as f:
        raw = f.read()
    try:
        cert = x509.load_pem_x509_certificate(raw)
    except ValueError:
        cert = x509.load_der_x509_certificate(raw)
    return cert.public_key(), cert


def _verify_signature(public_key, signed_data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            signed_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ── Manual Secure QR decoder ───────────────────────────────────────────
# pyaadhaar only recognises "V2"; newer UIDAI QRs use V3/V4/V5/… and
# the library crashes with an IndexError.  We decode manually instead.

def _decode_secure_qr(numeric_payload: str) -> dict:
    """Decode a UIDAI Secure QR (numeric big-int string) into a dict.

    Returns a dict with at least: the demographic fields, plus special
    keys ``_signed_data`` (bytes) and ``_signature`` (bytes) for
    downstream signature verification.

    Raises ValueError if the payload can't be decompressed / parsed.
    """
    qr_int = int(numeric_payload)
    raw_bytes = qr_int.to_bytes((qr_int.bit_length() + 7) // 8, "big")

    # Decompress — UIDAI uses gzip (magic 0x1f 0x8b)
    try:
        decompressed = zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)
    except zlib.error:
        # Fallback: try padded to 5000 bytes (pyaadhaar style)
        raw_bytes = qr_int.to_bytes(5000, "big").lstrip(b"\x00")
        decompressed = zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)

    # Signature is always the last 256 bytes (2048-bit RSA)
    signed_data = decompressed[:-256]
    signature = decompressed[-256:]

    # Detect version: versioned QRs start with "V2", "V3", … "V5" etc.
    # followed by the 0xFF delimiter.  Un-versioned ones start directly
    # with the email_mobile_status byte.
    prefix = decompressed[:2].decode("ISO-8859-1", errors="replace")
    is_versioned = len(prefix) == 2 and prefix[0] == "V" and prefix[1].isdigit()

    field_names = list(_VERSIONED_FIELDS if is_versioned else _UNVERSIONED_FIELDS)

    # Build delimiter positions (byte value 0xFF = 255)
    delimiters = [-1]
    for i in range(len(decompressed)):
        if decompressed[i] == 255:
            delimiters.append(i)

    # Extract text fields (stop at the number of expected fields or
    # available delimiters, whichever is smaller)
    data: dict = {}
    n = min(len(field_names), len(delimiters) - 1)
    for i in range(n):
        start = delimiters[i] + 1
        end = delimiters[i + 1]
        data[field_names[i]] = decompressed[start:end].decode(
            "ISO-8859-1", errors="replace"
        )

    # Derived convenience fields (tolerant of short/missing reference IDs)
    ref = data.get("referenceid", "")
    data["aadhaar_last_4_digit"] = ref[:4] if len(ref) >= 4 else ref
    data["aadhaar_last_digit"] = ref[3] if len(ref) >= 4 else (ref[-1] if ref else "")

    # email / mobile flags
    try:
        status = int(data.get("email_mobile_status", "0"))
    except ValueError:
        status = 0
    data["email"] = status in {1, 3}
    data["mobile"] = status in {2, 3}

    # Attach raw crypto material (not returned to callers, consumed internally)
    data["_signed_data"] = signed_data
    data["_signature"] = signature

    return data


def check_qr(
    image_path: str,
    uidai_cert_path: str = "keys/uidai_qr_signing_cert.cer",
    expected_name: Optional[str] = None,
    expected_dob: Optional[str] = None,
) -> QrResult:
    notes = []

    qr_payload = _locate_qr_payload(image_path)
    if not qr_payload:
        return QrResult(
            score=0.0, qr_found=False, decoded=False, signature_verified=None,
            fields={}, cross_check={},
            notes=["No QR code detected in the image. If this is a photo of the "
                   "physical card, make sure the QR corner isn't cropped, blurred, "
                   "or glared over — it needs to be readably sharp."],
        )

    # ── Route by QR format ────────────────────────────────────────────
    fmt = _qr_format(qr_payload)

    if fmt == "old_xml":
        # Old-format XML QR — parse demographics, no signature available
        try:
            xml_fields = _parse_old_xml_qr(qr_payload)
        except ValueError as e:
            return QrResult(
                score=0.05, qr_found=True, decoded=False, signature_verified=None,
                fields={}, cross_check={},
                notes=[f"QR found, XML detected but could not be parsed: {e}"],
            )

        cross_check = {}
        if expected_name and xml_fields.get("name"):
            qr_name_norm = " ".join(xml_fields["name"].lower().split())
            exp_name_norm = " ".join(expected_name.lower().split())
            cross_check["name_match"] = (
                exp_name_norm in qr_name_norm or qr_name_norm in exp_name_norm
            )
        if expected_dob and xml_fields.get("dob"):
            cross_check["dob_match"] = dobs_match(expected_dob, xml_fields["dob"])

        score = 0.4  # decoded demographics but no crypto proof
        if cross_check.get("name_match") is False or cross_check.get("dob_match") is False:
            score = 0.1

        return QrResult(
            score=round(score, 3),
            qr_found=True,
            decoded=True,
            signature_verified=None,  # old format has no signature
            fields=xml_fields,
            cross_check=cross_check,
            notes=[
                "Old-format XML QR decoded (PrintLetterBarcodeData). "
                "No cryptographic signature is present in this QR format — "
                "demographic fields only. Consider requesting a newer e-Aadhaar "
                "with a Secure QR for full cryptographic verification."
            ],
        )

    if fmt != "secure":
        return QrResult(
            score=0.05, qr_found=True, decoded=False, signature_verified=None,
            fields={}, cross_check={},
            notes=["QR found but payload format is unrecognised."],
        )

    # ── Secure QR (numeric big-int) path ─────────────────────────────

    try:
        fields = _decode_secure_qr(qr_payload)
    except Exception as e:
        return QrResult(
            score=0.05, qr_found=True, decoded=False, signature_verified=None,
            fields={}, cross_check={},
            notes=[f"QR was read but couldn't be parsed as a Secure QR payload: {e}."],
        )

    # Pull out crypto material before building the user-visible fields dict
    signed_data = fields.pop("_signed_data")
    signature_bytes = fields.pop("_signature")


    # Never keep the full reference id around longer than needed.
    safe_fields = {k: v for k, v in fields.items() if k != "referenceid"}
    safe_fields["referenceid_last4"] = fields.get("aadhaar_last_4_digit")

    signature_verified = None
    cert_expired = False
    cert_is_test = False
    try:
        pubkey, cert = _load_uidai_cert(uidai_cert_path)

        # Check certificate validity before trusting the verification result
        now = datetime.datetime.now(datetime.timezone.utc)
        cert_expired = now > cert.not_valid_after_utc

        # Detect obvious test / placeholder certs (self-signed, non-UIDAI)
        subj = cert.subject.rfc4514_string().lower()
        cert_is_test = "uidai" not in subj and "uid" not in subj

        signature_verified = _verify_signature(
            pubkey, signed_data, signature_bytes
        )
    except FileNotFoundError:
        notes.append(
            f"UIDAI public key certificate not found at '{uidai_cert_path}'. "
            "Decoded the QR fields but could NOT verify the signature — this is "
            "the step that actually proves the document wasn't tampered with. "
            "Download the cert (see module docstring) and re-run."
        )
    except Exception as e:
        notes.append(f"Signature verification failed to run: {e}")

    cross_check = {}
    if expected_name is not None:
        qr_name = fields.get("name", "").strip().lower()
        exp_name_clean = expected_name.strip().lower()
        cross_check["name_match"] = (
            exp_name_clean in qr_name or qr_name in exp_name_clean
        )
    if expected_dob is not None:
        cross_check["dob_match"] = dobs_match(expected_dob, fields.get("dob", ""))

    # --- scoring ---
    score = 0.3  # baseline for "found + decoded a Secure QR at all"
    if signature_verified is True:
        score = 1.0
        notes.append("Signature verified against UIDAI's public key — the QR "
                      "payload is provably unaltered since issuance.")
    elif signature_verified is False and not cert_expired and not cert_is_test:
        # Hard fail ONLY when we have a valid, current UIDAI cert and the
        # signature still doesn't match — that's a genuine crypto mismatch.
        score = 0.0
        notes.append("Signature verification FAILED with a current UIDAI cert — "
                      "the QR payload does not match UIDAI's signature. Treat as "
                      "tampered/forged and escalate to Tier 2 / manual review.")
    elif signature_verified is False and (cert_expired or cert_is_test):
        # The cert is stale or wrong — we can't distinguish 'tampered' from
        # 'signed with a newer key we don't have'.  Don't punish the user.
        score = 0.3
        reason_parts = []
        if cert_expired:
            reason_parts.append("the certificate has expired")
        if cert_is_test:
            reason_parts.append("the certificate appears to be a test/placeholder cert")
        notes.append(
            f"Signature did not verify, but {' and '.join(reason_parts)}. "
            "This likely means the cert doesn't match the key UIDAI used to "
            "sign this QR — download the latest certificate from UIDAI's "
            "website and re-run. Score reflects successful decode only."
        )
    else:
        notes.append("Signature verification not attempted (see notes above); "
                      "score reflects successful decode only, not authenticity.")

    if cross_check:
        for k, v in cross_check.items():
            if v is False:
                score *= 0.5
                notes.append(f"Cross-check '{k}' did not match what the user typed "
                              "at registration.")

    return QrResult(
        score=round(score, 3),
        qr_found=True,
        decoded=True,
        signature_verified=signature_verified,
        fields=safe_fields,
        cross_check=cross_check,
        notes=notes,
    )
