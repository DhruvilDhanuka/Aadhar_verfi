"""
Aadhaar Verification Pipeline.

Tri-verification architecture:
1. Registration Form Data (User Input)
2. UIDAI Secure QR Code Data (Cryptographic Truth)
3. Aadhaar Printed Card Text (OCR Data)

Security logic:
- If Secure QR is present:
    * Verify UIDAI RSA-SHA256 signature.
    * Match Registration Data with Secure QR (catches using someone else's Aadhaar).
    * Match Printed Card OCR Text with Secure QR (catches photoshopped/tampered card text).
- If Secure QR is missing:
    * Check Printed Card OCR Text with Registration Data.
    * If mismatch -> FAIL.
    * If match -> RE-UPLOAD REQUIRED (a QR code is strictly required to prevent digital forgeries).
"""
from __future__ import annotations

import argparse
import json
import sys

from .qr_verify import check_qr
from .ocr import extract_ocr, fuzzy_match_name, match_dob, dobs_match, normalize_dob_to_ddmmyyyy


def run_pipeline(
    image_path: str,
    cert_path: str,
    expected_name: str | None = None,
    expected_dob: str | None = None,
    is_image: bool = False,
) -> dict:
    """Run the complete tri-verification pipeline on an Aadhaar image or PDF render."""
    exp_name = expected_name.strip() if expected_name else None
    exp_dob = normalize_dob_to_ddmmyyyy(expected_dob.strip()) if expected_dob else None

    # 1. Attempt to decode Secure QR
    qr_result = check_qr(
        image_path,
        uidai_cert_path=cert_path,
        expected_name=exp_name,
        expected_dob=exp_dob,
    )

    # 2. Extract OCR data from the card image
    ocr_result = extract_ocr(image_path)

    # -------------------------------------------------------------
    # CASE A: Secure QR is FOUND and DECODED
    # -------------------------------------------------------------
    if qr_result.decoded:
        qr_fields = qr_result.fields or {}
        qr_name = qr_fields.get("name")
        qr_dob = qr_fields.get("dob") or qr_fields.get("yob")

        # Check 1: Cryptographic Signature
        if qr_result.signature_verified is False and qr_result.score == 0.0:
            return _build_response(
                verdict="FAIL",
                verdict_reason=(
                    "UIDAI cryptographic signature verification FAILED. "
                    "The Secure QR code payload does not match UIDAI's digital signature "
                    "and has been forged or tampered."
                ),
                reupload_required=True,
                reupload_message="Please upload an authentic Aadhaar issued by UIDAI.",
                exp_name=exp_name,
                exp_dob=exp_dob,
                qr_result=qr_result,
                ocr_result=ocr_result,
                reg_qr_match=False,
                qr_ocr_match=None,
                reg_ocr_match=None,
                is_image=is_image,
            )

        # Check 2: Registration Data vs QR Data
        # For image uploads, registrant information MUST be supplied and match the QR
        if is_image and not exp_name and not exp_dob:
            return _build_response(
                verdict="RE-UPLOAD",
                verdict_reason=(
                    "Registration details (Name or Date of Birth) are required to verify "
                    "an image upload against its QR code data."
                ),
                reupload_required=True,
                reupload_message="Please enter your name and date of birth as registered, and submit again.",
                exp_name=exp_name,
                exp_dob=exp_dob,
                qr_result=qr_result,
                ocr_result=ocr_result,
                reg_qr_match=False,
                qr_ocr_match=None,
                reg_ocr_match=None,
                is_image=is_image,
            )

        reg_qr_match = True
        failed_reg_checks = []
        if exp_name:
            if qr_name:
                name_match = (
                    exp_name.lower() in qr_name.lower()
                    or qr_name.lower() in exp_name.lower()
                    or fuzzy_match_name(exp_name, qr_name)
                )
                if not name_match:
                    reg_qr_match = False
                    failed_reg_checks.append("Name")
            else:
                reg_qr_match = False
                failed_reg_checks.append("Name")

        dob_matched_via_ocr = False
        if exp_dob:
            if qr_dob:
                dob_match = dobs_match(exp_dob, qr_dob)
                if not dob_match:
                    reg_qr_match = False
                    failed_reg_checks.append("Date of Birth")
            else:
                # If DOB is not found in the QR code, check the OCR text and registration data directly
                ocr_dob_matches = (
                    (ocr_result.detected_dob and dobs_match(exp_dob, ocr_result.detected_dob))
                    or match_dob(exp_dob, ocr_result.text)
                )
                if ocr_dob_matches:
                    dob_matched_via_ocr = True
                else:
                    reg_qr_match = False
                    failed_reg_checks.append("Date of Birth")

        if not reg_qr_match:
            return _build_response(
                verdict="FAIL",
                verdict_reason=(
                    f"Identity mismatch on: {', '.join(failed_reg_checks)}. "
                    f"The registration details do not match what is in the QR code "
                    f"(Registered: {exp_name or 'N/A'}, QR: {qr_name or 'N/A'}). "
                    f"This Aadhaar card does not belong to the registrant."
                ),
                reupload_required=True,
                reupload_message="Please upload your own Aadhaar card that matches your registration details.",
                exp_name=exp_name,
                exp_dob=exp_dob,
                qr_result=qr_result,
                ocr_result=ocr_result,
                reg_qr_match=False,
                qr_ocr_match=None,
                reg_ocr_match=None,
                is_image=is_image,
            )

        # Check 3: QR Data vs Printed Card Text (OCR) — Anti-Tampering Check
        qr_ocr_match = True
        if qr_name and ocr_result.text:
            is_qr_name_in_card = fuzzy_match_name(qr_name, ocr_result.text)
            if not is_qr_name_in_card and ocr_result.has_aadhaar_markers:
                qr_ocr_match = False
                return _build_response(
                    verdict="FAIL",
                    verdict_reason=(
                        f"Document tampering detected: The printed text on the card does not match "
                        f"the QR payload. The QR is for '{qr_name}', "
                        f"but the printed card text has been modified."
                    ),
                    reupload_required=True,
                    reupload_message="Tampered document detected. Please upload an untampered Aadhaar document.",
                    exp_name=exp_name,
                    exp_dob=exp_dob,
                    qr_result=qr_result,
                    ocr_result=ocr_result,
                    reg_qr_match=True,
                    qr_ocr_match=False,
                    reg_ocr_match=None,
                    is_image=is_image,
                )

        # Distinguish old XML (no signature) vs Secure QR (signature) for PDFs
        if not is_image and qr_result.signature_verified is None:
            return _build_response(
                verdict="PARTIAL_PASS",
                verdict_reason=(
                    "Old-format XML QR decoded and registration details match the QR data. "
                    "However, this QR format contains NO cryptographic signature — it cannot "
                    "be proven the QR data hasn't been tampered with. "
                    "For full verification, please re-upload a newer e-Aadhaar PDF with a Secure QR."
                ),
                reupload_required=True,
                reupload_message=(
                    "Upload a newer e-Aadhaar (downloaded from UIDAI / DigiLocker) "
                    "which contains a Secure QR with a digital signature."
                ),
                exp_name=exp_name,
                exp_dob=exp_dob,
                qr_result=qr_result,
                ocr_result=ocr_result,
                reg_qr_match=True,
                qr_ocr_match=qr_ocr_match,
                reg_ocr_match=True,
                is_image=is_image,
            )

        # All checks passed!
        pass_reason = (
            "Verification successful: QR code verified (Name matched). "
            "Date of Birth was not present in the QR code, but matched the printed card OCR text."
            if dob_matched_via_ocr
            else "Verification successful: QR code verified, registration details match the QR identity, and printed card text is consistent."
        )
        return _build_response(
            verdict="PASS",
            verdict_reason=pass_reason,
            reupload_required=False,
            reupload_message=None,
            exp_name=exp_name,
            exp_dob=exp_dob,
            qr_result=qr_result,
            ocr_result=ocr_result,
            reg_qr_match=True,
            qr_ocr_match=qr_ocr_match,
            reg_ocr_match=True,
            is_image=is_image,
        )


    # -------------------------------------------------------------
    # CASE B: Secure QR is MISSING / NOT DECODED
    # -------------------------------------------------------------
    # Check if any Aadhaar text or card markers exist at all
    if not ocr_result.has_aadhaar_markers and not ocr_result.masked_aadhaar_number:
        return _build_response(
            verdict="FAIL",
            verdict_reason=(
                "No Aadhaar details or Secure QR could be detected in the uploaded image. "
                "The image does not appear to be an Aadhaar card or is unreadable."
            ),
            reupload_required=True,
            reupload_message="Please upload a clear, legible photo of an Aadhaar card.",
            exp_name=exp_name,
            exp_dob=exp_dob,
            qr_result=qr_result,
            ocr_result=ocr_result,
            reg_qr_match=None,
            qr_ocr_match=None,
            reg_ocr_match=False,
            is_image=is_image,
        )

    # Check OCR text against registration details
    name_matched = fuzzy_match_name(exp_name, ocr_result.text) if exp_name else None
    dob_matched = match_dob(exp_dob, ocr_result.text) if exp_dob else None

    # Sub-case B1: Printed text does NOT match registration
    if (exp_name and name_matched is False) or (exp_dob and dob_matched is False):
        mismatched = []
        if exp_name and name_matched is False:
            mismatched.append("Name")
        if exp_dob and dob_matched is False:
            mismatched.append("Date of Birth")

        return _build_response(
            verdict="FAIL",
            verdict_reason=(
                f"Aadhaar text mismatch on: {', '.join(mismatched)}. "
                f"The printed details on the card do not match your registration information. "
                f"Furthermore, no Secure QR code was detected to corroborate identity."
            ),
            reupload_required=True,
            reupload_message="Please check your details and upload the correct Aadhaar card.",
            exp_name=exp_name,
            exp_dob=exp_dob,
            qr_result=qr_result,
            ocr_result=ocr_result,
            reg_qr_match=None,
            qr_ocr_match=None,
            reg_ocr_match=False,
            is_image=is_image,
        )

    # Sub-case B2: QR is missing
    # For image uploads, an authentic, scannable QR matching registrant data is strictly required to pass.
    if is_image:
        return _build_response(
            verdict="RE-UPLOAD",
            verdict_reason=(
                "For image uploads, verification strictly requires a readable and scannable "
                "QR code that matches your registration details. "
                "No scannable QR code was detected in this image."
            ),
            reupload_required=True,
            reupload_message=(
                "Please upload a clear, sharp photo/screenshot where the Aadhaar QR code "
                "is fully visible and scannable, or upload an official e-Aadhaar PDF."
            ),
            exp_name=exp_name,
            exp_dob=exp_dob,
            qr_result=qr_result,
            ocr_result=ocr_result,
            reg_qr_match=False if (exp_name or exp_dob) else None,
            qr_ocr_match=None,
            reg_ocr_match=True,
            is_image=is_image,
        )

    # Sub-case B3: For PDF uploads where QR is missing
    return _build_response(
        verdict="RE-UPLOAD",
        verdict_reason=(
            f"The printed text on the card matches your registration details ('{exp_name or 'registrant'}'), "
            f"but UIDAI's Secure QR code was NOT found in this image. "
            f"Because printed card text can be digitally manipulated without proof, "
            f"UIDAI's Secure QR is strictly required to complete verification."
        ),
        reupload_required=True,
        reupload_message=(
            "Please re-upload an image containing the Secure QR code "
            "(e.g., from mAadhaar, e-Aadhaar PDF, or the back side of your physical card)."
        ),
        exp_name=exp_name,
        exp_dob=exp_dob,
        qr_result=qr_result,
        ocr_result=ocr_result,
        reg_qr_match=None,
        qr_ocr_match=None,
        reg_ocr_match=True,
        is_image=is_image,
    )


def _build_response(
    verdict: str,
    verdict_reason: str,
    reupload_required: bool,
    reupload_message: str | None,
    exp_name: str | None,
    exp_dob: str | None,
    qr_result,
    ocr_result,
    reg_qr_match: bool | None,
    qr_ocr_match: bool | None,
    reg_ocr_match: bool | None,
    is_image: bool = False,
) -> dict:
    """Build a unified JSON response structured specifically for the frontend."""
    return {
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "reupload_required": reupload_required,
        "reupload_message": reupload_message,
        "file_type": "image" if is_image else "pdf",
        "is_image": is_image,
        "registration_data": {
            "name": exp_name,
            "dob": exp_dob,
        },
        "qr_data": {
            "decoded": qr_result.decoded,
            "signature_verified": qr_result.signature_verified,
            "name": qr_result.fields.get("name") if qr_result.decoded else None,
            "dob": (qr_result.fields.get("dob") or qr_result.fields.get("yob")) if qr_result.decoded else None,
            "gender": qr_result.fields.get("gender") if qr_result.decoded else None,
            "reference_id": (
                qr_result.fields.get("reference_id")
                or qr_result.fields.get("referenceid_last4")
                or qr_result.fields.get("aadhaar_last_4_digit")
            ) if qr_result.decoded else None,
        },
        "ocr_data": ocr_result.to_dict(),
        "cross_checks": {
            "registration_vs_qr": reg_qr_match,
            "qr_vs_card_text": qr_ocr_match,
            "registration_vs_card_text": reg_ocr_match,
        },
        # Backwards compatibility fields for frontend
        "qr_decoded": qr_result.decoded,
        "signature_verified": qr_result.signature_verified,
        "qr_fields": qr_result.fields if qr_result.decoded else None,
        "cross_check": qr_result.cross_check if qr_result.decoded else None,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Aadhaar verification — Secure QR + Card OCR Tri-Verification"
    )
    parser.add_argument("image", help="Path to Aadhaar image")
    parser.add_argument("--cert", default="keys/uidai_qr_signing_cert.cer", help="UIDAI cert path")
    parser.add_argument("--expected-name", default=None, help="Name from registration")
    parser.add_argument("--expected-dob", default=None, help="DOB from registration (DD-MM-YYYY)")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    result = run_pipeline(args.image, args.cert, args.expected_name, args.expected_dob)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"\nVerdict: {result['verdict']} - {result['verdict_reason']}\n")
        if result["reupload_required"]:
            print(f"Action: {result['reupload_message']}\n")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
