function Results({ data }) {
  const verdict = data.verdict; // "PASS", "FAIL", "RE-UPLOAD", "FLAG"
  const isPass = verdict === "PASS" || verdict === "PARTIAL_PASS";
  const isFail = verdict === "FAIL";
  const isReupload = verdict === "RE-UPLOAD" || verdict === "FLAG";

  const bannerClass = isPass ? "pass" : isFail ? "fail" : "reupload";
  const bannerIcon = isPass ? "✅" : isFail ? "❌" : "🔄";

  const qrData = data.qr_data || {};
  const ocrData = data.ocr_data || {};
  const regData = data.registration_data || {};
  const checks = data.cross_checks || {};

  return (
    <div className="results">
      {/* Verdict banner */}
      <div className={`verdict-banner ${bannerClass}`}>
        <span className="verdict-icon">{bannerIcon}</span>
        <div className="verdict-text">
          <h2>Verdict: {verdict === "RE-UPLOAD" ? "RE-UPLOAD REQUIRED" : verdict}</h2>
          <p>{data.verdict_reason}</p>
        </div>
      </div>

      {/* Prominent Action Callout for Re-upload */}
      {data.reupload_required && data.reupload_message && (
        <div className="reupload-callout">
          <div className="reupload-header">
            <span className="reupload-icon">⚠️</span>
            <strong>Action Required:</strong>
          </div>
          <p className="reupload-text">{data.reupload_message}</p>
        </div>
      )}

      {/* Tri-Verification Data Comparison Grid */}
      <div className="result-section">
        <h3>Verification Data Comparison</h3>
        <div className="comparison-grid">
          {/* Card 1: Registration Form */}
          <div className="compare-card">
            <div className="compare-card-title">1. Registration Form</div>
            <div className="compare-row">
              <span className="label">Name:</span>
              <span className="value">{regData.name || "—"}</span>
            </div>
            <div className="compare-row">
              <span className="label">DOB:</span>
              <span className="value">{regData.dob || "—"}</span>
            </div>
            <div className="compare-badge badge-neutral">User Input</div>
          </div>

          {/* Card 2: Secure QR Code */}
          <div className="compare-card">
            <div className="compare-card-title">2. UIDAI QR Code</div>
            <div className="compare-row">
              <span className="label">Status:</span>
              <span className={`value ${qrData.decoded ? "match" : "neutral"}`}>
                {qrData.decoded ? "Decoded" : "Unreadable / Missing"}
              </span>
            </div>
            {qrData.decoded ? (
              <>
                <div className="compare-row">
                  <span className="label">Name:</span>
                  <span className="value">{qrData.name || "—"}</span>
                </div>
                <div className="compare-row">
                  <span className="label">DOB:</span>
                  <span className="value">
                    {qrData.dob || (isPass && ocrData.detected_dob ? `${ocrData.detected_dob} (via Card)` : "—")}
                  </span>
                </div>
                <div className="compare-row">
                  <span className="label">Gender:</span>
                  <span className="value">{qrData.gender || "—"}</span>
                </div>
                <div className="compare-row">
                  <span className="label">Ref ID:</span>
                  <span className="value">{qrData.reference_id || "—"}</span>
                </div>
                <div className="compare-row">
                  <span className="label">PDF Signature:</span>
                  <span className="value match">Verified ✅</span>
                </div>
              </>
            ) : (
              <p className="missing-hint">QR unreadable — verified via Printed Card OCR fallback.</p>
            )}
            <div className={`compare-badge ${qrData.decoded ? "badge-success" : "badge-neutral"}`}>
              {qrData.decoded ? "UIDAI QR Data" : "Fell Back to OCR"}
            </div>
          </div>

          {/* Card 3: Card OCR */}
          <div className="compare-card">
            <div className="compare-card-title">3. Printed Card (OCR)</div>
            <div className="compare-row">
              <span className="label">Name in Text:</span>
              <span className="value">
                {checks.registration_vs_card_text ? "Found in Card ✅" : "—"}
              </span>
            </div>
            <div className="compare-row">
              <span className="label">DOB:</span>
              <span className="value">{ocrData.detected_dob || "—"}</span>
            </div>
            <div className="compare-badge badge-neutral">
              Printed Text
            </div>
          </div>
        </div>
      </div>

      {/* Cross-Check Results */}
      <div className="result-section">
        <h3>Cross-Check Matrix</h3>
        <ul className="cross-check-list">
          {/* Check 1: Registration vs QR */}
          <li className="cross-check-item">
            <span
              className={`check-icon ${
                !qrData.decoded
                  ? "neutral"
                  : checks.registration_vs_qr === true
                  ? "match"
                  : "mismatch"
              }`}
            >
              {!qrData.decoded ? "—" : checks.registration_vs_qr === true ? "✅" : "❌"}
            </span>
            <div className="check-detail">
              <strong>Registration ↔ QR Match</strong>
              <p>
                {qrData.decoded
                  ? checks.registration_vs_qr === true
                    ? "Registration details match the official QR code data."
                    : "Mismatch: The registered user does not match the person inside the QR!"
                  : "Skipped (QR unreadable, verified via Printed Card OCR instead)."}
              </p>
            </div>
          </li>

          {/* Check 2: QR vs Printed Card Text */}
          <li className="cross-check-item">
            <span
              className={`check-icon ${
                !qrData.decoded
                  ? "neutral"
                  : checks.qr_vs_card_text === true
                  ? "match"
                  : "mismatch"
              }`}
            >
              {!qrData.decoded ? "—" : checks.qr_vs_card_text === true ? "✅" : "❌"}
            </span>
            <div className="check-detail">
              <strong>QR ↔ Printed Card Text</strong>
              <p>
                {qrData.decoded
                  ? checks.qr_vs_card_text === true
                    ? "Printed text on the card matches the QR payload."
                    : "Printed card text differs from the QR payload."
                  : "Skipped (QR not decoded)."}
              </p>
            </div>
          </li>

          {/* Check 3: Registration vs Printed Card Text */}
          <li className="cross-check-item">
            <span
              className={`check-icon ${
                checks.registration_vs_card_text === true
                  ? "match"
                  : checks.registration_vs_card_text === false
                  ? "mismatch"
                  : "neutral"
              }`}
            >
              {checks.registration_vs_card_text === true
                ? "✅"
                : checks.registration_vs_card_text === false
                ? "❌"
                : "—"}
            </span>
            <div className="check-detail">
              <strong>Registration ↔ Printed Card Text (OCR)</strong>
              <p>
                {checks.registration_vs_card_text === true
                  ? "Printed text on the card matches the registration details."
                  : "Printed text on the card does not match the entered registration details."}
              </p>
            </div>
          </li>
        </ul>
      </div>
    </div>
  );
}

export default Results;
