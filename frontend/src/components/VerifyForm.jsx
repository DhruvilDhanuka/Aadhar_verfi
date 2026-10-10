import { useState, useRef } from "react";

function VerifyForm({ onSubmit, loading }) {
  const [name, setName] = useState("");
  const [dob, setDob] = useState("");
  const [file, setFile] = useState(null);
  const [fileError, setFileError] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!file) return;
    // Convert date from YYYY-MM-DD (input type=date) to DD-MM-YYYY
    let formattedDob = "";
    if (dob) {
      const [y, m, d] = dob.split("-");
      formattedDob = `${d}-${m}-${y}`;
    }
    onSubmit({ name: name.trim(), dob: formattedDob, file });
  };

  const isPdfFile = (f) => {
    if (!f) return false;
    return f.type === "application/pdf" || /\.pdf$/i.test(f.name);
  };

  const processSelectedFile = (f) => {
    if (!f) return;
    if (isPdfFile(f)) {
      setFile(f);
      setFileError(null);
    } else {
      setFile(null);
      setFileError("Only genuine PDF documents from UIDAI, DigiLocker, or mAadhaar are accepted. Images, scans, and screenshots cannot be verified.");
    }
  };

  const handleFileChange = (e) => {
    const f = e.target.files?.[0];
    processSelectedFile(f);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    processSelectedFile(f);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <form className="verify-form" onSubmit={handleSubmit}>
      <div className="form-row">
        <div className="form-group">
          <label htmlFor="expected-name">Name (as entered during registration)</label>
          <input
            id="expected-name"
            type="text"
            placeholder="e.g. Rajesh Kumar"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label htmlFor="expected-dob">Date of Birth</label>
          <input
            id="expected-dob"
            type="date"
            value={dob}
            onChange={(e) => setDob(e.target.value)}
          />
        </div>
      </div>

      <div className="upload-area">
        <div className="upload-header">
          <label>Official Aadhaar Document (PDF Only)</label>
          <div className="sources-pills">
            <span className="source-pill">🏛️ myAadhaar</span>
            <span className="source-pill">📂 DigiLocker</span>
            <span className="source-pill">📱 mAadhaar</span>
          </div>
        </div>

        <div
          className={`file-drop-zone${dragOver ? " drag-over" : ""}${file ? " has-file" : ""}${fileError ? " has-error" : ""}`}
          onClick={() => fileInputRef.current?.click()}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
        >
          {file ? (
            <>
              <div className="pdf-icon-indicator">📄 PDF Ready</div>
              <p className="file-name">{file.name}</p>
              <p className="file-size">{formatFileSize(file.size)}</p>
              <p className="change-hint">Click to change file</p>
            </>
          ) : (
            <div>
              <p className="drop-main-text">
                Drag &amp; drop your official Aadhaar PDF here, or click to browse
              </p>
              <p className="source-requirement-note">
                Only genuine PDF files downloaded from <strong>myAadhaar (UIDAI)</strong>, <strong>DigiLocker</strong>, or <strong>mAadhaar</strong> are accepted.
              </p>
              <div className="pdf-validation-guidelines">
                <span className="guideline-badge">✓ UIDAI Digital Signature required</span>
                <span className="guideline-badge restriction">✕ Photos/Scans/Images rejected</span>
              </div>
              <small className="password-hint">
                🔒 Password-protected PDFs are unlocked automatically using your registration Name &amp; Birth Year (e.g., DHRU2007)
              </small>
            </div>
          )}
        </div>

        {fileError && (
          <div className="file-format-error">
            <span className="error-icon">⚠️</span>
            <span>{fileError}</span>
          </div>
        )}

        <input
          ref={fileInputRef}
          type="file"
          accept="application/pdf,.pdf"
          onChange={handleFileChange}
          style={{ display: "none" }}
        />
      </div>

      <button
        type="submit"
        className={`submit-btn${loading ? " loading" : ""}`}
        disabled={!file || loading}
      >
        {loading ? "Verifying Digital Signature & Credentials..." : "Verify Aadhaar"}
      </button>
    </form>
  );
}

export default VerifyForm;
