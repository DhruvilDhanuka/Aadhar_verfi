import { useState, useRef } from "react";

function VerifyForm({ onSubmit, loading }) {
  const [name, setName] = useState("");
  const [dob, setDob] = useState("");
  const [file, setFile] = useState(null);
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

  const handleFileChange = (e) => {
    const f = e.target.files?.[0];
    if (f) setFile(f);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f && (f.type === "image/jpeg" || f.type === "image/png")) {
      setFile(f);
    }
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
        <label>Aadhaar Card Photo</label>
        <div
          className={`file-drop-zone${dragOver ? " drag-over" : ""}${file ? " has-file" : ""}`}
          onClick={() => fileInputRef.current?.click()}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
        >
          {file ? (
            <>
              <p className="file-name">{file.name}</p>
              <p className="file-size">{formatFileSize(file.size)}</p>
              <p className="change-hint">Click to change file</p>
            </>
          ) : (
            <p>
              Drag & drop an Aadhaar photo here, or click to browse
              <br />
              <small>PNG or JPEG, max 10 MB</small>
            </p>
          )}
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg,image/jpg"
          onChange={handleFileChange}
          style={{ display: "none" }}
        />
      </div>

      <button
        type="submit"
        className={`submit-btn${loading ? " loading" : ""}`}
        disabled={!file || loading}
      >
        {loading ? "Verifying..." : "Verify"}
      </button>
    </form>
  );
}

export default VerifyForm;
