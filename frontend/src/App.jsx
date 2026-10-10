import { useState } from "react";
import "./App.css";
import VerifyForm from "./components/VerifyForm";
import Results from "./components/Results";

const API_URL = "http://localhost:8000/api/verify";

function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleVerify = async ({ name, dob, file }) => {
    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append("aadhaar_image", file);
    formData.append("expected_name", name);
    formData.append("expected_dob", dob);

    try {
      const res = await fetch(API_URL, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.detail || `Server returned ${res.status}`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Something went wrong. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <h1>Aadhaar Verification</h1>
      <p className="app-subtitle">
        Upload an official Aadhaar PDF from genuine sources and verify it against registration details
      </p>

      <div className="privacy-banner">
        🔒 <strong>Zero-Retention Verification:</strong> Uploaded Aadhaar PDFs are verified in-memory and immediately destroyed. Only cryptographically genuine PDFs signed by UIDAI are processed.
      </div>

      <VerifyForm onSubmit={handleVerify} loading={loading} />

      {error && <div className="error-msg">{error}</div>}

      {result && <Results data={result} />}
    </div>
  );
}

export default App;
