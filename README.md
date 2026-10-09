# Aadhaar Verification

## Setup & Running

### 1. Backend (FastAPI)

In the root directory, open a terminal:

```bash
# Create and activate virtual environment
# Windows:
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend server
uvicorn app:app --reload --port 8000
```

> Backend will run at `http://localhost:8000`.

---

### 2. Frontend (React + Vite)

In a second terminal:

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

> Open `http://localhost:5173` in your browser.

---

### Prerequisites

- **Python 3.9+** and **Node.js 18+**
- **Tesseract OCR** (for card text reading):
  - Windows: Install from [UB-Mannheim](https://github.com/UB-Mannheim/tesseract/wiki) (defaults to `C:\Program Files\Tesseract-OCR`)
  - Linux: `sudo apt install tesseract-ocr libzbar0`
  - macOS: `brew install tesseract zbar`
