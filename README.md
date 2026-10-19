# PhishGuard — Phishing URL Detection Platform

**Detect suspicious URLs using machine learning and heuristic analysis.**

PhishGuard is a full-stack web application that analyzes URLs, assigns risk scores, explains suspicious signals, and helps users scan individual URLs or batches of URLs through a security-focused dashboard.

**Live Application:** https://phishing-url-detector-l6tu.onrender.com  
**Backend API:** https://phishguard-api-qxf5.onrender.com  
**Interactive API Documentation:** https://phishguard-api-qxf5.onrender.com/docs

---

## Overview

Phishing attacks use deceptive URLs and websites to trick users into revealing credentials, financial information, and other sensitive data. PhishGuard evaluates URL structure and machine-learning signals to help users identify potentially dangerous links.

The application combines a React frontend, a FastAPI backend, a machine-learning model, heuristic URL analysis, and SQLite-based scan history.

PhishGuard is a defensive analysis tool. Its results are assessments, not guarantees that a URL is safe or malicious.

## Features

### URL Scanner
- Analyze a URL through the web dashboard.
- Calculate a risk score from 0 to 100.
- Display a risk level and verdict.
- Show machine-learning and heuristic scores.
- Explain the assessment through security signals and URL analysis details.

### Machine Learning and Heuristic Analysis
- Uses the existing trained model and vectorizer.
- Combines model-based scoring with structural URL heuristics.
- Examines URL characteristics such as HTTPS usage, domain structure, suspicious keywords, unusual ports, encoded characters, and other indicators.
- Uses trusted-domain information as one legitimacy signal, with safeguards against ML-only score inflation.

### Batch Scanner
- Submit multiple URLs in a single request.
- Import URL lists from `.txt` and `.csv` files through the frontend.
- Review individual scan results and batch summaries.
- Export scan results to CSV.
- Handle individual scan failures without necessarily stopping the entire batch.

### Scan History
- Save completed scan results to a local SQLite database.
- Retrieve recent scans through the API.
- Review previous assessments in the dashboard.

### Dashboard and Analytics
- View scan statistics and risk distributions.
- Review safe, flagged, and high-risk assessment counts.
- Navigate between the dashboard, URL scanner, batch scanner, scan history, and analytics sections.

### REST API
- FastAPI-powered endpoints.
- Interactive Swagger documentation.
- Health checks that report whether the model is available.
- Structured JSON responses and request validation.

## Tech Stack

| Component | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Styling and UI | Tailwind CSS, Lucide React |
| Charts | Recharts |
| Backend | Python, FastAPI, Uvicorn |
| Machine Learning | scikit-learn, joblib |
| Data Analysis | NumPy, SciPy |
| Database | SQLite |
| Testing | pytest, Node.js test runner |
| Version Control | Git and GitHub |
| Deployment | Render Static Site and Web Service |

## System Architecture

```text
User
  |
  v
React + TypeScript Frontend
  |
  | HTTP / JSON
  v
FastAPI Backend
  |
  +---- URL Risk Engine
  |       |
  |       +---- Trained ML Model
  |       +---- URL Heuristics
  |       +---- Trusted Domain List
  |
  +---- SQLite Scan History
  |
  v
Risk Assessment JSON Response
  |
  v
Dashboard / Results / Analytics
```

The frontend communicates with the backend through REST API requests. The backend runs the risk analysis, returns the assessment, and saves successful scans to history.

## Risk Assessment

PhishGuard returns a risk score from 0 to 100.

| Risk Score | Risk Level |
|---|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

The risk engine combines the model score and heuristic score, with a trusted-domain safeguard where applicable.

**Important:** `model_score` is a model-derived signal, not a calibrated real-world probability that a URL is malicious. A low risk score does not guarantee that a URL is safe. Trusted-domain matches are also not a substitute for independent verification.

The API reports the analysis mode so clients can distinguish combined ML and heuristic analysis from heuristic-only fallback.

## Project Structure

```text
Phishing-URL-Detector/
|
+-- backend/
|   +-- app/
|   |   +-- api/
|   |   |   +-- routes/
|   |   |       +-- health.py
|   |   |       +-- scan.py
|   |   |       +-- history.py
|   |   +-- core/
|   |   |   +-- config.py
|   |   +-- schemas/
|   |   +-- services/
|   |   +-- main.py
|   +-- tests/
|   +-- requirements.txt
|
+-- frontend/
|   +-- src/
|   +-- tests/
|   +-- public/
|   +-- package.json
|   +-- vite.config.ts
|   +-- .env.example
|
+-- risk_engine.py
+-- url_analyzer.py
+-- phishing_model.pkl
+-- vectorizer.pkl
+-- trusted_domains.txt
+-- app.py
+-- README.md
+-- .gitignore
```

The root-level `app.py` is part of the earlier Streamlit implementation. The deployed full-stack application uses the FastAPI backend and React frontend.

## Getting Started Locally

### Prerequisites

Install the following:

- Python 3.12.10
- Node.js and npm
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/Frostheim29/Phishing-URL-Detector.git
cd Phishing-URL-Detector
```

### 2. Set Up the Backend

Create and activate a virtual environment from the repository root:

**Windows PowerShell**

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Return to the repository root and start the API:

```powershell
cd ..
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

The backend will be available at:

- API health: http://127.0.0.1:8000/api/health
- API documentation: http://127.0.0.1:8000/docs

Keep the backend terminal running while using the frontend.

### 3. Set Up the Frontend

Open a second terminal from the repository root:

```powershell
cd frontend
npm install
```

Create a local `.env` file inside `frontend/` with:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Start the development server:

```powershell
npm run dev
```

Open the local URL displayed by Vite, usually:

http://localhost:5173

The backend CORS configuration must allow the frontend's origin. The default configuration supports local development and the deployed frontend; additional origins can be configured with `PHISHGUARD_ALLOWED_ORIGINS`, using comma-separated origins.

## API Endpoints

The API is available at:

https://phishguard-api-qxf5.onrender.com

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Check API and model status |
| POST | `/api/scan` | Analyze one URL and save the result |
| POST | `/api/scan/batch` | Analyze multiple URLs |
| GET | `/api/history?limit=50` | Retrieve recent scan history |

### Example: Scan a URL

**Request**

```http
POST /api/scan
Content-Type: application/json
```

```json
{
  "url": "https://www.google.com"
}
```

**Example response structure**

```json
{
  "url": "https://www.google.com",
  "risk_score": 20,
  "risk_level": "Low",
  "verdict": "Likely Safe",
  "model_score": 99.23,
  "heuristic_score": 0,
  "analysis_mode": "ml_and_heuristic",
  "signals": [],
  "positive_signals": [],
  "negative_signals": [],
  "strong_malicious_signals": [],
  "analysis": {},
  "scanned_at": "2026-10-17T13:00:09Z"
}
```

This illustrates the response structure and a previously observed test result; scores and timestamps can vary by request.

### Health Check

Open:

https://phishguard-api-qxf5.onrender.com/api/health

The health endpoint reports whether the model is ready and which analysis mode is active. A healthy API process alone does not guarantee that the machine-learning artifacts loaded successfully, so check the reported model status as well.

## Running Tests

### Backend Tests

From the repository root, with the backend virtual environment installed:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests -v --basetemp .pytest-run -p no:cacheprovider
```

### Frontend Tests

From the repository root:

```powershell
cd frontend
npm test
```

### Frontend Production Build

```powershell
npm run build
```

### Lint

```powershell
npm run lint
```

## Deployment

PhishGuard is deployed on Render.

### Frontend — Static Site

- Repository: `Frostheim29/Phishing-URL-Detector`
- Branch: `main`
- Root directory: `frontend`
- Build command: `npm install && npm run build`
- Publish directory: `dist`
- Environment variable:

```dotenv
VITE_API_BASE_URL=https://phishguard-api-qxf5.onrender.com
```

Live URL: https://phishing-url-detector-l6tu.onrender.com

### Backend — Web Service

- Repository: `Frostheim29/Phishing-URL-Detector`
- Branch: `main`
- Python version: `3.12.10`
- Build command: `pip install -r backend/requirements.txt`
- Start command:

```bash
uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port $PORT
```

- Health check path: `/api/health`
- CORS origins are controlled by `PHISHGUARD_ALLOWED_ORIGINS` or the defaults in the backend configuration.

Live API: https://phishguard-api-qxf5.onrender.com

### Free Hosting Limitations

The application is hosted using Render's free services. Free web services can spin down after inactivity, which can make the first request slower.

The backend uses SQLite for scan history. Render's free web service does not provide a persistent disk, so locally stored scan history may be lost after restarts, redeployments, or other service lifecycle events. The current setup is suitable for a demonstration or portfolio project, not guaranteed durable storage for production use.

## Limitations and Responsible Use

- URL classification is probabilistic and can produce false positives and false negatives.
- A trusted-domain match does not guarantee that every URL or page hosted on that domain is safe.
- Heuristic rules may miss new or sophisticated phishing techniques.
- Model performance depends on the training data and its coverage of current phishing patterns.
- The application analyzes URL characteristics; a verdict is not a guarantee of the destination website's actual behavior.
- Avoid entering sensitive personal information into unfamiliar websites, even when a scanner reports a low risk score.

Use PhishGuard as an additional security aid alongside browser protections, reputable security tools, and careful verification of links.

## Future Improvements

- Add persistent database storage for scan history.
- Improve the training dataset with more recent and diverse URL examples.
- Add more comprehensive model evaluation and monitoring.
- Expand automated tests and production error monitoring.
- Improve accessibility and mobile responsiveness.
- Add additional URL intelligence sources where appropriate.

## Author

**Ananya Varshney**  
B.Tech — Computer Science & Engineering (AI/ML)  
GitHub: [Frostheim29](https://github.com/Frostheim29)

---

If you find this project useful, consider starring the repository on GitHub.
