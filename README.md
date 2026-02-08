# PhishR - AI-Powered Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green.svg)](https://www.mongodb.com/atlas)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A web-based phishing detection system that combines machine learning with real-time threat intelligence from VirusTotal and Google Safe Browsing APIs.

## Features

### URL Analysis
- **Single URL Scanning** - Analyze individual URLs with detailed threat breakdown
- **Batch Processing** - Scan multiple URLs at once (up to 10 URLs per batch)
- **Threat Intelligence Integration** - Real-time data from VirusTotal and Google Safe Browsing
- **Confidence Breakdown** - Shows how the combined score is calculated from ML (50%), VirusTotal (30%), and Google Safe Browsing (20%)

### Machine Learning
- **Binary Ensemble Classifier** - Combines XGBoost, Random Forest, and Gradient Boosting
- **80.5% Accuracy** - Trained on phishing and legitimate URL datasets
- **50+ Features** - URL structure, content analysis, and behavioral patterns
- **Smart Override** - Classification automatically changes to "Suspicious" or "Malicious" when threat intelligence detects threats

### User Features
- **User Authentication** - JWT-based login and registration
- **Scan History** - Track all your previous scans with results
- **Admin Dashboard** - User management and scan analytics
- **Responsive Design** - Works on desktop and mobile

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11, FastAPI |
| Database | MongoDB Atlas (Motor async driver) |
| ML Models | scikit-learn, XGBoost |
| Threat Intel | VirusTotal API v3, Google Safe Browsing API v4 |
| Authentication | JWT (python-jose), bcrypt |
| Frontend | HTML5, CSS3, JavaScript |
| Deployment | Render |

## Installation

### Prerequisites
- Python 3.11+
- MongoDB Atlas account
- VirusTotal API key (free at https://www.virustotal.com)
- Google Safe Browsing API key (free at https://console.cloud.google.com)

### Local Development

```bash
# Clone the repository
git clone https://github.com/ovlachi/phishing-detector.git
cd phishing-detector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env with your configuration

# Run the application
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Environment Variables

Create a `.env` file in the project root:

```env
# MongoDB Connection
MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net/
DB_NAME=phishing_detector

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
```

## Deployment on Render

1. Push your code to GitHub

2. Go to [Render](https://render.com) and create a new **Web Service**

3. Connect your GitHub repository

4. Configure the service:
   - **Build Command**: `pip install --upgrade pip && pip install --prefer-binary -r requirements.txt`
   - **Start Command**: `uvicorn src.api.main:app --host 0.0.0.0 --port $PORT`

5. Add Environment Variables:
   | Key | Value |
   |-----|-------|
   | `PYTHON_VERSION` | `3.11.4` |
   | `MONGO_URL` | Your MongoDB connection string |
   | `DB_NAME` | `phishing_detector` |
   | `VIRUSTOTAL_API_KEY` | Your VirusTotal API key |
   | `GOOGLE_SAFE_BROWSING_API_KEY` | Your Google API key |

6. Deploy

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/classify` | Analyze single URL | No |
| POST | `/classify-batch` | Analyze multiple URLs | Yes |
| POST | `/login` | User login | No |
| POST | `/register` | User registration | No |
| GET | `/scan-history` | Get user's scan history | Yes |
| GET | `/dashboard` | User dashboard | Yes |
| GET | `/admin` | Admin dashboard | Yes (Admin) |

### API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## How Classification Works

1. **ML Model Analysis** - Extracts 50+ features from URL and page content, runs through ensemble classifier

2. **VirusTotal Check** - Queries VirusTotal for existing scan results and domain reputation

3. **Google Safe Browsing** - Checks URL against Google's threat database (malware, social engineering, unwanted software)

4. **Combined Confidence Score**:
   ```
   Final Score = (ML Confidence × 50%) + (VirusTotal × 30%) + (Google Safe Browsing × 20%)
   ```

5. **Classification Override** - If threat intelligence finds threats but ML says "Legitimate":
   - Both VT and GSB flag it → **Malicious**
   - Only one flags it → **Suspicious**

## Database Schema

### Users Collection
```json
{
  "username": "string",
  "email": "string",
  "full_name": "string",
  "hashed_password": "string",
  "is_admin": "boolean",
  "created_at": "datetime"
}
```

### Scan History Collection
```json
{
  "user_id": "string",
  "url": "string",
  "disposition": "string",
  "classification": "string",
  "probabilities": "object",
  "threat_level": "string",
  "final_confidence": "float",
  "timestamp": "datetime",
  "source": "string"
}
```

## Project Structure

```
phishing-detector/
├── src/
│   ├── api/
│   │   ├── main.py              # FastAPI application
│   │   ├── predict.py           # Enhanced prediction with threat intel
│   │   ├── threat_intelligence.py # VirusTotal & GSB APIs
│   │   ├── database.py          # MongoDB operations
│   │   ├── auth.py              # JWT authentication
│   │   ├── models.py            # Pydantic models
│   │   ├── static/              # CSS, JS, images
│   │   └── templates/           # Jinja2 HTML templates
│   ├── features/
│   │   └── content_features.py  # Feature extraction
│   └── models/
│       └── ensemble_classifier.py
├── data/
│   └── processed/
│       └── models/              # Trained ML models
├── requirements.txt
├── render.yaml                  # Render deployment config
├── runtime.txt                  # Python version for Render
└── .env                         # Environment variables
```

## Test Credentials

For testing purposes:
- **Username**: `testuser`
- **Password**: `TestPassword123!`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
