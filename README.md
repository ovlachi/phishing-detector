# PhishR - AI-Powered Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green.svg)](https://www.mongodb.com/atlas)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An advanced web-based phishing detection system integrating hybrid machine learning models with real-time URL analysis capabilities.

## 🚀 Features

### Core Functionality

- **Single URL Analysis** - Real-time phishing detection with confidence scoring
- **Batch Processing** - CSV upload for bulk URL scanning (up to 1000 URLs)
- **User Authentication** - Secure JWT-based login and registration system
- **Scan History** - Complete tracking of all scanning activities with MongoDB
- **Admin Dashboard** - Administrative controls and system monitoring

### AI & Security

- **Hybrid ML Models** - XGBoost, Random Forest, and Gradient Boosting ensemble
- **VirusTotal Integration** - Real-time threat intelligence API
- **Google Safe Browsing** - Additional security layer validation
- **Feature Extraction** - 50+ URL and content-based features
- **Threat Classification** - High/Medium/Low risk categorization

### User Experience

- **Responsive Design** - Works seamlessly on desktop and mobile
- **Real-time Results** - Analysis typically completed in under 5 seconds
- **Detailed Explanations** - Modal dialogs explaining detection reasoning
- **Export Capabilities** - Download scan results in multiple formats
- **Enhanced Error Handling** - Clear explanations for failed analyses

## 🏗️ Architecture

### Frontend Architecture

- **Technologies**: HTML5, CSS3, JavaScript (ES6+)
- **Design**: Responsive, mobile-first approach
- **UI Components**: Modal dialogs, interactive tables, progress indicators
- **API Integration**: RESTful endpoints with error handling

### Backend Infrastructure

- **Framework**: Python FastAPI with asynchronous processing
- **Authentication**: JWT tokens with role-based access control
- **API Design**: RESTful endpoints supporting single and bulk operations
- **Performance**: Concurrent request handling with efficient response times

### Machine Learning Pipeline

- **Models**: Ensemble of XGBoost, Random Forest, Gradient Boosting
- **Feature Engineering**: URL structure, content analysis, domain reputation
- **Processing**: Real-time feature extraction with BeautifulSoup
- **Accuracy**: 95%+ detection rate with low false positive rate

### Database Design

- **Primary**: MongoDB Atlas for scalability and performance
- **Collections**: Users, scan history, system configurations
- **Fallback**: SQLite for local development
- **Design**: Horizontal scaling support with efficient indexing

## 🛠️ Installation

### Prerequisites

- Python 3.11+
- MongoDB Atlas account (or local MongoDB)
- VirusTotal API key
- Google Safe Browsing API key

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env with your API keys and database configuration

# Run the application
python -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

### Environment Variables

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
MONGO_URL=your_mongodb_connection_string
DB_NAME=phishing_detector
COLLECTION_NAME=scan_history
SECRET_KEY=your_jwt_secret_key
DEBUG=False
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:8000
```

## 🚀 Deployment

### Netlify Deployment

1. **Push to GitHub**
2. **Connect to Netlify**
3. **Configure Build Settings**:

   - Build command: `pip install -r requirements.txt`
   - Publish directory: `src/api/static`
   - Functions directory: `netlify/functions`

4. **Add Environment Variables** in Netlify dashboard
5. **Deploy**

### Docker Deployment

```bash
# Build the image
docker build -t phishing-detector .

# Run the container
docker run -p 8000:8000 --env-file .env phishing-detector
```

## 📖 API Documentation

Once running, visit:

- **Application**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

```
POST /classify          - Single URL analysis
POST /classify-batch    - Batch URL processing
POST /register          - User registration
POST /login            - User authentication
GET /scan-history      - Retrieve scan history
GET /health           - System health check
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_endpoints.py -v
python -m pytest tests/test_batch_processing.py -v

# Test with real URLs
python tests/test_with_real_urls.py
```

## 📊 Performance

- **Single URL Analysis**: < 5 seconds average
- **Batch Processing**: 100 URLs in ~2 minutes
- **Accuracy**: 95%+ detection rate
- **False Positives**: < 2%
- **Concurrent Users**: Supports 50+ simultaneous users

## 🔒 Security Features

- **Input Validation**: Comprehensive URL and file validation
- **Rate Limiting**: API endpoint protection
- **Authentication**: JWT-based secure authentication
- **Data Protection**: Environment variable encryption
- **CORS Configuration**: Restricted cross-origin access
- **SQL Injection Prevention**: Parameterized queries

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎓 Academic Context

This project was developed as part of advanced cybersecurity research at Swinburne University of Technology, focusing on machine learning applications in threat detection and web security.

## 📞 Support

For support, email [your-email@example.com] or create an issue in the GitHub repository.

## 🙏 Acknowledgments

- Swinburne University of Technology
- VirusTotal API
- Google Safe Browsing API
- Open source machine learning community

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. Always verify results with additional security measures in production environments.
