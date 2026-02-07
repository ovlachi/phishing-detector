import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from .threat_intelligence import VirusTotalAPI
from urllib.parse import urlparse
from typing import Dict, Any
import re
import requests
from datetime import datetime
import sys
import warnings

# Add project root to path to import your existing modules
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import your existing feature extraction systems
from src.features.content_features import extract_content_features

# Initialize VirusTotal API
vt_api = VirusTotalAPI()

# Load your ML models and transformers
BASE_DIR = Path(__file__).parent.parent.parent
MODEL_DIR = BASE_DIR / "data" / "processed" / "models"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

# Load models - using binary classifier for better accuracy (80.5% vs 71%)
try:
    # Try to load the binary ensemble model first (best performing - 80.5% accuracy)
    if (MODEL_DIR / "binary_ensemble.pkl").exists():
        model = joblib.load(MODEL_DIR / "binary_ensemble.pkl")
        model_name = "binary_ensemble"
        # Load matching binary transformer
        feature_transformer = joblib.load(PROCESSED_DIR / "feature_transformer_binary.pkl")
        print("✅ Using BINARY classifier (Legitimate vs Malicious)")
    elif (MODEL_DIR / "ensemble_model.pkl").exists():
        model = joblib.load(MODEL_DIR / "ensemble_model.pkl")
        model_name = "ensemble"
        feature_transformer = joblib.load(PROCESSED_DIR / "feature_transformer.pkl")
    elif (MODEL_DIR / "xgboost_base_model.pkl").exists():
        model = joblib.load(MODEL_DIR / "xgboost_base_model.pkl")
        model_name = "xgboost"
        feature_transformer = joblib.load(PROCESSED_DIR / "feature_transformer.pkl")
    elif (MODEL_DIR / "rf_base_model.pkl").exists():
        model = joblib.load(MODEL_DIR / "rf_base_model.pkl")
        model_name = "random_forest"
        feature_transformer = joblib.load(PROCESSED_DIR / "feature_transformer.pkl")
    elif (MODEL_DIR / "gb_base_model.pkl").exists():
        model = joblib.load(MODEL_DIR / "gb_base_model.pkl")
        model_name = "gradient_boosting"
        feature_transformer = joblib.load(PROCESSED_DIR / "feature_transformer.pkl")
    else:
        raise FileNotFoundError("No suitable model found")
    
    print(f"✅ ML models loaded successfully: {model_name}")
    print(f"✅ Feature transformer loaded")
    
except FileNotFoundError as e:
    print(f"⚠️  Warning: Could not load ML models: {e}")
    print(f"Available models in {MODEL_DIR}:")
    if MODEL_DIR.exists():
        for model_file in MODEL_DIR.glob("*.pkl"):
            print(f"  - {model_file.name}")
    model = None
    feature_transformer = None
    model_name = "none"
except Exception as e:
    print(f"⚠️  Warning loading models: {e}")
    model = None
    feature_transformer = None
    model_name = "none"

def get_ml_prediction(url: str) -> Dict:
    """Get ML prediction using your existing feature extraction system"""
    try:
        if model is None or feature_transformer is None:
            return {
                'url': url,
                'class_name': 'Legitimate',
                'probabilities': {'legitimate': 0.8, 'phishing': 0.2},
                'warning': 'Using default prediction - ML model not available',
                'model_used': 'none'
            }
        
        # Use your existing content feature extraction
        print(f"Extracting features for: {url}")
        content_features = extract_content_features([url], max_workers=1, timeout=10)
        
        if content_features.empty or content_features.iloc[0]['fetch_success'] == 0:
            return {
                'url': url,
                'class_name': 'Unknown',
                'probabilities': {'legitimate': 0.5, 'phishing': 0.5},
                'warning': 'Content fetch failed - limited prediction available',
                'model_used': model_name
            }
        
        # Prepare features for prediction
        # Remove non-feature columns AND problematic columns that weren't in training
        columns_to_remove = [
            'url', 'fetch_success', 'label',  # Standard non-feature columns
            'content_type', 'final_url'       # Problematic columns not in training
        ]
        
        feature_cols = [col for col in content_features.columns 
                       if col not in columns_to_remove]
        
        X = content_features[feature_cols]
        
        print(f"Features extracted: {X.shape[1]} features")
        print(f"Feature columns sample: {list(X.columns[:10])}")
        
        # Apply your existing feature transformer (which is already fitted)
        X_transformed = feature_transformer.transform(X)
        
        # Convert back to DataFrame with proper feature names to avoid warnings
        if hasattr(feature_transformer, 'feature_names_in_'):
            feature_names = feature_transformer.feature_names_in_
        else:
            feature_names = feature_cols
            
        X_transformed_df = pd.DataFrame(X_transformed, columns=feature_names)
        
        print(f"Features transformed: {X_transformed_df.shape}")
        
        # Suppress the sklearn warnings about feature names
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            # Make prediction
            prediction = model.predict(X_transformed_df)[0]
            probabilities = model.predict_proba(X_transformed_df)[0]
        
        print(f"Model prediction: {prediction}, probabilities: {probabilities}")
        
        # Map predictions to class names (your model has 3 classes)
        n_classes = len(probabilities)
        
        if n_classes == 2:
            class_mapping = {0: 'Legitimate', 1: 'Malicious'}
        elif n_classes == 3:
            class_mapping = {0: 'Legitimate', 1: 'Credential Phishing', 2: 'Malware Distribution'}
        else:
            # Handle other cases
            class_mapping = {i: f'class_{i}' for i in range(n_classes)}
        
        # Create probability dictionary
        prob_dict = {}
        for i, prob in enumerate(probabilities):
            class_name = class_mapping.get(i, f'class_{i}')
            prob_dict[class_name] = float(prob)
        
        predicted_class = class_mapping.get(prediction, 'unknown')
        
        return {
            'url': url,
            'class_name': predicted_class,
            'probabilities': prob_dict,
            'model_used': model_name,
            'content_features': content_features.iloc[0].to_dict()
        }
        
    except Exception as e:
        print(f"ML prediction error: {e}")
        return {
            'url': url,
            'class_name': 'Legitimate',
            'probabilities': {'legitimate': 0.7, 'phishing': 0.3},
            'error': f'ML prediction failed: {str(e)}',
            'model_used': model_name
        }

def get_threat_intelligence(url: str) -> Dict[str, Any]:
    """Get threat intelligence from VirusTotal"""
    try:
        # Get URL report
        url_report = vt_api.get_url_report(url)
        
        # Get domain report
        domain = urlparse(url).netloc
        domain_report = vt_api.get_domain_report(domain) if domain else None
        
        return {
            "url_analysis": url_report,
            "domain_analysis": domain_report,
            "provider": "virustotal"
        }
    except Exception as e:
        return {
            "error": str(e),
            "provider": "virustotal"
        }

def calculate_combined_threat_level(ml_prediction: Dict, threat_intel: Dict) -> str:
    """Combine ML prediction with threat intelligence"""
    
    # Get ML threat level
    ml_class = ml_prediction.get('class_name', '').lower()
    ml_confidence = max(ml_prediction.get('probabilities', {}).values()) if ml_prediction.get('probabilities') else 0
    
    ml_threat = "low"
    if ml_class in ['phishing', 'malware'] and ml_confidence > 0.7:
        ml_threat = "high"
    elif ml_class in ['phishing', 'malware'] and ml_confidence > 0.5:
        ml_threat = "medium"
    elif ml_class == 'unknown':
        ml_threat = "unknown"
    
    # Get VirusTotal threat level
    vt_threat = "unknown"
    url_analysis = threat_intel.get("url_analysis", {})
    if url_analysis and url_analysis.get("status") == "success":
        vt_threat = url_analysis.get("threat_level", "unknown")
    
    # Combine threats (prioritize higher threat levels)
    threat_levels = ["unknown", "low", "suspicious", "medium", "high"]
    ml_level = threat_levels.index(ml_threat) if ml_threat in threat_levels else 0
    vt_level = threat_levels.index(vt_threat) if vt_threat in threat_levels else 0
    
    combined_level = max(ml_level, vt_level)
    return threat_levels[combined_level]

def predict(url: str) -> Dict:
    """Enhanced prediction with threat intelligence"""
    try:
        # Get ML prediction using your existing feature extraction system
        ml_result = get_ml_prediction(url)
        
        # Get threat intelligence
        threat_intel = get_threat_intelligence(url)
        
        # Calculate combined threat level
        combined_threat_level = calculate_combined_threat_level(ml_result, threat_intel)
        
        # Calculate enhanced confidence score
        ml_confidence = max(ml_result.get('probabilities', {}).values()) if ml_result.get('probabilities') else 0
        
        # Adjust confidence based on threat intelligence
        vt_confidence = 0.5  # Default neutral confidence
        url_analysis = threat_intel.get("url_analysis", {})
        if url_analysis and url_analysis.get("status") == "success":
            total_detections = url_analysis.get("total", 0)
            if total_detections > 0:
                clean_ratio = url_analysis.get("harmless", 0) / total_detections
                threat_ratio = (url_analysis.get("malicious", 0) + url_analysis.get("suspicious", 0)) / total_detections
                
                if threat_ratio > 0.3:
                    vt_confidence = 0.9  # High confidence in threat
                elif threat_ratio > 0.1:
                    vt_confidence = 0.7  # Medium confidence in threat
                elif clean_ratio > 0.8:
                    vt_confidence = 0.1  # High confidence it's safe
                else:
                    vt_confidence = 0.5  # Neutral
        
        # Weighted average of ML and VirusTotal confidence
        final_confidence = (ml_confidence * 0.6) + (vt_confidence * 0.4)
        
        return {
            **ml_result,
            'threat_level': combined_threat_level,
            'final_confidence': final_confidence,
            'threat_intelligence': threat_intel,
            'confidence_breakdown': {
                'ml_confidence': ml_confidence,
                'virustotal_confidence': vt_confidence
            },
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'url': url,
            'error': str(e),
            'threat_level': 'unknown',
            'class_name': 'Error',
            'probabilities': {},
            'timestamp': datetime.now().isoformat()
        }

# Legacy function for backward compatibility
def classify_url(url: str, model=None, pipeline=None, fetch_params=None):
    """Legacy function for backward compatibility"""
    return predict(url)

def predict_with_fallback(url):
    """Enhanced prediction with better fallback handling"""
    
    try:
        # Try full prediction first
        result = predict(url)
        return result
        
    except Exception as e:
        print(f"Full prediction failed for {url}: {str(e)}")
        
        # Fallback to URL-only analysis
        try:
            from src.features.enhanced_url_features import extract_url_features
            
            # Extract URL features only
            url_features = extract_url_features([url])[0]
            
            if url_features and len(url_features) > 0:
                # Use URL features for basic classification
                # This is a simplified approach - you might want to train a URL-only model
                
                suspicious_indicators = 0
                total_indicators = 0
                
                # Check for suspicious URL patterns
                if url_features.get('domain_length', 0) > 20:
                    suspicious_indicators += 1
                total_indicators += 1
                
                if url_features.get('subdomain_count', 0) > 2:
                    suspicious_indicators += 1
                total_indicators += 1
                
                if url_features.get('path_length', 0) > 50:
                    suspicious_indicators += 1
                total_indicators += 1
                
                # Calculate basic confidence
                if total_indicators > 0:
                    suspicion_ratio = suspicious_indicators / total_indicators
                    confidence = 1 - suspicion_ratio
                    
                    if suspicion_ratio > 0.6:
                        classification = "Suspicious"
                        threat_level = "medium"
                    else:
                        classification = "Legitimate"
                        threat_level = "low"
                else:
                    classification = "Unknown"
                    threat_level = "low"
                    confidence = 0.5
                
                return {
                    'class_name': classification,
                    'threat_level': threat_level,
                    'final_confidence': confidence,
                    'url_features': url_features,
                    'probabilities': {
                        'legitimate': confidence if classification == "Legitimate" else 1-confidence,
                        'suspicious': 1-confidence if classification == "Suspicious" else confidence
                    },
                    'error': 'Content fetch failed - URL analysis only',
                    'analysis_type': 'url_only'
                }
            
        except Exception as url_error:
            print(f"URL-only analysis also failed: {str(url_error)}")
        
        # Final fallback
        return {
            'class_name': 'Unknown',
            'threat_level': 'low',
            'final_confidence': None,
            'probabilities': None,
            'url_features': None,
            'error': f'Complete analysis failed: {str(e)}',
            'analysis_type': 'failed'
        }

# Add this enhanced error handling to your predict function:

def get_detailed_error_explanation(error_message):
    """Convert technical errors into user-friendly explanations"""
    
    error_explanations = {
        'dns_resolution': {
            'reason': 'Domain Resolution Failed',
            'explanation': 'The domain name could not be found or resolved.',
            'possible_causes': [
                'Domain has expired or been taken down',
                'Domain is blocked by security filters',
                'DNS configuration issues',
                'Potentially malicious domain that has been sinkholed'
            ],
            'user_action': 'Double-check the URL for typos. If correct, this domain may be suspicious or no longer active.'
        },
        'connection_timeout': {
            'reason': 'Connection Timeout',
            'explanation': 'The website did not respond within the allowed time.',
            'possible_causes': [
                'Server is overloaded or down',
                'Network connectivity issues',
                'Website is blocking automated requests',
                'Slow or unreliable hosting'
            ],
            'user_action': 'Try accessing the website directly in your browser to verify if it loads normally.'
        },
        'connection_refused': {
            'reason': 'Connection Refused',
            'explanation': 'The server actively refused the connection.',
            'possible_causes': [
                'Website is down or maintenance',
                'Server configuration issues',
                'Firewall blocking requests',
                'Website no longer exists'
            ],
            'user_action': 'Check if the website loads in your browser. The site may be temporarily unavailable.'
        },
        'ssl_error': {
            'reason': 'SSL/Security Certificate Error',
            'explanation': 'There was an issue with the website\'s security certificate.',
            'possible_causes': [
                'Expired security certificate',
                'Invalid or self-signed certificate',
                'Potential security risk',
                'Misconfigured HTTPS'
            ],
            'user_action': 'Be cautious - this could indicate a security risk. Verify the website\'s legitimacy before proceeding.'
        },
        'http_error': {
            'reason': 'HTTP Error Response',
            'explanation': 'The website returned an error response.',
            'possible_causes': [
                'Page not found (404)',
                'Server error (500)',
                'Access forbidden (403)',
                'Website maintenance'
            ],
            'user_action': 'The specific page may not exist or the website may be experiencing issues.'
        },
        'malformed_url': {
            'reason': 'Invalid URL Format',
            'explanation': 'The provided URL is not properly formatted.',
            'possible_causes': [
                'Missing protocol (http:// or https://)',
                'Invalid characters in URL',
                'Malformed domain name',
                'Incomplete URL'
            ],
            'user_action': 'Please check the URL format and ensure it includes the full web address.'
        }
    }
    
    # Analyze the error message to determine the type
    error_lower = str(error_message).lower()
    
    if any(dns_term in error_lower for dns_term in ['nodename nor servname', 'name resolution', 'dns', 'resolve']):
        return error_explanations['dns_resolution']
    elif any(timeout_term in error_lower for timeout_term in ['timeout', 'timed out']):
        return error_explanations['connection_timeout']
    elif any(refused_term in error_lower for refused_term in ['connection refused', 'refused']):
        return error_explanations['connection_refused']
    elif any(ssl_term in error_lower for ssl_term in ['ssl', 'certificate', 'tls']):
        return error_explanations['ssl_error']
    elif any(http_term in error_lower for http_term in ['404', '500', '403', 'http']):
        return error_explanations['http_error']
    elif any(url_term in error_lower for url_term in ['invalid url', 'malformed']):
        return error_explanations['malformed_url']
    else:
        return {
            'reason': 'Analysis Failed',
            'explanation': 'Unable to analyze this URL due to technical issues.',
            'possible_causes': [
                'Network connectivity problems',
                'Website protection mechanisms',
                'Temporary service unavailability'
            ],
            'user_action': 'Please try again later or verify the URL manually in your browser.'
        }

# Update your predict function to use this:
async def predict_enhanced_with_explanation(url):
    """Enhanced prediction with detailed error explanations"""
    
    try:
        # Your existing prediction logic here
        result = await predict(url)
        return result
        
    except Exception as e:
        error_details = get_detailed_error_explanation(str(e))
        
        return {
            'url': url,
            'class_name': 'Unknown',
            'threat_level': 'unknown',
            'final_confidence': None,
            'probabilities': None,
            'error': str(e),  # Technical error for debugging
            'error_details': error_details,  # User-friendly explanation
            'analysis_status': 'failed',
            'timestamp': datetime.utcnow().isoformat()
        }