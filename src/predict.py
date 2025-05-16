import os
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
import logging

# Add project root to Python path
import sys
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.features.content_features import extract_content_features
from src.models.ensemble_classifier import FeaturePipeline, PhishingEnsembleClassifier
from src.features.enhanced_url_features import integrate_url_features_with_existing, calculate_url_confidence

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_model_and_pipeline(model_dir=None):
    """Load trained model and feature pipeline."""
    # Use absolute path if model_dir is not provided
    if model_dir is None:
        # Get the absolute path to the project root
        import os
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        model_dir = os.path.join(project_root, "data/processed")
    
    # Load feature pipeline
    pipeline = FeaturePipeline(output_dir=model_dir)
    if not pipeline.load_transformer():
        raise FileNotFoundError(f"Feature transformer not found in {model_dir}")
    
    # Load ensemble model
    ensemble = PhishingEnsembleClassifier(output_dir=f"{model_dir}/models")
    if not ensemble.load_model():
        raise FileNotFoundError(f"Ensemble model not found in {model_dir}/models")
    
    return ensemble, pipeline

def classify_url(url, model, pipeline, fetch_params=None):
    """
    Classify a single URL with enhanced URL features.
    
    Parameters:
    -----------
    url : str
        URL to classify
    model : PhishingEnsembleClassifier
        Trained classifier
    pipeline : FeaturePipeline
        Feature pipeline
    fetch_params : dict, optional
        Parameters for content fetching
    
    Returns:
    --------
    dict
        Classification result with enhanced features
    """
    # Set default fetch parameters
    if fetch_params is None:
        fetch_params = {'max_workers': 1, 'timeout': 5, 'delay': 0}
    
    # Extract content features
    content_features = extract_content_features([url], **fetch_params)
    
    # Check if fetch was successful
    fetch_success = content_features.at[0, 'fetch_success']
    
    # Get URL features separately without integrating yet
    url_features = extract_url_features(url)
    
    if fetch_success == 0:
        # Content fetch failed, but we can still return URL features
        return {
            'url': url,
            'error': 'Failed to fetch content',
            'class': None,
            'probabilities': None,
            'threat_level': determine_threat_level_from_url(url_features),
            'url_features': url_features,
            'url_confidence_score': url_features.get('url_confidence_score', 0)
        }
    
    # For successful content fetch, proceed with ML prediction
    # IMPORTANT: Only use original features for ML prediction to maintain compatibility
    feature_cols = [col for col in content_features.columns if col not in ['url', 'fetch_success']]
    
    # Transform features
    X = pipeline.transform(content_features[feature_cols])
    
    # Make prediction
    label = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    
    # Create class mapping
    class_mapping = {
        0: 'Legitimate',
        1: 'Credential Phishing',
        2: 'Malware Distribution'
    }
    
    # Calculate threat level
    threat_level = determine_threat_level(label, probabilities, url_features)
    final_confidence = calculate_final_confidence(probabilities, url_features)
    
    # Create enhanced result
    result = {
        'url': url,
        'class': class_mapping.get(label, f'Unknown ({label})'),
        'class_id': int(label),
        'probabilities': {
            class_mapping.get(i, f'Class {i}'): float(prob)
            for i, prob in enumerate(probabilities)
        },
        'threat_level': threat_level,
        'final_confidence': final_confidence,
        'url_features': url_features
    }
    
    return result

def extract_url_features(url):
    """Extract URL features only"""
    from src.features.enhanced_url_features import EnhancedURLFeatureExtractor, calculate_url_confidence
    
    # Extract features
    extractor = EnhancedURLFeatureExtractor()
    features = extractor.extract_url_structure_features(url)
    
    # Calculate confidence score
    confidence = calculate_url_confidence(features)
    
    # Return selected features for display
    return {
        'has_ip_address': features['has_ip_address'],
        'has_at_symbol': features['has_at_symbol'],
        'has_common_typos': features['has_common_typos'],
        'has_security_keywords': features['has_security_keywords'],
        'has_login_keywords': features['has_login_keywords'],
        'domain_age_days': features['domain_age_days'],
        'url_confidence_score': confidence
    }

def classify_batch(urls, model, pipeline, fetch_params=None):
    """
    Classify a batch of URLs.
    
    Parameters:
    -----------
    urls : list
        List of URLs to classify
    model : PhishingEnsembleClassifier
        Trained classifier
    pipeline : FeaturePipeline
        Feature pipeline
    fetch_params : dict, optional
        Parameters for content fetching
    
    Returns:
    --------
    list
        Classification results
    """
    # Set default fetch parameters
    if fetch_params is None:
        fetch_params = {'max_workers': 5, 'timeout': 5, 'delay': 0.5}
    
    # Extract content features
    content_features = extract_content_features(urls, **fetch_params)
    
    # Initialize results
    results = []
    
    # Process each URL
    for i, url in enumerate(urls):
        # Get URL features
        url_features = extract_url_features(url)
        
        # Check if fetch was successful
        if content_features.at[i, 'fetch_success'] == 0:
            results.append({
                'url': url,
                'error': 'Failed to fetch content',
                'class': None,
                'probabilities': None,
                'threat_level': determine_threat_level_from_url(url_features),
                'url_features': url_features,
                'url_confidence_score': url_features.get('url_confidence_score', 0)
            })
            continue
        
        # Create a single row DataFrame for this URL
        url_content_features = content_features.iloc[[i]].copy()
        
        # Select feature columns - only use original features for ML prediction
        feature_cols = [col for col in url_content_features.columns if col not in ['url', 'fetch_success']]
        
        # Transform features
        X = pipeline.transform(url_content_features[feature_cols])
        
        # Make prediction
        label = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]
        
        # Create class mapping
        class_mapping = {
            0: 'Legitimate',
            1: 'Credential Phishing',
            2: 'Malware Distribution'
        }
        
        # Calculate threat level and confidence
        threat_level = determine_threat_level(label, probabilities, url_features)
        final_confidence = calculate_final_confidence(probabilities, url_features)
        
        # Create result
        result = {
            'url': url,
            'class': class_mapping.get(label, f'Unknown ({label})'),
            'class_id': int(label),
            'probabilities': {
                class_mapping.get(i, f'Class {i}'): float(prob)
                for i, prob in enumerate(probabilities)
            },
            'threat_level': threat_level,
            'final_confidence': final_confidence,
            'url_features': url_features
        }
        
        results.append(result)
    
    return results

def determine_threat_level(label, probabilities, url_features):
    """
    Determine the threat level based on classification and features
    
    Parameters:
    -----------
    label : int
        Predicted label
    probabilities : list
        Prediction probabilities
    features : dict
        URL features
    
    Returns:
    --------
    str
        Threat level (high, medium, low, safe)
    """
    max_prob = max(probabilities)
    
    # High threat for malware or high-confidence phishing
    if label == 2:  # Malware Distribution
        return 'high'
    elif label == 1 and max_prob > 0.7:  # Credential Phishing with high confidence
        return 'high'
    elif label == 1:  # Credential Phishing with lower confidence
        return 'medium'
    elif url_features.get('url_confidence_score', 0) > 0.6:  # URL looks very suspicious
        return 'medium'
    elif label == 0 and max_prob > 0.9:  # Legitimate with high confidence
        return 'safe'
    else:
        return 'low'

def determine_threat_level_from_url(url_features):
    """
    Determine threat level based only on URL features
    
    Parameters:
    -----------
    url_features : dict
        URL features
    
    Returns:
    --------
    str
        Threat level (high, medium, low)
    """
    score = url_features.get('url_confidence_score', 0)
    
    if score > 0.7:
        return 'high'
    elif score > 0.4:
        return 'medium'
    else:
        return 'low'

def calculate_final_confidence(probabilities, url_features):
    """
    Calculate a final confidence score combining ML prediction and URL features
    
    Parameters:
    -----------
    probabilities : list
        Prediction probabilities
    features : dict
        URL features
    
    Returns:
    --------
    float
        Final confidence score between 0-1
    """
    # Get maximum probability from ML model
    ml_confidence = max(probabilities)
    
    # Get URL confidence score
    url_confidence = url_features.get('url_confidence_score', 0.5)
    
    # Weighted combination (ML model has more weight)
    final_confidence = (ml_confidence * 0.7) + (url_confidence * 0.3)
    
    return final_confidence

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Classify URLs')
    parser.add_argument('--url', help='URL to classify')
    parser.add_argument('--file', help='File with URLs to classify')
    parser.add_argument('--model-dir', default='data/processed', help='Model directory')
    
    args = parser.parse_args()
    
    # Load model and pipeline
    try:
        model, pipeline = load_model_and_pipeline(args.model_dir)
        
        if args.url:
            # Classify single URL
            result = classify_url(args.url, model, pipeline)
            print(f"\nResults for {args.url}:")
            if 'error' in result and result['error']:
                print(f"Error: {result['error']}")
                if 'url_features' in result:
                    print(f"URL-based Threat Level: {result.get('threat_level', 'unknown').upper()}")
                    print(f"URL Confidence Score: {result.get('url_confidence_score', 0):.4f}")
            else:
                print(f"Classification: {result['class']}")
                print(f"Threat Level: {result.get('threat_level', 'unknown').upper()}")
                print(f"Final Confidence: {result.get('final_confidence', 0):.4f}")
                print("Probabilities:")
                for class_name, prob in result['probabilities'].items():
                    print(f"  {class_name}: {prob:.4f}")
                
            if 'url_features' in result:
                print("\nKey URL Features:")
                for feature, value in result['url_features'].items():
                    print(f"  {feature}: {value}")
        
        elif args.file:
            # Classify batch of URLs
            urls = []
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            results = classify_batch(urls, model, pipeline)
            
            print(f"\nResults for {len(urls)} URLs:")
            for result in results:
                if 'error' in result and result['error']:
                    threat = result.get('threat_level', 'unknown').upper()
                    confidence = result.get('url_confidence_score', 0)
                    print(f"{result['url']}: Error - {result['error']} (URL Threat: {threat}, Confidence: {confidence:.4f})")
                else:
                    confidence = result.get('final_confidence', max(result['probabilities'].values()))
                    threat = result.get('threat_level', 'unknown').upper()
                    print(f"{result['url']}: {result['class']} ({threat}, confidence: {confidence:.4f})")
        
        else:
            print("Please provide either a URL or a file with URLs to classify.")
    
    except Exception as e:
        print(f"Error: {str(e)}")