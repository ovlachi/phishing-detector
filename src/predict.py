import os
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

# Add project root to Python path
import sys
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.features.content_features import extract_content_features
from src.models.ensemble_classifier import FeaturePipeline, PhishingEnsembleClassifier

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
    Classify a single URL.
    
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
        Classification result
    """
    # Set default fetch parameters
    if fetch_params is None:
        fetch_params = {'max_workers': 1, 'timeout': 5, 'delay': 0}
    
    # Extract content features
    features = extract_content_features([url], **fetch_params)
    
    # Check if fetch was successful
    if features.at[0, 'fetch_success'] == 0:
        return {
            'url': url,
            'error': 'Failed to fetch content',
            'class': None,
            'probabilities': None
        }
    
    # Select feature columns
    feature_cols = [col for col in features.columns if col not in ['url', 'fetch_success']]
    
    # Transform features
    X = pipeline.transform(features[feature_cols])
    
    # Make prediction
    label = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    
    # Create class mapping
    class_mapping = {
        0: 'Legitimate',
        1: 'Credential Phishing',
        2: 'Malware Distribution'
    }
    
    # Create result
    result = {
        'url': url,
        'class': class_mapping.get(label, f'Unknown ({label})'),
        'class_id': int(label),
        'probabilities': {
            class_mapping.get(i, f'Class {i}'): float(prob)
            for i, prob in enumerate(probabilities)
        }
    }
    
    return result

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
    features = extract_content_features(urls, **fetch_params)
    
    # Initialize results
    results = []
    
    # Process each URL
    for i, url in enumerate(urls):
        # Check if fetch was successful
        if features.at[i, 'fetch_success'] == 0:
            results.append({
                'url': url,
                'error': 'Failed to fetch content',
                'class': None,
                'probabilities': None
            })
            continue
        
        # Create a single row DataFrame for this URL
        url_features = features.iloc[[i]].copy()
        
        # Select feature columns
        feature_cols = [col for col in url_features.columns if col not in ['url', 'fetch_success']]
        
        # Transform features
        X = pipeline.transform(url_features[feature_cols])
        
        # Make prediction
        label = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]
        
        # Create class mapping
        class_mapping = {
            0: 'Legitimate',
            1: 'Credential Phishing',
            2: 'Malware Distribution'
        }
        
        # Create result
        result = {
            'url': url,
            'class': class_mapping.get(label, f'Unknown ({label})'),
            'class_id': int(label),
            'probabilities': {
                class_mapping.get(i, f'Class {i}'): float(prob)
                for i, prob in enumerate(probabilities)
            }
        }
        
        results.append(result)
    
    return results

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
            if 'error' in result:
                print(f"Error: {result['error']}")
            else:
                print(f"Classification: {result['class']}")
                print("Probabilities:")
                for class_name, prob in result['probabilities'].items():
                    print(f"  {class_name}: {prob:.4f}")
        
        elif args.file:
            # Classify batch of URLs
            urls = []
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            results = classify_batch(urls, model, pipeline)
            
            print(f"\nResults for {len(urls)} URLs:")
            for result in results:
                if 'error' in result and result['error']:
                    print(f"{result['url']}: Error - {result['error']}")
                else:
                    max_prob = max(result['probabilities'].values())
                    print(f"{result['url']}: {result['class']} (confidence: {max_prob:.4f})")
        
        else:
            print("Please provide either a URL or a file with URLs to classify.")
    
    except Exception as e:
        print(f"Error: {str(e)}")