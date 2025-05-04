import os
import argparse
import pandas as pd
import numpy as np
import json
from pathlib import Path

# Add project root to Python path
import sys
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.data.prepare_dataset import prepare_dataset
from src.features.content_features import extract_content_features
from src.models.ensemble_classifier import PhishingEnsembleClassifier, FeaturePipeline

def train_ensemble_classifier(
    legitimate_path="data/raw/legitimate.csv",
    phishing_path="data/raw/phishing.csv",
    output_dir="data/processed",
    model_types=['xgboost', 'rf', 'gb'],
    weights=None,
    class_weights=None,
    max_workers=5,
    batch_size=100
):
    """Train an ensemble phishing and malware classification model."""
    # Step 1: Prepare dataset
    print("Step 1: Preparing dataset")
    train_df, val_df, test_df = prepare_dataset(
        legitimate_path=legitimate_path,
        phishing_path=phishing_path,
        output_dir=output_dir
    )
    
    # Step 2: Extract content features
    print("Step 2: Extracting content features")
    
    # Training set
    if os.path.exists(f"{output_dir}/train_content_features.csv"):
        print("Loading cached training features...")
        train_features = pd.read_csv(f"{output_dir}/train_content_features.csv")
    else:
        # Process in batches for large datasets
        if batch_size < len(train_df):
            all_features = []
            for i in range(0, len(train_df), batch_size):
                end_idx = min(i + batch_size, len(train_df))
                print(f"Processing training batch {i+1}-{end_idx} of {len(train_df)}")
                
                batch_urls = train_df['url'].iloc[i:end_idx]
                batch_features = extract_content_features(batch_urls, max_workers=max_workers)
                
                # Add labels
                batch_features['label'] = train_df['label'].iloc[i:end_idx].values
                all_features.append(batch_features)
            
            train_features = pd.concat(all_features, ignore_index=True)
        else:
            train_features = extract_content_features(train_df['url'], max_workers=max_workers)
            train_features['label'] = train_df['label'].values
        
        # Save to CSV
        train_features.to_csv(f"{output_dir}/train_content_features.csv", index=False)
    
    # Validation set
    if os.path.exists(f"{output_dir}/val_content_features.csv"):
        print("Loading cached validation features...")
        val_features = pd.read_csv(f"{output_dir}/val_content_features.csv")
    else:
        val_features = extract_content_features(val_df['url'], max_workers=max_workers)
        val_features['label'] = val_df['label'].values
        val_features.to_csv(f"{output_dir}/val_content_features.csv", index=False)
    
    # Test set
    if os.path.exists(f"{output_dir}/test_content_features.csv"):
        print("Loading cached test features...")
        test_features = pd.read_csv(f"{output_dir}/test_content_features.csv")
    else:
        test_features = extract_content_features(test_df['url'], max_workers=max_workers)
        test_features['label'] = test_df['label'].values
        test_features.to_csv(f"{output_dir}/test_content_features.csv", index=False)
    
    # Step 3: Apply feature pipeline
    print("Step 3: Processing features")
    pipeline = FeaturePipeline(output_dir=output_dir)
    
    # Remove non-feature columns before transformation
    feature_cols = [col for col in train_features.columns if col not in ['url', 'label']]
    
    # Transform features
    X_train = pipeline.fit_transform(train_features[feature_cols])
    X_val = pipeline.transform(val_features[feature_cols])
    X_test = pipeline.transform(test_features[feature_cols])
    
    y_train = train_features['label']
    y_val = val_features['label']
    y_test = test_features['label']
    
    # Step 4: Train ensemble model
    print("Step 4: Training ensemble model")
    ensemble = PhishingEnsembleClassifier(
        model_types=model_types,
        weights=weights,
        class_weights=class_weights,
        output_dir=f"{output_dir}/models"
    )
    ensemble.train(X_train, y_train, X_val, y_val)
    
    # Step 5: Evaluate model
    print("Step 5: Evaluating ensemble model")
    print("\nTraining set evaluation:")
    train_results = ensemble.evaluate(X_train, y_train)
    
    print("\nValidation set evaluation:")
    val_results = ensemble.evaluate(X_val, y_val)
    
    print("\nTest set evaluation:")
    test_results = ensemble.evaluate(X_test, y_test)
    
    return {
        'model': ensemble,
        'pipeline': pipeline,
        'results': {
            'train': train_results,
            'validation': val_results,
            'test': test_results
        }
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train ensemble phishing classifier')
    parser.add_argument('--legitimate', required=True, help='Path to legitimate URLs CSV')
    parser.add_argument('--phishing', required=True, help='Path to phishing URLs CSV')
    parser.add_argument('--output', default='data/processed', help='Output directory')
    parser.add_argument('--models', nargs='+', default=['xgboost', 'rf', 'gb'], 
                        help='List of models to include in ensemble')
    parser.add_argument('--weights', nargs='+', type=float, help='Model weights')
    parser.add_argument('--class-weights', type=json.loads, 
                        help='Class weights as JSON, e.g. \'{"0": 1.0, "1": 2.0, "2": 5.0}\'')
    parser.add_argument('--workers', type=int, default=5, help='Number of parallel workers')
    parser.add_argument('--batch-size', type=int, default=100, help='Batch size for processing')
    
    args = parser.parse_args()
    
    # Validate weights if provided
    if args.weights and len(args.weights) != len(args.models):
        parser.error("Number of weights must match number of models")
    
    train_ensemble_classifier(
        legitimate_path=args.legitimate,
        phishing_path=args.phishing,
        output_dir=args.output,
        model_types=args.models,
        weights=args.weights,
        class_weights=args.class_weights,
        max_workers=args.workers,
        batch_size=args.batch_size
    )