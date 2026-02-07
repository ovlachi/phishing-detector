import numpy as np
import pandas as pd
import os
import pickle
import json
from sklearn.ensemble import VotingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

class FeaturePipeline:
    def __init__(self, output_dir="data/processed"):
        """Initialize the feature processing pipeline."""
        self.output_dir = output_dir
        self.transformer = None
        os.makedirs(output_dir, exist_ok=True)
    
    def fit_transform(self, features, y=None):
        """Fit and transform features."""
        # Select numeric features
        numeric_features = features.select_dtypes(include=['int64', 'float64']).columns.tolist()
        
        # Remove URL column if present
        if 'url' in numeric_features:
            numeric_features.remove('url')
            
        # Remove fetch_success column if present
        if 'fetch_success' in numeric_features:
            numeric_features.remove('fetch_success')
        
        # Create transformer pipeline
        self.transformer = Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])
        
        # Fit and transform
        features_transformed = pd.DataFrame(
            self.transformer.fit_transform(features[numeric_features]),
            columns=numeric_features
        )
        
        # Save transformer
        with open(f"{self.output_dir}/feature_transformer.pkl", 'wb') as f:
            pickle.dump(self.transformer, f)
        
        return features_transformed
    
    def transform(self, features):
        """Transform features using pre-fit transformer."""
        if self.transformer is None:
            raise ValueError("Pipeline not fitted. Call fit_transform first.")
        
        # Select numeric features
        numeric_features = features.select_dtypes(include=['int64', 'float64']).columns.tolist()
        
        # Remove URL column if present
        if 'url' in numeric_features:
            numeric_features.remove('url')
            
        # Remove fetch_success column if present
        if 'fetch_success' in numeric_features:
            numeric_features.remove('fetch_success')
        
        # Transform
        features_transformed = pd.DataFrame(
            self.transformer.transform(features[numeric_features]),
            columns=numeric_features
        )
        
        return features_transformed
    
    def load_transformer(self):
        """Load pre-trained transformer from disk. Prioritizes binary transformer."""
        try:
            # Try binary transformer first (matches binary model)
            binary_path = f"{self.output_dir}/feature_transformer_binary.pkl"
            standard_path = f"{self.output_dir}/feature_transformer.pkl"

            if os.path.exists(binary_path):
                with open(binary_path, 'rb') as f:
                    self.transformer = pickle.load(f)
                print("✅ Loaded binary feature transformer")
                return True
            elif os.path.exists(standard_path):
                with open(standard_path, 'rb') as f:
                    self.transformer = pickle.load(f)
                return True
            else:
                return False
        except FileNotFoundError:
            return False

class PhishingEnsembleClassifier:
    def __init__(self, model_types=['xgboost', 'rf', 'gb'], weights=None, class_weights=None, output_dir="data/models"):
        """
        Initialize the ensemble classifier.
        
        Parameters:
        -----------
        model_types : list
            List of base model types to include in the ensemble
        weights : list, optional
            Weights for each model in the ensemble
        class_weights : dict, optional
            Weights for each class (0=legitimate, 1=phishing, 2=malware)
        output_dir : str
            Directory to save model files
        """
        self.model_types = model_types
        self.weights = weights
        self.class_weights = class_weights
        self.output_dir = output_dir
        self.base_models = []
        self.ensemble_model = None
        os.makedirs(output_dir, exist_ok=True)
    
    def _create_base_model(self, model_type, params=None):
        """Create a base model of the specified type."""
        if params is None:
            params = {}
            
        if model_type == 'xgboost':
            default_params = {
                'objective': 'multi:softprob',
                'learning_rate': 0.05,  # Lower for better generalization
                'max_depth': 8,  # Increased depth
                'min_child_weight': 3,  # Prevent overfitting
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'eval_metric': 'mlogloss',
                'use_label_encoder': False,
                'random_state': 42,
                'n_estimators': 200,  # More trees
                'reg_alpha': 0.1,  # L1 regularization
                'reg_lambda': 1.0,  # L2 regularization
                'gamma': 0.1  # Minimum loss reduction
            }

            # Add class weights for XGBoost - multiclass case requires special handling
            # We don't use scale_pos_weight for multiclass, as it's only for binary classification
            default_params.update(params)
            return xgb.XGBClassifier(**default_params)
            
        elif model_type == 'rf':
            default_params = {
                'n_estimators': 300,  # More trees for better accuracy
                'max_depth': 15,  # Deeper trees
                'min_samples_split': 5,  # Prevent overfitting
                'min_samples_leaf': 2,  # Prevent overfitting
                'random_state': 42,
                'n_jobs': -1,  # Use all cores
                'max_features': 'sqrt'  # Feature subsampling
            }

            # Add class weights for Random Forest - always use balanced_subsample for imbalanced data
            if self.class_weights:
                # Convert string keys to integers for sklearn
                class_weights_dict = {int(k): v for k, v in self.class_weights.items()}
                default_params['class_weight'] = class_weights_dict
            else:
                default_params['class_weight'] = 'balanced_subsample'  # Better for imbalanced data

            default_params.update(params)
            return RandomForestClassifier(**default_params)
            
        elif model_type == 'gb':
            default_params = {
                'n_estimators': 200,  # More estimators
                'learning_rate': 0.05,  # Lower for better generalization
                'max_depth': 5,  # Deeper trees
                'random_state': 42,
                'min_samples_split': 5,  # Prevent overfitting
                'min_samples_leaf': 2,  # Prevent overfitting
                'subsample': 0.8,  # Stochastic gradient boosting
                'max_features': 'sqrt'  # Feature subsampling
            }

            # Gradient Boosting doesn't support class_weight directly
            # Sample weights will be computed in training

            default_params.update(params)
            return GradientBoostingClassifier(**default_params)
            
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def train(self, X_train, y_train, X_val=None, y_val=None):
        """
        Train the ensemble classifier.
        
        Parameters:
        -----------
        X_train : pandas.DataFrame
            Training features
        y_train : array-like
            Training labels
        X_val : pandas.DataFrame, optional
            Validation features
        y_val : array-like, optional
            Validation labels
        """
        print(f"Training ensemble classifier with {len(self.model_types)} base models...")
        
        # Determine number of classes for XGBoost
        num_classes = len(np.unique(y_train))
        
        # Initialize and train base models
        estimators = []
        for i, model_type in enumerate(self.model_types):
            print(f"Training base model {i+1}/{len(self.model_types)}: {model_type}")
            
            # Add num_class parameter for XGBoost
            params = {'num_class': num_classes} if model_type == 'xgboost' else {}
            
            # Create the model
            model = self._create_base_model(model_type, params)
            
            # Create sample weights for class imbalance handling
            sample_weight = None
            if self.class_weights:
                sample_weight = np.ones(len(y_train))
                for class_idx, weight in self.class_weights.items():
                    sample_weight[y_train == int(class_idx)] = weight
                print(f"  Using sample weights: {dict(zip(*np.unique(y_train, return_counts=True)))}")

            # Train the model
            if model_type == 'xgboost' and X_val is not None and y_val is not None:
                # First train with early stopping using validation data
                eval_set = [(X_val, y_val)]
                try:
                    model.fit(
                        X_train, y_train,
                        eval_set=eval_set,
                        sample_weight=sample_weight,  # Add sample weights
                        verbose=False
                    )
                except ValueError:
                    # Fallback if validation fails
                    model.fit(X_train, y_train, sample_weight=sample_weight)
                
                # Disable early stopping for ensemble use
                if hasattr(model, 'set_params'):
                    model.set_params(early_stopping_rounds=None)
            elif model_type == 'gb' and sample_weight is not None:
                # Train GB with sample weights
                model.fit(X_train, y_train, sample_weight=sample_weight)
            else:
                model.fit(X_train, y_train)
            
            # Save the individual model
            model_path = f"{self.output_dir}/{model_type}_base_model.pkl"
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            
            # Add to estimators list
            estimators.append((model_type, model))
            self.base_models.append(model)
        
        # Create and train the ensemble model
        self.ensemble_model = VotingClassifier(
            estimators=estimators,
            voting='soft',
            weights=self.weights
        )
        
        # Fit the ensemble
        self.ensemble_model.fit(X_train, y_train)
        
        # Save the ensemble model
        ensemble_path = f"{self.output_dir}/ensemble_model.pkl"
        with open(ensemble_path, 'wb') as f:
            pickle.dump(self.ensemble_model, f)
        
        print(f"Ensemble model saved to {ensemble_path}")
    
    def predict(self, X):
        """Make predictions with the ensemble model."""
        if self.ensemble_model is None:
            raise ValueError("Ensemble model not trained. Call train first.")
        
        return self.ensemble_model.predict(X)
    
    def predict_proba(self, X):
        """Get prediction probabilities from the ensemble model."""
        if self.ensemble_model is None:
            raise ValueError("Ensemble model not trained. Call train first.")
        
        return self.ensemble_model.predict_proba(X)
    
    def evaluate(self, X, y_true):
        """Evaluate ensemble model performance."""
        if self.ensemble_model is None:
            raise ValueError("Ensemble model not trained. Call train first.")
        
        y_pred = self.predict(X)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        report = classification_report(y_true, y_pred, output_dict=True)
        conf_matrix = confusion_matrix(y_true, y_pred)
        
        # Create results dictionary
        results = {
            'accuracy': accuracy,
            'report': report,
            'confusion_matrix': conf_matrix
        }
        
        # Print results
        print(f"Ensemble Accuracy: {accuracy:.4f}")
        print("\nEnsemble Classification Report:")
        print(classification_report(y_true, y_pred))
        print("\nEnsemble Confusion Matrix:")
        print(conf_matrix)
        
        # Evaluate and compare with base models
        print("\nComparison with base models:")
        for i, model in enumerate(self.base_models):
            base_y_pred = model.predict(X)
            base_acc = accuracy_score(y_true, base_y_pred)
            print(f"{self.model_types[i]}: {base_acc:.4f}")
        
        return results
    
    def load_model(self):
        """Load pre-trained ensemble model from disk. Prioritizes binary model for better accuracy."""
        try:
            # Try binary ensemble first (80.5% accuracy vs 71% for 3-class)
            binary_path = f"{self.output_dir}/binary_ensemble.pkl"
            ensemble_path = f"{self.output_dir}/ensemble_model.pkl"

            if os.path.exists(binary_path):
                with open(binary_path, 'rb') as f:
                    self.ensemble_model = pickle.load(f)
                print("✅ Loaded BINARY classifier (Legitimate vs Malicious) - 80.5% accuracy")
                self.base_models = []  # Binary model is self-contained
                return True
            elif os.path.exists(ensemble_path):
                with open(ensemble_path, 'rb') as f:
                    self.ensemble_model = pickle.load(f)
                # Load base models for 3-class ensemble
                self.base_models = []
                for model_type in self.model_types:
                    model_path = f"{self.output_dir}/{model_type}_base_model.pkl"
                    if os.path.exists(model_path):
                        with open(model_path, 'rb') as f:
                            self.base_models.append(pickle.load(f))
                return True
            else:
                raise FileNotFoundError("No ensemble model found")

        except FileNotFoundError as e:
            print(f"Error loading model: {str(e)}")
            return False