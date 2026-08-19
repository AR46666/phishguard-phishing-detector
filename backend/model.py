import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from .feature_extractor import FeatureExtractor

class PhishingClassifier:
    """Machine Learning classifier for phishing URL detection."""
    
    def __init__(self, model_path=None, scaler_path=None):
        # Determine reasonable defaults relative to the project root
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        models_dir = os.path.join(base_dir, 'models')

        # If explicit paths not provided, try common filenames and fall back
        if model_path is None:
            candidate = os.path.join(models_dir, 'phishing_model.pkl')
            if os.path.exists(candidate):
                model_path = candidate
            else:
                # Try to find any file that looks like a phishing model
                model_path = None
                try:
                    for fname in os.listdir(models_dir):
                        if 'phish' in fname.lower():
                            model_path = os.path.join(models_dir, fname)
                            break
                except Exception:
                    model_path = os.path.join('..', 'models', 'phishing_model.pkl')

        if scaler_path is None:
            candidate = os.path.join(models_dir, 'scaler.pkl')
            if os.path.exists(candidate):
                scaler_path = candidate
            else:
                scaler_path = None
                try:
                    for fname in os.listdir(models_dir):
                        if 'scaler' in fname.lower():
                            scaler_path = os.path.join(models_dir, fname)
                            break
                except Exception:
                    scaler_path = os.path.join('..', 'models', 'scaler.pkl')

        # Keep stored values (may still be relative paths if models not present)
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.feature_names = None
    
    def _generate_training_data(self, urls, labels):
        """Generate feature vectors for a list of URLs."""
        features_list = []
        valid_indices = []
        
        for i, url in enumerate(urls):
            try:
                vec = self.feature_extractor.get_feature_vector(url)
                features_list.append(vec)
                valid_indices.append(i)
            except Exception as e:
                print(f"Error extracting features from {url}: {e}")
                continue
        
        if not features_list:
            raise ValueError("No features could be extracted from the provided URLs")
        
        X = np.array(features_list)
        y = np.array([labels[i] for i in valid_indices])
        
        # Get feature names
        if self.feature_names is None:
            self.feature_names = self.feature_extractor.get_feature_names()
        
        return X, y
    
    def train(self, csv_path=None, urls=None, labels=None, test_size=0.2, random_state=42):
        """
        Train the Random Forest classifier.
        
        Args:
            csv_path: Path to CSV with 'url' and 'label' columns (label: 0=legit, 1=phishing)
            urls: List of URL strings (alternative to csv_path)
            labels: List of labels (alternative to csv_path)
        """
        
        if csv_path:
            import pandas as pd
            df = pd.read_csv(csv_path)
            urls = df['url'].values
            labels = df['label'].values
        
        print(f"Loading {len(urls)} URLs for feature extraction...")
        X, y = self._generate_training_data(urls, labels)
        print(f"Successfully extracted features. Feature matrix shape: {X.shape}")
        
        # Split into train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest classifier...")
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=25,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced',
            random_state=random_state,
            n_jobs=-1
        )
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_proba)
        
        print("\n=== Model Performance ===")
        print(f"Accuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")
        print(f"AUC-ROC:   {auc:.4f}")
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        print(f"\nCross-validation scores: {cv_scores}")
        print(f"Mean CV accuracy: {cv_scores.mean():.4f}")
        
        # Feature importance
        if self.feature_names:
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[::-1]
            print("\nTop 10 Most Important Features:")
            for i in range(min(10, len(indices))):
                print(f"  {i+1}. {self.feature_names[indices[i]]}: {importances[indices[i]]:.4f}")
        
        # Save model
        self._save_model()
        
        return {
            'accuracy': accuracy,
            'precision': precision, 
            'recall': recall,
            'f1': f1,
            'auc': auc,
            'cv_mean': cv_scores.mean()
        }
    
    def predict(self, url):
        """Predict whether a single URL is phishing or legitimate."""
        if self.model is None:
            self._load_model()
        
        features = np.array([self.feature_extractor.get_feature_vector(url)])
        
        if self.scaler:
            features = self.scaler.transform(features)
        
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0]
        
        return {
            'ml_prediction': int(prediction),
            'ml_verdict': 'phishing' if prediction == 1 else 'legitimate',
            'ml_probability': float(probability[1]),
            'ml_confidence': float(max(probability))
        }
    
    def predict_batch(self, urls):
        """Predict for a list of URLs."""
        results = []
        for url in urls:
            
            results.append(self.predict(url))
        return results
    
    def _save_model(self):
        """Save trained model and scaler to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        print(f"Model saved to {self.model_path}")
        print(f"Scaler saved to {self.scaler_path}")
    
    def _load_model(self):
        """Load trained model and scaler from disk."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model not found at {self.model_path}. Train the model first."
            )
        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)
        print(f"Model loaded from {self.model_path}")
    
    def get_feature_importance(self):
        """Return feature importance DataFrame."""
        import pandas as pd

        if self.model is None:
            self._load_model()
        
        if self.feature_names is None:
            self.feature_names = self.feature_extractor.get_feature_names()
        
        importances = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        return importances