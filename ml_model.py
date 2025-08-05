import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

class URLClassifier:
    def __init__(self):
        self.model = None
        self.feature_names = [
            'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
            'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
            'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
            'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
        ]
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the ML model with pre-trained weights or train a new one"""
        model_path = 'url_classifier_model.pkl'
        
        try:
            # Try to load existing model
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logging.info("Loaded existing ML model")
            else:
                # Train a new model with synthetic data
                self._train_model()
                # Save the model
                with open(model_path, 'wb') as f:
                    pickle.dump(self.model, f)
                logging.info("Trained and saved new ML model")
                
        except Exception as e:
            logging.error(f"Error initializing model: {e}")
            # Create a simple fallback model
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self._train_model()
    
    def _train_model(self):
        """Train the model with synthetic training data"""
        # Generate synthetic training data based on phishing URL patterns
        X_train, y_train = self._generate_training_data()
        
        # Initialize and train the model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        X_train_split, X_test, y_train_split, y_test = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42
        )
        
        self.model.fit(X_train_split, y_train_split)
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logging.info(f"Model trained with accuracy: {accuracy:.3f}")
        logging.debug(f"Classification Report:\n{classification_report(y_test, y_pred)}")
    
    def _generate_training_data(self, n_samples=10000):
        """Generate synthetic training data for URL classification"""
        np.random.seed(42)
        
        # Generate features for legitimate URLs (class 0)
        n_legit = n_samples // 2
        legit_features = []
        
        for _ in range(n_legit):
            features = [
                np.random.choice([0, 1], p=[0.98, 0.02]),  # UsingIP - almost never for legit
                np.random.choice([0, 1], p=[0.7, 0.3]),   # LongURL - sometimes long for legit
                np.random.choice([0, 1], p=[0.99, 0.01]), # ShortURL - rarely short URLs
                np.random.choice([0, 1], p=[0.995, 0.005]), # Symbol@ - very rare in legit URLs
                np.random.choice([0, 1], p=[0.98, 0.02]), # Redirecting// - very rare
                np.random.choice([0, 1], p=[0.6, 0.4]),   # PrefixSuffix- - common in legit sites
                np.random.choice([0, 1, 2], p=[0.5, 0.4, 0.1]), # SubDomains - often 0-1
                np.random.choice([0, 1], p=[0.85, 0.15]), # HTTPS - mostly use HTTPS
                np.random.choice([0, 1], p=[0.9, 0.1]),   # DomainRegLen - mostly long reg
                np.random.choice([0, 1], p=[0.95, 0.05]), # Favicon - usually from same domain
                np.random.choice([0, 1], p=[0.98, 0.02]), # NonStdPort - usually standard
                np.random.choice([0, 1], p=[0.9, 0.1]),   # HTTPSDomainURL
                np.random.choice([0, 1], p=[0.9, 0.1]),   # RequestURL
                np.random.choice([0, 1], p=[0.85, 0.15]), # AnchorURL
                np.random.choice([0, 1], p=[0.9, 0.1]),   # LinksInScriptTags
                np.random.choice([0, 1], p=[0.98, 0.02]), # ServerFormHandler
                np.random.choice([0, 1], p=[0.4, 0.6]),   # InfoEmail - many legit sites have email
                np.random.choice([0, 1], p=[0.95, 0.05]), # AbnormalURL
                np.random.choice([0, 1], p=[0.98, 0.02]), # WebsiteForwarding
                np.random.choice([0, 1], p=[0.99, 0.01]), # StatusBarCust
                np.random.choice([0, 1], p=[0.99, 0.01]), # DisableRightClick
                np.random.choice([0, 1], p=[0.98, 0.02]), # UsingPopupWindow
                np.random.choice([0, 1], p=[0.95, 0.05]), # IframeRedirection
                np.random.choice([0, 1], p=[0.9, 0.1]),   # AgeofDomain - most legit sites are old
                np.random.choice([0, 1], p=[0.98, 0.02]), # DNSRecording
                np.random.choice([0, 1], p=[0.8, 0.2]),   # WebsiteTraffic - better distribution for legit
                np.random.choice([0, 1], p=[0.8, 0.2]),   # PageRank - better for legit
                np.random.choice([0, 1], p=[0.9, 0.1]),   # GoogleIndex - most legit sites indexed
                np.random.choice([0, 1], p=[0.75, 0.25]), # LinksPointingToPage
                np.random.choice([0, 1], p=[0.7, 0.3])    # StatsReport
            ]
            legit_features.append(features)
        
        # Generate features for malicious URLs (class 1)
        n_malicious = n_samples - n_legit
        malicious_features = []
        
        for _ in range(n_malicious):
            features = [
                np.random.choice([0, 1], p=[0.3, 0.7]),   # UsingIP - more likely in malicious
                np.random.choice([0, 1], p=[0.4, 0.6]),   # LongURL - often long
                np.random.choice([0, 1], p=[0.6, 0.4]),   # ShortURL - sometimes short
                np.random.choice([0, 1], p=[0.8, 0.2]),   # Symbol@ - more common
                np.random.choice([0, 1], p=[0.7, 0.3]),   # Redirecting// - more common
                np.random.choice([0, 1], p=[0.4, 0.6]),   # PrefixSuffix- - often present
                np.random.choice([0, 1, 2], p=[0.2, 0.3, 0.5]), # SubDomains - often multiple
                np.random.choice([0, 1], p=[0.3, 0.7]),   # HTTPS - often no HTTPS
                np.random.choice([0, 1], p=[0.2, 0.8]),   # DomainRegLen - often short reg
                np.random.choice([0, 1], p=[0.3, 0.7]),   # Favicon - often external
                np.random.choice([0, 1], p=[0.7, 0.3]),   # NonStdPort - sometimes non-std
                np.random.choice([0, 1], p=[0.3, 0.7]),   # HTTPSDomainURL
                np.random.choice([0, 1], p=[0.2, 0.8]),   # RequestURL - often external
                np.random.choice([0, 1], p=[0.3, 0.7]),   # AnchorURL - often external
                np.random.choice([0, 1], p=[0.4, 0.6]),   # LinksInScriptTags
                np.random.choice([0, 1], p=[0.6, 0.4]),   # ServerFormHandler
                np.random.choice([0, 1], p=[0.3, 0.7]),   # InfoEmail - often missing
                np.random.choice([0, 1], p=[0.2, 0.8]),   # AbnormalURL - often abnormal
                np.random.choice([0, 1], p=[0.6, 0.4]),   # WebsiteForwarding
                np.random.choice([0, 1], p=[0.7, 0.3]),   # StatusBarCust - sometimes used
                np.random.choice([0, 1], p=[0.7, 0.3]),   # DisableRightClick
                np.random.choice([0, 1], p=[0.6, 0.4]),   # UsingPopupWindow
                np.random.choice([0, 1], p=[0.5, 0.5]),   # IframeRedirection
                np.random.choice([0, 1], p=[0.1, 0.9]),   # AgeofDomain - usually new
                np.random.choice([0, 1], p=[0.6, 0.4]),   # DNSRecording
                np.random.choice([0, 1], p=[0.2, 0.8]),   # WebsiteTraffic - usually low
                np.random.choice([0, 1], p=[0.2, 0.8]),   # PageRank - usually low
                np.random.choice([0, 1], p=[0.3, 0.7]),   # GoogleIndex - often not indexed
                np.random.choice([0, 1], p=[0.2, 0.8]),   # LinksPointingToPage - usually few
                np.random.choice([0, 1], p=[0.1, 0.9])    # StatsReport - usually none
            ]
            malicious_features.append(features)
        
        # Combine features and labels
        X = np.array(legit_features + malicious_features)
        y = np.array([0] * n_legit + [1] * n_malicious)
        
        return X, y
    
    def predict(self, features):
        """Predict if URL is malicious based on extracted features"""
        try:
            # Convert features dict to array in correct order
            feature_array = []
            for feature_name in self.feature_names:
                feature_array.append(features.get(feature_name, 1))  # Default to suspicious if missing
            
            feature_array = np.array(feature_array).reshape(1, -1)
            
            # Check if model is initialized
            if self.model is None:
                raise ValueError("Model not initialized")
            
            # Get prediction and probability
            prediction = self.model.predict(feature_array)[0]
            probability = self.model.predict_proba(feature_array)[0]
            
            # Get feature importance
            feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
            
            return {
                'prediction': int(prediction),
                'probability': float(probability[1]),  # Probability of being malicious
                'confidence': float(probability.max()),
                'classification': 'Malicious' if prediction == 1 else 'Legitimate',
                'feature_importance': feature_importance
            }
            
        except Exception as e:
            logging.error(f"Error making prediction: {e}")
            return {
                'prediction': 1,
                'probability': 0.8,
                'confidence': 0.8,
                'classification': 'Malicious',
                'feature_importance': {}
            }
    
    def get_feature_importance(self):
        """Get feature importance from the trained model"""
        if self.model:
            return dict(zip(self.feature_names, self.model.feature_importances_))
        return {}
