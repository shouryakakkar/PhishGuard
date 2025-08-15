import pandas as pd
import numpy as np
import re
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
import joblib
from urllib.parse import urlparse
import tld
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailPhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1, 2))
        self.model = LogisticRegression(random_state=42)
        self.is_trained = False
        self.phishing_keywords = [
            'urgent', 'verify', 'suspend', 'click here', 'act now', 'limited time',
            'confirm identity', 'update payment', 'security alert', 'account blocked',
            'immediate action', 'verify account', 'click link', 'suspended account',
            'update information', 'confirm details', 'expire', 'winner', 'congratulations',
            'claim prize', 'tax refund', 'inheritance', 'lottery', 'bitcoin', 'cryptocurrency'
        ]
    
    def preprocess_email(self, text: str) -> str:
        """Clean and preprocess email text"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove URLs (but keep them for separate analysis)
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', '', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def extract_features(self, text: str) -> Dict:
        """Extract additional features from email text"""
        features = {}
        
        # Keyword matching
        keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in text.lower())
        features['keyword_count'] = keyword_count
        
        # Text statistics
        features['text_length'] = len(text)
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['caps_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        
        return features
    
    def train_on_synthetic_data(self):
        """Train model on synthetic phishing data for demo purposes"""
        logger.info("Training email model on synthetic data...")
        
        # Synthetic phishing emails
        phishing_emails = [
            "URGENT: Your account will be suspended! Click here to verify immediately.",
            "Security Alert: Unusual activity detected. Confirm your identity now.",
            "Your PayPal account has been limited. Update your payment information.",
            "Congratulations! You've won $1000. Click link to claim your prize.",
            "IRS Tax Refund: You are eligible for $2,500 refund. Verify details.",
            "Your bank account will be closed. Act now to prevent suspension.",
            "Bitcoin investment opportunity! Limited time offer - act fast!",
            "Update your Netflix password immediately or lose access.",
            "Your Amazon order needs verification. Click here to confirm.",
            "Microsoft security team: Your account has been compromised.",
        ]
        
        # Legitimate emails
        legitimate_emails = [
            "Thank you for your purchase. Your order has been confirmed.",
            "Meeting reminder: Weekly team standup at 10 AM tomorrow.",
            "Your monthly statement is now available in your account.",
            "Welcome to our newsletter! Here are this week's updates.",
            "Project deadline reminder: Please submit your reports by Friday.",
            "Your subscription has been renewed successfully.",
            "New features are now available in your dashboard.",
            "Thank you for contacting customer support. Here's your ticket.",
            "Your appointment has been scheduled for next Tuesday.",
            "System maintenance scheduled for this weekend.",
        ]
        
        # Create training data
        emails = phishing_emails + legitimate_emails
        labels = [1] * len(phishing_emails) + [0] * len(legitimate_emails)
        
        # Preprocess and vectorize
        processed_emails = [self.preprocess_email(email) for email in emails]
        X = self.vectorizer.fit_transform(processed_emails)
        
        # Train model
        self.model.fit(X, labels)
        self.is_trained = True
        
        logger.info("Email model training completed!")
        return True
    
    def predict(self, email_text: str) -> Dict:
        """Predict if email is phishing"""
        if not self.is_trained:
            self.train_on_synthetic_data()
        
        processed_text = self.preprocess_email(email_text)
        features = self.extract_features(email_text)
        
        # Vectorize text
        X = self.vectorizer.transform([processed_text])
        
        # Predict
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(max(probability)),
            'risk_score': float(probability[1]),  # Probability of being phishing
            'features': features,
            'classification': 'Phishing' if prediction else 'Legitimate'
        }

class URLPhishingDetector:
    def __init__(self):
        self.model = LogisticRegression(random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.click', '.download']
        self.phishing_keywords = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'banking', 'secure', 'verification', 'confirm', 'update', 'login'
        ]
    
    def extract_url_features(self, url: str) -> np.array:
        """Extract features from URL"""
        features = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            # Basic URL features
            features.append(len(url))  # URL length
            features.append(len(domain))  # Domain length
            features.append(len(path))  # Path length
            features.append(url.count('.'))  # Number of dots
            features.append(url.count('/'))  # Number of slashes
            features.append(url.count('-'))  # Number of hyphens
            features.append(url.count('_'))  # Number of underscores
            features.append(url.count('?'))  # Number of question marks
            features.append(url.count('='))  # Number of equals
            features.append(url.count('@'))  # Number of @ symbols
            
            # Suspicious character patterns
            features.append(1 if '//' in path else 0)  # Double slash in path
            features.append(1 if '@' in url else 0)  # @ symbol present
            features.append(1 if any(tld in domain for tld in self.suspicious_tlds) else 0)  # Suspicious TLD
            
            # Keyword matching
            keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in url.lower())
            features.append(keyword_count)
            
            # IP address check
            features.append(1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0)
            
            # HTTPS check
            features.append(1 if parsed.scheme == 'https' else 0)
            
            # Subdomain count
            features.append(len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0)
            
            # URL shortening services
            shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']
            features.append(1 if any(short in domain for short in shorteners) else 0)
            
        except Exception as e:
            logger.error(f"Error extracting URL features: {e}")
            features = [0] * 18  # Default feature vector
        
        return np.array(features).reshape(1, -1)
    
    def train_on_synthetic_data(self):
        """Train model on synthetic URL data"""
        logger.info("Training URL model on synthetic data...")
        
        # Synthetic phishing URLs
        phishing_urls = [
            "http://paypal-security.tk/verify-account?user=12345",
            "https://amazon-update.ml/confirm-payment.php",
            "http://microsoft-security.cf/login.html",
            "https://secure-banking.xyz/update-info",
            "http://192.168.1.100/phishing.php",
            "https://apple-verification.click/confirm",
            "http://facebook-security.ga/verify.php",
            "https://google-update.top/signin.html",
            "http://paypal.secure-login.tk/verify",
            "https://amazon.security-check.ml/update",
        ]
        
        # Legitimate URLs
        legitimate_urls = [
            "https://www.paypal.com/signin",
            "https://www.amazon.com/account",
            "https://www.microsoft.com/security",
            "https://www.apple.com/support",
            "https://www.google.com/accounts",
            "https://www.facebook.com/login",
            "https://github.com/security",
            "https://stackoverflow.com/questions",
            "https://docs.python.org/3/",
            "https://www.reddit.com/r/programming",
        ]
        
        # Create training data
        urls = phishing_urls + legitimate_urls
        labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
        
        # Extract features
        X = np.vstack([self.extract_url_features(url) for url in urls])
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled, labels)
        self.is_trained = True
        
        logger.info("URL model training completed!")
        return True
    
    def predict(self, url: str) -> Dict:
        """Predict if URL is phishing"""
        if not self.is_trained:
            self.train_on_synthetic_data()
        
        # Extract features
        features = self.extract_url_features(url)
        features_scaled = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(max(probability)),
            'risk_score': float(probability[1]),  # Probability of being phishing
            'classification': 'Malicious' if prediction else 'Safe',
            'url_length': len(url),
            'suspicious_patterns': self._analyze_patterns(url)
        }
    
    def _analyze_patterns(self, url: str) -> List[str]:
        """Analyze URL for suspicious patterns"""
        patterns = []
        
        if len(url) > 100:
            patterns.append("Unusually long URL")
        
        if '@' in url:
            patterns.append("Contains @ symbol")
        
        if '//' in url.split('://', 1)[-1]:
            patterns.append("Contains double slashes in path")
        
        if any(tld in url.lower() for tld in self.suspicious_tlds):
            patterns.append("Suspicious top-level domain")
        
        if re.match(r'.*\d+\.\d+\.\d+\.\d+.*', url):
            patterns.append("Uses IP address instead of domain")
        
        return patterns

# Initialize global models
email_detector = EmailPhishingDetector()
url_detector = URLPhishingDetector()