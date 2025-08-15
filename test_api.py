#!/usr/bin/env python3
"""
Test script for PhishGuard API
This script tests the email and URL analysis endpoints
"""

import requests
import json
import time

API_BASE_URL = "http://localhost:8001"

def test_health():
    """Test the health endpoint"""
    print("🔍 Testing health endpoint...")
    try:
        response = requests.get(f"{API_BASE_URL}/api/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed: {data}")
            return data['models']
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return None

def test_email_analysis():
    """Test email analysis endpoint"""
    print("\n📧 Testing email analysis...")
    
    # Test 1: Legitimate email
    print("  Testing legitimate email...")
    legitimate_email = {
        "subject": "Weekly Team Meeting",
        "body": "Hi everyone, don't forget about our weekly team meeting tomorrow at 2 PM.",
        "sender": "manager@company.com"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/api/analyze-email", json=legitimate_email)
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Legitimate email result: {data['data']['classification']} (confidence: {data['data']['confidence']:.2f})")
        else:
            print(f"  ❌ Legitimate email failed: {response.status_code}")
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  ❌ Legitimate email error: {e}")
    
    # Test 2: Phishing email
    print("  Testing phishing email...")
    phishing_email = {
        "subject": "Urgent PayPal Account Verification Required",
        "body": "Your PayPal account has been temporarily suspended due to unusual activity. Please verify your identity immediately by clicking the link below to avoid permanent account closure. Verify Now: http://paypal-verify.tk/account",
        "sender": "security@paypal.com"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/api/analyze-email", json=phishing_email)
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Phishing email result: {data['data']['classification']} (confidence: {data['data']['confidence']:.2f})")
        else:
            print(f"  ❌ Phishing email failed: {response.status_code}")
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  ❌ Phishing email error: {e}")

def test_url_analysis():
    """Test URL analysis endpoint"""
    print("\n🔗 Testing URL analysis...")
    
    # Test 1: Legitimate URL
    print("  Testing legitimate URL...")
    legitimate_url = {
        "url": "https://www.google.com"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/api/analyze-url", json=legitimate_url)
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Legitimate URL result: {data['data']['classification']} (confidence: {data['data']['confidence']:.2f})")
        else:
            print(f"  ❌ Legitimate URL failed: {response.status_code}")
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  ❌ Legitimate URL error: {e}")
    
    # Test 2: Malicious URL
    print("  Testing malicious URL...")
    malicious_url = {
        "url": "http://paypal-verify.tk/account"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/api/analyze-url", json=malicious_url)
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Malicious URL result: {data['data']['classification']} (confidence: {data['data']['confidence']:.2f})")
        else:
            print(f"  ❌ Malicious URL failed: {response.status_code}")
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  ❌ Malicious URL error: {e}")

def main():
    """Run all tests"""
    print("🧪 PhishGuard API Test Suite")
    print("=" * 50)
    
    # Test health endpoint
    models = test_health()
    if not models:
        print("❌ Cannot proceed without healthy API")
        return
    
    # Wait a moment for models to be ready
    time.sleep(1)
    
    # Test email analysis
    test_email_analysis()
    
    # Test URL analysis
    test_url_analysis()
    
    print("\n🎉 Test suite completed!")

if __name__ == "__main__":
    main()
