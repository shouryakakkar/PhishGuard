import requests
import sys
import json
from datetime import datetime

class PhishingDetectionAPITester:
    def __init__(self, base_url="https://phishdetect-4.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
        
        self.test_results.append({
            'test': name,
            'success': success,
            'details': details
        })

    def test_health_endpoint(self):
        """Test the health check endpoint"""
        try:
            response = requests.get(f"{self.base_url}/api/health", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'status' in data and 'models' in data:
                    models = data['models']
                    if 'email_detector' in models and 'url_detector' in models:
                        self.log_test("Health Check", True, f"Models status: {models}")
                        return True, data
                    else:
                        self.log_test("Health Check", False, "Missing model status in response")
                else:
                    self.log_test("Health Check", False, "Missing required fields in response")
            else:
                self.log_test("Health Check", False, f"Status code: {response.status_code}")
                
        except Exception as e:
            self.log_test("Health Check", False, f"Exception: {str(e)}")
        
        return False, {}

    def test_email_analysis_phishing(self):
        """Test email analysis with phishing email"""
        phishing_email = {
            "subject": "URGENT: Account Suspended",
            "body": "Your PayPal account has been suspended. Click here to verify your identity immediately: http://paypal-security.tk/verify",
            "sender": "security@paypal-fake.com"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/analyze-email", 
                json=phishing_email,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'data' in data:
                    result = data['data']
                    # Check if it correctly identifies as phishing
                    if result.get('is_phishing') and result.get('risk_score', 0) > 0.5:
                        self.log_test("Email Analysis - Phishing Detection", True, 
                                    f"Risk score: {result.get('risk_score'):.2f}, Classification: {result.get('classification')}")
                        return True, result
                    else:
                        self.log_test("Email Analysis - Phishing Detection", False, 
                                    f"Failed to detect phishing. Risk score: {result.get('risk_score')}")
                else:
                    self.log_test("Email Analysis - Phishing Detection", False, "Invalid response structure")
            else:
                self.log_test("Email Analysis - Phishing Detection", False, f"Status code: {response.status_code}")
                
        except Exception as e:
            self.log_test("Email Analysis - Phishing Detection", False, f"Exception: {str(e)}")
        
        return False, {}

    def test_email_analysis_legitimate(self):
        """Test email analysis with legitimate email"""
        legitimate_email = {
            "subject": "Meeting Reminder",
            "body": "Don't forget about our team meeting tomorrow at 10 AM. We'll be discussing the quarterly reports.",
            "sender": "team@company.com"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/analyze-email", 
                json=legitimate_email,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'data' in data:
                    result = data['data']
                    # Check if it correctly identifies as legitimate
                    if not result.get('is_phishing') and result.get('risk_score', 1) < 0.5:
                        self.log_test("Email Analysis - Legitimate Detection", True, 
                                    f"Risk score: {result.get('risk_score'):.2f}, Classification: {result.get('classification')}")
                        return True, result
                    else:
                        self.log_test("Email Analysis - Legitimate Detection", False, 
                                    f"False positive. Risk score: {result.get('risk_score')}")
                else:
                    self.log_test("Email Analysis - Legitimate Detection", False, "Invalid response structure")
            else:
                self.log_test("Email Analysis - Legitimate Detection", False, f"Status code: {response.status_code}")
                
        except Exception as e:
            self.log_test("Email Analysis - Legitimate Detection", False, f"Exception: {str(e)}")
        
        return False, {}

    def test_url_analysis_malicious(self):
        """Test URL analysis with malicious URL"""
        malicious_url = {
            "url": "http://paypal-security.tk/verify-account?user=12345"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/analyze-url", 
                json=malicious_url,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'data' in data:
                    result = data['data']
                    # Check if it correctly identifies as malicious
                    if result.get('is_phishing') and result.get('risk_score', 0) > 0.5:
                        self.log_test("URL Analysis - Malicious Detection", True, 
                                    f"Risk score: {result.get('risk_score'):.2f}, Classification: {result.get('classification')}")
                        return True, result
                    else:
                        self.log_test("URL Analysis - Malicious Detection", False, 
                                    f"Failed to detect malicious URL. Risk score: {result.get('risk_score')}")
                else:
                    self.log_test("URL Analysis - Malicious Detection", False, "Invalid response structure")
            else:
                self.log_test("URL Analysis - Malicious Detection", False, f"Status code: {response.status_code}")
                
        except Exception as e:
            self.log_test("URL Analysis - Malicious Detection", False, f"Exception: {str(e)}")
        
        return False, {}

    def test_url_analysis_safe(self):
        """Test URL analysis with safe URL"""
        safe_url = {
            "url": "https://www.paypal.com/signin"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/analyze-url", 
                json=safe_url,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'data' in data:
                    result = data['data']
                    # Check if it correctly identifies as safe
                    if not result.get('is_phishing') and result.get('risk_score', 1) < 0.5:
                        self.log_test("URL Analysis - Safe Detection", True, 
                                    f"Risk score: {result.get('risk_score'):.2f}, Classification: {result.get('classification')}")
                        return True, result
                    else:
                        self.log_test("URL Analysis - Safe Detection", False, 
                                    f"False positive. Risk score: {result.get('risk_score')}")
                else:
                    self.log_test("URL Analysis - Safe Detection", False, "Invalid response structure")
            else:
                self.log_test("URL Analysis - Safe Detection", False, f"Status code: {response.status_code}")
                
        except Exception as e:
            self.log_test("URL Analysis - Safe Detection", False, f"Exception: {str(e)}")
        
        return False, {}

    def test_empty_input_validation(self):
        """Test error handling for empty inputs"""
        # Test empty email
        try:
            response = requests.post(
                f"{self.base_url}/api/analyze-email", 
                json={"subject": "", "body": ""},
                timeout=10
            )
            
            if response.status_code == 400:
                self.log_test("Empty Email Validation", True, "Correctly rejected empty email")
            else:
                self.log_test("Empty Email Validation", False, f"Expected 400, got {response.status_code}")
        except Exception as e:
            self.log_test("Empty Email Validation", False, f"Exception: {str(e)}")

        # Test empty URL
        try:
            response = requests.post(
                f"{self.base_url}/api/analyze-url", 
                json={"url": ""},
                timeout=10
            )
            
            if response.status_code == 400:
                self.log_test("Empty URL Validation", True, "Correctly rejected empty URL")
            else:
                self.log_test("Empty URL Validation", False, f"Expected 400, got {response.status_code}")
        except Exception as e:
            self.log_test("Empty URL Validation", False, f"Exception: {str(e)}")

    def test_bulk_analysis(self):
        """Test bulk analysis endpoint"""
        bulk_data = {
            "emails": [
                {"subject": "URGENT: Verify Account", "body": "Click here to verify your account immediately"},
                {"subject": "Meeting Update", "body": "The meeting has been moved to 3 PM"}
            ],
            "urls": [
                "http://paypal-security.tk/verify",
                "https://www.google.com"
            ]
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/analyze-bulk", 
                json=bulk_data,
                timeout=20
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'data' in data:
                    result = data['data']
                    if 'email_results' in result and 'url_results' in result and 'summary' in result:
                        self.log_test("Bulk Analysis", True, f"Processed {len(result['email_results'])} emails, {len(result['url_results'])} URLs")
                        return True, result
                    else:
                        self.log_test("Bulk Analysis", False, "Missing required fields in bulk response")
                else:
                    self.log_test("Bulk Analysis", False, "Invalid response structure")
            else:
                self.log_test("Bulk Analysis", False, f"Status code: {response.status_code}")
                
        except Exception as e:
            self.log_test("Bulk Analysis", False, f"Exception: {str(e)}")
        
        return False, {}

    def test_stats_endpoint(self):
        """Test statistics endpoint"""
        try:
            response = requests.get(f"{self.base_url}/api/stats", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'data' in data:
                    stats = data['data']
                    if 'models' in stats and 'detection_capabilities' in stats:
                        self.log_test("Statistics Endpoint", True, "Retrieved model statistics")
                        return True, stats
                    else:
                        self.log_test("Statistics Endpoint", False, "Missing required fields in stats")
                else:
                    self.log_test("Statistics Endpoint", False, "Invalid response structure")
            else:
                self.log_test("Statistics Endpoint", False, f"Status code: {response.status_code}")
                
        except Exception as e:
            self.log_test("Statistics Endpoint", False, f"Exception: {str(e)}")
        
        return False, {}

    def run_all_tests(self):
        """Run all backend API tests"""
        print("🚀 Starting Phishing Detection API Tests")
        print(f"📍 Testing endpoint: {self.base_url}")
        print("=" * 60)
        
        # Test all endpoints
        self.test_health_endpoint()
        self.test_email_analysis_phishing()
        self.test_email_analysis_legitimate()
        self.test_url_analysis_malicious()
        self.test_url_analysis_safe()
        self.test_empty_input_validation()
        self.test_bulk_analysis()
        self.test_stats_endpoint()
        
        # Print summary
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed! Backend API is working correctly.")
            return 0
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests failed. Check the issues above.")
            return 1

def main():
    tester = PhishingDetectionAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())