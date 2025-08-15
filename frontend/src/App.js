import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Button } from './components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Textarea } from './components/ui/textarea';
import { Input } from './components/ui/input';
import { Badge } from './components/ui/badge';
import { Alert, AlertDescription } from './components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Progress } from './components/ui/progress';
import { Shield, AlertTriangle, CheckCircle, Mail, Link, Brain, Zap } from 'lucide-react';
import './App.css';

const API_BASE_URL = 'http://127.0.0.1:8001';

function App() {
  const [emailData, setEmailData] = useState({ subject: '', body: '', sender: '' });
  const [urlData, setUrlData] = useState({ url: '' });
  const [emailResult, setEmailResult] = useState(null);
  const [urlResult, setUrlResult] = useState(null);
  const [loading, setLoading] = useState({ email: false, url: false });
  const [modelStatus, setModelStatus] = useState({ email_detector: false, url_detector: false });

  useEffect(() => {
    checkModelStatus();
  }, []);

  const checkModelStatus = async () => {
    try {
      console.log('Checking model status from:', `${API_BASE_URL}/api/health`);
      const response = await axios.get(`${API_BASE_URL}/api/health`, {
        timeout: 5000
      });
      console.log('Model status response:', response.data);
      setModelStatus(response.data.models);
    } catch (error) {
      console.error('Error checking model status:', error);
      console.error('Model status error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      // Set default status if health check fails
      setModelStatus({ email_detector: false, url_detector: false });
    }
  };

  const analyzeEmail = async () => {
    if (!emailData.subject.trim() && !emailData.body.trim()) {
      alert('Please enter email subject or body');
      return;
    }

    setLoading({ ...loading, email: true });
    try {
      console.log('Sending email analysis request to:', `${API_BASE_URL}/api/analyze-email`);
      console.log('Email data:', emailData);
      
      const response = await axios.post(`${API_BASE_URL}/api/analyze-email`, emailData, {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 10000
      });
      
      console.log('Email analysis response:', response.data);
      setEmailResult(response.data.data);
    } catch (error) {
      console.error('Error analyzing email:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      
      let errorMessage = 'Error analyzing email. Please try again.';
      if (error.response?.status === 500) {
        errorMessage = 'Server error. Please try again later.';
      } else if (error.code === 'ECONNABORTED') {
        errorMessage = 'Request timeout. Please try again.';
      } else if (error.message.includes('Network Error')) {
        errorMessage = 'Network error. Please check your connection.';
      }
      
      alert(errorMessage);
    } finally {
      setLoading({ ...loading, email: false });
    }
  };

  const analyzeUrl = async () => {
    if (!urlData.url.trim()) {
      alert('Please enter a URL');
      return;
    }

    setLoading({ ...loading, url: true });
    try {
      console.log('Sending URL analysis request to:', `${API_BASE_URL}/api/analyze-url`);
      console.log('URL data:', urlData);
      
      const response = await axios.post(`${API_BASE_URL}/api/analyze-url`, urlData, {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 10000
      });
      
      console.log('URL analysis response:', response.data);
      setUrlResult(response.data.data);
    } catch (error) {
      console.error('Error analyzing URL:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      
      let errorMessage = 'Error analyzing URL. Please try again.';
      if (error.response?.status === 500) {
        errorMessage = 'Server error. Please try again later.';
      } else if (error.code === 'ECONNABORTED') {
        errorMessage = 'Request timeout. Please try again.';
      } else if (error.message.includes('Network Error')) {
        errorMessage = 'Network error. Please check your connection.';
      }
      
      alert(errorMessage);
    } finally {
      setLoading({ ...loading, url: false });
    }
  };

  const getRiskLevel = (riskScore) => {
    if (riskScore >= 0.8) return { level: 'High', color: 'destructive', icon: AlertTriangle };
    if (riskScore >= 0.5) return { level: 'Medium', color: 'warning', icon: AlertTriangle };
    if (riskScore >= 0.2) return { level: 'Low', color: 'secondary', icon: Shield };
    return { level: 'Safe', color: 'success', icon: CheckCircle };
  };

  const ResultCard = ({ result, type }) => {
    if (!result) return null;

    const risk = getRiskLevel(result.risk_score);
    const IconComponent = risk.icon;

    return (
      <Card className="mt-6 shadow-lg border-l-4" style={{ borderLeftColor: result.is_phishing ? '#ef4444' : '#10b981' }}>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <IconComponent className={`h-5 w-5 ${result.is_phishing ? 'text-red-500' : 'text-green-500'}`} />
              Analysis Result - {result.classification}
            </CardTitle>
            <Badge variant={result.is_phishing ? 'destructive' : 'success'}>
              {result.is_phishing ? 'THREAT DETECTED' : 'SAFE'}
            </Badge>
          </div>
          <CardDescription>
            Risk Level: <strong>{risk.level}</strong> | Confidence: <strong>{(result.confidence * 100).toFixed(1)}%</strong>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium text-gray-600">Risk Score</label>
            <Progress value={result.risk_score * 100} className="mt-2" />
            <p className="text-xs text-gray-500 mt-1">{(result.risk_score * 100).toFixed(1)}% probability of being malicious</p>
          </div>

          {type === 'email' && result.features && (
            <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50 rounded-lg">
              <div>
                <p className="text-sm"><strong>Suspicious Keywords:</strong> {result.features.total_keywords}</p>
                <p className="text-sm"><strong>Text Length:</strong> {result.features.text_length} chars</p>
              </div>
              <div>
                <p className="text-sm"><strong>Exclamation Marks:</strong> {result.features.exclamation_count}</p>
                <p className="text-sm"><strong>Caps Ratio:</strong> {(result.features.caps_ratio * 100).toFixed(1)}%</p>
              </div>
            </div>
          )}

          {type === 'url' && result.suspicious_patterns && result.suspicious_patterns.length > 0 && (
            <div className="p-4 bg-red-50 rounded-lg">
              <h4 className="font-medium text-red-800 mb-2">Suspicious Patterns Detected:</h4>
              <ul className="list-disc list-inside space-y-1">
                {result.suspicious_patterns.map((pattern, index) => (
                  <li key={index} className="text-sm text-red-700">{pattern}</li>
                ))}
              </ul>
            </div>
          )}

          {result.is_phishing && (
            <Alert className="border-red-200 bg-red-50">
              <AlertTriangle className="h-4 w-4 text-red-600" />
              <AlertDescription className="text-red-800">
                <strong>Warning:</strong> This {type} has been flagged as potentially malicious. 
                Do not click any links, download attachments, or provide personal information.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-indigo-600 rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">PhishGuard AI</h1>
                <p className="text-sm text-gray-600">Advanced Phishing Detection System</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Brain className="h-5 w-5 text-indigo-600" />
              <span className="text-sm font-medium text-gray-700">ML-Powered</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Status Banner */}
        <div className="mb-8 grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="bg-gradient-to-r from-blue-500 to-indigo-600 text-white">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold">Email Detector</h3>
                  <p className="text-blue-100 text-sm">NLP + ML Classification</p>
                </div>
                <div className="flex items-center space-x-2">
                  {modelStatus.email_detector ? (
                    <CheckCircle className="h-5 w-5 text-green-300" />
                  ) : (
                    <Zap className="h-5 w-5 text-yellow-300" />
                  )}
                  <span className="text-sm">{modelStatus.email_detector ? 'Ready' : 'Training...'}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-purple-500 to-pink-600 text-white">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold">URL Detector</h3>
                  <p className="text-purple-100 text-sm">Pattern Analysis Engine</p>
                </div>
                <div className="flex items-center space-x-2">
                  {modelStatus.url_detector ? (
                    <CheckCircle className="h-5 w-5 text-green-300" />
                  ) : (
                    <Zap className="h-5 w-5 text-yellow-300" />
                  )}
                  <span className="text-sm">{modelStatus.url_detector ? 'Ready' : 'Training...'}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Analysis Interface */}
        <Card className="shadow-xl">
          <CardHeader className="text-center">
            <CardTitle className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
              Phishing Detection Analysis
            </CardTitle>
            <CardDescription className="text-lg">
              Upload emails or URLs to detect potential phishing attempts using advanced AI
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="email" className="w-full">
              <TabsList className="grid w-full grid-cols-2 mb-8">
                <TabsTrigger value="email" className="flex items-center space-x-2">
                  <Mail className="h-4 w-4" />
                  <span>Email Analysis</span>
                </TabsTrigger>
                <TabsTrigger value="url" className="flex items-center space-x-2">
                  <Link className="h-4 w-4" />
                  <span>URL Analysis</span>
                </TabsTrigger>
              </TabsList>

              <TabsContent value="email" className="space-y-6">
                <div className="grid gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-2 block">Email Subject</label>
                    <Input
                      placeholder="Enter email subject..."
                      value={emailData.subject}
                      onChange={(e) => setEmailData({ ...emailData, subject: e.target.value })}
                      className="w-full"
                    />
                  </div>
                  
                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-2 block">Sender (Optional)</label>
                    <Input
                      placeholder="sender@example.com"
                      value={emailData.sender}
                      onChange={(e) => setEmailData({ ...emailData, sender: e.target.value })}
                      className="w-full"
                    />
                  </div>

                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-2 block">Email Body</label>
                    <Textarea
                      placeholder="Paste the email content here..."
                      value={emailData.body}
                      onChange={(e) => setEmailData({ ...emailData, body: e.target.value })}
                      className="min-h-[200px] w-full"
                    />
                  </div>

                  <Button 
                    onClick={analyzeEmail} 
                    disabled={loading.email}
                    className="w-full bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 text-white font-semibold py-3"
                  >
                    {loading.email ? (
                      <div className="flex items-center space-x-2">
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                        <span>Analyzing...</span>
                      </div>
                    ) : (
                      <div className="flex items-center space-x-2">
                        <Brain className="h-4 w-4" />
                        <span>Analyze Email</span>
                      </div>
                    )}
                  </Button>
                </div>

                <ResultCard result={emailResult} type="email" />
              </TabsContent>

              <TabsContent value="url" className="space-y-6">
                <div className="grid gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-2 block">URL to Analyze</label>
                    <Input
                      placeholder="https://example.com or example.com"
                      value={urlData.url}
                      onChange={(e) => setUrlData({ url: e.target.value })}
                      className="w-full"
                    />
                  </div>

                  <Button 
                    onClick={analyzeUrl} 
                    disabled={loading.url}
                    className="w-full bg-gradient-to-r from-purple-500 to-pink-600 hover:from-purple-600 hover:to-pink-700 text-white font-semibold py-3"
                  >
                    {loading.url ? (
                      <div className="flex items-center space-x-2">
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                        <span>Analyzing...</span>
                      </div>
                    ) : (
                      <div className="flex items-center space-x-2">
                        <Brain className="h-4 w-4" />
                        <span>Analyze URL</span>
                      </div>
                    )}
                  </Button>
                </div>

                <ResultCard result={urlResult} type="url" />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* Features Section */}
        <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="text-center hover:shadow-lg transition-shadow">
            <CardContent className="p-6">
              <div className="w-12 h-12 bg-blue-100 rounded-lg mx-auto mb-4 flex items-center justify-center">
                <Mail className="h-6 w-6 text-blue-600" />
              </div>
              <h3 className="font-semibold mb-2">Email Analysis</h3>
              <p className="text-sm text-gray-600">Advanced NLP algorithms analyze email content for phishing patterns, suspicious keywords, and malicious intent.</p>
            </CardContent>
          </Card>

          <Card className="text-center hover:shadow-lg transition-shadow">
            <CardContent className="p-6">
              <div className="w-12 h-12 bg-purple-100 rounded-lg mx-auto mb-4 flex items-center justify-center">
                <Link className="h-6 w-6 text-purple-600" />
              </div>
              <h3 className="font-semibold mb-2">URL Detection</h3>
              <p className="text-sm text-gray-600">Comprehensive URL analysis detecting suspicious domains, malicious patterns, and known phishing indicators.</p>
            </CardContent>
          </Card>

          <Card className="text-center hover:shadow-lg transition-shadow">
            <CardContent className="p-6">
              <div className="w-12 h-12 bg-green-100 rounded-lg mx-auto mb-4 flex items-center justify-center">
                <Brain className="h-6 w-6 text-green-600" />
              </div>
              <h3 className="font-semibold mb-2">AI-Powered</h3>
              <p className="text-sm text-gray-600">Machine learning models trained on real phishing data provide accurate, real-time threat detection.</p>
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center">
            <p className="text-gray-600">
              © 2025 PhishGuard AI. Protecting users from phishing attacks with advanced machine learning.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;