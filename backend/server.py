from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
from dotenv import load_dotenv
import logging
from ml_models_real import email_detector_real as email_detector, url_detector_real as url_detector
from real_world_data import real_data_loader

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Phishing Detection API", description="AI-powered phishing detection for emails and URLs")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class EmailAnalysisRequest(BaseModel):
    subject: str
    body: str
    sender: Optional[str] = None

class URLAnalysisRequest(BaseModel):
    url: str

class BulkAnalysisRequest(BaseModel):
    emails: Optional[list] = None
    urls: Optional[list] = None

# Response models
class AnalysisResponse(BaseModel):
    success: bool
    data: Dict[str, Any]
    message: str

@app.on_event("startup")
async def startup_event():
    """Initialize models on server startup"""
    logger.info("🚀 Starting PhishGuard API server...")
    
    try:
        # Initialize and train email detector
        logger.info("📧 Initializing email detector...")
        if not email_detector.is_trained:
            logger.info("🔄 Training email detector on real-world data...")
            email_detector.train_on_real_data()
            logger.info("✅ Email detector trained successfully")
        else:
            logger.info("✅ Email detector already trained")
        
        # Initialize and train URL detector
        logger.info("🔗 Initializing URL detector...")
        if not url_detector.is_trained:
            logger.info("🔄 Training URL detector on real-world data...")
            url_detector.train_on_real_data()
            logger.info("✅ URL detector trained successfully")
        else:
            logger.info("✅ URL detector already trained")
        
        logger.info("🎉 All models initialized and ready!")
        
    except Exception as e:
        logger.error(f"❌ Error during model initialization: {e}")
        raise e

@app.get("/")
async def root():
    return {"message": "Phishing Detection API is running", "status": "healthy"}

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "models": {
            "email_detector": email_detector.is_trained,
            "url_detector": url_detector.is_trained
        }
    }

@app.post("/api/analyze-email", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email for phishing patterns"""
    try:
        # Combine subject and body for analysis
        email_content = f"{request.subject} {request.body}".strip()
        
        if not email_content:
            raise HTTPException(status_code=400, detail="Email content cannot be empty")
        
        # Ensure model is trained
        if not email_detector.is_trained:
            logger.info("🔄 Email detector not trained, training now...")
            email_detector.train_on_real_data()
        
        # Analyze email
        logger.info(f"🔍 Analyzing email: {email_content[:100]}...")
        result = email_detector.predict(email_content)
        
        # Add additional metadata
        result['email_metadata'] = {
            'subject': request.subject,
            'body_length': len(request.body),
            'sender': request.sender,
            'has_subject': bool(request.subject.strip()),
            'has_body': bool(request.body.strip())
        }
        
        logger.info(f"✅ Email analysis completed: {result['classification']} (confidence: {result['confidence']:.2f})")
        
        return AnalysisResponse(
            success=True,
            data=result,
            message="Email analysis completed successfully"
        )
        
    except Exception as e:
        logger.error(f"❌ Error analyzing email: {e}")
        logger.error(f"Error details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze-url", response_model=AnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    """Analyze URL for malicious patterns"""
    try:
        if not request.url.strip():
            raise HTTPException(status_code=400, detail="URL cannot be empty")
        
        # Ensure model is trained
        if not url_detector.is_trained:
            logger.info("🔄 URL detector not trained, training now...")
            url_detector.train_on_real_data()
        
        # Basic URL validation
        if not (request.url.startswith('http://') or request.url.startswith('https://')):
            # Add protocol if missing
            url_to_analyze = f"http://{request.url}"
        else:
            url_to_analyze = request.url
        
        # Analyze URL
        logger.info(f"🔍 Analyzing URL: {url_to_analyze}")
        result = url_detector.predict(url_to_analyze)
        result['original_url'] = request.url
        result['analyzed_url'] = url_to_analyze
        
        logger.info(f"✅ URL analysis completed: {result['classification']} (confidence: {result['confidence']:.2f})")
        
        return AnalysisResponse(
            success=True,
            data=result,
            message="URL analysis completed successfully"
        )
        
    except Exception as e:
        logger.error(f"❌ Error analyzing URL: {e}")
        logger.error(f"Error details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze-bulk", response_model=AnalysisResponse)
async def analyze_bulk(request: BulkAnalysisRequest):
    """Analyze multiple emails and URLs in bulk"""
    try:
        results = {
            'email_results': [],
            'url_results': [],
            'summary': {
                'total_emails': 0,
                'total_urls': 0,
                'phishing_emails': 0,
                'malicious_urls': 0
            }
        }
        
        # Analyze emails
        if request.emails:
            for i, email_data in enumerate(request.emails):
                try:
                    email_content = f"{email_data.get('subject', '')} {email_data.get('body', '')}".strip()
                    if email_content:
                        result = email_detector.predict(email_content)
                        result['index'] = i
                        result['email_data'] = email_data
                        results['email_results'].append(result)
                        
                        if result['is_phishing']:
                            results['summary']['phishing_emails'] += 1
                except Exception as e:
                    logger.error(f"Error analyzing email {i}: {e}")
            
            results['summary']['total_emails'] = len(request.emails)
        
        # Analyze URLs
        if request.urls:
            for i, url in enumerate(request.urls):
                try:
                    if url.strip():
                        # Add protocol if missing
                        url_to_analyze = url if url.startswith(('http://', 'https://')) else f"http://{url}"
                        result = url_detector.predict(url_to_analyze)
                        result['index'] = i
                        result['original_url'] = url
                        results['url_results'].append(result)
                        
                        if result['is_phishing']:
                            results['summary']['malicious_urls'] += 1
                except Exception as e:
                    logger.error(f"Error analyzing URL {i}: {e}")
            
            results['summary']['total_urls'] = len(request.urls)
        
        return AnalysisResponse(
            success=True,
            data=results,
            message="Bulk analysis completed successfully"
        )
        
    except Exception as e:
        logger.error(f"Error in bulk analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")

@app.get("/api/dataset-info")
async def get_dataset_info():
    """Get information about the real-world datasets being used"""
    try:
        stats = real_data_loader.get_dataset_stats()
        
        dataset_info = {
            'data_source': 'Real-world phishing patterns from security research',
            'training_type': 'Supervised learning on actual phishing samples',
            'email_dataset': {
                'description': 'Real phishing emails from security reports and research',
                'total_samples': stats['email_dataset']['total_samples'],
                'phishing_samples': stats['email_dataset']['phishing_samples'],
                'legitimate_samples': stats['email_dataset']['legitimate_samples'],
                'balance_ratio': f"{stats['email_dataset']['phishing_ratio']:.1%} phishing"
            },
            'url_dataset': {
                'description': 'Real malicious URLs from security research and threat intelligence',
                'total_samples': stats['url_dataset']['total_samples'],
                'malicious_samples': stats['url_dataset']['malicious_samples'],
                'legitimate_samples': stats['url_dataset']['legitimate_samples'],
                'balance_ratio': f"{stats['url_dataset']['malicious_ratio']:.1%} malicious"
            },
            'model_improvements': [
                'Advanced feature engineering with 25+ URL features',
                'Enhanced NLP preprocessing with n-gram analysis',
                'Real-world phishing keyword patterns',
                'Typosquatting and brand impersonation detection',
                'Suspicious TLD and domain pattern recognition'
            ]
        }
        
        return AnalysisResponse(
            success=True,
            data=dataset_info,
            message="Real-world dataset information retrieved successfully"
        )
        
    except Exception as e:
        logger.error(f"Error getting dataset info: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dataset info: {str(e)}")

@app.get("/api/stats")
async def get_statistics():
    """Get detection statistics and model info"""
    try:
        stats = {
            'models': {
                'email_detector': {
                    'trained': email_detector.is_trained,
                    'type': 'Logistic Regression + TF-IDF',
                    'features': 'Keywords, Text patterns, Statistical features'
                },
                'url_detector': {
                    'trained': url_detector.is_trained,
                    'type': 'Logistic Regression + Feature Engineering',
                    'features': 'URL patterns, Length, Suspicious domains'
                }
            },
            'detection_capabilities': {
                'email_analysis': True,
                'url_analysis': True,
                'bulk_analysis': True,
                'real_time': True
            },
            'supported_formats': {
                'emails': ['subject + body text', 'plain text'],
                'urls': ['http/https URLs', 'domain names']
            }
        }
        
        return AnalysisResponse(
            success=True,
            data=stats,
            message="Statistics retrieved successfully"
        )
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)