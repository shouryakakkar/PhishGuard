#!/usr/bin/env python3
"""
Development server script for PhishGuard backend
This script properly configures uvicorn for local development
"""

import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

if __name__ == "__main__":
    # Development server configuration
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info",
        access_log=True
    )
