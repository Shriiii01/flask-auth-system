#!/usr/bin/env python3
"""
Root-level run script that executes the backend application.
This allows running the app from the project root.
"""
import sys
import os

# Add backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Change to backend directory for proper imports
os.chdir(os.path.join(os.path.dirname(__file__), 'backend'))

# Import and run the app
from run import app
import uvicorn
import logging

logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    uvicorn.run(
        "run:app",
        host="0.0.0.0",
        port=5001,
        reload=True,
        log_level="debug"
    )

