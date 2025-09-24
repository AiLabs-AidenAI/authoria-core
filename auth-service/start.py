#!/usr/bin/env python3
"""
Quick start script for the authentication service
"""

import subprocess
import sys
import os

def main():
    """Start the authentication service"""
    try:
        # Change to auth-service directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(script_dir)
        
        print("🚀 Starting Authentication Service...")
        print("📍 Running on: http://localhost:8000")
        print("📚 API Docs: http://localhost:8000/docs")
        print("🛑 Press Ctrl+C to stop")
        print("-" * 50)
        
        # Run the FastAPI application with uvicorn
        result = subprocess.run([
            sys.executable, "-m", "uvicorn", "main:app",
            "--host", "0.0.0.0",
            "--port", "8000", 
            "--reload",
            "--access-log"
        ])
        
        return result.returncode
        
    except KeyboardInterrupt:
        print("\n🛑 Shutting down authentication service...")
        return 0
    except Exception as e:
        print(f"❌ Failed to start service: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)