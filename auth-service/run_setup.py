"""
Quick setup runner for the authentication service
"""

import subprocess
import sys
import os

def run_setup():
    """Run the complete setup"""
    try:
        # Change to auth-service directory
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        
        print("🔧 Setting up authentication service...")
        
        # Run the setup script
        result = subprocess.run([sys.executable, "setup_complete.py"], 
                              capture_output=True, text=True)
        
        print(result.stdout)
        
        if result.stderr:
            print("Warnings/Errors:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("\n✅ Setup completed! You can now run the service.")
            print("\nTo start the service:")
            print("cd auth-service")
            print("python main.py")
        else:
            print(f"\n❌ Setup failed with code {result.returncode}")
            return False
            
        return True
        
    except Exception as e:
        print(f"Setup runner error: {e}")
        return False

if __name__ == "__main__":
    success = run_setup()
    sys.exit(0 if success else 1)