#!/usr/bin/env python3
"""
Adaptive Folder Encryption & Security System
Main entry point with enhanced error handling and dependency checking
"""

import sys
import os
import subprocess
import importlib.util

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = {
        'customtkinter': 'customtkinter',
        'PIL': 'Pillow',
        'cryptography': 'cryptography',
        'argon2': 'argon2-cffi',
        'watchdog': 'watchdog'
    }
    
    missing_packages = []
    for import_name, package_name in required_packages.items():
        try:
            importlib.import_module(import_name)
            print(f"✓ {package_name}")
        except ImportError:
            missing_packages.append(package_name)
            print(f"✗ {package_name} - missing")
    
    return missing_packages

def install_dependencies(missing_packages):
    """Install missing dependencies"""
    if not missing_packages:
        return True
        
    print(f"\nInstalling missing dependencies: {', '.join(missing_packages)}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
        print("All dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        return False

def main():
    """Main application entry point"""
    print("=" * 60)
    print("Adaptive Folder Encryption & Security System")
    print("=" * 60)
    
    # Check dependencies
    print("\nChecking dependencies...")
    missing_packages = check_dependencies()
    
    if missing_packages:
        print(f"\n{len(missing_packages)} dependencies missing.")
        response = input("Do you want to install them automatically? (y/n): ")
        if response.lower() in ['y', 'yes']:
            if not install_dependencies(missing_packages):
                print("\nPlease install dependencies manually using:")
                print("pip install -r requirements.txt")
                input("Press Enter to exit...")
                return
        else:
            print("\nPlease install dependencies manually using:")
            print("pip install -r requirements.txt")
            input("Press Enter to exit...")
            return
    
    # Import and run the application
    try:
        print("\nStarting application...")
        from src.gui import SecureGUI
        app = SecureGUI()
    except Exception as e:
        print(f"Error starting application: {e}")
        print("Please ensure all dependencies are installed correctly.")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()