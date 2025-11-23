import os
import sys
import subprocess
import shutil
from pathlib import Path

def create_executable():
    """Create standalone executable using PyInstaller"""
    print("Creating standalone executable...")
    
    # PyInstaller configuration
    pyinstaller_cmd = [
        'pyinstaller',
        '--name=AdaptiveFolderEncryption',
        '--onefile',
        '--windowed',
        '--icon=assets/icon.ico' if os.path.exists('assets/icon.ico') else '',
        '--add-data=src;src',
        '--hidden-import=customtkinter',
        '--hidden-import=PIL',
        '--hidden-import=cryptography',
        '--hidden-import=argon2',
        '--hidden-import=watchdog',
        'run.py'
    ]
    
    # Remove empty strings
    pyinstaller_cmd = [cmd for cmd in pyinstaller_cmd if cmd]
    
    try:
        subprocess.run(pyinstaller_cmd, check=True)
        print("Executable created successfully!")
        
        # Create distribution folder
        dist_folder = "dist/AdaptiveFolderEncryption"
        if os.path.exists(dist_folder):
            shutil.rmtree(dist_folder)
        os.makedirs(dist_folder)
        
        # Copy executable and resources
        shutil.copy("dist/AdaptiveFolderEncryption.exe", dist_folder)
        
        # Create README and license
        with open(os.path.join(dist_folder, "README.txt"), "w") as f:
            f.write("Adaptive Folder Encryption & Security System\n\n")
            f.write("Simply run AdaptiveFolderEncryption.exe to start the application.\n")
            f.write("No installation required - it's portable!\n\n")
            f.write("System Requirements:\n")
            f.write("- Windows 10/11 (64-bit)\n")
            f.write("- 4GB RAM minimum, 8GB recommended\n")
            f.write("- 500MB free disk space\n")
        
        print(f"Distribution package created in: {dist_folder}")
        
    except subprocess.CalledProcessError as e:
        print(f"Error creating executable: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    create_executable()