import os
import sys
import subprocess
import shutil

def build_executable():
    """Build standalone executable using PyInstaller for src structure"""
    print("Building Secure Folder executable...")
    
    # PyInstaller configuration for src structure
    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=SecureFolder",
        "--onefile",
        "--windowed",
        f"--add-data=src{os.pathsep}src",  # Important: Add src folder
        "--hidden-import=customtkinter",
        "--hidden-import=PIL",
        "--hidden-import=cryptography",
        "--hidden-import=argon2",
        "--hidden-import=watchdog",
        "--hidden-import=src.adaptive_encryptor",  # Add hidden imports for src modules
        "--hidden-import=src.file_monitor",
        "--hidden-import=src.gui",
        "--hidden-import=src.config",
        "run.py"  # Use run.py as entry point
    ]
    
    try:
        print("Running PyInstaller...")
        print("Command:", " ".join(pyinstaller_cmd))
        
        result = subprocess.run(pyinstaller_cmd, check=True, capture_output=True, text=True)
        print("✓ PyInstaller completed successfully!")
        
        if result.stdout:
            print("Output:", result.stdout)
        
        # Check if executable was created
        exe_path = "dist/SecureFolder.exe"
        if os.path.exists(exe_path):
            print(f"✓ Executable created: {os.path.abspath(exe_path)}")
            
            # Create portable version
            portable_dir = "dist/Portable_SecureFolder"
            os.makedirs(portable_dir, exist_ok=True)
            shutil.copy(exe_path, portable_dir)
            
            # Create README for portable version
            with open(os.path.join(portable_dir, "README.txt"), "w") as f:
                f.write("Secure Folder - Portable Encryption System\n\n")
                f.write("Just run SecureFolder.exe - no installation needed!\n\n")
                f.write("Features:\n")
                f.write("- Automatic file encryption\n")
                f.write("- Real-time folder monitoring\n")
                f.write("- Adaptive security levels\n")
                f.write("- User-friendly interface\n\n")
                f.write("Usage:\n")
                f.write("1. Run SecureFolder.exe\n")
                f.write("2. Set your master password\n")
                f.write("3. Configure watch and storage folders\n")
                f.write("4. Start monitoring and encryption\n")
            
            print(f"✓ Portable version created in: {portable_dir}")
            print(f"✓ File size: {os.path.getsize(exe_path) / (1024*1024):.2f} MB")
            
            return True
        else:
            print("✗ Executable was not created")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"✗ PyInstaller failed with error: {e}")
        if e.stderr:
            print("Error details:", e.stderr)
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

def main():
    print("=" * 50)
    print("Secure Folder - Executable Builder")
    print("=" * 50)
    
    # Check if PyInstaller is available
    try:
        subprocess.run([sys.executable, "-m", "PyInstaller", "--version"], 
                      check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("PyInstaller not found!")
        response = input("Do you want to install PyInstaller? (y/n): ")
        if response.lower() in ['y', 'yes']:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
                print("✓ PyInstaller installed successfully!")
            except subprocess.CalledProcessError as e:
                print(f"✗ Failed to install PyInstaller: {e}")
                return
        else:
            print("Please install PyInstaller manually: pip install pyinstaller")
            return
    
    # Build the executable
    if build_executable():
        print("\n🎉 Build completed successfully!")
        print("\nNext steps:")
        print("1. Test the executable: dist\\SecureFolder.exe")
        print("2. Share the portable version: dist\\Portable_SecureFolder\\")
        print("3. Create a GitHub release with the executable")
    else:
        print("\n❌ Build failed!")
        print("\nTroubleshooting:")
        print("- Make sure all dependencies are installed: pip install -r requirements.txt")
        print("- Check if there are any syntax errors in your Python code")
        print("- Make sure all files are in the src folder")

if __name__ == "__main__":
    main()