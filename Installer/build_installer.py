import os
import sys
import subprocess

def build_installer():
    """Build Windows installer using Inno Setup"""
    
    if not os.path.exists("dist/AdaptiveFolderEncryption.exe"):
        print("Error: Executable not found. Run create_executable.py first.")
        return
    
    # Create Inno Setup script
    iss_content = """
#define MyAppName "Adaptive Folder Encryption"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Your Name"
#define MyAppURL "https://github.com/yourusername/AdaptiveFolderEncryption"
#define MyAppExeName "AdaptiveFolderEncryption.exe"

[Setup]
AppId={{{{{MyAppName}}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={{autopf}}\\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
OutputDir=Output
OutputBaseFilename=AdaptiveFolderEncryptionSetup
SetupIconFile=assets/icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\\AdaptiveFolderEncryption.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "docs\\*"; DestDir: "{app}\\docs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"
Name: "{group}\\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
"""
    
    with open("installer/setup.iss", "w") as f:
        f.write(iss_content)
    
    # Build installer
    try:
        subprocess.run(['iscc', 'installer/setup.iss'], check=True)
        print("Installer created successfully!")
        print("Check the 'Output' folder for AdaptiveFolderEncryptionSetup.exe")
    except FileNotFoundError:
        print("Error: Inno Setup not found. Please install Inno Setup from:")
        print("https://jrsoftware.org/isdl.php")
    except subprocess.CalledProcessError as e:
        print(f"Error building installer: {e}")

if __name__ == "__main__":
    build_installer()