; Inno Setup Script for CryptoFlow-IDS Desktop Application
; Produces CryptoFlow-IDS-Setup.exe for GitHub Releases

#define MyAppName "CryptoFlow-IDS"
#define MyAppVersion "2.1.0"
#define MyAppPublisher "CryptoFlow Security"
#define MyAppURL "https://github.com/Santhosh939s/CryptoFlow-IDS"
#define MyAppExeName "CryptoFlow-IDS.exe"

[Setup]
AppId={{D3F77A91-4D90-4A42-9B74-C38A1821A832}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=CryptoFlow-IDS-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\CryptoFlow-IDS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
var
  ErrorCode: Integer;
  NpcapInstalled: Boolean;
begin
  Result := True;

  // Check Windows Registry for Npcap Kernel Service and Installation Keys
  NpcapInstalled := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap') or
                    RegKeyExists(HKLM, 'SOFTWARE\Npcap') or
                    RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap') or
                    DirExists(ExpandConstant('{sys}\Npcap'));

  if not NpcapInstalled then
  begin
    if MsgBox('CryptoFlow-IDS requires the Npcap packet capture driver on Windows.' + #13#10 + #13#10 +
              'Npcap does not appear to be installed.' + #13#10 +
              'Would you like to open the Npcap download page now?' + #13#10 + #13#10 +
              '(Note: During Npcap setup, remember to check "Support loopback traffic")', 
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
    end;
  end;
end;
