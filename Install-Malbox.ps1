################################
############ CONFIG ############
################################

# Chocolatey packages list
$Packages = @(
  "chocolatey-compatibility.extension",
  "python",
  "oraclejdk",
  "dotnet",
  "dotnet-5.0-runtime",
  "dotnet-5.0-sdk",
  "sublimetext3",
  "fiddler",
  "wireshark",
  "microsoft-windows-terminal",
  "brave",
  "upx",
  "7zip",
  "everything"
)

$TaskBarTools = @(
  # (<Tool name>, <Location to search>)

  ("ProcessHacker.exe", "~\Desktop\MalBox"),    # Process Hacker
  ("wt.exe", $env:LOCALAPPDATA),                # Windows Terminal
  ("sublime_text.exe", $env:ProgramFiles),      # Sublime Text3
  ("procmon64.exe", "~\Desktop\MalBox"),        # Process Monitor
  ("hxd.exe", "~\Desktop\MalBox"),              # HxD
  ("die.exe", "~\Desktop\MalBox"),              # Detect It Easy
  ("pestudio.exe", "~\Desktop\MalBox")          # PEStudio
  ("cutter.exe", "~\Desktop\MalBox"),           # Cutter
  ("x96dbg.exe", "~\Desktop\MalBox"),           # x64dbg (x32/x64)
  ("dnSpy.exe", "~\Desktop\MalBox")             # dnSpyex

)

$Wallpaper = ".\Wallpapers\4.png" 

################################
############ CONFIG ############
################################

function Pin-Tool
{
  param(
    [string] $ToolName,
    [string] $Location
    )
  $FindToolCommand = where.exe /F /R (Resolve-Path $Location) $ToolName
  $ToolPath = (($FindToolCommand) -split "`n")[0]
  .\Utils\pttb.exe $ToolPath
}

Function Set-WallPaper 
{
  # Took from https://www.joseespitia.com/2017/09/15/set-wallpaper-powershell-function/
  param (
    [parameter(Mandatory=$True)]
    # Provide path to image
    [string]$Image,
    # Provide wallpaper style that you would like applied
    [parameter(Mandatory=$False)]
    [ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
    [string]$Style
)
 
$WallpaperStyle = Switch ($Style) {
  
    "Fill" {"10"}
    "Fit" {"6"}
    "Stretch" {"2"}
    "Tile" {"0"}
    "Center" {"0"}
    "Span" {"22"}
  
}
 
If($Style -eq "Tile") {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 1 -Force
 
}
Else {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
 
}
 
Add-Type -TypeDefinition @" 
using System; 
using System.Runtime.InteropServices;
  
public class Params
{ 
    [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
    public static extern int SystemParametersInfo (Int32 uAction, 
                                                   Int32 uParam, 
                                                   String lpvParam, 
                                                   Int32 fuWinIni);
}
"@ 
  
  $SPI_SETDESKWALLPAPER = 0x0014
  $UpdateIniFile = 0x01
  $SendChangeEvent = 0x02

  $fWinIni = $UpdateIniFile -bor $SendChangeEvent

  $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}

# Disable Defender
Write-Output "[*] Disabling Windows Defender..."
Start-Process ".\Utils\disable-defender.exe"

# Disable Windows updates 
Write-Output "[*] Disabling Windows updates..."
$RegPathWU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (!(Test-Path $RegPathWU)) {
    New-Item -Path $RegPathWU -Force | Out-Null
}
Set-ItemProperty -Path $RegPathWU -Name NoAutoUpdate -Value 1 -Force

# Disable ASLR
Write-Output "[*] Disabling ASLR..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 0 -Type DWORD -Force

# Show file extensions
Write-Output "[*] Setting file extension visible..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force

# Show hidden Files
Write-Output "[*] Setting hidden files visible..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Force

# Extend the trial period of Windows
Write-Output "[*] Extending Windows trial..."
slmgr /rearm

# Install Chocolatey
Write-Output "[*] Downloading and installing Chocolatey..."
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Chocolatey packages
Write-Output "[*] Installing Chocolatey packages..."
$ChocoInstallCmd = "choco install -y "
foreach ($t in $Packages) {$ChocoInstallCmd = $ChocoInstallCmd + " " + $t}
Invoke-Expression $ChocoInstallCmd 

# Extract MalBox archive to desktop
Write-Output "[*] Extracting MalBox archive to desktop..."
7z.exe x .\MalBoxSplitted
Move-Item .\MalBox ~\Desktop
Remove-Item -Recurse .\MalBoxSplitted

# Pin tools of choice to the taskbar
foreach ($Tool in $TaskBarTools)
{
  Pin-Tool -ToolName $Tool[0] -Location $Tool[1]
}

# Set background wallpaper
Set-WallPaper -Image (Resolve-Path $Wallpaper) -Style Fit

Write-Output "[!] All done!"