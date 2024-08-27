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
  "dotnet3.5",
  "sublimetext3",
  "fiddler",
  "wireshark",
  "upx",
  "7zip",
  "everything",
  "x64dbg.portable",
  "cutter",
  "ghidra",
  "dnspyex",
  "hxd",
  "imhex",
  "die",
  "explorersuite",
  "pebear",
  "pestudio",
  "reshack.porable",
  "apimonitor",
  "systeminformer-nightlybuilds",
  "hollowshunter",
  "pesieve",
  "procmon",
  "tcpview",
  "winobj",
  "cyberchef",
  "autoruns",
  "sigcheck",
  "floss"
)

$MalboxTools = @(
  # (<Tool name>, <Malbox folder>, <Is shortcut>, <install location>)

  ("x96dbg.exe", "Debuggers", $true, ""),
  ("ghidraRun.bat", "Disassemblers & Decompilers", $true, ""),
  ("cutter.exe", "Disassemblers & Decompilers", $true, ""),
  ("dnSpy.exe", "Dotnet", $true, ""),
  ("imhex-gui.exe", "Hex Viewers", $true, ""),
  ("hxd.exe", "Hex Viewers", $true, "$env:ProgramFiles\hxd"),
  ("die.exe", "PE Analyzers", $true, ""),
  ("PE-bear.exe", "PE Analyzers", $true, ""),
  ("pestudio.exe", "PE Analyzers", $true, ""),
  ("ResourceHacker.exe", "PE Analyzers", $true, "$env:ProgramFiles (x86)\Resource Hacker"),
  ("SystemInformer.exe", "Process Monitors & Scanners", $true, "$env:ProgramFiles\SystemInformer"),
  ("apimonitor-x64.exe", "Process Monitors & Scanners", $true, ""),
  ("apimonitor-x86.exe", "Process Monitors & Scanners", $true, ""),
  ("pe-sieve.exe", "Process Monitors & Scanners", $false, ""),
  ("hollows_hunter.exe", "Process Monitors & Scanners", $false, ""),
  ("procmon64.exe", "Process Monitors & Scanners", $true, ""),
  ("cyberchef.lnk", "Utils & Misc", $true, "~\Desktop"),
  ("upx.exe", "Utils & Misc", $false, ""),
  ("Autoruns64.exe", "Utils & Misc", $true, ""),
  ("tcpview64.exe", "Utils & Misc", $true, ""),
  ("sigcheck.exe", "Utils & Misc", $false, ""),
  ("Winobj.exe", "Utils & Misc", $true, ""),
  ("floss.exe", "Utils & Misc", $false, "")
)

$TaskBarTools = @(
  # (<Tool name>, <Location to search>)

  ("SystemInformer.exe.lnk", "~\Desktop\MalBox"),   # Process Hacker
  ("sublime_text.exe", $env:ProgramFiles),          # Sublime Text3
  ("procmon64.exe.lnk", "~\Desktop\MalBox"),        # Process Monitor
  ("hxd.exe.lnk", "~\Desktop\MalBox"),              # HxD
  ("die.exe.lnk", "~\Desktop\MalBox"),              # Detect It Easy
  ("pestudio.exe.lnk", "~\Desktop\MalBox")          # PEStudio
  ("cutter.exe.lnk", "~\Desktop\MalBox"),           # Cutter
  ("x96dbg.exe.lnk", "~\Desktop\MalBox"),           # x64dbg (x32/x64)
  ("dnSpy.exe.lnk", "~\Desktop\MalBox")             # dnSpyex
)

$Wallpaper = ".\Wallpapers\6.png"

################################
############ CONFIG ############
################################

Function Create-LnkInMalboxDir 
{
  param(
    [string] $SrcDir = "$($env:ProgramData)\chocolatey\lib\",
    [string] $ToolName,
    [string] $TrgMalboxDir,
    [boolean] $Shortcut
    )
    $FindToolCommand = where.exe /R (Resolve-Path $SrcDir) $ToolName
    $ToolPath = (($FindToolCommand) -split "`n")[0]
    $TrgMalboxDir = Resolve-Path ("~\Desktop\MalBox\" + $TrgMalboxDir)
    if (-not ($Shortcut)) 
    {
        New-Item -Type SymbolicLink -Value (Resolve-Path $ToolPath) -Path "$($TrgMalboxDir)\$($ToolName)"
    }
    else 
    {
        $lnk = (New-Object -COM WScript.Shell).CreateShortcut("$($TrgMalboxDir)\$($ToolName).lnk")
        $lnk.TargetPath=(Resolve-Path $ToolPath).Path
        $lnk.Save()
    }
}

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
$DisableDefender = Resolve-Path ".\Utils\disable-defender.exe"
Unblock-File $DisableDefender
Start-Process $DisableDefender

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

# Disable UAC
Write-Output "[*] Disabling UAC..."
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0 -Type DWORD -Force

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
7z.exe x .\MalBox.zip
Move-Item .\MalBox ~\Desktop
Remove-Item .\MalBox.zip

# Copy tools to Malbox dir
Write-Output "[*] Copying tools to Malbox directory..."
foreach ($Tool in $MalboxTools)
{
    if ($Tool[3] -eq "") 
    {
        Create-LnkInMalboxDir -ToolName $Tool[0] -TrgMalboxDir $Tool[1] -Shortcut $Tool[2]
    }
    else 
    {
        Create-LnkInMalboxDir -ToolName $Tool[0] -TrgMalboxDir $Tool[1] -Shortcut $Tool[2] -SrcDir (Resolve-Path $Tool[3])
    }
}

# Pin tools of choice to the taskbar
Write-Output "[*] Pinning tools to taskbar..."
foreach ($Tool in $TaskBarTools)
{
  Pin-Tool -ToolName $Tool[0] -Location $Tool[1]
}

# Set background wallpaper
Write-Output "[*] Setting Malbox wallpaper..."
Set-WallPaper -Image (Resolve-Path $Wallpaper) -Style Fit

# Done
Write-Output "[!] All done! please reboot."