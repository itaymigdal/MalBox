# MalBox

*Malbox is a quick and dirty setup to create a malware analysis VM (but the way I like)*

<img src="/Wallpapers/4.png" width=60% height=60%>

# Why

Because I prefer to have my malware analysis box customized according to my own preferences. I found that existing setup tools often missed some steps or resulted in a messy outcome, which didn't sit well with my OCD.

# Installation

1. Own a fresh Windows VM guest
> Run the following steps only inside the VM guest!
2. Disable manually Windows Defender (all switches)
3. Download the repository
4. Open administrator Powershell prompt
5. `cd .\MalBox`
6. `Set-ExecutionPolicy Unrestricted -Force`
7. `.\Install-MalBox.ps1`
8. Go grab a ~~coffee~~ meal

# What the script does

1. Uninstalls Windows Defender using [Defender-Control](https://github.com/qtkite/defender-control)
2. Disables automatic Windows updates
3. Disables ASLR
4. Disables UAC
5. Sets file extensions and hidden files to be visible
6. Extends the trial period of Windows (so it won't reboot every 10 minutes)
7. Installs Chocolatey
8. Installs Chocolatey packages (configurable in the script's config)
9. Extracts MalBox archive to desktop
10. Adds (sym)links to Malbox directory
11. Pins tools of choice to the taskbar using [PTTB](https://github.com/0x546F6D/pttb_-_Pin_To_TaskBar) (configurable in the script's config)
12. Sets background wallpaper (configurable in the script's config)

> Check the wallpapers directory for the awesome images created by Midjourney

> Comment out any step according to your needs

## Chocolatey Packages

- Python & Java & Dotnet
- Sublime Text 3
- Fiddler
- Wireshark
- UPX
- 7-Zip
- Everything

## Tools In Archive

### Debuggers
- x64dbg
  
### Disassemblers & Decompilers
- Ghidra
- Cutter

### Dotnet
- DnSpyex
- GarbageMan

### Hex Viewers
- Imhex
- HxD

### PE Analyzers
- Detect It Easy
- Explorer suite
- PE-Bear
- PE-Studio
- Resource-Hacker

### Process Monitors
- API Monitor
- System Informer (Process Hacker)
- Hollows-Hunter
- PE-Sieve
- Process Monitor

### Utils & Misc
- CyberChef
- UPX
- Autoruns
- Blob Runner
- CMDWatcher
- PE Unmapper
- SigCheck
- Floss
- TCP Viewer
- WinObj

# Similar projects that do it better than me
- [Flare-VM](https://github.com/mandiant/flare-vm)
- [Reverse Engineer's Toolkit](https://github.com/mentebinaria/retoolkit)
