# MalBox

Malbox is a quick and dirty setup to create a malware analysis VM.

# Installation

1. Own a fresh Windows VM guest
> Run the following stepts only inside the VM guest!
2. Disable manually Windows Defender
3. Download the repository
4. `cd .\MalBox`
5. `Set-ExecutionPolicy Unrestricted`
6. `.\Install-MalBox.ps1`
7. Go grab a coffee

# What the script does?

1. Disables Windows Defender using [Defender-Control](https://github.com/qtkite/defender-control)
2. Disables automatic Windows updates
3. Disables ASLR
4. Sets file extensions and hidden files to be visible
5. Extends the trial period of Windows (so it won't reboot every 10 minutes)
6. Installs Chocolatey
7. Installs Chocolatey packages (configurable in the script's config)
8. Extracts MalBox archive to desktop
9. Pin tools of choise to the taskbar using [PTTB](https://github.com/0x546F6D/pttb_-_Pin_To_TaskBar) (configurable in the script's config)
10. Sets background wallpaper (configurable in the script's config)
> Check the wallpapers directory for the awsome images created by Midjourney

## Chocolatey Packages

- Python & Java & Dotnet
- Sublime Text 3
- Fiddler
- Wireshark
- Windows Terminal
- Brave browser
- UPX
- 7-Zip
- Everything

## Tools In Archive

### Debuggers
- x64dbg + plugins
  
### Disassemblers & Decompilers
- Ghidra
- Cutter

### Dotnet
- DnSpyex
- ILSpy
- De4dot
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
- Process Hacker
- Hollows-Hunter
- PE-Sieve
- Process Explorer
- Process Monitor

### Utils & Misc
- CyberChef
- UPX
- Autoruns
- Blob Runner
- CMDWatcher
- Dll 2 Exe
- PE Unmapper
- SigCheck
- Strings
- Floss
- TCPView
- WinObj

# Tools that do it better than me
- [Flare-VM](https://github.com/mandiant/flare-vm)
- [Reverse Engineer's Toolkit](https://github.com/mentebinaria/retoolkit)