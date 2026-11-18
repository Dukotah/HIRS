# Unzip tools in the working directory
Expand-Archive -Path ..\tcg_eventlog_tool.zip -DestinationPath .\tcg_eventlog_tool
# Create a shortcut to start the HIRS tools shell
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\HIRS_tools.lnk")
$Shortcut.TargetPath = "powershell.exe"
$ScriptPath = "$PWD\hirsshell.ps1"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$ScriptPath`""
$Shortcut.WorkingDirectory = "$PWD"
$Shortcut.Save()
