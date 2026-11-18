# Script to start a new shell with an elt alias
$StartInfo = new-object System.Diagnostics.ProcessStartInfo
$StartInfo.FileName = "$pshome\powershell.exe"
$StartInfo.Arguments = "-NoExit -Command 
               `$Host.UI.RawUI.WindowTitle=`'HIRS TOOLS`'; 
               Set-Alias elt '$PWD\eventlog.ps1';
	       Write-Output 'for eventlog usage type: elt -h'
               Set-Location -Path $PWD;
               function prompt {'HIRS > '};"
[System.Diagnostics.Process]::Start($StartInfo)
