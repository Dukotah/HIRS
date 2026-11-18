This README is part of the ZIP_Files.zip generated from hirs_package_linux.yml the goal of this zip is to have the TCG Eventlog tool available on windows. The TCG RIM tool now lives in the [RIM-Tool repository](https://github.com/nsacyber/RIM-Tool). 

To get the tools running on windows follow the instructions below:  

1- Unzip "ZIP_Files" 

2- open powershell as administrator and navigate to the hirstools folder. 

3- run the following command: ```powershell -ExecutionPolicy Bypass -File '.\create_hirstools_desktop_shortcut.ps1'```

4- double-click the HIRS_tools shortcut on your desktop. 

To run the eventlog tool:

elt -f  C:\Windows\Logs\MeasuredBoot\[.log file here] -e

Eventlog files are found here windows:
C:\Windows\Logs\MeasuredBoot

Example Command would be: 
> elt -f  C:\Windows\Logs\MeasuredBoot\000000001-000000001.log -e (file name needs to match on on your system)
