@setlocal enableextensions
@cd /d "%~dp0"

powershell.exe -executionpolicy bypass -File ".\Scripts\sccm-check-for-software.ps1" 