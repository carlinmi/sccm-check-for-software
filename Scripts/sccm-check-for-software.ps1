<#
 Summary: This is a powershell script template designed for an Application Deployment Type Install in SCCM 2012
 Created by: Aaron Miller and Craig Woodford (with help from Jeff Bolduan)
 
 Packager: oit-reedx305
 Last Update: 3/11/2021

 Application runs config manager actions.
 
 For detailed instructions on how to use this script template, see the ScriptDescription region at the end of the script template.
#>

#region Variables
#########################################################################################################################################

#region RequiredVariables
#*****************************************************************************************
# Required Variables
	
# Define these variables so the log files will have the correct program name and version
$ProgramName = "Software Center Manual Check-in"
$Version = "1.0"
	
# This is the log file for the program installer
# Leave this variable as is
$LogFile = "$env:systemdrive\Windows\Temp\OITCM-$($ProgramName.Replace(' ','-'))-$Version-Install.log"
	
# This is the log file for anything other than the installer and script errors
# Leave this variable as is
$ScriptLog = "$env:systemdrive\Windows\Temp\OITCM-$($ProgramName.Replace(' ','-'))-$Version-Install-Script.log"

$TimestampFile = "$env:systemdrive\Windows\Temp\$($ProgramName.Replace(' ','-'))-timestamp.txt"
	
# This is a scriptblock which contains the install actionscommand line - See comments below for more information.
$InstallCMD = {

    Write-Log -Message "------------------------------------------" -Path $Scriptlog
    Write-Log -Message "Running $ProgramName Version: $version" -Path $Scriptlog

    #Running Machine Policy Retrieval Cycle
    $ExitVal = (Invoke-WMIMethod -ComputerName LocalHost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}").exitcode
    Write-Log -Message "Attempting to run Machine Policy Retrieval Cycle with Exit Code: $ExitVal" -Path $Scriptlog

    #Running Machine Policy Evaluation Cycle
    $ExitVal = (Invoke-WMIMethod -ComputerName LocalHost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}").exitcode
    Write-Log -Message "Attempting to run Machine Policy Evaluation Cycle with Exit Code: $ExitVal" -Path $Scriptlog

    #Running Application Deployment Evaluation Cycle
    $ExitVal = (Invoke-WMIMethod -ComputerName LocalHost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}").exitcode
    Write-Log -Message "Attempting to run Application Deployment Evaluation Cycle with Exit Code: $ExitVal" -Path $Scriptlog

    #Running Discovery Data Collection Cycle
    $ExitVal = (Invoke-WMIMethod -ComputerName LocalHost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000003}").exitcode
    Write-Log -Message "Attempting to run Discovery Data Collection Cycle with Exit Code: $ExitVal" -Path $Scriptlog

    #Running Software Update Scan Cycle
    $ExitVal = (Invoke-WMIMethod -ComputerName LocalHost -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000113}").exitcode
    Write-Log -Message "Attempting to run Software Update Scan Cycle with Exit Code: $ExitVal" -Path $Scriptlog
    
    Write-Log -Message "Completed." -Path $Scriptlog	
    Write-Log -Message "Creating Timestamp file at $TimestampFile" -Path $Scriptlog
    
    try {
    New-Item -ItemType "file" -Path $TimestampFile -Force
        Set-Content -Path $TimestampFile -Value (Get-Date)
    }
    catch{
        Write-Log -Message "Creating Timestamp file at $TimestampFile failed." -Path $Scriptlog
    }
	Write-Log -Message "------------------------------------------" -Path $Scriptlog

    #Added cooldown
    Start-Sleep -s 5

    #Always returns success
    $ExitVal = "0"
}
#*****************************************************************************************
	
#*****************************************************************************************
# Optional Variables
	
# This is an array that contains any running processes that may interfere with the install - See comments below for more information.
$Processes = @()

# $KillProcesses - This is an array of strings that contains any running processes that should be stopped before continuing with the install - See comments below for more information.
$KillProcesses = @()

# $PreFlightCMD - This is a script block which contains all pre-install commands that you need to run - See comments below for more information.
$PreFlightCMD = {

}

#*****************************************************************************************
#endregion

	
#region VariableInformation
#*****************************************************************************************
# Information about required & optional variables
	
<# Install Actions
	   
	Executing a non-powershell command or program
	=============================================
	   
	While Powershell commands tend to behave in a predictable manner, some non-Powershell commands can behave in non-standard ways.  The most common problem
	is that the Powershell will not wait for the non-Powershell program to finish.  If you need to execute a non-Powershell command or program you should 
	leverage one of these four methods:
	   
	&  -  The call operator (referenced by &), which can run non-Powershell programs and script-blocks but will not always wait for the program to return
	Invoke-Command  -  Will run non-Powershell programs and script-blocks but will not always wait for the program to return
	Start-Job  -  Can be used to execute script-blocks and can be instructed to wait for the program to return
	Start-Process  -  Can be used to execute non-Powershell commands (but not script-blocks) and can be instructed to wait for the program to return
	   
	See Google or the cmdlet help for more information (ex: help Start-Job).
	
	Log Files
	=========
	 
	Use the $LogFile variable for the location of the install log file
	Log any action you take to the $ScriptLog using the Write-Log function (provided below).
	Ex:  Write-Log -Message "This is the message I want to send" -Path $ScriptLog
	   
	File Location Issues
	====================
	   
	Sometimes executables require that files be referenced in the current directory by pre-pending .\ (such as .\config.ini).  Other executables may require
	that files be referenced using their full path, in which case you should use the $sourcePath variable (such as $sourcePath\config.ini).
	   
	Issues with quotes
	==================
	   
	Some executables require that parts of their commmand line be wrapped in double-quotes.  Please see the following links for more information:
	http://www.techotopia.com/index.php/Windows_PowerShell_1.0_String_Quoting_and_Escape_Sequences
	http://ss64.com/ps/syntax-esc.html
	http://ofps.oreilly.com/titles/9781449320683/strings_and_unstructured_text.html
	   
	Examples
	========
	   
	Simple Installs
	   
	$InstallCMD = {
		Copy-Item -Path "$sourcePath\bar.txt" -Destination 'C:\Foo\bar.txt' -Force
		Write-Log -Message "Copied bar.txt to C:\Foo\" -Path $ScriptLog
		New-Item -Path "hkcu:\Software\Foo" -Force
		Write-Log -Message "Created registry key hkcu:\Software\Foo" -Path $ScriptLog
	}
	   
#>
	
#*****************************************************************************************
	
<# Running processes check
	If your program install will fail if a process is running (for example if you don't want to run the install if Firefox is running)
	you should add the procees to the $Processes variable.  Be sure to use the actual process name and not just the executable name (for example
	Firefox has a process of firefox and not firefox.exe).
	To get a list of currently running processes in powershell:  Get-Process | Select ProcessName
	If you do not need to check if a process is running do not modify the $Process variable
	Ex: $Processes = @("iexplore","firefox")
#>
	
#*****************************************************************************************
#endregion

#region AdvancedVariables
#*****************************************************************************************
# These variables should not need to be modified normally
	
# If you need to change success codes make sure that you also adjust the Return Codes tab for the deployment type
# See this page for more information http://msdn.microsoft.com/en-us/library/aa368542.aspx
$SuccessCodes = @(0,1707,3010,1641)
	
# This code tells Configuration Manager 2012 that it should re-try the install quickly
$FastRetryExitCode = 1618
	
# This code tells Configuration Manager 2012 that a fatal error occurred and the install failed
$FatalErrorCode = 1603
	
# This code tells Configuration Manager 2012 that a soft error occurred and the install failed
$SoftErrorCode = 1604
	
# This sets the $sourcePath variable to the current location that the script is invoked from which required in some cases
# because relative pathing is broken when trying to run some commands when deploying applications via Configuration Manager 2012
$sourcePath = $myInvocation.MyCommand.Path | Split-Path
	
# This variable is used to enable or disable debugging mode, set the variable equal to $true to enable debugging mode
# Debugging mode will output all actions the script takes to the console
$debugScript = $false
	
# This variable is used to capture installer exit codes and as the script's final return code
# It is set to 0 as a default in case it is not checked.  You should set this in the $installCMD variable if the installer provides a useful 
# variable.
$ExitVal = 0
#*****************************************************************************************
#endregion

# End of Variables section
#########################################################################################################################################
#endregion


#region Functions
#########################################################################################################################################

Function Write-Log {
	<#
		.SYNOPSIS
			This function is used to pass messages to a ScriptLog.  It can also be leveraged for other purposes if more complex logging is required.
		.DESCRIPTION
			Write-Log function is setup to write to a log file in a format that can easily be read using CMTrace.exe. Variables are setup to adjust the output.
		.PARAMETER Message
			The message you want to pass to the log.
		.PARAMETER Path
			The full path to the script log that you want to write to.
		.PARAMETER Severity
			Manual indicator (highlighting) that the message being written to the log is of concern. 1 - No Concern (Default), 2 - Warning (yellow), 3 - Error (red).
		.PARAMETER Component
			Provide a non null string to explain what is being worked on.
		.PARAMETER Context
			Provide a non null string to explain why.
		.PARAMETER Thread
			Provide a optional thread number.
		.PARAMETER Source
			What was the root cause or action.
		.PARAMETER Console
			Adjusts whether output is also directed to the console window.
		.NOTES
			Name: Write-Log
			Author: Aaron Miller
			LASTEDIT: 01/23/2013 10:09:00
		.EXAMPLE
			Write-Log -Message $exceptionMsg -Path $ScriptLog -Severity 3
			Writes the content of $exceptionMsg to the file at $ScriptLog and marks it as an error highlighted in red
	#>

	PARAM(
		[Parameter(Mandatory=$True)][String]$Message,
		[Parameter(Mandatory=$False)][String]$Path = "$env:TEMP\CMTrace.Log",
		[Parameter(Mandatory=$False)][int]$Severity = 1,
		[Parameter(Mandatory=$False)][string]$Component = " ",
		[Parameter(Mandatory=$False)][string]$Context = " ",
		[Parameter(Mandatory=$False)][string]$Thread = "1",
		[Parameter(Mandatory=$False)][string]$Source = "",
		[Parameter(Mandatory=$False)][switch]$Console
	)
				
	# Setup the log message
		
		$time = Get-Date -Format "HH:mm:ss.fff"
		$date = Get-Date -Format "MM-dd-yyyy"
		$LogMsg = '<![LOG['+$Message+']LOG]!><time="'+$time+'+000" date="'+$date+'" component="'+$Component+'" context="'+$Context+'" type="'+$Severity+'" thread="'+$Thread+'" file="'+$Source+'">'
				
	# Write out the log file using the ComObject Scripting.FilesystemObject
		
		$ForAppending = 8
		$oFSO = New-Object -ComObject scripting.filesystemobject
		$oFile = $oFSO.OpenTextFile($Path, $ForAppending, $True)
		$oFile.WriteLine($LogMsg)
		$oFile.Close()
		Remove-Variable oFSO
		Remove-Variable oFile
			
	# Write to the console if $Console is set to True
		
		if ($Console -eq $True) {Write-Host $Message}
			
}

Function Exit-OnError {
	<#
		.SYNOPSIS
			This is a function used to exit out of the script when an error is detected and to log the error.
		.DESCRIPTION
			Exit-OnError function is designed to take in an exception then to log a detailed error message before exiting the script. It leverages the
			Write-Log function for logging purposes.  Exit status is determined by where in the script the exception occurs. The log file in the $ScriptLog
			variable is used for logging.
		.PARAMETER ErrorVar
			This is the exception you want to pass to the function.  Within a catch block it can be referenced by $_
		.PARAMETER Section
			This is the section of the script that the execption occurred in.  If the section equals "Install" then the script will exit with a fatal error,
			otherwise the script will exit with a soft error.
		.NOTES
			Name: Exit-OnError
			Author: Aaron Miller
			Last Edit: 1/31/2013
		.EXAMPLE
			Exit-OnError -ErrorVar $_ -Section "Pre-flight"
			Writes the error message of the exception to the log then exits with a soft error.
	#>
	
	PARAM(
		$ErrorVar,
		$Section
	)
		
	Write-Log -Message "$Section error encountered! Details are below: " -Path $ScriptLog -Severity 2
		
	# $ErrorVar.Exception.Message - The error message itself.
	$Message = ($ErrorVar.Exception.Message)
		
	# $ErrorVar.FullyQualifiedErrorId - What kind of error it was.
	$Component = ($ErrorVar.FullyQualifiedErrorId)
		
	# $myInvocation.MyCommand.Path - Name of the script
	# $ErrorVar.InvocationInfo.ScriptLineNumber - Line number of the script where the error occured
	# $ErrorVar.InvocationInfo.OffsetInLine - Where in the line the error occurred
	$Source = "$($myInvocation.MyCommand.Path) Line:$($ErrorVar.InvocationInfo.ScriptLineNumber) Char:$($ErrorVar.InvocationInfo.OffsetInLine)"
		
	Write-Log -Message $Message -Source $Source -Component $Component -Path $ScriptLog -Severity 3
		
	If ($Section -eq "install") {Exit $FatalErrorCode} Else {Exit $SoftErrorCode}
		
}

Function Get-ARP {
	<#
		.SYNOPSIS
			This function is designed to return all ARP entries
		.DESCRIPTION
			This function returns an object containing all arp entries and details for each sub item property. On 64-bit powershell sessions there's dynamic paramters to specify the the 32-bit registry or 64-bit registry only
		.NOTES
			Name: Get-ARP
			Author: Aaron Miller
			LASTEDIT: 05/08/2013
		.EXAMPLE
			$ARP = Get-ARP
			This returns all arp entries into a variable for processing later.
	#>
    [CmdletBinding(DefaultParameterSetName='none')]
    Param ()
 
    DynamicParam {
        if ([IntPtr]::size -eq 8) {
            $att1 = new-object -Type System.Management.Automation.ParameterAttribute -Property @{ParameterSetName="x64ARP"}
            $attC1 = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
            $attC1.Add($att1)
            $dynParam1 = new-object -Type System.Management.Automation.RuntimeDefinedParameter("x64ARP", [switch], $attC1)
            
            $att2 = new-object -Type System.Management.Automation.ParameterAttribute -Property @{ParameterSetName="x86ARP"}
            $attC2 = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
            $attC2.Add($att2)
            $dynParam2 = new-object -Type System.Management.Automation.RuntimeDefinedParameter("x86ARP", [switch], $attC2)

            $paramDictionary = new-object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add("x64ARP", $dynParam1)
            $paramDictionary.Add("x86ARP", $dynParam2)
            return $paramDictionary
        }
    }
    
    Begin {
        $Primary = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $Wow = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        $toProcess = @()
        switch ($PsCmdlet.ParameterSetName) {
            "x64ARP" {$toProcess+=$Primary}
            "x86ARP" {$toProcess+=$Wow}
            default {$toProcess+=$Primary;if ([IntPtr]::size -eq 8) {$toProcess+=$Wow}}
        }
    }

    End {Return [array]($toProcess | ForEach-Object {Get-ChildItem $_} | ForEach-Object {Get-ItemProperty $_.pspath})}
}

Function Remove-MSIInstallations {
	<#
		.SYNOPSIS
			This function is designed to remove all instances of an application
		.DESCRIPTION
			This application will use the uninstall registry keys GUID value to perform a msiexec uninstall and log each specific application to a seperate uninstall log
		.PARAMETER AppName
			This string controls what is queried to uninstall
		.PARAMETER ARP
			This should be the full list of arp entries.
		.NOTES
			Name: Remove-MSIInstallations
			Author: Aaron Miller
			LASTEDIT: 05/08/2013
			Requirements:
				If you want this function to also msizap installations when msiexec uninstall fails please include msizap.exe in the root of the folder as well.
				$ARP should be generated by using the function Get-ARP or similar;
				$ARP = 'gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ea 0 | % {gp $_.pspath}
		.EXAMPLE
			Remove-MSIInstallations -AppName "Java 7" -ARP $ARP
			This removes any instance of Java 7 found in $ARP.
		.Link
			Get-ARP
	#>
    [CmdLetBinding()]
	PARAM(
		$AppName,
		$ARP
	)
    $InstallerProducts = "HKLM:\SOFTWARE\Classes\Installer\Products"
    [array]$InstalledProducts = Get-ChildItem $InstallerProducts -ErrorAction SilentlyContinue | ForEach-Object {Get-ItemProperty $_.pspath}
    $SRAppName = $AppName.Replace(' ','-')
	$ARP | Where-Object {($_.DisplayName -like "$AppName*") -and ($_.PSChildName -like "{*}")} | Foreach-Object {
        $displayName = $_.DisplayName
        $dispVersion = $_.DisplayVersion
        $productCode = $_.PsChildName
        $uninstallRegKey = $_.PSPath
        $installLocation = $_.InstallLocation
		$UninstallLog = "$env:SystemDrive\Windows\Temp\CM-$SRAppName-$dispVersion-Uninstall.Log"

        Write-Output "Running msiexec uninstall for: $productCode"
        Write-Output "Uninstall log path: $UninstallLog"
		$return = (Start-Process 'msiexec.exe' -ArgumentList ("/x $productCode /L*v `"$UninstallLog`" /qn REBOOT=ReallySuppress /norestart") -PassThru -Wait -NoNewWindow).ExitCode
        If (test-path .\msizap.exe) {
            Write-Output "Running msizap on product code: $productCode"
            Start-Process .\msizap.exe -ArgumentList ("T $productCode") -Wait -NoNewWindow -ErrorAction SilentlyContinue
        }
        If (Test-Path $installLocation) {
            Write-Output "Removing installation directory: $installLocation"
            Remove-Item -Path $installLocation -Recurse -Force -ErrorAction SilentlyContinue
        }
        If (Test-Path $uninstallRegKey) {
            Write-Output "Removing registry key: $uninstallRegKey"
            Remove-Item -Path "$uninstallRegKey" -Recurse -Force -ErrorAction SilentlyContinue
        }
        $InstalledProducts | Where-Object {($_.ProductName -eq "$displayName")} | Foreach-Object {
            Write-Output "Removing installer product key: $($_.PSPath)"
            Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
		Write-Output "Starting to sleep for 10 seconds..."
		Start-Sleep -s 10
	}
}

Function Remove-MSIInstall {
	<#
		.SYNOPSIS
			This function is designed to remove a specific GUID install.
		.DESCRIPTION
			This function will take the GUID ensure it exists and if it does run a standard uninstall including logging.
			If the GUID does not exist it will log that it didn't remove anything.
		.PARAMETER GUID
			The GUID for the application to be removed.
		.NOTES
			Name: Remove-MSIInstall
			Author: Jeff Bolduan
			LASTEDIT: 8/2/2016
		.EXAMPLE
			Remove-MSIInstall -GUID "{00000000-0000-0000-0000-000000000000}"
		.REQUIREMENTS
			Get-ARP
	#>
	[CmdletBinding()]
	param(
		$GUID
	)
	$ReturnVal = 0
	$ArpTable = Get-Arp
	if($ArpTable.PSChildName.Contains($GUID)) {
		Write-Log -Message "Found $GUID in ARP, attempting to remove" -Path $ScriptLog
		$ReturnVal = (Start-Process 'msiexec.exe' -ArgumentList ("/X $GUID /qn /l*v $LogFile") -Wait -PassThru -NoNewWindow).ExitCode
		Write-Log -Message "Removal of the GUID $GUID complete with $ReturnVal" -Path $ScriptLog
	} else {
		Write-Log -Message "$GUID was not detected in ARP" -Path $ScriptLog
	}

	return $ReturnVal
}

Function New-RegistryProperty {
	<#
		.SYNOPSIS
			This is a function used to create new registry entries in the script.
		.DESCRIPTION
			New-RegistryProperty takes in properties related to the new registry property being created. It then
			ensures that the registry key and values are created when needed logging using Write-Log to ensure the
			whole process is recorded in the log file.
		.PARAMETER RegistryKeyPath
			The key path in the registry where the property will be created. (eg. HKLM:\Software\Policies)
		.PARAMETER PropertyName
			The name of the item property which is to be created or updated in the registry.
		.PARAMETER PropertyValue
			The value to be placed inside the property.
		.PARAMETER PropertyType
			The type of registry value to create (String, ExpandString, Binary, DWord, MultiString, Qword, Unknown)
		.NOTES
			Name: New-RegistryProperty
			Author: Jeff Bolduan
			Last Edit: 8/2/2016
		.EXAMPLE
			New-RegistryProperty -RegistryKeyPath "HKLM:\SOFTWARE\Policies\Google\Update" -PropertyName "DisableUpdates" -PropertyValue 0 -PropertyType DWord
	#>
	param(
		[Parameter(Mandatory=$true)]
		[string]$RegistryKeyPath,

		[Parameter(Mandatory=$true)]
		[string]$PropertyName,

		[Parameter(Mandatory=$true)]
		$PropertyValue,

		[Parameter(Mandatory=$true)]
		[ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword", "Unknown")]
		[string]$PropertyType
	)

	# Registry setting to disable automatic updates.
	Write-Log -Message "Creating new registry setting" -Path $ScriptLog

	if(-not (Test-Path $RegistryKeyPath)) {
		Write-Log -Message "Creating new registry key: $RegistryKeyPath" -Path $ScriptLog
		New-Item -Path $RegistryKeyPath -Force
	} else {
		Write-Log -Message "Key already exists: $RegistryKeyPath" -Path $ScriptLog
	}
        
	$Key = Get-Item -LiteralPath $RegistryKeyPath -Force
	if($Key.GetValue($PropertyName, $null) -eq $null) {
		Write-Log -Message "Adding new registry value named $PropertyName with the value $PropertyValue of type $PropertyType in $RegistryKeyPath" -Path $ScriptLog
		New-ItemProperty -LiteralPath $RegistryKeyPath -Name $PropertyName -Value $PropertyValue -PropertyType $PropertyType -Force
	} else {
		Write-Log -Message "Value already exists: $PropertyName with value: $($Key.GetValue($PropertyName, "ERROR")) updating value to be $PropertyValue" -Path $ScriptLog
		Set-ItemProperty -LiteralPath $RegistryKeyPath -Name $PropertyName -Value $PropertyValue -Type $PropertyType -Force
	}

	Write-Log -Message "Finished creating new registry key" -Path $ScriptLog
	# End registry setting
}

	
# End of Functions Section
#########################################################################################################################################
#endregion

#########################################################################################################################################
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!# Try to avoid modifying anything beyond this point.  #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
#########################################################################################################################################

#region ScriptExecution

# Check for debugging
if ($debugScript) {Set-PSDebug -trace 2}

#region Pre-flightActions
#########################################################################################################################################

# Note: For generally static information use requirements on the deployment type. I.E. OS or Bitlevel

Write-Log -Message "Install of $ProgramName $Version has started" -Path $ScriptLog

Write-Log -Message "Running script from location: $sourcePath" -Path $ScriptLog

# Check for running processes
Write-Log -Message "Checking if any process will stop us from executing." -Path $ScriptLog
if (($Processes.Count -gt 0) -and (Get-Process $Processes -ErrorAction SilentlyContinue)) {
	# If process is running halt execution and exit with fast retry code.
	Write-Log -Message "Process running exiting now to quick retry" -Path $ScriptLog
	Exit $FastRetryExitCode
}
Write-Log -Message "No process found to stop us from executing." -Path $ScriptLog

# Check for running processes to stop
Write-Log -Message "Checking if any process is running that we need to stop before executing." -Path $ScriptLog
if ($KillProcesses.Count -gt 0)	{
	Get-Process $KillProcesses -ErrorAction SilentlyContinue | ForEach-Object {
		try {
			$procID = $_.Id
			Stop-Process $procID -Force
			Write-Log -Message "$($_.ProcessName) has been detected in a running state but was stopped." -Path $ScriptLog
		}
		catch {
			if (Get-Process -Id $procID -ErrorAction SilentlyContinue) {
				# There was an error stopping processes, log this then halt execution and return an error code
				Exit-OnError -ErrorVar $_ -Section "Stopping processes"
			}
			# The process that was supposed to be stopped is not running, it likely stopped before Stop-Process got to it
			else { continue }
		}
	}
	Write-Log -Message "Processes that could interfere with execution have been stopped." -Path $ScriptLog


}
		
# End of Pre-flight Actions Section
#########################################################################################################################################
#endregion

	
#region Install
#########################################################################################################################################

Write-Log -Message "Starting execution of the install command line" -Path $ScriptLog

try {
	# Run the install command using the $InstallerPath and $InstallerArgs and capture the exit value of the installer
	Invoke-Command -ScriptBlock $InstallCMD | Out-Null
}
catch {
	# There was an error running the install command line, log this then halt execution and return an error code
	Exit-OnError -ErrorVar $_ -Section "install"
}
	
Write-Log -Message "Finished execution of the install command line" -Path $ScriptLog
Read-Host -Prompt "Press Enter to exit"
# End of install Section
#########################################################################################################################################
#endregion


# Exit
#########################################################################################################################################

# We've succeeded, return the exit code
Exit $ExitVal

# End of Exit Section
#########################################################################################################################################
#endregion

#region ScriptDescription
<#

Purpose
=======
 This script template is designed to be used with the University of Minnesota's Configuration Manager 2012 implementation.
 The purpose of this script template is to provide a common framework for the University's Computer Management community to perform
 program installations that require pre or post install actions (often called pre or post flight actions). By working from a common
 template the community should be more effectively able to share knowledge and troubleshooting problems should become simpler. This
 script template should provide the reqiured functionality for the vast majority of Custom Application Deployment Type Installations
 that will be created within the University's Computer Management community. There will be programs which have requirements the
 template does not meet in which case you should feel free to modify or abandon the template as required.  This template is designed for 
 simple installs which do not call an executable file.


Using this template
===================
 Before you begin modifying this script template you should determine the following:
  1. What is the command line that will install your program?
  2. Should the install not proceed if one or more specific processes are running?
  3. What OS and bit-level do you want this install to work for?
  4. Are there any additional actions that need to be taken to cleanup before or after the install?

 You should then test the command lines required for your install actions.  Those commands should successfully install the program
 on the OS and bit-level you are intending before you move on.  Remember that Configuration Manager 2012 will run these commands
 as the System account, not as a user level account.  Usually running your commands with a administrator level access will provide the access 
 that you need.  Once you have a working command lines you should the fill out the following variables in this script template:

   $ProgramName - This is the name of the program such as "Adobe Reader" and it is used for logging purposes.
   $Version - This is the version of the program which is used for logging purposes.
   $InstallCMD - This is a scriptblock which contains the install actions.
   $Processes - This is an array that contains any running processes that may interfere with the install.  It can contain more then one process or be left blank.

 You should then test out executing the script manually to ensure that it successfully installs the program.  Once you are satisfied with the script, copy it 
 to the location of your Application source files.  You should re-name it to something relevent.  You can then create a deployment type and set the Install Program 
 field on the Program tab to be something like:
 powershell.exe -executionPolicy Bypass -NoProfile -file scriptNameInstall.ps1

What not to try to do with this template
========================================
 This template leverages the application model of Configuration Manager 2012.  You should try to avoid doing the following within the script:

   1. Trying to handle different OS's or bit-levels within the script.  You should create different deployment types for each OS and bit level that requires
      customized actions.  You can use the Requirements tab for each Deployment type to differentiate which deployment type goes to which OS and bit level.

   2. Running multiple installers (either .MSI files or .EXE files) within the installation command line (as defined by $InstallCMD).  The application model of
      Configuration Manager 2012 expects each installer to have it's own Application.  You can use the Dependencies tab for your deployment type to add any other
      installs that need to take place in concurrence with your program.

   3. Uninstall a program before installing it.  In most cases this is not required as usually installers can handle a previous version being present.  If 
      the program you want to install requires that a previous version be uninstalled first and the installer does not automatically handle this you should 
      try to use Application supersedence (the supersendence tab of the Application properties) to handle this.  Using supersedence requires that an 
      Application exist for the previous version and that there is a working Uninstall command line for the appropriate deployment type. If supersedence is not an option
	  then you should use the pre-flight section to perform the uninstall.
#>
#endregion

# End of CM-install-Template.ps1
#########################################################################################################################################