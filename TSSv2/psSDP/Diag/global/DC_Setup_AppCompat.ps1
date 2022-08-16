#************************************************
# DC_Setup_AppCompat.ps1
# Version 1.0
# Date: 2009-2019
# Author: Walter Eder (waltere@microsoft.com)
# Description: Collects additional AppCompat information.
# Called from: TS_AutoAddCommands_Setup.ps1
#*******************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status $ScriptVariable.ID_CTSAddonsDescription

$sectionDescription = "Additional Components"

# detect OS version
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

function isOSVersionAffected
{
	if ([int]$bn -gt [int](9600))
	{
		return $true
	}
	else
	{
		return $false
	}
}

function RunNet ([string]$NetCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSSMBClient -Status "net $NetCommandToExecute"
	
	$NetCommandToExecuteLength = $NetCommandToExecute.Length + 6
	"`n`n`n" + "=" * ($NetCommandToExecuteLength) + "`r`n" + "net $NetCommandToExecute" + "`r`n" + "=" * ($NetCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c net.exe " + $NetCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $OutputFile -append
}


function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n" | Out-File -FilePath $OutputFile -append
}


<#----------Copy Components Registry hive -- done in DC_ServicingLogs.ps1
# $ComponentsHivOutputFileName = Join-Path $pwd.path ($ComputerName + "_reg_Components.HIV")
# copy $ENV:windir\system32\config\components $ComponentsHivOutputFileName /y
$sectionDescription = "Additional Components Registry hive"
$OutputFile = $ComputerName + "_reg_Components.HIV"
$ComponentsHiv = "$ENV:windir\system32\config\components"
if (test-path $ComponentsHiv)
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Copy $ComponentsHiv"
	Copy-Item -Path $ComponentsHiv -Destination $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "Components Registry hive file" -SectionDescription $sectionDescription
}
else
{
  "$ComponentsHiv Does not exist" | WriteTo-StdOut
}
#>

#--- Section for things that need to be started early, will check at end of this script if Process has terminated
if (isOSVersionAffected)
{ #write-host -fore cyan "BN=$bn isOSVersionAffected2=True "
	
	$sectionDescription = "Additional Components DXdiag"
	$dxdiagOutputFileName = Join-Path $pwd.path ($ComputerName + "_dxdiag.txt")
	$CommandToRun = "dxdiag /t $dxdiagoutputFileName"
	RunCMD -commandToRun $CommandToRun -collectFiles $true
	#dxdiag takes some number of seconds to write output after completion. -- will check at end 
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "...running: dxdiag /t "
	#$dxdiagID = (Get-Process dxdiag).id
<#	$i = 0
	$maxWasitSec=40
	while (-not (Test-Path $dxdiagOutputFileName))
	{
		$i++
		if ($i -ge $maxWasitSec)
		{
			"[error]:  waited for $maxWasitSec seconds for dxdiag output, giving up." | WriteTo-StdOut
			break
		}
		Start-Sleep 1
	}

	collectfiles -filesToCollect $dxdiagOutputFileName -fileDescription "dxdiag output" -sectionDescription "Additional Components DXdiag"
		#>
}

#--- Section for App Compat Info  Only run if flag set
Write-Host "$(Get-Date -UFormat "%R:%S") : Compress App Compat AppPatch Log files"
	#		Command: All logs in %windir%\AppPatch*\CompatAdmin.log
	$sectiondescription = "Compress AppPatch files"
	$logFilePath = (join-path $env:SystemRoot "AppPatch\CompatAdmin.log")
	if (test-path $logFilePath)
		{	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status $sectiondescription
			CompressCollectFiles -filesToCollect $logFilePath -Recursive -fileDescription "App Compat Log Files" -sectionDescription $sectiondescription -DestinationFileName "AppCompat_logs.zip" -RenameOutput $true
		}
	else
		{
		  "$logFilePath Does not exist" | WriteTo-StdOut
		}
	$sectiondescription = "Compress AppPatch64 files"
	$logFilePath = (join-path $env:SystemRoot "AppPatch64\CompatAdmin.log")
	if (test-path $logFilePath)
		{	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status $sectiondescription
			CompressCollectFiles -filesToCollect $logFilePath -Recursive -fileDescription "App Compat 64 Log Files" -sectionDescription $sectiondescription -DestinationFileName "AppCompat64_logs.zip" -RenameOutput $true
		}
	else
		{
		  "$logFilePath Does not exist" | WriteTo-StdOut
		}

#----------Event Logs
Write-Host "$(Get-Date -UFormat "%R:%S") : App Compat EventLogs"
	$sectiondescription = "Get EventLog files"
	#		Command: All App Compat EventLogs in %windir%\System32\Winevt\Logs
	#		OutputFileName: AppCompat_*_EventLogs.zip
	if (test-path $env:SystemRoot\System32\Winevt\Logs\*compatibility*.evtx)
	{	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription compatibility*.evtx"
		CompressCollectFiles -filesToCollect (join-path $env:SystemRoot "System32\Winevt\Logs\*compatibility*.evtx") -Recursive -fileDescription "Get Event Logs" -sectionDescription $sectiondescription -DestinationFileName "AppCompat_evt_compatibility_EventLogs.zip" -RenameOutput $true
	}
	if (test-path $env:SystemRoot\System32\Winevt\Logs\*inventory*.evtx)
	{	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription *inventory*.evtx"
		CompressCollectFiles -filesToCollect (join-path $env:SystemRoot "System32\Winevt\Logs\*inventory*.evtx") -Recursive -fileDescription "Get Event Logs" -sectionDescription $sectiondescription -DestinationFileName "AppCompat_evt_inventory_EventLogs.zip" -RenameOutput $true
	}
	if (test-path $env:SystemRoot\System32\Winevt\Logs\*program-telemetry*.evtx)
	{	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription *program-telemetry*.evtx"
		CompressCollectFiles -filesToCollect (join-path $env:SystemRoot "System32\Winevt\Logs\*program-telemetry*.evtx") -Recursive -fileDescription "Get Event Logs" -sectionDescription $sectiondescription -DestinationFileName "AppCompat_evt_program-telemetry_EventLogs.zip" -RenameOutput $true
	}

#----------Dir Outputs
Write-Host "$(Get-Date -UFormat "%R:%S") : Directory outputs"
	$sectionDescription = "Dir C:\Program Files\"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_AppCompat_Dir_ProgramFiles.txt")
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription"
	# RunPS "get-Childitem $ENV:Programfiles -recurse -Exclude *Defender*,*ScriptStore*,*CSC*,*RtBackup* -ErrorAction SilentlyContinue"
	$CommandToExecute = 'dir /a /s "C:\Program Files\" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "App Compat: Dir C:\Program Files\ output" -sectionDescription $sectionDescription
	
	$sectionDescription = "Dir C:\Program Files (x86)\"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_AppCompat_Dir_ProgramFilesx86.txt")
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription"
	$CommandToExecute = 'dir /a /s "C:\Program Files (x86)" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "App Compat: Dir C:\Program Files (x86)\ output" -sectionDescription $sectionDescription

#----------Registry
Write-Host "$(Get-Date -UFormat "%R:%S") : Registry outputs, will take minutes..."

		$AppCompatFlagsKeyHKLM = 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags'
		$OutputFile= $ComputerName + "_AppCompatFlags_Reg_HKLM.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get AppCompatFlags_Reg_HKLM file"
		RegQuery -RegistryKeys $AppCompatFlagsKeyHKLM -OutputFile $OutputFile -fileDescription "AppCompatFlags HKLM Reg key" -Recursive $true

		$AppCompatFlagsKeyHKCU = 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags'
		$OutputFile= $ComputerName + "_AppCompatFlags_Reg_HKCU.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get AppCompatFlags_Reg_HKCU file"
		RegQuery -RegistryKeys $AppCompatFlagsKeyHKCU -OutputFile $OutputFile -fileDescription "AppCompatFlags HKCU Reg key" -Recursive $true

		$InstallerKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Installer'
		$OutputFile= $ComputerName + "_AppCompat_Reg_WindowsInstaller.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get Reg_WindowsInstaller file"
		RegQuery -RegistryKeys $Installerkey -OutputFile $OutputFile -fileDescription "Installer Reg key" -Recursive $true

<#		$HKCUsoftwareKey = 'HKCU\Software'
		$OutputFile= $ComputerName + "_reg_HKCU_CurrentUser-Software.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get HKCU\Software TXT file"
		RegQuery -RegistryKeys $HKCUsoftwareKey -OutputFile $OutputFile -fileDescription "Reg_CurrentUser-Software Hive TXT file" -Recursive $true
		
		$HKLMsoftwareKey = 'HKLM\Software'
		$OutputFile= $ComputerName + "_reg_HKLM_LocalMachine-Software.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get HKLM\Software TXT file"
		RegQuery -RegistryKeys $HKLMsoftwareKey -OutputFile $OutputFile -fileDescription "Reg_LocalMachine-Software Hive TXT file" -Recursive $true
#>
		# much faster to collect .HIV instead of RegQuery / REG EXPORT
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get Reg Software-User.HIV"
		$OutputFile= $MachineName + "__reg_HKCU-Software-User.HIV"
		RegSave -RegistryKey "HKCU\Software" -OutputFile $OutputFile -fileDescription "HKCU-Software-User Hive"

		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get Reg Software.HIV"
		$OutputFile= $MachineName + "__reg_HKLM-Software.HIV"
		RegSave -RegistryKey "HKLM\Software" -OutputFile $OutputFile -fileDescription "HKLM-Software Hive"

#----------End section
Write-Host "$(Get-Date -UFormat "%R:%S") : App Compat end section"
# Waiting until Process DXdiag completes
	if (Get-Process -Name DXdiag -EA SilentlyContinue) {
		Write-Host "$(Get-Date -UFormat "%R:%S") ...waiting max 40 seconds on DXdiag $dxdiagID to complete"
		#Wait-Process -Id $dxdiagID -Timeout 40 -EA SilentlyContinue
		Wait-Process -Name DXdiag -Timeout 40 -EA SilentlyContinue
		collectfiles -filesToCollect $dxdiagOutputFileName -fileDescription "dxdiag output" -sectionDescription "Additional Components DXdiag"
	}


# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCznXlu9o0GFfxx
# 1e1OkTSbX89dXBQE9ROkiXgMVmGuV6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXTCCFVkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgvPrwzEUe
# yKOrKF2CRBKGO6495u30WA1EyTx/VurLZa4wOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAHjjQmmdvo2C/KM0bFNlNWbihr4ng1Sz6zJrVgZ7H+XPdn5CeYusrzdt
# 7UaPoeiFe/IwZJ6hk1HAxO3+IIaS2ZeYnnsFTuJM1iK+yOC8ym9NR2FbVP1KGOVY
# 7d6CHA2zNXlVJmYmnuhOI6K0MdEd1a8jh9Qe2bcMZIbWXTKGk4//wQW8VblM1ITe
# 0JLH2edDXKCNCBolEDn5tWNlwXeu4+w9U9o/4mCmgUIVUlitrvrCA2kQcZnr3P4C
# syzor8VorXvBZFW7w55mTVfX7Je5dwMnZyl7Flu0CmrCK40huA50B+QnAgqWNHg+
# pUcCYbgBEj9MsUqkIyMie+ruOxhbK0WhghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgrHZSTt7iHB0TBfOy3gktRmDJJEvlKMuJkrixaZQUvWECBmGB3Gir
# XhgTMjAyMTExMTExNjUzMzYuMTc2WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjYw
# QkMtRTM4My0yNjM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFaLLluRDTLbygAAAAAAVowDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjE2WhcNMjIwNDExMTkwMjE2WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjYwQkMtRTM4My0yNjM1
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsL1cHFcNrScIrvQd/4aKHo3FGXWYCHMU
# l2iTxuzfGknztMzbysR4eRkBoT4pv0aL1S9OlDfOsRbJZKkhCTLG/9Z/RwiEDWYk
# 6rK7bRM3eX3pm+DNivM7+tCU+9spbv2gA7j5gWx6RAK2vMz2FChLkFgbA+H1DPro
# G5LEf1DB7LA0FCyORWiKSkHGRL4RdIjOltrZp++dExfsst7Z6vJz4+U9eZNI58fV
# Y3KRzbm73OjplfSAB3iNSkHN0wuccK0TrZsvY87TRyYAmyK2qBqi/7eUWt93Sw8A
# LBMY72LKaUmVvaxq/COpKePlHMbhHEbqtTaLt61udBOjNHvc4cwY5QIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFGRzJT/1HI+SftAGhdk5NDzA3jFnMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAAAAbex8WBtSLDiBYxXxU7GVsgb8IgxKJyIO0hmc8vzg
# 4w3iUl5Xkt4mv4dgFyjHmu5Zmbj0rb2IGYm/pWJcy0/zWlhnUQUzvfTpj7MsiH+1
# Lnvg95awe88PRA7FDgc4zYY0+8UB1S+jzPmmBX/kT6U+7rW5QIgFMMRKIc743utq
# CpvcwRM+pEo8s0Alwo8NxqUrOeYY+WfNjo/XOin/tr3RVwEdEopD+FO+f/wLxjpv
# 4y+TmRgmHrso1tVVy64FbIVIxlMcZ6cee4dWD2y8fv6Wb9X/AhtlQookk7QdCbKh
# 3JJ4P8ksLs02wNhGkU37b10tG3HR5bJmiwmZPyopsEgwggZxMIIEWaADAgECAgph
# CYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2
# NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvt
# fGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzX
# Tbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+T
# TJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9
# ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDp
# mc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIw
# EAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1V
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7P
# BeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2
# zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95
# gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7
# Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt
# 0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2
# onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA
# 3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7
# G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Ki
# yc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5X
# wdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P
# 3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjYwQkMtRTM4My0y
# NjM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQDMgAWYvcYcdZwAliLeFobCWmUaLqCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TePeDAiGA8y
# MDIxMTExMTE2NDc1MloYDzIwMjExMTEyMTY0NzUyWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN494AgEAMAoCAQACAiYUAgH/MAcCAQACAhEuMAoCBQDlOOD4AgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEARgjej0SbSLQSMcUwvN12chrEC28n
# cvB5Y3XUAVhEcy1SU+s/DPBT7RaNwTGRnmi6Mq9YdOCw28LOQagQobT23OIXtlQk
# v6/VnsW+JiF8q2A2Zvn08thSlcdfEr1B4nsYLVrR78o0MGag24mYk75Z6ATsfNVT
# HmPR653hJHGQ0OcxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVosuW5ENMtvKAAAAAABWjANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCA7Xzcd
# RY49zcd8DIRt/arhVZ3P6n4XwJBAUP8L2GeX3jCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIJP8qCZ0xLLkXTDDghqv1yZ/kizekzSFS4gicvltsX+wMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFaLLluRDTLbygA
# AAAAAVowIgQgMnaZvhznlep5/TqcHsVpqibeOA9Q6qLRQqPN0sxjsvwwDQYJKoZI
# hvcNAQELBQAEggEAQY+Yqkr6UoBDpewoM1LH6/qtE3NvOOi2j58x1PaVsaA8IBE/
# JNl4OEsgu+J5D+Ww0NLFg0SG/GzyWWOQJ3sz4Q3rPBmTqgOqW8aWchODA0LVg5uH
# oTkOCvS+7ny22HpSFAoium5C9+gYLuC/a4oM7SHQj6x7F7gsoF+WT1eVEHyhl4NP
# 06xtgIWtIM+RAun+IGLYrDaSOF0iktY7bfae1HQQHBmNRwh95CQWC3soUBd9p4cD
# mL2Ckn4KnCI/CGYRyHSmOe1CbI/QZ5bdj3u+e52hYd98osQZwwURrnzduNApGKQt
# HdRrd8K/YMNE1sm9sIh7fJ5Hb4n2RoCcjWqYKQ==
# SIG # End signature block
