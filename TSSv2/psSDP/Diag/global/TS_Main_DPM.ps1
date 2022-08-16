# Copyright ? 2008, Microsoft Corporation. All rights reserved.

# You may use this code and information and create derivative works of it,
# provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for
# troubleshooting a) Windows and b) products for Windows, in either case using
# the Windows Troubleshooting Platform
# 2. Any copies of this code and information
# and any derivative works must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
# INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
# WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

#************************************************
# Version 2.0.0
# Date: 09-01-2011
# Author: Patrick Lewis - patlewis@microsoft.com
# Co-Author: Wilson Souza - wsouza@microsoft.com
# Description: 
#         1) Gets computer information, name, etc from DC_BasicSystemInformation
#         2) Gets all version info from both drivers and DPM directories for dll, exe and sys files
#         3) Collect System, Application, and DPM Alerts event logs
#         4) Grab logs from DPM\Temp directories
#************************************************
#$debug = $false
$global:BackgroundProcess

# Load Common Library:
. ./utils_cts.ps1
. ./TS_RemoteSetup.ps1
. ./Functions.ps1

function MenuDiagInput-LocalOrRemote
{
    Write-Host -ForegroundColor Yellow 	"============ Collect DPM Information =============="
    Write-Host "1: Local"
    Write-Host "2: Remote"
	Write-Host "q: Press Q  or Enter to skip"
}
function MenuDiagInput-DPMDB_COLLECT
{
    Write-Host -ForegroundColor Yellow 	"============ Collect DPMDB database Information =============="
    Write-Host "1: DPMDB_COLLECT"
    Write-Host "2: DPMDB_DO_NOT_COLLECT"
	Write-Host "q: Press Q  or Enter to skip"
}

$FirstTimeExecution = FirstTimeExecution

if ($FirstTimeExecution) {

$IsDPMInstalled = IsDPMInstalled
$isMABInstalled = IsMABInstalled

	if($IsDPMInstalled -or $IsMABInstalled)
	{
		$ExpressionToRunOnMachine = @'
			. ./Functions.ps1
			Run-DiagExpression .\DC_BasicSystemInformation.ps1
			if (IsDPMInstalled)
			{
				Run-DiagExpression .\DC_ChkSym_DPM.ps1 -Range @("DPM", "Drivers")			
				Run-DiagExpression .\DC_CollectDPMLogs.ps1
				Run-DiagExpression .\DC_GetDPMInfo.ps1
				Run-DiagExpression .\DC_DPMEventLogs.ps1
			}
			Run-DiagExpression .\DC_GetSystemInfo.ps1			
			if (IsMABInstalled)
			{
				Run-DiagExpression .\DC_CBEngine.ps1
			}			
			.\TS_AutoAddCommands.ps1
'@

		Write-DiagProgress -Activity "Attempting to get input" -Status "Waiting for input"
		if ($IsDPMInstalled)
		{
			#_# $LocalOrRemote = Get-DiagInput -Id ID_DataCollector_LocalOrRemote
			<#MenuDiagInput-LocalOrRemote
			$Selection = Read-Host "Choose the local or a remote DPM server"
			WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DPM Selection: $Selection" -shortformat
			switch ($Selection)
				{
					1 {$LocalOrRemote = "Local"}
					2 {$LocalOrRemote = "Remote"}
					'q' {}
				} #>
			$LocalOrRemote = "Local"
		}

		if($LocalOrRemote -eq "Remote") #remote server collect #_# not implemented so far 2020-12-09
		{
			$Machines = @()
			if(IsDPMServer) #DPM server
			{
				$Machines += @{"Name"="$ComputerName [DPM Server] (Local)"; "Value"=$ComputerName;"Description"="$ComputerName"; "ExtensionPoint"="<Default/>"}

				LoadDPMNamespace
				Disconnect-DPMServer # make sure the connection to DPM server is ended, and then Get-DPMProductionServer will not get an error.
				$AllServers = Get-ProductionServer $ComputerName
				if($null -ne $AllServers)
				{
					$ProtectedServerList = $AllServers | Where-Object { $_.possibleowners -eq $null -and $_.serverprotectionstate -ne 'Deleted' -and $_.isdpminstalled -eq $false} | sort-object NetBiosName
					if($null -ne $ProtectedServerList)
					{
						foreach($Server in $ProtectedServerList )
						{
							if($Server.MachineName -ne $ComputerName)
							{
								$protectedServer = @{}
								$protectedServer.Name = $Server.MachineName
								$protectedServer.Value = $Server.MachineName
								$protectedServer.Description = $Server.MachineName
								$Machines += $protectedServer
							}
						}
					}
				}		
				$DPMServer = $ComputerName
			}
			else #Protected server
			{
				if (IsDPMInstalled)
				{
				    $Machines += @{"Name"="$ComputerName (Local)"; "Value"=$ComputerName;"Description"="$ComputerName"; "ExtensionPoint"="<Default/>"}
				    [xml] $xml = [System.Text.Encoding]::UNICODE.GetString((Get-ItemProperty "hklm:SOFTWARE\Microsoft\Microsoft Data Protection Manager\Agent\2.0").configuration)
				    $MapedDPMServer = $xml.DLSConfig.FirstChild.AuthorizedMachines.MachineName
				    if($null -ne $MapedDPMServer)
				    {
					    $MapedDPMServer = $MapedDPMServer.Substring(0,$MapedDPMServer.IndexOf('.'))
					    if($MapedDPMServer -ne $ComputerName)
					    {
						    $DPMServer = @{}
						    $DPMServer.Name = $MapedDPMServer + " [DPM Server]"
						    $DPMServer.Value = $MapedDPMServer
						    $DPMServer.Description = $MapedDPMServer
						    $DPMServer.ExtensionPoint = "<Default/>"
						    $Machines += $DPMServer
					    }
				    }
				    $DPMServer = $MapedDPMServer							
				}
			}
			
			$SelectedRemoteMachines = Get-DiagInput -Id ID_ProtectedServers -Choice $Machines
			if(($null -ne $SelectedRemoteMachines) -and ($SelectedRemoteMachines -contains $DPMServer))
			{
				$DiagResponse = Get-DiagInput -id "TroubleshootingType"
				if($DiagResponse -eq "DPMDB_COLLECT")
				{
					$ExpressionToRunOnMachine += "`r`n Run-DiagExpression .\DC_CollectDPMDB.ps1"
				}

				$VerboseLogging = Get-DiagInput -Id ID_VerboseLoggingCollector
				if($VerboseLogging -eq 'Collect')
				{
					$VerboseLoggingOrNot = Get-DiagInput -Id ID_Run_Verbose_Logging
					if($VerboseLoggingOrNot -eq "Yes")
					{
						"one" | out-file c:\temp\one.txt
						$ExpressionToRunOnMachine += "`r`n Run-DiagExpression .\DC_DPMVerboseTracing.ps1"

						$CanEnableVerboseLogsMachines = @()
						foreach($machine in $SelectedRemoteMachines)
						{
							Trap [Exception]
							{
								"Unable to communicate with server " + $machine + " due the following error: " + ($_.Exception.get_Message()) | WriteTo-StdOut -ShortFormat
								WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "Communicating with $machine"
								continue 
							}

							if(Test-Path "\\$machine\admin$")
							{
								$CanEnableVerboseLogsMachines += $machine
							}
							else
							{
								"Unable to communicate with server " + $machine | WriteTo-StdOut -ShortFormat
							}
						}

						$CanEnableVerboseLogsMachines | Out-File SelectedMachines.txt -Encoding "utf8"
					}
				}
			}

			#Collect remote machines
			if($null -ne $SelectedRemoteMachines)
			{
				$RemoteMachineList = @()
				$ExpressionArray = @()
				foreach($Machine in $SelectedRemoteMachines )
				{
					$RemoteMachineList += $Machine
					$ExpressionArray += $ExpressionToRunOnMachine
				}

				ExecuteRemoteExpression -ComputerNames $RemoteMachineList -Expression $ExpressionArray -ShowDialog
			}
		}
		else #Local server collect
		{
			if(IsDPMServer)
			{
				#_#$DiagResponse = Get-DiagInput -id "TroubleshootingType"
				<#MenuDiagInput-DPMDB_COLLECT
				$Selection = Read-Host "Choice for DPMDB_COLLECT"
				WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DPMDB Selection: $Selection" -shortformat
				switch ($Selection)
				{
					1 {$DiagResponse = "DPMDB_COLLECT"}
					2 {$DiagResponse = "DPMDB_DO_NOT_COLLECT"}
					'q' {}
				}#>
				$DiagResponse = "DPMDB_COLLECT"

				if($DiagResponse -eq "DPMDB_COLLECT")
				{
					$ExpressionToRunOnMachine += "`r`n Run-DiagExpression .\DC_CollectDPMDB.ps1"
				}

				#_#$VerboseLogging = Get-DiagInput -Id ID_VerboseLoggingCollector
				$VerboseLogging = 'Collect'
				if($VerboseLogging -eq 'Collect')
				{
					#_#$VerboseLoggingOrNot = Get-DiagInput -Id ID_Run_Verbose_Logging
					write-host "Please choose verbose logging mode" -ForegroundColor Yellow
					$VerboseLoggingOrNot = Read-Host 'Do you allow to Run_Verbose_Logging? [Yes|No] '  #_# UserInput
					
					#_# if($VerboseLoggingOrNot -eq "Yes")
					if($VerboseLoggingOrNot -match "Y") #_# 
					{
						"two" | out-file c:\temp\two.txt
						$ExpressionToRunOnMachine += "`r`n Run-DiagExpression .\DC_DPMVerboseTracing.ps1"
					}
				}
			}

			#Collect the local machine
			Invoke-Expression $ExpressionToRunOnMachine
		}
	}
	else # not a DPM or Protected Server, will exit.
	{
		#_# Get-DiagInput -Id ID_WaitingForExit
		Write-Host "This is not a DPM or Protected Server, will exit."
		"This is not a DPM or Protected Server: " + $env:COMPUTERNAME | WriteTo-StdOut -ShortFormat
	}

	EndDataCollection

} else {
	#2nd execution. Delete the temporary flag file then exit
	EndDataCollection -DeleteFlagFile $True
}


# SIG # Begin signature block
# MIInlgYJKoZIhvcNAQcCoIInhzCCJ4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBNZ4IEOCufDy0D
# lS5HvsGr9X/dWXy1gKxxBh2TGb5KL6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILDL9lWBEuigGL/9VtWlaQJU
# eZY12h3/lzfDbGUrgTfqMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCVdr0BfJF7iBwKY12oCxhTxMvuUQOMxQDX3o1eDC2w4+n7ql3NMam+
# zGPBOI9EX+Dpgi6X7EvDVJM3iLsQxx0mEHX8A+gFPVmVxaiN2UbmRL91zOYqt2JS
# gS01cK7iI/Pn15FfaWRcvu7di3x424HHWHxoyornbW/ME3QJxSDWfw+MnQ/t/1BO
# YkQO5jkUNMgpKHfm9E0+Jb66vP6HtfAh3r7HyID0mB9PLdSQTRQCc5zZtRZ/QC6s
# f8Ex+bKA8yEwaYlHIdd88QKHYZem/XoFyfn+BBXPkqfq5+q+17oEBjPF9WP+HOKg
# qw419UVgmO+6yljsrVvcnqNgUSvoDcvioYIW/jCCFvoGCisGAQQBgjcDAwExghbq
# MIIW5gYJKoZIhvcNAQcCoIIW1zCCFtMCAQMxDzANBglghkgBZQMEAgEFADCCAU8G
# CyqGSIb3DQEJEAEEoIIBPgSCATowggE2AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGFWmc5D6gz67dg90JFVQpw4EuqmBdim8pcdso2vwQ2CAgZi2BAX
# CAwYETIwMjIwODAxMDgwNTEyLjJaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFQUNFLUUz
# MTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVcwggcMMIIE9KADAgECAhMzAAABmsB1osQhbT6FAAEAAAGaMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIxMTIwMjE5MDUx
# N1oXDTIzMDIyODE5MDUxN1owgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMxNi1DOTFEMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA2nIGrCort2RhFP5q+gObfaFwIG7AiatDZzrvueM2T7fW
# P7axB0k5aRNp+I7muFZ2nROLH9jYPMX1MQ0DzuFW/91B4YXR4gpy6FCLFt8LRNjj
# 8xxYQHFDc8bkqZOuu6JuKPxnGj5cIiDeGXQ8Ujs+qI0jU/Ws7Cl8EBQHLuHPbbL1
# 4rpffbInwt7NnRBCdPwYch4iQMLHFODdp5tVA3+LjAHwtQe0gUGS99LLD8olI1O4
# CIo69SEZQQHQWJoskdBe0Sb88vnYsI5tCLI93/G7FSKvYGZFFscRZCmS3wcpXhKO
# ATJkTGRPfgH06a0J3upnI7VQHQS0Sl714y0lz0eoeeKbbbEoSmldyD+g6em10X9h
# m9gn3VUsbctxxwFMmV7hcILiFdjlt4Bd5BUCt7i+kGbzfGuigdIbaNOlffDrXstT
# kzr59ZkZwL1buFo/H9XXPvXDj3T4LRc+HHd+5kUTxJAHV9mGnk4KXDRMWvowmzkj
# fvlbTUnMcLuAIz6E30I7kPi9afEjGX4IE/JIWl2llmfby7zuzyMCGeG9kit/15lq
# ZNAJmk4WuUBtH7ubr3eGGf8S7iP5IsB1nE8pL4gGTpcJK57KGGSSdN0bCAFr+lB5
# 2IwCPBt1IAhRZQJtJ4LkN6yF+eKZro0vN5YK5tWKmy9i65YZovfDJNpLQhwlykcC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRftp5Z8JzbUemlWb0KlcitNivRcDAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQAAE7uHzEbUR9tPpzcxgFxcXVxKUT032zNCyQ3jXuEAsY9BTPsKyXbulCqzNsEL
# jt9VA3EOJ61CQXvNTeltkbxGvMTV42ztKszYrcFHzlS3maeh1RnDU7WBDALyvZP/
# 9HWgRcW6dOAczGiMmh0cu8vyv82fXJBMO4xfVbCapa8KpMfR6iPyAbAqSXZU7SgZ
# f/i0Ww/LVr8OhQ60pL/yA4inGqzxNAVOv/2xV72ef4e3YhNd3ar+Qz1OSp+PfR71
# DgHBxt9YK/0yTxH7aqiuNHX6QftWwT0swHn+fKycUSVzSeutRmzmeXuuBLsiEL9F
# aOWabWlmYn7UOaYJs7WmQrjSCL8TxwsryAI5kn0bl+1MpHtJNva0k67kbAVSLInx
# t/YJXbG8ozr5Aze0t6SbU8CVdE6AuFVoNNJKbp5O9jzkbqd9WoVvfX1N48QYdnx4
# 4nn42VGtPHf50EHS1gs2nbbaZGbwoB/3XPDLbNgsK3MQj2eafVbhnKshYStiOj0t
# DzpzLn+9Ed5a5eWPO3TvH+Cr/N25IauYPiK2OSry3CBBEeZLebrqK6VsyZgTRgfu
# tjlTTM/dmCRZfy7fjb5BhU7hmcvekyzD3S3KzUqTxleah6px5a/8FM/VAFYkyiQK
# 70m75P7IlO5otvaKkcW9GoQeKGFTzbr+3HB0wRqjTRqJeDCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLOMIICNwIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RUFDRS1FMzE2LUM5MUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAAG6rjJ1Ampv5uzsdVL/xjbNY5rvoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDmkbeMMCIYDzIwMjIwODAxMTAyMzA4WhgPMjAyMjA4MDIxMDIzMDhaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOaRt4wCAQAwCgIBAAICFzICAf8wBwIBAAIC
# EZowCgIFAOaTCQwCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCQ1jkwR8Fk
# +zg3b78DfN304JmCWlxzWGq7bMlRfa6R0sbfzHgs0Rt3ibiL+zTegBsGEPIkiFSq
# C5VoCUAX3V3KSR/Z6T02jhRhjqdAp3jqzBA62QC6GL0iToDgjT7mV41qzwzNCPU1
# M3s2/LAhebjhQ6Yme8Tm09830aE29F4PtTGCBA0wggQJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABmsB1osQhbT6FAAEAAAGaMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIJyhqZFAPFbvYGSkjlBFxRydixVTgwzN9FCnmJvTCbp4MIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgAU5A4zgRFH2Z5YoCYi+d/S8fp7K/zRVU
# 5yhV9N9IjWAwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAZrAdaLEIW0+hQABAAABmjAiBCC1LZuE6YrF6Bu5E7MTiOdSDJBYbjsg+l5v
# sgK/ICIdPTANBgkqhkiG9w0BAQsFAASCAgDSPJq2AtqqlvWyG6Qu16+crP51xdsM
# +AsgAW1K6aNsmhWT12RN/tmjE3xP4FPuluW7gEZrfc1YTOYVfKAlQfHGpxqF9T/K
# TUB4JyMnLT2AAwkcstsMrVOUyVtiGafPZsXZeW8ssHTXS7rznwzpWtOflC+QHMPA
# X4/f8ZgeTjM5cBUmGRuXEbyRjYQbQm5o/d3RYJDoDyKBtIJ7W/+B+2sSsOJRqad5
# EfMo+52dPnGDAQgYLYsAGD2oxiuE0cBp77uGt5/jCB8DouPhG+9RG0fTBn7z/A1Q
# F4ymIL35KBqTsp8IFp+B/8JujXYMo47YS2nJuyNymYJJdzYR3KUgS1ok2Fbop4AH
# TjLEhM+7G5D5yzdoqf+wCxr3fjj9OKTJD31Nlbg/eQ7Eay8cfDI5KLw+ItZSUUeS
# cXMw96BRPXK+XuG7JOZLUmgmMX16O/fcLSlzr1l3ieyDNa4kSawZnT4uxnCTGtWW
# oAEY0uj0wXOREjZwv8Ss6cZLYjlCN9GtfMnHG80PwjkV788DYmrTEkALoQdRb2aN
# 2ppif44klM0oycXa9OnsDpaopFubgZvT8uGOcJ4SlosOr2BgD9CUidwCIYl9Gonx
# qCAbKfi43V33k2fYC14wC/9kfV0oUBh5YPWzurriwH8gexOJ/U9kgSYY1g2NJbOB
# 4LOMr8Y34q2Zmw==
# SIG # End signature block
