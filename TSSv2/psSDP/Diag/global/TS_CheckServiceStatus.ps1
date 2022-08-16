#************************************************
# Version 1.0
# Date: 12-04-2013
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:  
# 		Checks status of SMS related services and raises and alert if any service(s) are stopped
#************************************************
 
trap [Exception] 
{ 
	WriteTo-ErrorDebugReport -ErrorRecord $_ 
	continue 
}

Function Check-ServiceStatus (
	$ServiceName, 
	$DesiredState="Running",
	$DesiredStartMode="Automatic",
	$RCDescription="")
{
	$RootCauseName = "RC_ServiceStatus"	
	$InformationCollected = New-Object PSObject
	$Service = Get-CimInstance Win32_Service | Where-Object {$_.Name -eq $ServiceName}
	if ($Service -is [WMI])
	{
		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_CheckServiceStatus -Status ($ScriptStrings.ID_SCCM_CheckServiceStatusDesc + ": " + $Service.DisplayName)

		if ($Service.State -ne $DesiredState)
		{			
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Name" -value ($Service.Name)
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Start Mode" -value ($Service.StartMode)
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Current State" -value ($Service.State)
			Update-DiagRootCause -id $RootCauseName -Detected $true -InstanceId $ServiceName -Parameter @{"ServiceName" = $Service.DisplayName; "DesiredStartMode" = $DesiredStartMode; "RCDescription" = $RCDescription}
			Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		}
	}
}

Function Check-ServiceDisabled (
	$ServiceName, 
	$DesiredStartMode="Manual",
	$RCDescription="")
{
	$RootCauseName = "RC_ServiceMode"
	
	$InformationCollected = New-Object PSObject
	$Service = Get-CimInstance Win32_Service | Where-Object {$_.Name -eq $ServiceName}
	if ($Service -is [WMI])
	{
		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_CheckServiceStatus -Status ($ScriptStrings.ID_SCCM_CheckServiceStatusDesc + ": " + $Service.DisplayName)

		if ($Service.StartMode -eq "Disabled")
		{
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Name" -value ($Service.Name)
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Start Mode" -value ($Service.StartMode)
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Current State" -value ($Service.State)
			Update-DiagRootCause -id $RootCauseName -Detected $true -InstanceId $ServiceName -Parameter @{"ServiceName" = $Service.DisplayName; "DesiredStartMode" = $DesiredStartMode; "RCDescription" = $RCDescription}
			Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		}
	}
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings

### Check if Stopped ###
# WMI
Check-ServiceStatus -ServiceName "WinMgmt" -DesiredState "Running"

# SMS Agent Host
Check-ServiceStatus -ServiceName "CcmExec" -DesiredState "Running" -DesiredStartMode "Automatic (Delayed Start)"

# Windows Update
if (($OSVersion.Major -ge 6) -and($OSVersion.Minor -ge 2))
{	# Win8 or Above
	Check-ServiceDisabled -ServiceName "WuAuServ" -DesiredStartMode "Manual" -RCDescription "If the service is Disabled, it would lead to issues with Update Deployments"
}
else
{
	Check-ServiceStatus -ServiceName "WuAuServ" -DesiredState "Running" -RCDescription "If the service is Stopped, it could lead to issues with Update Deployments"
}

# Microsoft Policy Platform Local Authority
Check-ServiceDisabled -ServiceName "lpasvc" -DesiredStartMode "Manual"

# Microsoft Policy Platform Processor
Check-ServiceDisabled -ServiceName "lppsvc" -DesiredStartMode "Manual" 

# BITS
Check-ServiceDisabled -ServiceName "BITS" -DesiredStartMode "Manual"

# Network List Service
Check-ServiceDisabled -ServiceName "netprofm" -DesiredStartMode "Manual" -RCDescription "If the service is Disabled, it could lead to client installation issues, failures to start ccmexec, MP issues and/or other network issues"

# Network Location Awareness
Check-ServiceStatus -ServiceName "NlaSvc" -DesiredState "Running" -RCDescription "If the service is Stopped, it could lead to client installation issues, failures to start ccmexec, MP issues and/or other network issues"

# Windows Installer
Check-ServiceDisabled -ServiceName "msiserver" -DesiredStartMode "Manual" -RCDescription "If the service is Disabled, it would lead to issues with Application and/or Update Installations"

# SMS_EXECUTIVE
Check-ServiceStatus -ServiceName "SMS_EXECUTIVE" -DesiredState "Running"

# CONFIGURATION_MANAGER_UPDATE
Check-ServiceStatus -ServiceName "CONFIGURATION_MANAGER_UPDATE" -DesiredState "Running"

# SMS_SITE_COMPONENT_MANAGER
Check-ServiceStatus -ServiceName "SMS_SITE_COMPONENT_MANAGER" -DesiredState "Running"

# SMS_NOTIFICATION_SERVER
Check-ServiceDisabled -ServiceName "SMS_NOTIFICATION_SERVER" -DesiredStartMode "Manual"

# SMS_SITE_BACKUP
Check-ServiceDisabled -ServiceName "SMS_SITE_BACKUP" -DesiredStartMode "Manual"

# SMS_SITE_VSS_WRITER
Check-ServiceStatus -ServiceName "SMS_SITE_VSS_WRITER" -DesiredState "Running"

if ($Is_SiteSystem)
{
	# Remote Registry
	Check-ServiceDisabled -ServiceName "RemoteRegistry" -DesiredStartMode "Manual" -RCDescription "If the service is Disabled, it could lead to issues on Site Servers and Site Systems."

	# Volume Shadow Copy
	Check-ServiceDisabled -ServiceName "VSS" -DesiredStartMode "Manual" -RCDescription "If the service is Disabled, it would cause issues with Backups"

	# Server
	Check-ServiceStatus -ServiceName "LanManServer" -DesiredState "Running" -RCDescription "If the service is Stopped, other machines would not be able to make SMB connections to this Server."

	# Workstation
	Check-ServiceStatus -ServiceName "LanManWorkstation" -DesiredState "Running" -RCDescription "If the service is Stopped, this machine would not be able to make SMB connections to other Servers."
}

if ($Is_WSUS)
{
	# Update Services
	Check-ServiceStatus -ServiceName "WsusService" -DesiredState "Running"
}

if ($Is_PXE)
{
	# Windows Deployment Services Server
	Check-ServiceStatus -ServiceName "WDSServer" -DesiredState "Running"
}

if ($Is_IIS)
{
	# IIS Admin Service
	Check-ServiceStatus -ServiceName "IISADMIN" -DesiredState "Running"

	# World Wide Web Publishing Service
	Check-ServiceStatus -ServiceName "W3SVC" -DesiredState "Running"
}

TraceOut "Completed"


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACYD8AG9BUCu12
# ptjOxE1jN0U2YZNKqrD8dJsqLETjqqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIG2b8Ietu1KHTPz93DKkqrJk
# O61fAF3NF53uMPlv6d4DMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBsytoQfqa1sTlOWGAM70NL959ZKRonfjLaWs3br6bRTkMGimN4gDIJ
# zsf/CKgHanCp4UmI/lKlF3de/qzreANYDNp36UdBPqpWg3pgjAOrKdd0fec3JK09
# 1n54aWRolN6paGf4ItaJuUXj4tNG/AMVvDv0ohXoCfQ8MZdZMy1N8dRi6P9zsWAS
# KfOfZGmMhkRCMS6ayFGMCgCwQ2/bhohbxposwjrBFfWS6WTCy1oOaWPBKvNhmpx3
# 9V/zmB+NXqAsFS03G/IuGbpQ0M5Y2Ezw4s/Dg45JgK2Z5iPcLpZG+xVegpm31bJX
# XGHweA4PGDerqmOUjBwROoM2oyRwe0jmoYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEICkXxENRc/YJ/f0PJEzLcHsPR7uOVWPK/j4erVWxWsJIAgZi1+uY
# Y1QYEzIwMjIwODAxMDgwMDE2LjU3NVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMt
# RTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE0WhcNMjMwMjI4MTkwNTE0WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIzM0MxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDtAErqSkFN8/Ce/csrHVWcv1iSjNTArPKEMqKPUTpY
# JX8TBZl88LNrpw4bEpPimO+Etcli5RBoZEieo+SzYUnb0+nKEWaEYgubgp+HTFZi
# D85Lld7mk2Xg91KMDE2yMeOIH2DHpTsn5p0Lf0CDlfPE5HOwpP5/vsUxNeDWMW6z
# sSuKU69aL7Ocyk36VMyCKjHNML67VmZMJBO7bX1vYVShOvQqZUkxCpCR3szmxHT0
# 9s6nhwLeNCz7nMnU7PEiNGVxSYu+V0ETppFpK7THcGYAMa3SYZjQxGyDOc7J20kE
# ud6tz5ArSRzG47qscDfPYqv1+akex81w395E+1kc4uukfn0CeKtADum7PqRrbRMD
# 7wyFnX2FvyaytGj0uaKuMXFJsZ+wfdk0RsuPeWHtVz4MRCEwfYr1c+JTkmS3n/pv
# Hr/b853do28LoPHezk3dSxbniQojW3BTYJLmrUei/n4BHK5mTT8NuxG6zoP3t8HV
# mhCW//i2sFwxVHPsyQ6sdrxs/hapsPR5sti2ITG/Hge4SeH7Sne942OHeA/T7sOS
# JXAhhx9VyUiEUUax+dKIV7Gu67rjq5SVr5VNS4bduOpLsWEjeGHpMei//3xd8dxZ
# 42G/EDkr5+L7UFxIuBAq+r8diP/D8yR/du7vc4RGKw1ppxpo4JH9MnYfd+zUDuUg
# cQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG3PAc8o6zBullUL0bG+3X69FQBgMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAARI2GHSJO0zHnshct+Hgu4dsPU0b0yUsDXBhAdAGdH1T+uDeq3c3Hp7v5C4
# QowSEqp0t/eDlFHhH+hkvm8QlVZR8hIf+hJZ3OqtKGpyZPg7HNzYIGzRS2fKilUO
# bhbYK6ajeq7KRg+kGgZ16Ku8N13XncDCwmQgyCb/yzEkpsgF5Pza2etSeA2Y2jy7
# uXW4TSGwwCrVuK9Drd9Aiev5Wpgm9hPRb/Q9bukDeqHihw2OJfpnx32SPHwvu4E8
# j8ezGJ8KP/yYVG+lUFg7Ko/tjl2LlkCeNMNIcxk1QU8e36eEVdRweNc9FEcIyqom
# DgPrdfpvRXRHztD3eKnAYhcEzM4xA0i0k5F6Qe0eUuLduDouemOzRoKjn9GUcKM2
# RIOD7FXuph5rfsv84pM2OqYfek0BrcG8/+sNCIYRi+ABtUcQhDPtYxZJixZ5Q8Vk
# jfqYKOBRjpXnfwKRC0PAzwEOIBzL6q47x6nKSI/QffbKrAOHznYF5abV60X4+TD+
# 3xc7dD52IW7saCKqN16aPhV+lGyba1M30ecB7CutvRfBjxATa2nSFF03ZvRSJLEy
# YHiE3IopdVoMs4UJ2Iuex+kPSuM4fyNsQJk5tpZYuf14S8Ov5A1A+9Livjsv0Brw
# uvUevjtXAnkTaAISe9jAhEPOkmExGLQqKNg3jfJPpdIZHg32MIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAYUDSsI2YSTTNTXYNg0YxTcHWY9Gg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRkxgwIhgPMjAyMjA4MDEwNzQ3MzZaGA8yMDIyMDgwMjA3NDczNlow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pGTGAIBADAHAgEAAgIeizAHAgEAAgIR
# wzAKAgUA5pLkmAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAF1eQuLWB69l
# cRkwlDC//Q8t6MKhMl4o4Q+GcAYe9w/P1hDjWpsFI3X3Q+q6z8QtX/Q1c4IK5S6G
# JXMlxEbcKpiXknCiQ8r4UssZYTe3qUIeBsh0XohckQUJEbEzUMUAqe474r3Ibf4d
# gwN5gry9881JMrkws7I0ZHaZmL36EBVuMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgcXcVpWjTy1I5SWIuDO7pOapqR8UtF8eIIqyj8Cy1Z58wgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBbe9obEJV6OP4EDMVJ8zF8dD5vHGSoLDwu
# Qxj9BnimvzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABlwPPWZxriXg/AAEAAAGXMCIEIJ3XeUNIGOGvXHlvVJ8soX+gMgA0CH0mLbWJ
# R46ykrvfMA0GCSqGSIb3DQEBCwUABIICAF2hL63f8iFou0eZtR51tqmMLWVtjFfE
# AP8+MEDqfAMgbxGoVNKJ21Ef4uVOIjOzCZ9NNTTaLWS6ahSujNTbDPmkAp7w5WtL
# eW5hlVJpgCXs7w99jpfv3U9BEDr3NZrMPIwMTO89pxEg4nVOrq4B/Nj8iOSSWrBX
# zx0YEUQm+TkbQSmCCCzpMsFX1HLyrHAkpDAXf/pEDTP9fonEBdYgtq80wV2Bd0pp
# GlDNkH//RXoTIuJSWRV+m8EteM3xmeVBq5hN3EqpkmgF+tP+sbE3+LAqBdcGM6Q6
# 0VtTKBv9nxgUmBsWHh6ftv/ZWiLBNMkyr4YU7hhzWBiXBVLodZfyJ0st1webWT1/
# cANiuDGQVhAvu1Vdh6hwu7svuai+JQ/oEc/PvTtfAmIYO7wxxvIejqRpLBIiHprZ
# oV1/tncL9o5KP2oXvgWrTt2zHb39OxW2EN3E1me8LeBSTzshBctNwh9JiE8MMcck
# 7MeEP7ZeQbHT5HmjVW9AcN6StZ3FwKLBNRG7eiCy2SFGUbti16eSdT/ir+6PZgRo
# YRy/ilzul7RS/JVBLCSnt5b9SXNF+GuFeVi9loxglUtg8vfycsIhJ+LVoziv231S
# z3dAUoaMLkE04LqVhPLylBFsOHFo8P5E0rsPAQt8NZf3ifF2LKifg5R8ykPcQ4gL
# g8iAAfGipKiU
# SIG # End signature block
