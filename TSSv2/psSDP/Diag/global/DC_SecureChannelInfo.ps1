#************************************************
# Gather_Secure_Channel_Info.ps1
# Version 1.1
# Date: 3-30-2012
# Author: Tim Springston
# Description: This script queries the currently cached 
#              secure channel information for a domain member
#              or domain controller.
#			   -Added logic to detect OS ver and role and 
#			   reveal information about secure channels 
#			   selectively based on that.
#************************************************

Import-LocalizedData -BindingVariable MaxConcurrentApiLogStrings -FileName DC_SecureChannelInfo -UICulture en-us
Write-DiagProgress -Activity $MaxConcurrentApiLogStrings.ID_CTSMCASecureChannel -Status $MaxConcurrentApiLogStrings.ID_CTSMCAGetSecureChannelLog

#----- Gather Secure Channel Information

#For testing, dump OS version info into file.
#Get-CimInstance Win32_OperatingSystem >> $OutputFileName
$OSVersion = Get-CimInstance -Class Win32_OperatingSystem
#$ComputerName = Get-CimInstance -Class Win32_ComputerSystem
$OutputFileName = Join-Path $Pwd.Path ($ComputerName + "_Secure Channels.txt")

"Secure Channel Information" >> $OutputFileName 
"`n`r" >> $OutputFileName
"This script pulls the current secure channel for workstation computers and member servers, including the domain controller that the computer is looking to at that time." >>   $OutputFileName
"`n`r" >> $OutputFileName
"For domain controllers this script will gather the trust information for which DCs this DC has it's secure channel to at that time." >> $OutputFilename
"`n`r" >> $OutputFileName
"This script also gathers information about the local domain and forest." >> $OutputFileName
"`n`r" >> $OutputFileName
"`n`r" >> $OutputFileName

"This computer's Operating System and domain role (workstation, member server or domain controller)" >>   $OutputFileName
"******************************************************" >>   $OutputFileName
#Determine whether a workstation, server or DC and what OS
$OSVersion = Get-CimInstance -Class Win32_OperatingSystem -ComputerName localhost
$cs = Get-CimInstance -class win32_computersystem
$DomainRole = $cs.domainrole
"`n`r" >> $OutputFileName
switch -regex ($DomainRole) {
[0-1] { "This computer is a workstation." >>   $OutputFileName
					if ($OSVersion.BuildNumber -eq 3790)
	{ "Operating system is Windows XP." >>   $OutputFileName}
	else
		{ if ($OSVersion.BuildNumber -eq 6002)
			{ "Operating system is Windows Vista." >>   $OutputFileName}
				else 
					{if ($OSVersion.BuildNumber -eq 7600)
						{"Operating system is Windows 7." >>   $OutputFileName}
						else 
							{if ($OSVersion.BuildNumber -eq 7601)
								{"Operating system is Windows 7." >>   $OutputFileName}
								else
									{}

									}}}
		}
[2-3] { "This computer is a member server."  >>   $OutputFileName
			if ($OSVersion.BuildNumber -eq 3790)
	{ "Operating system is Windows Server 2003." >>   $OutputFileName}
	else
		{ if ($OSVersion.BuildNumber -eq 6002)
			{ "Operating system is Windows Server 2008 RTM." >>   $OutputFileName}
				else 
					{if ($OSVersion.BuildNumber -eq 7600)
						{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
						else 
							{if ($OSVersion.BuildNumber -eq 7601)
								{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
								else
									{}

									}}}
		}
[4-5] { "This computer is a domain controller." >>   $OutputFileName 
					if ($OSVersion.BuildNumber -eq 3790)
	{ "Operating system is Windows Server 2003." >>   $OutputFileName}
	else
		{ if ($OSVersion.BuildNumber -eq 6002)
			{ "Operating system is Windows Server 2008 RTM." >>   $OutputFileName}
				else 
					{if ($OSVersion.BuildNumber -eq 7600)
						{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
						else 
							{if ($OSVersion.BuildNumber -eq 7601)
								{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
								else
									{}

									}}}
		}
default { "Unknown value."}
}

#Determine whether a workstation, server or DC
$cs = Get-CimInstance -class win32_computersystem
$DomainRole = $cs.domainrole

#Get only local domain secure channel info
$v = "select * from win32_ntdomain where domainname = '" + $env:userdomain + "'"
$v2 = Get-CimInstance -query $v

"`n`r" >> $OutputFileName
switch -regex ($DomainRole) {
[0-1] {"This computer's Secure Channel information."  >> $OutputFileName
"******************************************************" >>   $OutputFileName
$v2 >> $OutputFileName
	}
[2-3] {"This computer's Secure Channel information."  >> $OutputFileName
"******************************************************" >>   $OutputFileName
$v2 >> $OutputFileName
		}
[4-5] { "This domain controller's Trust Secure Channel information for all trusted domains." >> $OutputFileName
"******************************************************" >>   $OutputFileName
#Dump all secure channel info, including trusts.
$DCTrusts = Get-CimInstance win32_ntdomain 
$DCTrusts >> $OutputFileName 
		}
default { "Unknown value." >> $Outputfilename}
}

"General Domain Information" >> $OutputFilename
"******************************************************" >>   $OutputFileName
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domain >> $OutputFileName

# Collect Files
$fileDescription = "Cached values for Secure Channel info from Netlogon."
$sectionDescription = "Secure Channel Info"

CollectFiles -filesToCollect $OutputFileName -fileDescription $fileDescription -sectionDescription $sectionDescription -renameOutput $false -noFileExtensionsOnDescription

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyrkS+7AQQm65m
# tZzd2gLRoepO9oaPVZ5qaQzJu7bPCKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPvR6rKp9L4P9MRRC4iEkbcU
# qP2gekbCTuSG8oi6td7uMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBn/zL6Atr1fXExYx+ZD2Sb3ROUZFodieBgZiwqnZjwWR4bKwKOBZrz
# V6Vq9Ec8Tq4Bf5WIKyYS+SAds12VJ3UJ8kZ08drXLkPUlUd7nwetghi2VsxH2JWC
# LLCeRf+NWVZ177ScEF83Dd4Ur+1PpaaS/YfQjJLXGaUqha17VO02L2FyvrPs82dM
# J1/G5FhPoq0dTL50+hWjdpaJSgSs+U7mYeGlnukRuQ+1A8KrpGyHbFqt+3QTJ2qW
# yp4DiykBZKBBS6FGFsyqgUJ7TO/jh4HwhBozUKVlI2kartQRfCaf5oClhUztprrW
# HGl3hrv6SQKRG8lEHKqSbDlXgvmCROcyoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEhvV4EZtgTGBghRFr5KGGvgdx4OFNgxbIL+a0JX9g3PAgZi0EWM
# ELMYEzIwMjIwODAxMDc1MDU0LjgwMVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQt
# RTNFNy0xNjg1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGe/cIt2DFatrEAAQAAAZ4wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTIwWhcNMjMwMjI4MTkwNTIwWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDZCRC1FM0U3LTE2ODUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDu6VylSHXD8Da8XkVNIqDgwWpTrhL5XXBaw2Zzerm2
# srxV+NpL/Zv7pVASO/TDGhAEMcwZTxyajt8I4vZ4DnnF9TD4tP6EE5Qx1LQQoZAj
# q55UH9qqpc1nwRJNBlQi+WdAV7IiGjQBe8J+WYV3yvDqlEYFC5VMe8OsB7yOMpFr
# AIZq3DhPpTLJM1LRdNEVAtGFlLT5BbBw3FG6EgfQt6DifBYtsZquhPAaER9PIALF
# QxA138+ihNRZJMJUMhXYaAS6oLRN6pYZDDoXy4qqcGGeINsRBRZ91TN6lQgad8Cn
# a+qH0tDQsQSJQfv74nJdgzkIpvz/DnvUFNZ9vqmh2OxNn82pX4nLuzAZCP4+zmFG
# YPAlo6ycnTc9Y8XNu8XVJYvno8uYYigRdRm2AYIfw04DYFhURE9hkckKIhxjqERN
# RxA0ZeHTUHA5t6ZS3xTOJOWgeB5W3PRhuAQyhITjGaUQUAgSyXzDzrOakNTVbjj7
# +X8OGsFtR8OYPzBe7l31SLvudNOq8Sxh2VA+WoGmdzhf+W7JmIEGAto//9u8HUtn
# oNzJK/dwS2MYucnimlOrxKVrnq9jv1hpgmHPobWHnnLhAgXnH4SjabyPkF1CZd8I
# 2DLC56I4weWpcrtp+TdhpvwBFvWi6onTs1uSFg4UBAotOVJjdXNK+01JVZF7nxs1
# cQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFGjTPoPRdY6XPtQkSTroh9lkZbutMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAFS5VY6hmc8GH2D18v+STQA+A+gT1duE3yuNn1mH41TLquzVNLW03AzAvuuc
# Yea1VaitRE5UYbIzxUsV9G8sTrXbdiczeVG66IpLullh4Ixqfn+xzGbPOZWUT6wA
# tgXq3FfMGY9k73qo/IQ5shoToeMhBmHLWeg53+tBcu8SzocSHJTieWcv5KmnAtoJ
# ra5SmDdZdFBCz0cP3IUq4kedN0Q2KhKrMDRAeD/CCza2DX8Bj9tRePycTnvfsScC
# c5VsxDNCannq8tVJ+HQazRVK8ANW2UMDgV63i7SKGb3+slKI/Y92ouMrTFhai6h4
# rCojzSsQtJQTCcnI0QTDoextzmaLsmtKu3jF2Ayh8gFed+KRDiDhtNcyZoJm+fmq
# aKhTIi9guPoed7wvn5zde93Zr6RXBTtXL0dlR0FMw/wPQVJjLVEaEnYWnKZH9lU8
# XZJV+xOmWFBFZkd+RnVOW3ZW5eBGsLeuzDCAamruyotw4PD36T6eYGJv5YvrX1iR
# YADrxXCUYidrZJY2s0IVZFicqGgp5FtYYnAMpE7tyuIj2o4y+ol1by3lQV6Ob0P4
# RnK6gnuECWBfmWSjevOfr+02mkseW8oREHAm9y9XfcdUcQ57vbbau8+AQia8wGQc
# NXpxAnoLDwJ+RAycDlpe3e2Yha9nXuYzcVMk92r/bKI0fyGOMIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpENkJELUUzRTctMTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAhXCOZBbDxA/B5Tei6Rf80L9Gheg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaR1dkwIhgPMjAyMjA4MDExMjMyMjVaGA8yMDIyMDgwMjEyMzIyNVow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pHV2QIBADAKAgEAAgIbgwIB/zAHAgEA
# AgIScTAKAgUA5pMnWQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBACz2BKsO
# kY4eCgnR1CVNrjW3rxtpze4TquB5aTlw/xd+kQubVbGYYWd73ikeFEY7po7vl+m1
# ZIHc6Hevasv27dLx4NI0N4toLKiWpapJ2B8cMU8Rw0zU+M58KW5FhUpu7uHcAqK2
# v3ENB4CBO5Dy4N4ZfjMb9mtj8aTV/D4n7hjNMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGe/cIt2DFatrEAAQAAAZ4wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQg3CwBScWUZG4i8wr1HAwL2ku/i1txdeqSqeRtWaNfxJYwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOxVYyIv5cj0+pZkJurJ+yCrq0Re5X
# grkfStUO/W88GTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnv3CLdgxWraxAAEAAAGeMCIEII9PegTZ8d2KX9FUMghLDItXW1f/2zle
# bOFKG4uRd0wIMA0GCSqGSIb3DQEBCwUABIICAOxLQdzXcFUi3cach8Q3gnIOLJ23
# iPQE1Hm1TYkfPYdPmXO5k3rLP9e8uGuBlV4GpkGm002zcpJMWJrzuOyJFPNl6sPQ
# lpW9C+f55tnj2re1TvbMpLcwPMY4L3lT2U2y/U+iXeEHraplKPbEkMTCo78HGD3E
# G7eko9z39gwY/svx02CI2oVmRaHmWMMZZRTUZWVBruGGVQkcRB363RDeOPRuj+xX
# 0QM96zdIWNs9QqJbsIGpnVvmg0e/gcMFVOnerrAe6SJ0MafbVh4NZY/T3jZ6CXN8
# 9pUb8q4yriIztKqO3+/mNwm4dYjeG/GNW3yxVceaL4tkmzFdFAwIIziIAuLrcr/y
# 8grof8nI+cCv4c5VJ+Q4YRN5sPpWBOhI/5FjVWBRcJm61kZiVlXzMawcPCfCp2k1
# SkWW8R8JVISKXeAFKmeZZiLIs4HyN1bEM4tVT9Fk3facCQq2F6vx/ZUdnLzZkGiA
# JaeIeJZHRmsyUV2VQzasH4JZUMabb5mw94Hr1OQW/SJ9sd1H/MZJ4+UK6148KLA+
# BG+X9lEZRKZ1eE9fx+U283o5/aW1gx37OKsIwYKH3DjCr2NsjVIkZCAAPVkG9Snl
# 5nPS3BeGFUCtsOBOyp26YEzrpTqWnWnX0d9IV/2t5vSDFTH93eOrvO5hkJyZhx2G
# QVsuz99yc8ix5KUS
# SIG # End signature block
