# 2019-03-20 WalterE added Trap #_#

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Common ---"
	# version of the psSDP Diagnostic
	Run-DiagExpression .\DC_NetworkingDiagnostic.ps1
	
	# Basic System Information [AutoAdded]
	Run-DiagExpression .\DC_BasicSystemInformation.ps1

	# MSInfo [AutoAdded]
	Run-DiagExpression .\DC_MSInfo.ps1
	
	# Obtain pstat output
	Run-DiagExpression .\DC_PStat.ps1
	
	# CheckSym - in Main
	#_#Run-DiagExpression .\DC_ChkSym.ps1

	# AutoRuns Information
	Run-DiagExpression .\DC_Autoruns.ps1

	# WhoAmI
	-DiagExpression .\DC_Whoami.ps1

	# Collects System and Application Event Logs 
	Run-DiagExpression .\DC_SystemAppEventLogs.ps1
	
	# Collects BCD information via BCDInfo tool or boot.ini
	Run-DiagExpression .\DC_BCDInfo.ps1

	# PoolMon
	Run-DiagExpression .\DC_PoolMon.ps1
	
	# Collect summary report 
	Run-DiagExpression .\DC_SummaryReliability.ps1		

	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Storage ---"
	# By adding San.exe to the SDP manifest we should be able to solve cases that have a 512e or Advanced Format (4K) disk in it faster.
	Run-DiagExpression .\DC_SanStorageInfo.ps1

	# Collects Fiber Channel information using fcinfo utility
	Run-DiagExpression .\DC_FCInfo.ps1

	# Obtain information about MS-DOS device names (symbolic links) via DOSDev utility
	Run-DiagExpression .\DC_DOSDev.ps1

	# Collects Information about iSCSI though the iscsicli utility
	Run-DiagExpression .\DC_ISCSIInfo.ps1

	# Parse Storage related event logs on System log using evParse.exe and dump to a HTML file
	Run-DiagExpression .\DC_EvParser.ps1

	# Collects VSS information via VSSAdmin tool
	Run-DiagExpression .\DC_VSSAdmin.ps1

	# Collect Machine Registry Information for Storage Related Diagnostics
	Run-DiagExpression .\DC_RegistryStorage.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: VSS ---"

	# Collect diagnostic information for VSS and Backup [AutoAdded]
	Run-DiagExpression .\DC_VSSPSS.ps1

	# Collect Event Logs for VSS and Backup [AutoAdded]
	Run-DiagExpression .\DC_VSSBackupEvtLogs.ps1

	# Collect registry information for VSS and Backup [AutoAdded]
	Run-DiagExpression .\DC_VSSBackupRegistry.ps1

	# Collect Files for VSS and Backup [AutoAdded]
	Run-DiagExpression .\DC_VSSBackupFiles.ps1

	# Collect Files for Windows Azure Backup [AutoAdded]
	Run-DiagExpression .\DC_CloudBackup.ps1

	# Detect 4KB Drives (Disk Sector Size) [AutoAdded]
	Run-DiagExpression .\TS_DriveSectorSizeInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "*** $(Get-Date -UFormat "%R:%S") DONE TS_AutoAddCommands_VSS.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"



# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCZN6G08JDTMCRJ
# QePUgLzMqIF1QGDAcPUmqCVmW428gaCCDYUwggYDMIID66ADAgECAhMzAAACU+OD
# 3pbexW7MAAAAAAJTMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMzAwWhcNMjIwOTAxMTgzMzAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDLhxHwq3OhH+4J+SX4qS/VQG8HybccH7tnG+BUqrXubfGuDFYPZ29uCuHfQlO1
# lygLgMpJ4Geh6/6poQ5VkDKfVssn6aA1PCzIh8iOPMQ9Mju3sLF9Sn+Pzuaie4BN
# rp0MuZLDEXgVYx2WNjmzqcxC7dY9SC3znOh5qUy2vnmWygC7b9kj0d3JrGtjc5q5
# 0WfV3WLXAQHkeRROsJFBZfXFGoSvRljFFUAjU/zdhP92P+1JiRRRikVy/sqIhMDY
# +7tVdzlE2fwnKOv9LShgKeyEevgMl0B1Fq7E2YeBZKF6KlhmYi9CE1350cnTUoU4
# YpQSnZo0YAnaenREDLfFGKTdAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUlZpLWIccXoxessA/DRbe26glhEMw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ2NzU5ODAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AKVY+yKcJVVxf9W2vNkL5ufjOpqcvVOOOdVyjy1dmsO4O8khWhqrecdVZp09adOZ
# 8kcMtQ0U+oKx484Jg11cc4Ck0FyOBnp+YIFbOxYCqzaqMcaRAgy48n1tbz/EFYiF
# zJmMiGnlgWFCStONPvQOBD2y/Ej3qBRnGy9EZS1EDlRN/8l5Rs3HX2lZhd9WuukR
# bUk83U99TPJyo12cU0Mb3n1HJv/JZpwSyqb3O0o4HExVJSkwN1m42fSVIVtXVVSa
# YZiVpv32GoD/dyAS/gyplfR6FI3RnCOomzlycSqoz0zBCPFiCMhVhQ6qn+J0GhgR
# BJvGKizw+5lTfnBFoqKZJDROz+uGDl9tw6JvnVqAZKGrWv/CsYaegaPePFrAVSxA
# yUwOFTkAqtNC8uAee+rv2V5xLw8FfpKJ5yKiMKnCKrIaFQDr5AZ7f2ejGGDf+8Tz
# OiK1AgBvOW3iTEEa/at8Z4+s1CmnEAkAi0cLjB72CJedU1LAswdOCWM2MDIZVo9j
# 0T74OkJLTjPd3WNEyw0rBXTyhlbYQsYt7ElT2l2TTlF5EmpVixGtj4ChNjWoKr9y
# TAqtadd2Ym5FNB792GzwNwa631BPCgBJmcRpFKXt0VEQq7UXVNYBiBRd+x4yvjqq
# 5aF7XC5nXCgjbCk7IXwmOphNuNDNiRq83Ejjnc7mxrJGMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGX8wghl7AgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAJT44Pelt7FbswAAAAA
# AlMwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJSu
# tGjLxI9DC/W5gyxoaNb/Kojutau0Lum4EcqNR3ljMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAohnkViPbW93SqfEOuFwi1wnGupweC0reTH2Q
# vt/hUZivDxgpBPkMnsjWBAe5Nhk5jSshQfuipa2dvQ9nvDbN5//yRHld4jemz8NQ
# TZTdA7O/KuiWhSF/sYxCEvxNQoI6vONYgPSOaCDaRn/W36RZJ93ogEoOkyG2CbfT
# 2g72L3FxMo8jJa0lgeSbvKF7uDEwCVQqyreWK0r1BBH/9EMO2i7UhwDnBRQ092rQ
# sBUnd0LlYZ+K3bo2mRFNwiukGKkea81g/YlS788VTvJdthhdj39e5jendMNoDU3p
# fV3d+AET0tcpUqcvpokDrP0kroXRYoqXbwdgu0guToYVuQoReKGCFwkwghcFBgor
# BgEEAYI3AwMBMYIW9TCCFvEGCSqGSIb3DQEHAqCCFuIwghbeAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFVBgsqhkiG9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDC/o2Xbm+2DqZYlLUhARq0pLAQpoHwilQU
# d3ew94ZdmAIGYi+0CPCdGBMyMDIyMDQxOTA4MzYzNC40NThaMASAAgH0oIHUpIHR
# MIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQL
# EyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RjdBNi1FMjUxLTE1MEExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghFcMIIHEDCCBPigAwIBAgITMwAAAaUA3gjEQAdx
# TgABAAABpTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMjAzMDIxODUxMTlaFw0yMzA1MTExODUxMTlaMIHOMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQg
# T3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# RjdBNi1FMjUxLTE1MEExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC6sYboIGpIvMLq
# DjDHe67BEJ5gIbVfIlNWNIrbB6t9E3QlyQ5r2Y2mfMrzh2BVYU8g9W+SRibcGY1s
# 9X4JQqrMeagcT9VsdQmZ7ENbYkbEVkHNdlZBE5pGPMeOjIB7BsgJoTz6bIEZ5JRm
# oux6kBQd9cf0I5Me62wJa+j25QeLTpmkdZysZeFSILLQ8H53imqBBMOIjf8U3c7W
# Y8MhomOYTaem3nrZHIs4CRTt/8kR2IdILZPm0RIa5iIG2q664G8+zLJwO7ZSrxnD
# vYh3OvtrMpqwFctws0OCDDTxXE08fME2fpKb+pRbNXhvMZX7LtjQ1irIazJSh9ia
# WM1gFtXwjg+Yq17BOCzr4sWUL253kBOvohnyEMGm4/n0XaLgFNgIhPomjbCA2qXS
# mm/Fi8c+lT0WxC/jOjBZHLKIrihx6LIQqeyYZmfYjNMqxMdl3mzoWv10N+NirERr
# NodNoKV+sAcsk/Hg9zCVSMUkZuDCyIpb1nKXfTd66KGsGy1OoHZO4KClkuvfsNo7
# aLlwhGLeiD32avJXYtC/wsGG7b+5mx5iGfTnNCRCXOm/YHFQ36D4npjCnM9eQS3q
# cse56UNjIgyiLHDqioV7mSPj2XqzTh4Yv77MtvxY/ZQepCazGEn1dBdn67wUgVzA
# e8Y7/KYKl+UF1HvJ08W+FHydHAwLwQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFF+m
# jwMAl66urXDu+9xZF0toqRrfMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1
# GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEp
# LmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUy
# MFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwDQYJKoZIhvcNAQELBQADggIBAJabCxflMDCihEdqdFiZ6OBuhhhp34N6
# ow3Wh3Obr12LRuiph66gH/2Kh5JjaLUq+mRBJ5RgiWEe1t7ifuW6b49N8Bahnn70
# LCiEdvquk686M7z+DbKHVk0+UlafwukxAxriwvZjkCgOLci+NB01u7cW9HAHX4J8
# hxaCPwbGaPxWl3s0PITuMVI4Q6cjTXielmL1+TQvh7/Z5k8s46shIPy9nFwDpsRF
# r3zwENZX8b67VMBu+YxnlGnsJIcLc2pwpz95emI8CRSgep+/017a34pNcWNZIHr9
# ScEOWlHT8cEnQ5hhOF0zdrOqTzovCDtffTn+gBL4eNXg8Uc/tdVVHKbhp+7SVHkk
# 1Eh7L80PBAjo+cO+zL+efxfIVrtO3oJxvEq1o+fkxcTTwqcfwBTb88/qHU0U2XeC
# 1rqJnDB1JixYlBjgHXrRekqHxxuRHBZ9A0w9WqQWcwj/MbBkHGYMFaqO6L9t/7iC
# ZTAiwMk2GVfSEwj9PXIlCWygVQkDaxhJ0P1yxTvZsrMsg0a7x4VObhj3V8+Cbdv2
# TeyUGEblTUrgqTcKCtCa9bOnIg7xxHi8onM8aCHvRh90sn2x8er/6YSPohNw1qNU
# wiu+RC+qbepOYt+v5J9rklV3Ux+OGVZId/4oVd7xMLO/Lhpb7IjHKygYKaNx3XIw
# x4h6FrFH+BiMMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+
# F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU
# 88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqY
# O7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzp
# cGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0Xn
# Rm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1
# zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZN
# N3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLR
# vWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTY
# uVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUX
# k8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB
# 2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKR
# PEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0g
# BFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQM
# MAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQ
# W9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
# bS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBa
# BggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOX
# PTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6c
# qYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/z
# jj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz
# /AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyR
# gNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdU
# bZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo
# 3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4K
# u+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10Cga
# iQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9
# vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGC
# As8wggI4AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8g
# UmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RjdBNi1FMjUxLTE1MEExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVALPJcNtFs5sQyojdS4Ye5mVl7rSooIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmCFX+MCIYDzIwMjIwNDE5
# MDEyNjIyWhgPMjAyMjA0MjAwMTI2MjJaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOYIVf4CAQAwBwIBAAICCSUwBwIBAAICElUwCgIFAOYJp34CAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCE4kWtBkWtQfpRF2K1+b778two8dKDOMEegAYhGXc5
# XoUmD46NlyLpr6XBvH+vAuAMJNvp2xVETujpTrNmpq/Sigf7DwrImBAiW+Ha1Oxq
# CqyBDA96GgYgt3sFwl/CfCDklDQBlARDAa5i4D2qtsRK0afXtWc9NhIsG2o7lbhg
# CjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABpQDeCMRAB3FOAAEAAAGlMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIIFFXneEtv01xFdj/tlz
# JsLc5syM73p38TfkiLkIpoEaMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# uAo4cX5mBLGgrdgFPNyoYfuiR5cpNwe9L3zBzJQS3FwwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaUA3gjEQAdxTgABAAABpTAiBCDI
# hBNIw17gCIAmgMuVHQNzJIr/qPTai6mYJszzZ+ZzPDANBgkqhkiG9w0BAQsFAASC
# AgCSkeNreUzNBiosqdgQnKB8j9eGNyWrmyRSXz1p11cOaxL8dtHeKrBbJek29aJc
# ogawypAJYA7PGW8gAMUwNAdrnSc/kTj3s8H89ziruEyDIDBJ7p6Rfa2VqhbQ/ORQ
# dZooZ1RRHE01lsT2IzK4lBnGVU7PS9S+RTNnVY9Flp8QvBi7MVKGR5FL+8hjCJJv
# cdk/Dl9/ebe6l8Oq90RqxcqzLJjlfmmnPpnf8+VajoJ0a8zDnQ2aYz4w0O8EHvXd
# Dgy8Pc47r9zokDdzw9v1zTiqrkQcal+7svXDFXg2DbBazj5OmdBK1xZskD49/zs4
# ssh6V4rGu819NvXSdpOj+yc30eZFbteFDow1lK/Zn5ZWJy/5VrJqHs8YLfSofZ9N
# 5Y7bkUqCfKiSrcLD0hh0wryNRxk4je/dzeX7YZ2U2/At9C7XKy8Taks5Lf3XQ+P6
# CRG6EseApAeTzsmFhoK5vEA0fsur/JvN1igY+ijNhhA9JehzDaa5M6psc7jJ7NOs
# IpgPBNzN8KdewXjn6SV6aeEoi6UWJrZDjGGwOcUNhiuRXJk92gpWstVK0Kihkk0O
# tNd7wAdolmZc5G7hcde1MN0yU5T8pCPw8wVm1zKDDQ6cY4kJZ5zGi/ZeDCWEcuo4
# rsMnB0fvHXfAUXe3UwS6zY3shmGqPk6gxLlnAQLlO/bvQw==
# SIG # End signature block
