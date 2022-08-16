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

	# MSInfo
	Run-DiagExpression .\DC_MSInfo.ps1

	# Obtain pstat output
	Run-DiagExpression .\DC_PStat.ps1

	# CheckSym
	Run-DiagExpression .\DC_ChkSym.ps1

	# AutoRuns Information
	Run-DiagExpression .\DC_Autoruns.ps1

	# Collects Windows Server 2008/R2 Server Manager Information
	Run-DiagExpression .\DC_ServerManagerInfo.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_ScheduleTasks.ps1

	# Collects System and Application Event Logs 
	Run-DiagExpression .\DC_SystemAppEventLogs.ps1

	# Collect Machine Registry Information for Setup and Performance Diagnostics
	Run-DiagExpression .\DC_RegistrySetupPerf.ps1

	# GPResults.exe Output
	Run-DiagExpression .\DC_RSoP.ps1

	# Basic System Information
	Run-DiagExpression .\DC_BasicSystemInformation.ps1

	# Collects information about Driver Verifier (verifier.exe utility)
	Run-DiagExpression .\DC_Verifier.ps1

	# User Rights (privileges) via the userrights.exe tool
	Run-DiagExpression .\DC_UserRights.ps1

	# WhoAmI
	Run-DiagExpression .\DC_Whoami.ps1

	# PoolMon
	Run-DiagExpression .\DC_PoolMon.ps1
	
	#_# Collect summary report 
	Run-DiagExpression .\DC_SummaryReliability.ps1

	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1

	# TaskListSvc
	Run-DiagExpression .\DC_TaskListSvc.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Net ---"
	# DHCP Client Component
	Run-DiagExpression .\DC_DhcpClient-Component.ps1

	# DNS Client Component
	Run-DiagExpression .\DC_DNSClient-Component.ps1

	# Firewall
	Run-DiagExpression .\DC_Firewall-Component.ps1

	# IPsec
	Run-DiagExpression .\DC_IPsec-Component.ps1

	# NetLBFO
	Run-DiagExpression .\DC_NetLBFO-Component.ps1

	# RPC
	Run-DiagExpression .\DC_RPC-Component.ps1

	# SMB Client Component
	Run-DiagExpression .\DC_SMBClient-Component.ps1

	# SMB Server Component
	Run-DiagExpression .\DC_SMBServer-Component.ps1

	# TCPIP Component
	Run-DiagExpression .\DC_TCPIP-Component.ps1

	# WINSClient
	Run-DiagExpression .\DC_WINSClient-Component.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: HyperV  ---"
	# Hyper-V Networking Settings
	Run-DiagExpression .\DC_HyperVNetworking.ps1

	# Hyper-V Network Virtualization
	Run-DiagExpression .\DC_HyperVNetworkVirtualization.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: DOM ---"
	# Applied Security Templates
	Run-DiagExpression .\DC_AppliedSecTempl.ps1

	# Collects functional level and local group membership information (DSMisc)
	Run-DiagExpression .\DC_DSMisc.ps1

	# Obtain Netlogon Log
	Run-DiagExpression .\DC_NetlogonLog.ps1

	# Collects NetSetup.Log from %windir%\debug
	Run-DiagExpression .\DC_NetSetupLog.ps1

	# Collects winlogon Log from %windir%\security\logs\winlogon.log 
	Run-DiagExpression .\DC_WinlogonLog.ps1

	# Run Repadmin tool with showrepl argument and obtain output
	Run-DiagExpression .\DC_Repadmin.ps1

	# Collects system security settings (INF) via secedit utility
	Run-DiagExpression .\DC_SystemSecuritySettingsINF.ps1

	# Collects registry entries for Directory Services support
	Run-DiagExpression .\DC_DSRegEntries.ps1

	# auditpol output
	Run-DiagExpression .\DC_AuditPol.ps1

	# Kerberos tickets and TGT via klist utility
	Run-DiagExpression .\DC_KList.ps1

	# DCPromo Logs
	Run-DiagExpression .\DC_DCPromoLogs.ps1

	# Determines FSMO role owners
	Run-DiagExpression .\DC_NetdomFSMO.ps1

	# Copies Userenv Log files
	Run-DiagExpression .\DC_UserenvLogs.ps1

	# Collects environment variables (output of SET command)
	Run-DiagExpression .\DC_EnvVars.ps1

	# Collecting Secure Channel Info
	Run-DiagExpression .\DC_SecureChannelInfo.ps1

	# Directory Services related Event Logs
	Run-DiagExpression .\DC_ADEventLogs.ps1

	#_# Dfsr Informaton - in Main
	#_# Run-DiagExpression .\DC_DfsrInfo.ps1

	# BPA DS
	if ($Global:skipBPA -ne $true) {
	Run-DiagExpression .\DC_BPA-DS.ps1
	}

	# Active Directory environment data collection scripts.
	Run-DiagExpression .\DC_CurrentDomainInfo.ps1
	Run-DiagExpression .\DC_DCSiteInfo.ps1
	Run-DiagExpression .\DC_ForestInfo.ps1
	Run-DiagExpression .\DC_TrustList.ps1
	Run-DiagExpression .\DC_UserLogonInfo.ps1

	# Collects W32Time information
	Run-DiagExpression .\DC_W32Time.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Setup ---"
	# Fltmc
	Run-DiagExpression .\DC_Fltmc.ps1
	# Obtain information about Upper and lower filters Information fltrfind.exe utility
	Run-DiagExpression .\DC_Fltrfind.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Update ---"
	# Update History
	Run-DiagExpression .\DC_UpdateHistory.ps1

	# Collect WindowsUpdate.Log
	Run-DiagExpression .\DC_WindowsUpdateLog.ps1

	# NetworkAdapters
	Run-DiagExpression .\DC_NetworkAdapters-Component.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase: Done ---"	
Write-Host "...Next step: Troubleshooting section, if it hangs, run script with parameter SkipTS"

if ($Global:skipTS -ne $true) {
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_common ---"

	Run-DiagExpression .\TS_DumpCollector.ps1 -CopyWERMinidumps -CopyMachineMiniDumps

	# Detects and alerts evaluation media
	Run-DiagExpression .\TS_EvalMediaDetection.ps1

	# Debug/GFlags check
	Run-DiagExpression .\TS_DebugFlagsCheck.ps1

	# RC_32GBMemoryKB2634907
	Run-DiagExpression .\RC_32GBMemoryKB2634907.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Net ---"
	# Check for ephemeral port usage
	Run-DiagExpression .\TS_PortUsage.ps1
	
	# RC_KB2647170_CnameCheck
	Run-DiagExpression .\RC_KB2647170_CnameCheck.ps1

	# FirewallCheck
	Run-DiagExpression .\RC_FirewallCheck.ps1

	# IPv66To4Check
	Run-DiagExpression .\RC_IPv66To4Check.ps1

	# RC_HTTPRedirectionTSGateway
	Run-DiagExpression .\RC_HTTPRedirectionTSGateway.ps1

	# SMB2ClientDriverStateCheck
	Run-DiagExpression .\TS_SMB2ClientDriverStateCheck.ps1

	# SMB2ServerDriverStateCheck
	Run-DiagExpression .\TS_SMB2ServerDriverStateCheck.ps1

	# Opportunistic Locking has been disabled and may impact performance.
	Run-DiagExpression .\TS_LockingKB296264Check.ps1

	# Evaluates whether InfocacheLevel should be increased to 0x10 hex. To resolve slow logon, slow boot issues.
	Run-DiagExpression .\TS_InfoCacheLevelCheck.ps1

	# RSASHA512 Certificate TLS 1.2 Compat Check
	Run-DiagExpression .\TS_DetectSHA512-TLS.ps1

	# IPv6Check
	Run-DiagExpression .\TS_IPv6Check.ps1

	# PMTU Check
	Run-DiagExpression .\TS_PMTUCheck.ps1

	# Checks for modified TcpIP Reg Parameters and recommend KB
	Run-DiagExpression .\TS_TCPIPSettingsCheck.ps1

	# 'Checks if the number of 6to4 adapters is larger than the number of physical adapters
	Run-DiagExpression .\TS_AdapterKB980486Check.ps1

	# Checks if Windows Server 2008 R2 SP1, Hyper-V, and Tunnel.sys driver are installed if they are generate alert
	Run-DiagExpression .\TS_ServerCoreKB978309Check.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_HyperV ---"
	# Detect Virtualization
	Run-DiagExpression .\TS_Virtualization.ps1

	# Missing Hotfix 
	Run-DiagExpression .\TS_HyperVEvent106Check.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_DOM ---"
	# DCDiag information
	Run-DiagExpression .\TS_DCDiag.ps1
	
	# Check AD Replication Status
	Run-DiagExpression .\TS_ADReplCheck.ps1

	# Checks if CrashOnAuditFail is either 1 or 2
	Run-DiagExpression .\TS_CrashOnAuditFailCheck.ps1

	# SYSVOL and/or NETLOGON shares are missing on domain controller
	Run-DiagExpression .\TS_LSASSHighCPU.ps1

	# SYSVOL and/or NETLOGON shares are missing on domain controller
	Run-DiagExpression .\TS_SysvolNetLogonShareCheck.ps1

	# Missing Rid Set reference attribute detected
	Run-DiagExpression .\TS_ADRidSetReferenceCheck.ps1

	# AD Integrated DNS Server should not point only to itself if it has replica partners.
	Run-DiagExpression .\TS_DCCheckDnsExclusiveToSelf.ps1

	# [Idea ID 3768] [Windows] New rule to verify USN Roll Back
	Run-DiagExpression .\TS_USNRollBackCheck.ps1

	# [Idea ID 2882] [Windows] The stop of Intersite Messaging service on ISTG causes DFSN cannot calculate site costs
	Run-DiagExpression .\TS_IntersiteMessagingStateCheck.ps1

	# [Idea ID 2831] [Windows] DFSR Reg setting UpdateWorkerThreadCount = 64 may cause hang
	Run-DiagExpression .\TS_DfsrUpdateWorkerThreadCountCheck.ps1

	# [Idea ID 2593] [Windows] UDP 389 on DC does not respond
	Run-DiagExpression .\TS_IPv6DisabledonDCCheck.ps1

	# [Idea ID 4724] [Windows] W32Time and time skew
	Run-DiagExpression .\TS_Win32TimeTimeSkewRegCheck.ps1

	# [Idea ID 4796] [Windows] MaxConcurrentApi Problem Detection Lite
	Run-DiagExpression .\TS_MCALite.ps1

	# [Idea ID 5009] [Windows] Weak Key Block Detection
	Run-DiagExpression .\TS_DetectWeakKeys.ps1

	# [Idea ID 6816] [Windows] Detect Certificate Root Store Size Problems
	Run-DiagExpression .\TS_DetectRootSize.ps1

	# Check DFSR configuration
	Run-DiagExpression .\TS_DFSRRootCausesCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Storage ---"
	# Detect 4KB Drives (Disk Sector Size)
	Run-DiagExpression .\TS_DriveSectorSizeInfo.ps1

	# [Idea ID 7345] [Windows] Perfmon - Split IO Counter
	Run-DiagExpression .\TS_DetectSplitIO.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Setup ---"
	# Checks 32 bit windows server 2003 / 2008 to see is DEP is disabled, if so it might not detect more than 4 GB of RAM.
	Run-DiagExpression .\TS_DEPDisabled4GBCheck.ps1

	# [Idea ID 2695] [Windows] Check the Log On account for the Telnet service to verify it's not using the Local System account
	Run-DiagExpression .\TS_TelnetSystemAccount.ps1

	# [Idea ID 2389] [Windows] Hang caused by kernel memory depletion due 'SystemPages' reg key with wrong value
	Run-DiagExpression .\TS_MemoryManagerSystemPagesCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_3rd party ---"
	# [Idea ID 7521] [Windows] McAfee HIPS 7.0 adds numerous extraneous network adapter interfaces to registry
	Run-DiagExpression .\TS_McAfeeHIPS70Check.ps1

	# Check for Sophos BEFLT.SYS version 5.60.1.7
	Run-DiagExpression .\TS_B2693877_Sophos_BEFLTCheck.ps1

	# [KSE Rule] [ Windows V3] HpCISSs2 version 62.26.0.64 causes 0xD1 or 0x9E
	Run-DiagExpression .\TS_HpCISSs2DriverIssueCheck.ps1

	# Symantec Intrusion Prevenstion System Check
	Run-DiagExpression .\TS_SymantecIPSCheck.ps1

	# [Idea ID 2842] [Windows] Alert Engineers if they are working on a Dell machine models R910, R810 and M910
	Run-DiagExpression .\TS_DellPowerEdgeBiosCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- Diag Phase:TS_obsolete W2K3/XP ---"
	# [Idea ID 7065] [Windows] Alert users about Windows XP EOS
	#_# Run-DiagExpression .\TS_WindowsXPEOSCheck.ps1

}

	# Hotfix Rollups
	Run-DiagExpression .\DC_HotfixRollups.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "*** $(Get-Date -UFormat "%R:%S") DONE TS_AutoAddCommands_DOM.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"



# SIG # Begin signature block
# MIInowYJKoZIhvcNAQcCoIInlDCCJ5ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCxP//nJlYrmo51
# /MYWqBfhoLbZjbJuApyHWHkB/0gAwqCCDXYwggX0MIID3KADAgECAhMzAAACURR2
# zMWFg24LAAAAAAJRMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDBIpXR3b1IYAMunV9ZYBVYsaA7S64mqacKy/OJUf0Lr/LW/tWlJDzJH9nFAhs0
# zzSdQQcLhShOSTUxtlwZD9dnfIcx4pZgu0VHkqQw2dVc8Ob21GBo5sVrXgEAQxZo
# rlEuAl20KpSIFLUBwoZFGFSQNSMcqPudXOw+Mhvn6rXYv/pjXIjgBntn6p1f+0+C
# 2NXuFrIwjJIJd0erGefwMg//VqUTcRaj6SiCXSY6kjO1J9P8oaRQBHIOFEfLlXQ3
# a1ATlM7evCUvg3iBprpL+j1JMAUVv+87NRApprPyV75U/FKLlO2ioDbb69e3S725
# XQLW+/nJM4ihVQ0BHadh74/lAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUMLgM7NX5EnpPfK5uU6FPvn2g/Ekw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ2NzU5NjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIVJlff+Fp0ylEJhmvap
# NVv1bYLSWf58OqRRIDnXbHQ+FobsOwL83/ncPC3xl8ySR5uK/af4ZDy7DcDw0yEd
# mKbRLzHIfcztZVSrlsg0GKwZuaB2MEI1VizNCoZlN+HlFZa4DNm3J0LhTWrZjVR0
# M6V57cFW0GsV4NlqmtelT9JFEae7PomwgAV9xOScz8HzvbZeERcoSRp9eRsQwOw7
# 8XeCLeglqjUnz9gFM7RliCYP58Fgphtkht9LNEcErLOVW17m6/Dj75zg/IS+//6G
# FEK2oXnw5EIIWZraFHqSaee+NMgOw/R6bwB8qLv5ClOJEpGKA3XPJvS9YgOpF920
# Vu4Afqa5Rv5UJKrsxA7HOiuH4TwpkP3XQ801YLMp4LavXnvqNkX5lhFcITvb01GQ
# lcC5h+XfCv0L4hUum/QrFLavQXJ/vtirCnte5Bediqmjx3lswaTRbr/j+KX833A1
# l9NIJmdGFcVLXp1en3IWG/fjLIuP7BqPPaN7A1tzhWxL+xx9yw5vQiT1Yn14YGmw
# OzBYYLX0H9dKRLWMxMXGvo0PWEuXzYyrdDQExPf66Fq/EiRpZv2EYl2gbl9fxc3s
# qoIkyNlL1BCrvmzunkwt4cwvqWremUtqTJ2B53MbBHlf4RfvKz9NVuh5KHdr82AS
# MMjU4C8KNTqzgisqQdCy8unTMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYMwghl/AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAJRFHbMxYWDbgsAAAAAAlEwDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIE6RbXVToWg8Bt1EMqANeOJB
# /WY5RzoIxd8DiuYMKQJ/MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAl12ewVREvVK7K+XDbYH8k8883Imq98wo8/bz0WV4gXhwi/v97grhT
# RXO4kdmT/03p2crXnfZpFiVBGKmmVm2kdph/Duau2x5/TzccYsJQqpvva03no0xn
# j7RQXRj5c50pncXtmcKZrvGmhpKb3Qo7hcEPA/iOKb+c4x+fi5su4S0DUKFrWQIo
# fyJHGCfd3tNgxhYocP4rifTnca5ggzUjQEw/wLXnS7KCPsDXIw94WENorko7ToxE
# /MhN72DrFoMZ63kjP/2xriTcUNuVk2eVKM+jTrHX8Lx4IGh7ydMZ/MlaB2tOfDlR
# mhYkL4XlKWPJ2jd7pQHdpTOsGs9DL+qCoYIXCzCCFwcGCisGAQQBgjcDAwExghb3
# MIIW8wYJKoZIhvcNAQcCoIIW5DCCFuACAQMxDzANBglghkgBZQMEAgEFADCCAVQG
# CyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIIfupNbOE4pBhyYoOzplIt9F4Y4pxcIU7PirgxRws1J4AgZisiLZ
# LxAYEjIwMjIwNzEzMTA0MDE0LjgxWjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMy
# QkQtRTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIRXzCCBxAwggT4oAMCAQICEzMAAAGt/N9NWONdMukAAQAAAa0wDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwMzAy
# MTg1MTM2WhcNMjMwNTExMTg1MTM2WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMyQkQtRTNENS0zQjFE
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6J5TKqVNKtUuG9jtM7y+AL5Pk3/L8xd5
# Heg3ATSssjUSD+AzmD02E/4qqolz/u48vhOygAtv5FV/quhg2WXJCtiaq5SPCyrb
# rYwPkv2X2tTWmXPa0w96E/xp11WU0iNggGHQ0LgLIwTq3FWmlCvt4V39tbRf22dn
# LVoNb7OhokHYVjyFqiSrlxE40Rbi6hWxNNewgKRtg4Bh98ggZqQwVdW8HfQ1yy6I
# Ofq4OTzdddOzS2dKvwXHM+gPxKA88hxZpY8SMJAuvkjQHF91SWLA08cg8SCWqiys
# KVGNcbutxlZtZ44OABOLSLoNSy/VafQs5biy8rj9a5z+/12Wa4itqa/3CFuALKRS
# 5hnLwzFPOxCpTZHFybyHz0JcDmN/WTuTdmJotQnTTcyO1O01fOWBv6TUDl4vXsbc
# LgSPDkChWIz5QEZC/G5PGkV5oahAWp44Ya0QrSqTTB1Rf2n/gC71eyV7kPl+/KkF
# 2xxcGyVQFxPr4JirSRD2yaxPKFXgMr3Bv1mfs5sQ59PQBDKmkjqPDMGMeEAYXKsp
# iMhuCUxoSLGNG/td02JzZW5grJLvUDSGzp1tsPH9XuENt2/ayu1nZVM7TLYT7hCo
# xEq0AG/gCCCNgrPlNga5DhVts9jx8E71eq9rcafHVkM5DecZUUofBqsYNw10Hep6
# y+0lsgYmAmMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBR9UHQdBLyqIVpuaoSo5X0u
# ssbBWTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNy
# b3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUH
# AQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEp
# LmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3
# DQEBCwUAA4ICAQCL0B1FuzH+A5J0Fed3BF6NC661Cpx7eTduCzWyU+NlLHoUNenU
# hnOM7JPUmj/d5RYMEUl2L4d67U2jIN0af28vqvGXLUvrwrgyd8sGb7JvKM37FrV4
# 1rj7hw6g67ETYq3yO2ZlsiHHaO9jsX2pj+VqdHk9JtQrIKWE1CHGyc1Sn8lJD6ju
# cC5An7CwLA8KtdgTsL5O8oONrp7pZTQrhGIFcUZTXPoy3cr3CUwP9AZTj78gZkOY
# T79n+TQl8mNnLEICVyaF7euB2EPMCwbElirg9uUZlMF2vzCRDCk/aOCDIwxrAwzk
# OCDC9doNuuoJDyCSw2EJnNOp9LZ1uAsXSbsd/CVQytyfOL9t1NJFbMheDlCwfW3l
# dpogf5NnW5kG3BcnwQ5evpL7YDqrxFBVjXQqcEfpikYT06Fc9+4i7zzaa4UR2HgR
# ds90BFRHUgxIjGDzySFIEL9gHBCEKmNOSyrkndn6PIdZngyddflHjaYBHnziJFhz
# tqBi+6i0MSpwPRT2UiOBbfU+p+plDW25hlOIZwoT1Bxga9kUqdV2SorxXQz176QX
# kKoM6swxhFXb4j8WHJCwkfEr8bncPQ7lu90iHaAOcQdEAWKF1mPb1ntbSloY+i0Z
# fSgHmv3Co2Mzetu+4R7oUnfbcw9jXH383WDXbpP9KiSoAMkFMqrIFg3jMzCCB3Ew
# ggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1p
# Y3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkz
# MDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5
# osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVri
# fkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFEx
# N6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S
# /rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3j
# tIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKy
# zbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX78
# 2Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjt
# p+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2
# AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb
# 3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3ir
# Rbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUB
# BAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYD
# VR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGC
# N0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8E
# TzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBM
# MEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEA
# nVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx8
# 0HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ
# 7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2
# KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZ
# QhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa
# 2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARx
# v2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRr
# akURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6T
# vsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4
# JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6
# ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLSMIICOwIBATCB/KGB
# 1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcG
# A1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjMyQkQtRTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBAktGtRVHhlsEO
# BY+O42pVy1TOkKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5nj42TAiGA8yMDIyMDcxMzExNTUwNVoYDzIwMjIw
# NzE0MTE1NTA1WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDmePjZAgEAMAoCAQAC
# AiUuAgH/MAcCAQACAhFRMAoCBQDmekpZAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwG
# CisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEF
# BQADgYEAiwOVyZECDZVf4sgyvpRLP+YFmi8vZIWOl7LCHkftvyuMXH3fX04/ItLd
# kWTmuF6Ou2o5Ya+XzeyIXnfSKvN86GNtrekGmDkPECAAh0e2AFNj3+6PTHs41HGg
# mhtOzDOvQvwmD+BssSDg6ibPD8gGzg2s/gFs72jW/FCGkz+OxikxggQNMIIECQIB
# ATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAa38301Y410y
# 6QABAAABrTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDskNeyQZjuwT0MV4vUEyBbsdqQ50fjzhQV
# cbzY2wJ+8jCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIJ/qfD0JHl7X4621
# yfXD33YqafxgxNj8NY8gd4xsy1CCMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTACEzMAAAGt/N9NWONdMukAAQAAAa0wIgQgFqFgcufmYRiDKqZT
# SMQp0oN1L0tkmEYtH1+Jn7sDCi0wDQYJKoZIhvcNAQELBQAEggIAcDj+Rc07L75L
# b+URBgqvIxDpQwVxLdZiI0jbaLlZyusG3b3fSzKd2fO+xiUXMoOybR8YkQewr2F7
# W3p2mSSWH+C6MO7/JY8hwuX6rtGse0/wcqvL8CcieK6bF3By/d2D62iPv9yEvhrg
# EDcAxfRBaKiXns+QNlgEmLmT7ECfBvUi5Z2+tHdig6uJlPM5Pd/Hl0wRqmrUAkwW
# K3z3cJ5nrewEcPI8iKbMstjA6dlkXkNX8SWU1Ll7y2DL+wRYHq4wMD2IQdIX/ca+
# 9NmMhnZLYg2AVThMLkIwsNXB/KFOsldSUjBmqrsuw2Mm3nlRfyPsKUkvW8eCBlLR
# kUvEZAaq97gN7fM3NPOeca42+QX5M3CxLWTUgnbqawFjb9AIDWq2BDdSEzUZxPE0
# xTva/FNib76ZUwvJLSh+wlVk8qgQnPKvc8u0PoMUEjWZrlwc7P3slyoSEw56ZaNE
# P7USNKMQFBvQG3i4pdaEVebmQbGqzujoD2U3cRAUHIpaqYfUIRlhFZ9jbMvZsG48
# Tdo4NEt61YbD7NAyUpcjFiMhf/nqK0NR9WzNCSCpaBm5dFJYdMKwxUnU1LcJu8xE
# POXZfT/Z5Td/DOxALEh71hBe8N1+vKUMWjJxFgKJwdEJsm6x70Fli+7Q9+G59cSi
# GZ5VnuXHoPu8lx7BkvaXxTJaeRzlMJ4=
# SIG # End signature block
