#************************************************
# DC_DirectAccessDiag.ps1
# Version 1.0: Apr2013
# Version 1.5: Jun2013
# Version 1.6: Oct-Nov2013 (added hotfix checking and fixed issues - published Nov 15, 2013)
# Version 1.7: Nov2013 (added ETL tracing for Schannel and DASrvPSLogging - published Nov 19, 2013)
# Version 1.8: Mar2014 (added BasicSystemInformation and output files)
# Version 1.9.11.14.13: Added the DAClientAlerts and DAServerAlerts
# Version 2.1.04.02.14: Added IpHlpSvc logging. TFS264081
# Version 2.2.07.31.14: Added HyperV output for nvspbind info in DASharedNetInfo function; added DiagnosticVersion.TXT
# Version 2.3.08.14.14: Added data collection for windir\inf\netcfg*.etl files, and BasicSystemInformationTXT. TFS264081
# Version 2.4.08.24.14: Within the interactive section, we now enable Ncasvc/Operational and Ncsi/operational eventlogs.
# Date: 2013-2014 / 2020 /waltere
# Authors:
#	Boyd Benson (bbenson@microsoft.com); Joel Christiansen (joelch@microsoft.com DirectAccess SME Lead)
# Description: Collects information about the DirectAccess Client.
# Called from: DirectAccess Diag, Main Networking Diag
#*******************************************************

. ./utils_cts.ps1
. ./utils_Remote.ps1

Trap [Exception] 
	{
		#_# WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Stopping DataCollectorSet")
		Write-host $_
		continue
	}

Import-LocalizedData -BindingVariable ScriptVariable

function MenuDiagInput-StaticInteractive
{
    Write-Host -ForegroundColor Yellow 	"============ 1. DirectAccess Menu ============="
    Write-Host "1: Collect DirectAccess Static"
    Write-Host "2: Collect DirectAccess Interactive"
	Write-Host "q: Press Q  or Enter to skip"
}
function MenuDiagInput-CliSrv
{
    Write-Host -ForegroundColor Yellow 	"================ 2. DirectAccess Client Server Menu  =============="
    Write-Host "1: DA Client"
    Write-Host "2: DA Server"
	Write-Host "q: Press Q  or Enter to skip"
}
function DiagInput-ClientServer
{
        $Selection = Read-Host "Choose the DirectAccess Client or Server"
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DA datacollection type: $Selection" -shortformat
		switch ($Selection)
		{
			1 {$Script:ResultsClientOrServer = "DirectAccessCli"}
			2 {$Script:ResultsClientOrServer = "DirectAccessSrv"}
			'q' {}
		}
}
#_# $ResultsCollectionType = Get-DiagInput -Id "DirectAccessCollectionTypeChoice"
#_# DirectAccessStatic -or- DirectAccessInteractive
		MenuDiagInput-StaticInteractive
        $Selection = Read-Host "Choose the DirectAccess datacollection type"
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DA datacollection type: $Selection" -shortformat
		switch ($Selection)
		{
			1 {$ResultsCollectionType = "DirectAccessStatic"}
			2 {$ResultsCollectionType = "DirectAccessInteractive"}
			'q' {}
		}

function DAClientInfo
{
	#-----------
	# DirectAccess Client
		.\DC_DirectAccessClient-Component.ps1
	#-----------
	# DNS Client
		.\DC_DnsClient-Component.ps1
	#-----------
	# NAP Client
		.\DC_NAPClient-Component.ps1
	#-----------
}

function DAServerInfo
{
	#-----------
	# DNS Client
		.\DC_DnsClient-Component.ps1
	#-----------
	# DirectAccess Server
		.\DC_DirectAccessServer-Component.ps1
	#-----------
	# HTTP
		.\DC_HTTP-Component.ps1
	#-----------
	# NAP Server
		.\DC_NAPServer-Component.ps1
	#-----------
	# Network LBFO	
		.\DC_NetLBFO-Component.ps1
	#-----------	
	# NLB Server
		.\DC_NLB-Component.ps1
	#-----------
}

function DASharedNetInfo
{
	#-----------
	# Kerberos
		.\DC_Kerberos-Component.ps1
	# Certificates
		.\DC_Certificates-Component.ps1
	#-----------
	# ProxyConfig
		.\DC_ProxyConfiguration.ps1
	# InternetExplorer
		.\DC_InternetExplorer-Component.ps1
	# SChannel
		.\DC_SChannel-Component.ps1
	# WinHTTP
		.\DC_WinHTTP-Component.ps1
	#-----------
	# TCPIP and Winsock
		.\DC_Winsock-Component.ps1
		.\DC_TCPIP-Component.ps1
	# Firewall and IPsec
		.\DC_Firewall-Component.ps1
		.\DC_PFirewall.ps1
		.\DC_IPsec-Component.ps1
	#-----------
	# Network Adapters
		.\DC_NetworkAdapters-Component.ps1
	# NetworkConnections	
		.\DC_NetworkConnections-Component.ps1
	# NetworkList
		.\DC_NetworkList-Component.ps1
	# NetworkLocationAwareness
		.\DC_NetworkLocationAwareness-Component.ps1
	# NetworkStoreInterface
		.\DC_NetworkStoreInterface-Component.ps1
	#-----------
	#GPClient registry and event logs
		.\DC_GroupPolicyClient-Component.ps1
	#GPResults
		.\DC_RSoP.ps1
	#WhoAmI
		.\DC_Whoami.ps1
	#----------- 
	#BasicSysInfo
		.\DC_BasicSystemInformation.ps1
		.\DC_BasicSystemInformationTXT.ps1
	#ChkSym
		.\DC_ChkSym.ps1
	#-----------
	#Event Logs - System & Application logs
		$sectionDescription = "Event Logs (System and Application)"
		$EventLogNames = "System", "Application"
		Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription
	#-----------
	#Services (running)
		.\DC_Services.ps1
	#TaskListSvc
		.\DC_TaskListSvc.ps1
	#ScheduledTasks
		.\DC_ScheduleTasks.ps1
	#-----------
	# HyperV output file that network binding information (added 7/24/14)
		.\DC_HyperVNetInfo.ps1
	#-----------
}

function DAGeneralInfo
{
	#MSINFO32
		.\DC_MSInfo.ps1
}

function DAClientAlerts
{
	"[info] DirectAccess DAClient Alerts section begin" | WriteTo-StdOut
	$sectionDescription = "DirectAccess Client Alerts"

	#ALERTS FILE
	$OutputFile= $Computername + "_ALERTS.TXT"

	# detect OS version and SKU
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	[int]$bn = [int]$wmiOSVersion.BuildNumber
	$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)

	#----------determine OS architecture
	Function GetComputerArchitecture() 
	{ 
		if (($Env:PROCESSOR_ARCHITEW6432).Length -gt 0) #running in WOW 
		{ $Env:PROCESSOR_ARCHITEW6432 }
		else
		{ $Env:PROCESSOR_ARCHITECTURE } 
	}
	$OSArchitecture = GetComputerArchitecture			

"`n`n`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Client Configuration Issue Detection" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append

	#----------------------------------------
	# 1
	# DirectAccess Client: Check for "DirectAccess Client has Incorrect SKU"
	#   (W7/WS2008R2 and W8/WS2012)
	#----------------------------------------
	if ($true)
	{
	# This check is to verify that the DirectAccess Client is Enterprise or Ultimate for Win7 or Enterprise for Win8
	"[info] Checking for `"DirectAccess Client: DirectAccess Client has Incorrect SKU`"" | WriteTo-StdOut
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"DirectAccess Client: DirectAccess Client has Incorrect SKU`"" | Out-File -FilePath $OutputFile -append
	if (($bn -gt 9000) -and ($sku -ne 4))
	{
		"*" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"*" | Out-File -FilePath $OutputFile -append
		"The Windows SKU of this Windows 8+ client does NOT support DirectAccess." | Out-File -FilePath $OutputFile -append
		"Please use Windows Enterprise Edition." | Out-File -FilePath $OutputFile -append
	}			
	elseif (($bn -eq 7601) -and (($sku -ne 1) -and ($sku -ne 4)))
	{
		"*" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"*" | Out-File -FilePath $OutputFile -append
		"The Windows SKU of this Windows 7 client does NOT support DirectAccess." | Out-File -FilePath $OutputFile -append
		"Please use Windows Enterprise Edition or Ultimate." | Out-File -FilePath $OutputFile -append
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"The client SKU supports DirectAccess." | Out-File -FilePath $OutputFile -append
	}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# 2
	# DirectAccess Client: Checking for "Proxy server is configured for WinHTTP"
	#   (W7/WS2008R2)
	#----------------------------------------
	if ($true)
	{
	"[info] Checking for `"DirectAccess Client: Proxy server is configured for WinHTTP`"" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"DirectAccess Client: Proxy server is configured for WinHTTP`""  | Out-File -FilePath $OutputFile -append
	if ($bn -ge 7601)
	{
		$inetConnections = get-itemproperty -path "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
		$proxyWinHTTP = $inetConnections.WinHttpSettings

		# Offset 8 is the key to knowing if the WinHTTP proxy is set.
		# If it is 1, then there is no proxy. If it is 3, then there is a proxy set.
		[int]$proxyWinHTTPcheck = $proxyWinHTTP[8]
		If ($proxyWinHTTPcheck -ne 1)
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Proxy server is configured for WinHTTP." | Out-File -FilePath $OutputFile -append
			"Refer to the output file named ComputerName_ProxyConfiguration.TXT" | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Proxy server settings for WinHTTP are in the default configuration."  | Out-File -FilePath $OutputFile -append
		}
	}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# 3
	# DirectAccess Client: Checking for "Proxy server is configured for Internet Explorer System Context"
	#----------------------------------------
	if ($true)
	{
	"[info] `"DirectAccess Client: Proxy server is configured for Internet Explorer System Context`"" | WriteTo-StdOut
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: `"DirectAccess Client: Proxy server is configured for Internet Explorer in System Context`"" | Out-File -FilePath $OutputFile -append
		#----------
		# Verifying HKU is in the psProviderList. If not, add it
		#----------
		#
		# HKU may not be in the psProviderList, so we need to add it so we can reference it
		#
		$psProviderList = Get-PSDrive -PSProvider Registry
		$psProviderListLen = $psProviderList.length
		for ($i=0;$i -le $psProviderListLen;$i++)
		{
			if (($psProviderList[$i].Name) -eq "HKU")
			{
				$hkuExists = $true
				$i = $psProviderListLen
			}
			else
			{
				$hkuExists = $false
			}
		}
		if ($hkuExists -eq $false)
		{
			"[info]: Creating a new PSProvider to enable access to HKU" | WriteTo-StdOut
			New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
		}

		#----------
		# Verify "\Internet Settings\Connections" exists, if not display message that IE System Context is not configured.
		#   $ieConnectionsCheck and associated code block added 10/11/2013
		#----------
		$ieConnections = $null
		# Get list of regvalues in "HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"		
		$ieConnectionsCheck = Test-path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
		$ieProxyConfigProxyEnable   = (Get-ItemProperty -path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyEnable		
		if ($ieProxyConfigProxyEnable -eq 1)
		{
			#Changed this detection from "-ne 0" to "-eq 1" because if the registry value did NOT exist, "-ne 0" caused a false positive.
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"A proxy server is configured for IE System Settings." | Out-File -FilePath $OutputFile -append
			"Refer to the output file named <ComputerName>_ProxyConfiguration.TXT to confirm." | Out-File -FilePath $OutputFile -append
			"This alert currently checks for ProxyEnable -eq 1." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Proxy server settings (ProxyEnable) for IE System is not enabled."  | Out-File -FilePath $OutputFile -append
			"Refer to the output file named <ComputerName>_ProxyConfiguration.TXT to confirm." | Out-File -FilePath $OutputFile -append
			"This alert currently checks for ProxyEnable -ne 0." | Out-File -FilePath $OutputFile -append
		}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	}

	#----------
	# 4
	# DirectAccess Client: Detect if the StaticProxy registry value exists in any subkey of "HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr"
	#   RegSubKey example: "HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr\{4BB9AF47-8767-4835-899E-08D4230EA18E}"
	#   Added 3/28/14
	#----------	
	if ($true)
	{	
	"[info] Checking for `"DirectAccess Client: Detect if the StaticProxy registry value exists in any subkey of HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr`"" | WriteTo-StdOut
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"DirectAccess Client: Detect if the StaticProxy registry value exists in any subkey of HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr`""  | Out-File -FilePath $OutputFile -append
	
		$keyPath = "HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr"
		if (Test-Path $keyPath)
		{
			$ProxyMgr = Get-ChildItem $keyPath
			$ProxyMgrLen = $ProxyMgr.length
			$StaticProxyCount=0
			for ($i=0;$i -lt $ProxyMgrLen;$i++)
			{
				$subKeyPath = $ProxyMgr[$i].Name
				$subKeyPath = "REGISTRY::" + $subKeyPath
				$StaticProxyValue = (Get-ItemProperty -Path $subKeyPath).StaticProxy
				if ($StaticProxyValue)
				{
					$StaticProxyCount++
				}
			}
			if ($StaticProxyValue)
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"The DirectAccess Client configuration has the StaticProxy regvalue within HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr." | Out-File -FilePath $OutputFile -append
				"This registry value may cause connectivity issues." | Out-File -FilePath $OutputFile -append
				"Refer to the output file named <ComputerName>_TCPIP_reg_output.TXT registry value to confirm." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"The DirectAccess Client configuration does NOT have the StaticProxy regvalue within HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr." | Out-File -FilePath $OutputFile -append
				"This registry value has been known to cause connectivity issues." | Out-File -FilePath $OutputFile -append
				"Refer to the output file named <ComputerName>_TCPIP_reg_output.TXT registry value to confirm." | Out-File -FilePath $OutputFile -append
			}
		}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	}

#----------------------------------------------------
# DirectAccess Client Hotfix Detection
#----------------------------------------------------

"`n`n`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Client Hotfix Detection: W8/WS2012, W8.1/WS2012R2" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append

	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2855269
	#   (W8/WS2012)
	#   (backport for W7/WS2008R2 due Dec2013)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2855269" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2855269`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9600)
	{
		# W8.1 version of DaOtpCredentialProvider.dll is 6.3.9600.16384
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append
	}
	elseif ($bn -eq 9200)
	{
		# "Checking for existence of Daotpauth.dll or Daotpcredentialprovider.dll." | Out-File -FilePath $OutputFile -append
		If (Test-path "$env:windir\system32\Daotpcredentialprovider.dll")
		{
			if ($OSArchitecture -eq "AMD64")
			{
				if (CheckMinimalFileVersion "$env:windir\system32\Daotpcredentialprovider.dll" 6 2 9200 20732)
				{
					"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
					"Hotfix KB 2855269 is installed." | Out-File -FilePath $OutputFile -append
				}
				else
				{
					"*" | Out-File -FilePath $OutputFile -append
					"****************************************" | Out-File -FilePath $OutputFile -append
					"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
					"****************************************" | Out-File -FilePath $OutputFile -append
					"*" | Out-File -FilePath $OutputFile -append
					"Hotfix KB 2855269 is not installed." | Out-File -FilePath $OutputFile -append
				}
			}
			<#
				"Which files exists?" | Out-File -FilePath $OutputFile -append
				If (Test-path "$env:windir\system32\Daotpauth.dll")
				{ "Daotpauth.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
				else
				{ "Daotpauth.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
				
				If (Test-path "$env:windir\system32\Daotpcredentialprovider.dll")
				{ "Daotpcredentialprovider.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
				else
				{ "Daotpcredentialprovider.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
			#>
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append			
	"2855269 - Error message when you use an account that contains a special character in its DN to connect to a Windows Server 2012-based Direct Access server" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2855269/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2769240
	#   (W8/WS2012)
	#   (with LDRGDR detection)
	#----------------------------------------
	if ($true)
	{
	# W8 x86
	#  (windir\system32) kerberos.dll; LDR=6.2.9200.16432; GDR=6.2.9200.20533
	# W8 x64
	#  (windir\system32) kerberos.dll; LDR=6.2.9200.16432; GDR=6.2.9200.20533
	#  (x86: windir\syswow64) kerberos.dll; LDR=6.2.9200.16432; GDR=6.2.9200.20533
	#
	"[info] DirectAccess Client: Hotfix verification for KB 2769240" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB2769240`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9600)
	{
		# W8.1 version of DaOtpCredentialProvider.dll is 6.3.9600.16384
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append
	}
	elseif ($bn -eq 9200)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 16432 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 20533 -LDRGDR) -and 
			    (CheckMinimalFileVersion "$env:windir\SysWOW64\kerberos.dll" 6 2 9200 16432 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\SysWOW64\kerberos.dll" 6 2 9200 20533 -LDRGDR))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 16432 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 20533 -LDRGDR))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2769240 - You cannot connect a DirectAccess client to a corporate network in Windows 8 or Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2769240/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client/Server: Hotfix Verification for KB 2795944
	#   (W8/WS2012)
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Feb2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2795944" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2795944`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# file versions identical for x64/x86
		#
		# Iphlpsvc.dll  6.2.9200.16496;  ;6.2.9200.20604  
		# Iphlpsvcmigplugin.dll  6.2.9200.16496;  ;6.2.9200.20604
		# Ncbservice.dll  6.2.9200.16449  
		# Netprofm.dll  6.2.9200.16496;  ;6.2.9200.20604 		
		#
		if ( ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 16496 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\Iphlpsvc.dll" 6 2 9200 20604 -LDRGDR)) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 16496) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 2 9200 20604)) -and
		     (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 16449) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 20604 -LDRGDR)) )
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2795944 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2795944 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2795944 - Windows 8 and Windows Server 2012 update rollup: February 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2795944/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client/Server: Hotfix Verification for KB 2779768
	#   (W8/WS2012)
	#   Bugcheck due to IPsec; LBFO + MAC Spoofing (MAC flipping) issues
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Dec2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2779768" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2779768`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# x86
		# Checking 3 specific binaries:
		#   Bfe.dll  6.2.9200.16451; 6.2.9200.20555
		#   Http.sys  6.2.9200.16451; 6.2.9200.20555
		#   Ikeext.dll  6.2.9200.16451; 6.2.9200.20555  
		#
		if ( ((CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 20555 -LDRGDR)) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 20555 -LDRGDR)) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 20555 -LDRGDR)) )
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2779768 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2779768 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2779768 - Windows 8 and Windows Server 2012 update rollup: December 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2779768/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

"`n`n`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Client Hotfix Detection: W7/WS2008R2" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2796313
	#   (W7/WS2008R2 SP1)
	#----------------------------------------
	if ($true)
	{
	# W7/WS2008R2 x86
	#  (windir\system32) iphlpsvc.dll: 6.1.7600.21421; ;6.1.7601.22214
	#  (windir\system32) iphlpsvcmigplugin.dll: 6.1.7600.16385; ;6.1.7601.22214
	#  (windir\system32) Netcorehc.dll:	6.1.7601.22214 
	#
	# W7/WS2008R2 x64
	#  (windir\system32) iphlpsvc.dll: 6.1.7600.21421; ;6.1.7601.22214;
	#  (windir\system32\migration) iphlpsvcmigplugin.dll: 6.1.7600.16385; ;6.1.7601.22214
	#  (x86: windir\syswow64\migration) iphlpsvcmigplugin.dll: 6.1.7600.21421; ;6.1.7601.22214 
	#  (x86: windir\syswow64) netcorehc.dll: 6.1.7600.21421; ;6.1.7601.22214
	#

	"[info] DirectAccess Client: Hotfix verification for KB 2796313" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2796313`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			#checking for x64 version of files AND the associated x86 version of files
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22214) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22214) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22214) -and 
			    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22214) -and (CheckMinimalFileVersion "$env:windir\SysWOW64\Netcorehc.dll" 6 1 7601 22214))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22214) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22214) -and
			    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22214))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}			
		}
	}
	elseif ($bn -eq 7600)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 21421) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 21421))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll " 6 1 7600 21421) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 16385))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2796313 - Long reconnection time after a DirectAccess server disconnects a Windows 7-based DirectAccess client" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2796313/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2758949
	#   (W7/WS2008R2 SP1)
	#----------------------------------------
	if ($true)
	{
	# W7/WS2008R2 x86
	#  (windir\system32) Iphlpsvc.dll 6.1.7601.22130
	#  (windir\system32\migration) Iphlpsvcmigplugin.dll 6.1.7601.22130 
	#  (windir\system32) Netcorehc.dll 6.1.7601.22130 
	#	
	# W7/WS2008R2 x64
	#  (windir\system32) Iphlpsvc.dll 6.1.7601.22130
	#  (windir\system32\migration) Iphlpsvcmigplugin.dll 6.1.7601.22130 
	#  (x86: windir\syswow64\migration) Iphlpsvcmigplugin.dll 6.1.7601.22130
	#  (windir\system32) Netcorehc.dll 6.1.7601.22130 
	#

	"[info] DirectAccess Client: Hotfix verification for KB 2758949" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2758949`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		# since the only difference between x86 and x64 was the following, we are skipping this file detection:  -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22130)
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22130) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22130) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22130)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2758949 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2758949 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2758949 - You cannot build an IP-HTTPS protocol-based connection on a computer that is running Windows 7 or Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2758949/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2718654
	#   (W7/WS2008R2 RTM and SP1)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2718654" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2718654`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		# since the only difference between x86 and x64 was the following, we are skipping this file detection:  -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22130)	
		if ((CheckMinimalFileVersion "$env:windir\system32\Dnsapi.dll" 6 1 7601 22011) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnsapi.dll" 6 1 7601 22011) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Dnscacheugc.exe" 6 1 7601 22011) -and 
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnscacheugc.exe" 6 1 7601 22011) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Dnsrslvr.dll" 6 1 7601 22011))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	elseif ($bn -eq 7600)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Dnsapi.dll" 6 1 7600 21226) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnsapi.dll" 6 1 7600 21226) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Dnscacheugc.exe" 6 1 7600 21226) -and 
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnscacheugc.exe" 6 1 7600 21226) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Dnsrslvr.dll" 6 1 7600 21226)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2718654 - Long reconnection time after a DirectAccess server disconnects a Windows 7-based DirectAccess client" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2718654/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2680464
	#   (W7/WS2008R2 SP1)
	#----------------------------------------
	If ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2680464" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2680464`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Ncsi.dll" 6 1 7601 21928) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Ncsi.dll" 6 1 7601 21928) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Nlaapi.dll" 6 1 7601 21928) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Nlaapi.dll" 6 1 7601 21928) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Nlasvc.dll" 6 1 7601 21928)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2680464 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2680464 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2680464 - Location detection feature in DirectAccess is disabled intermittently in Windows 7 or in Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2680464/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2535133
	#   (W7/WS2008R2 RTM and SP1)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2535133" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2535133`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 21728) -and
		    (CheckMinimalFileVersion "$env:windir\SysWOW64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 21728)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	elseif ($bn -eq 7600)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 20967) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 20967)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2535133 - IP-HTTPS clients may disconnect from Windows Server 2008 R2-based web servers intermittently after two minutes of idle time" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2535133/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2288297
	#   (W7/WS2008R2 RTM)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2288297" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2288297`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7600)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\webclnt.dll" 6 1 7600 20787) -and
			    (CheckMinimalFileVersion "$env:windir\syswow64\webclnt.dll" 6 1 7600 20787))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is installed." | Out-File -FilePath $OutputFile -append	
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\webclnt.dll" 6 1 7600 20787))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is installed." | Out-File -FilePath $OutputFile -append	
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2288297 - You are unexpectedly prompted to enter your credentials when you try to access a WebDAV resource in a corporate network by using a DirectAccess connection in Windows 7 or in Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2288297/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 979373
	#   (W7/WS2008R2 RTM)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 979373" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 979373`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7600)
	{
		# file versions are identical for x86/x64
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 20614) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 979373 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 979373 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"979373 - The DirectAccess connection is lost on a computer that is running Windows 7 or Windows Server 2008 R2 that has an IPv6 address" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/979373/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 978738
	#   (W7/WS2008R2 RTM)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 978738" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 978738`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7600)
	{
		# file versions are identical for x86/x64
		if ((CheckMinimalFileVersion "$env:windir\system32\Dnsapi.dll" 6 1 7600 20621) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Dnscacheugc.exe" 6 1 7600 20621) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Dnsrslvr.dll" 6 1 7600 20621))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 978738 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 978738 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"978738 - You cannot use DirectAccess to connect to a corporate network from a computer that is running Windows 7 or Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/978738/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Collect Alerts File
	#----------------------------------------	
	"[info] DirectAccess Client: Collect alerts file" | WriteTo-StdOut			
	# Collect _ALERTS output file
	CollectFiles -filesToCollect $OutputFile -fileDescription "DirectAccess ALERTS" -SectionDescription $sectionDescription
	"[info] DirectAccess DAClient Alerts section end" | WriteTo-StdOut
}


function DAServerAlerts
{
	"[info] DirectAccess DAServer Alerts section begin" | WriteTo-StdOut
	$sectionDescription = "DirectAccess Server Alerts"
	# ALERTS FILE
	$OutputFile= $Computername + "_ALERTS.TXT"
	
	"`n`n" | Out-File -FilePath $OutputFile -append
	"=========================================================" | Out-File -FilePath $OutputFile -append
	" DirectAccess Server Configuration Issue Detection" | Out-File -FilePath $OutputFile -append
	"=========================================================" | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append

	# detect if OS is WS2012+ and is Server SKU
	$OSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	$OSBuildNumber = $OSVersion.BuildNumber
	$ProductType = (Get-CimInstance -Class Win32_OperatingSystem).ProductType

	# detect OS version and SKU
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	$bn = $wmiOSVersion.BuildNumber
	$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)

	#----------determine OS architecture
	function GetComputerArchitecture() 
	{ 
		if (($Env:PROCESSOR_ARCHITEW6432).Length -gt 0) #running in WOW 
		{ $Env:PROCESSOR_ARCHITEW6432 }
		else
		{ $Env:PROCESSOR_ARCHITECTURE } 
	}
	$OSArchitecture = GetComputerArchitecture			

	#----------------------------------------
	# 1
	# DirectAccess Server: Check for "DirectAccess Server with KerberosProxy and ForceTunnel Enabled"
	#----------------------------------------
	if ($true)
	{
		"[info] DirectAccess DAServer: Check for `"DirectAccess Server with KerberosProxy and ForceTunnel Enabled`"" | WriteTo-StdOut
		'--------------------' | Out-File -FilePath $OutputFile -append
		"Rule: KerberosProxy and ForceTunnel check" | Out-File -FilePath $OutputFile -append
		# This functionality is only available in WS2012+
		
		if ($bn -ge 9200)
		{
			# If the OS is a Server SKU
			if (($ProductType -eq 2) -or ($ProductType -eq 3))
			{
				# Add registry check to determine if Get-RemoteAccess is available.
				$regkeyRemoteAccessCheck = "HKLM:\SYSTEM\CurrentControlSet\Services\RaMgmtSvc"
				if (Test-Path $regkeyRemoteAccessCheck) 
				{
					$daRemoteAccess = Get-RemoteAccess
					#This first If statement added 3/20/14 to detect new issue in WS2012 R2. Working with JoelCh.
					If (($bn -ge 9600) -and ($daRemoteAccess.ComputerCertAuthentication -eq "Enabled") -and ($daRemoteAccess.ForceTunnel -eq "Enabled") -and ($daRemoteAccess.Downlevel -eq "Disabled"))
					{
						# Detect if WS2012R2 DA Server has ForceTunnel+ComputerCertAuth enabled and Downlevel disabled. If so, flag it.
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server has both KerberosProxy enabled AND ForceTunnel enabled AND Downlevel disabled. These should never be enabled simultaneously." | Out-File -FilePath $OutputFile -append
						"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
						"For more information:" | Out-File -FilePath $OutputFile -append
						"  Remote Access (DirectAccess) Unsupported Configurations" | Out-File -FilePath $OutputFile -append
						"  http://technet.microsoft.com/en-us/library/dn464274.aspx" | Out-File -FilePath $OutputFile -append
					}
					elseif (($bn -ge 9200) -and ($daRemoteAccess.ComputerCertAuthentication -eq "Disabled") -and ($daRemoteAccess.ForceTunnel -eq "Enabled"))
					{
						# Detect if WS2012R2 DA Server has ComputerCertAuthentication disabled and ForceTunnel enabled. If so, flag it.				
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server has both KerberosProxy AND ForceTunnel enabled. These should never be enabled simultaneously." | Out-File -FilePath $OutputFile -append
						"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
						"For more information:" | Out-File -FilePath $OutputFile -append
						"  Remote Access (DirectAccess) Unsupported Configurations" | Out-File -FilePath $OutputFile -append
						"  http://technet.microsoft.com/en-us/library/dn464274.aspx" | Out-File -FilePath $OutputFile -append
					}
					else
					{
						"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server does not have both KerberosProxy AND ForceTunnel enabled. These should never be enabled simultaneously." | Out-File -FilePath $OutputFile -append
						"For more information:" | Out-File -FilePath $OutputFile -append
						"  Remote Access (DirectAccess) Unsupported Configurations" | Out-File -FilePath $OutputFile -append
						"  http://technet.microsoft.com/en-us/library/dn464274.aspx" | Out-File -FilePath $OutputFile -append
					}
				}
			}
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"This check only applies to W8/WS2012 and W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append		
		}
		'--------------------' | Out-File -FilePath $OutputFile -append
		"`n`n" | Out-File -FilePath $OutputFile -append
	}



	#----------------------------------------
	# 2
	# DirectAccess Server: Checking for "Proxy server is configured for WinHTTP"
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Server: Checking for `"Proxy server is configured for WinHTTP`"" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Proxy server is configured for WinHTTP`"" | Out-File -FilePath $OutputFile -append
	if ($bn -ge 7601)
	{
		$inetConnections = get-itemproperty -path "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
		$proxyWinHTTP = $inetConnections.WinHttpSettings

		# Offset 8 is the key to knowing if the WinHTTP proxy is set.
		# If it is 1, then there is no proxy. If it is 3, then there is a proxy set.
		[int]$proxyWinHTTPcheck = $proxyWinHTTP[8]
		If ($proxyWinHTTPcheck -ne 1)
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Proxy server is configured for WinHTTP." | Out-File -FilePath $OutputFile -append
			"Refer to the output file named ComputerName_ProxyConfiguration.TXT" | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Proxy server settings for WinHTTP are in the default configuration."  | Out-File -FilePath $OutputFile -append
		}
	}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# 3-4
	# DirectAccess Server: Checking for "DNS64 State Disabled"
	# DirectAccess Server: Checking for "DNS64 AcceptInterface does not have the DNS64 IP address bound."
	#----------------------------------------
	if ($true)
	{
		$NetDNSTransitionConfiguration = Get-NetDnsTransitionConfiguration
				
		# Checking for "DNS64 State Disabled"
		'--------------------' | Out-File -FilePath $OutputFile -append
		"Rule: Check for `"DNS64 State Disabled`"" | Out-File -FilePath $OutputFile -append
		
		$NetDNSTransitionState = $NetDNSTransitionConfiguration.State
		If ($NetDNSTransitionState -eq "Disabled")
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"NetDNSTransition is Disabled."  | Out-File -FilePath $OutputFile -append
			"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
			'--------------------' | Out-File -FilePath $OutputFile -append
		}
		else
		{
			# Checking for "DNS64 AcceptInterface does not have the DNS64 IP address bound."
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"DNS64 State is Enabled"  | Out-File -FilePath $OutputFile -append
			'--------------------' | Out-File -FilePath $OutputFile -append
			"Rule: Check for `"DNS64 AcceptInterface does not have the DNS64 IP address bound.`"" | Out-File -FilePath $OutputFile -append
			
			$AcceptInterface = $NetDNSTransitionConfiguration.AcceptInterface
			$DNS64Adapter = Get-NetIpAddress -InterfaceAlias $AcceptInterface
			$InterfaceAlias = $DNS64Adapter.InterfaceAlias
			$DNS64AdapterIP = $DNS64Adapter.IPAddress
			$DNS64AdapterIPLen = $DNS64AdapterIP.length
			$DNS64IPExists = $false
			for($DNS64IPCount=0;$DNS64IPCount -lt $DNS64AdapterIPLen;$DNS64IPCount++)
			{
				If ($DNS64AdapterIP[$DNS64IPCount].contains(":3333:") -eq $true)
				{
					$DNS64IPExists = $true
				}
			}	

			If ($DNS64IPExists -eq $false)
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Root cause detected." | Out-File -FilePath $OutputFile -append
				"DNS64 AcceptInterface does not have the DNS64 IP address bound." | Out-File -FilePath $OutputFile -append
				"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
				'--------------------' | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"DNS64 AcceptInterface has the DNS64 IP address bound." | Out-File -FilePath $OutputFile -append
			}
		}
		'--------------------' | Out-File -FilePath $OutputFile -append
		"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# 5
	# DirectAccess Server: Checking for "DirectAccess Server with OTP and ForceTunnel Enabled"
	#----------------------------------------
	if ($true)
	{
		"[info] DirectAccess DAServer: Check for `"DirectAccess Server with OTP Authentication Enabled and ForceTunnel Enabled`"" | WriteTo-StdOut
		'--------------------' | Out-File -FilePath $OutputFile -append
		"Rule: OTP and ForceTunnel check" | Out-File -FilePath $OutputFile -append
		# This functionality is only available in WS2012+
		
		if ($bn -ge 9200)
		{
			# If the OS is a Server SKU
			if (($ProductType -eq 2) -or ($ProductType -eq 3))
			{
				# Add registry check to determine if Get-RemoteAccess is available.
				$regkeyRemoteAccessCheck = "HKLM:\SYSTEM\CurrentControlSet\Services\RaMgmtSvc"
				if (Test-Path $regkeyRemoteAccessCheck) 
				{
					$daRemoteAccess = Get-RemoteAccess
					$daOTPAuth = Get-DAOtpAuthentication
					if (($daOTPAuth.OtpStatus -eq "Enabled") -and ($daRemoteAccess.ForceTunnel -eq "Enabled"))
					{
						# Detect if WS2012R2 DA Server has OTP and ForceTunnel Enabled. If so, flag it.
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server has both OTP Authentication enabled AND ForceTunnel enabled." | Out-File -FilePath $OutputFile -append
						"This may cause issues."  | Out-File -FilePath $OutputFile -append
						"Refer to Bemis 2956023 for more information."  | Out-File -FilePath $OutputFile -append
					}
					else
					{
						"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server does NOT have both OTP Authentication enabled AND ForceTunnel enabled." | Out-File -FilePath $OutputFile -append
						"Refer to Bemis 2956023 for more information."  | Out-File -FilePath $OutputFile -append
					}
				}
			}
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"This check only applies to W8/WS2012 and W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append		
		}
		'--------------------' | Out-File -FilePath $OutputFile -append
		"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
#----------------------------------------------------
# DirectAccess Server Hotfix Detection
#----------------------------------------------------
"`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Server Hotfix Detection: W7/WS2008R2, W8/WS2012, and W8.1/WS2012R2" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2859347
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2859347" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2859347`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\Raconfigtask.dll " 6 2 9200 20737)
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2859347 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{						
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2859347 is not installed." | Out-File -FilePath $OutputFile -append
			"Check for the configuration Alert above named `"DirectAccess Server: Checking for `"DNS64 AcceptInterface does not have the DNS64 IP address bound.`" `"." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2859347 - IPv6 address of a DirectAccess server binds to the wrong network interface in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2859347/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2788525
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2788525" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2788525`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\wbem\RAMgmtPSProvider.dll" 6 2 9200 20580) -and
		    (CheckMinimalFileVersion "$env:windir\system32\damgmt.dll" 6 2 9200 20580))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2788525 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2788525 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2788525 - You cannot enable external load balancing on a Windows Server 2012-based DirectAccess server" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2788525/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2782560
	#   (with LDRGDR detection)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2782560" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2782560`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Firewallapi.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Firewallapi.dll" 6 2 9200 20559 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Icfupgd.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Icfupgd.dll" 6 2 9200 20559 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\drivers\Mpsdrv.sys" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Mpsdrv.sys" 6 2 9200 20559 -LDRGDR)  -and
		    (CheckMinimalFileVersion "$env:windir\system32\Mpssvc.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Mpssvc.dll" 6 2 9200 20559 -LDRGDR)  -and
		    (CheckMinimalFileVersion "$env:windir\system32\Wfapigp.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Wfapigp.dll" 6 2 9200 20559 -LDRGDR)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2782560 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2782560 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2782560 - Clients cannot connect to IPv4-only resources when you use DirectAccess and external load balancing in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2782560/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2748603 --> NOT A HOTFIX - THIS IS A WORKAROUND
	#----------------------------------------
	# 2748603 - The process may fail when you try to enable Network Load Balancing in DirectAccess in Window Server 2012
	# http://support.microsoft.com/kb/2748603/EN-US

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2836232
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2836232" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2836232`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\wbem\Ramgmtpsprovider.dll" 6 2 9200 20682)
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2836232 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2836232 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2836232 - Subnet mask changes to an incorrect value and the server goes offline in DirectAccess in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2836232/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2849568
	#   (with LDRGDR detection)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2849568" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2849568`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\drivers\Winnat.sys" 6 2 9200 16654) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Winnat.sys" 6 2 9200 20762))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2849568 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2849568 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2849568 - MS13-064: Vulnerability in the Windows NAT driver could allow denial of service: August 13, 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2849568/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2765809
	#   (with LDRGDR detection)
	#   (W7/WS2008R2 and W8/WS2012)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2765809" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2765809`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		# WS2012 (many files in the fix - checking the following)
		# Adhapi.dll  6.2.9200.16449;				Adhapi.dll  6.2.9200.20553
		# Adhsvc.dll  6.2.9200.16449;				Adhsvc.dll  6.2.9200.20553
		# Httpprxm.dll  6.2.9200.16449;				Httpprxm.dll  6.2.9200.20553  
		# Httpprxp.dll  6.2.9200.16449;				Httpprxp.dll  6.2.9200.20553
		# Iphlpsvc.dll  6.2.9200.16449;				Iphlpsvc.dll  6.2.9200.20553  
		# Iphlpsvcmigplugin.dll  6.2.9200.16449;	Iphlpsvcmigplugin.dll  6.2.9200.20553
		# Keepaliveprovider.dll  6.2.9200.16449;	Keepaliveprovider.dll  6.2.9200.20553  
		# Ncbservice.dll  6.2.9200.16449;			Ncbservice.dll  6.2.9200.20553  
		# Netdacim.dll  6.2.9200.16449;				Netdacim.dll  6.2.9200.20553  
		# Netnccim.dll  6.2.9200.16449;				Netnccim.dll  6.2.9200.20553  
		# Netttcim.dll  6.2.9200.16449;				Netttcim.dll  6.2.9200.20553  
		#
		if ((CheckMinimalFileVersion "$env:windir\system32\Adhapi.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Adhapi.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Adhsvc.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Adhsvc.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Httpprxm.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Httpprxm.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Httpprxp.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Httpprxp.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Keepaliveprovider.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Keepaliveprovider.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Netdacim.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netdacim.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Netnccim.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netnccim.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Netttcim.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netttcim.dll" 6 2 9200 20553 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	elseif ($bn -eq 7601)
	{
		#
		# WS2008R2 RTM x64
		# Iphlpsvc.dll 6.1.7600.17157; Iphlpsvc.dll 6.1.7600.21360
		# Iphlpsvcmigplugin.dll 6.1.7600.16385
		#
		# WS2008R2 RTM x86
		# windir\system32\migration\
		#  Iphlpsvcmigplugin.dll 6.1.7600.17157; Iphlpsvcmigplugin.dll 6.1.7600.21360
		# 
		# WS2008R2 SP1 x64
		# Iphlpsvc.dll  6.1.7601.17989; Iphlpsvc.dll  6.1.7601.22150 
		# windir\system32\migration\
		#  Iphlpsvcmigplugin.dll  6.1.7601.17989; Iphlpsvcmigplugin.dll  6.1.7601.22150  
		# windir\SysWOW64\
		#  Netcorehc.dll  6.1.7601.17989; Netcorehc.dll  6.1.7601.22150
		# x86 files
		# windir\system32\migration\
		#  Iphlpsvcmigplugin.dll  6.1.7601.17989; Iphlpsvcmigplugin.dll  6.1.7601.22150 
		# windir\SysWOW64\
		#   Netcorehc.dll  6.1.7601.17989; Netcorehc.dll  6.1.7601.22150
		#

		#x64
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22150 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22150 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22150 -LDRGDR) -and	
		    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22150 -LDRGDR)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}	
	}
	elseif ($bn -eq 7600)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 17157 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 21360 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 17157 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 21360 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2 and W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2765809 - MS12-083: Vulnerability in IP-HTTPS component could allow security feature bypass: December 11, 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2765809/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2855269
	#  (Backport for W7/WS2008R2 due Dec2013)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Server: Hotfix verification for KB 2855269" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2855269`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9600)
	{
		# W8.1 version of DaOtpCredentialProvider.dll is 6.3.9600.16384
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append
	}
	elseif ($bn -eq 9200)
	{
		# "Checking for existence of Daotpauth.dll or Daotpcredentialprovider.dll." | Out-File -FilePath $OutputFile -append
		#   DAServer: Daotpauth.dll
		#   DAClient: Daotpcredentialprovider.dll
		
		# If the OS is a Server SKU
		if (($ProductType -eq 2) -or ($ProductType -eq 3))
		{		
			If (Test-path "$env:windir\system32\Daotpauth.dll")
			{
				if ($OSArchitecture -eq "AMD64")
				{
					if (CheckMinimalFileVersion "$env:windir\system32\Daotpauth.dll" 6 2 9200 20732)  
					{
						"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
						"Hotfix KB 2855269 is installed." | Out-File -FilePath $OutputFile -append
					}
					else
					{
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"Hotfix KB 2855269 is not installed." | Out-File -FilePath $OutputFile -append
					}
				}
				<#
					"Which files exists?" | Out-File -FilePath $OutputFile -append
					If (Test-path "$env:windir\system32\Daotpauth.dll")
					{ "Daotpauth.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
					else
					{ "Daotpauth.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
					
					If (Test-path "$env:windir\system32\Daotpcredentialprovider.dll")
					{ "Daotpcredentialprovider.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
					else
					{ "Daotpcredentialprovider.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
				#>
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append			
	"2855269 - Error message when you use an account that contains a special character in its DN to connect to a Windows Server 2012-based Direct Access server" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2855269/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2845152
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2845152" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2845152`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\drivers\Winnat.sys" 6 2 9200 20711) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2845152 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2845152 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2845152 - DirectAccess server cannot ping a DNS server or a domain controller in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2845152/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2844033
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2844033" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2844033`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Damgmt.dll" 6 2 9200 20708) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Ramgmtui.exe" 6 2 9200 20708))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2844033 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2844033 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2844033 - Add an Entry Point Wizard fails on a Windows Server 2012-based server in a domain that has a disjoint namespace" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2844033/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2796394
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2796394" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2796394`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\Ramgmtpsprovider.dll" 6 2 9200 20588)
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2796394 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2796394 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2796394 - Error when you run the Get-RemoteAccess cmdlet during DirectAccess setup in Windows Server 2012 Essentials" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2796394/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2769240
	#----------------------------------------
	# Implemented in the DirectAccess Server section

	#----------------------------------------
	# DirectAccess Client-Server: Hotfix Verification for KB 2795944
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Feb2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2795944" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2795944`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# file versions identical for x64/x86
		#
		# Iphlpsvc.dll  6.2.9200.16496;  ;6.2.9200.20604  
		# Iphlpsvcmigplugin.dll  6.2.9200.16496;  ;6.2.9200.20604
		# Ncbservice.dll  6.2.9200.16449  
		# Netprofm.dll  6.2.9200.16496;  ;6.2.9200.20604 		
		#
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 16496 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\Iphlpsvc.dll" 6 2 9200 20604 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 16496) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 2 9200 20604) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 16449) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 20604 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}	
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2795944 - Windows 8 and Windows Server 2012 update rollup: February 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2795944/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client/Server: Hotfix Verification for KB 2779768
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Dec2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2779768" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2779768`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# x86
		# Checking 4 specific fixes:
		#   Bfe.dll  6.2.9200.16451; 6.2.9200.20555
		#   Http.sys  6.2.9200.16451; 6.2.9200.20555
		#   Ikeext.dll  6.2.9200.16451; 6.2.9200.20555  
		#
		if ((CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 20555 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 20555 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 20555 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2795944 - Windows 8 and Windows Server 2012 update rollup: February 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2795944/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# Collect _ALERTS output file
	#----------------------------------------
	CollectFiles -filesToCollect $OutputFile -fileDescription "DirectAccess Server ALERTS" -SectionDescription $sectionDescription
}


$sectionDescription = "Diagnostic Version"
$OutputFile= "DiagnosticVersion_DA.TXT"
"`n"											| Out-File -FilePath $OutputFile -append
"Diagnostic  : DirectAccess Diagnostic"			| Out-File -FilePath $OutputFile -append
"Publish Date: 10.20.14"						| Out-File -FilePath $OutputFile -append
"`n`n`n"											| Out-File -FilePath $OutputFile -append
CollectFiles -filesToCollect $OutputFile -fileDescription "Diagnostic Version" -SectionDescription $sectionDescription	

$sectionDescription = "DirectAccess Diagnostic"
		
#----------------------------------------
#----- Static Data Collection BEGIN
#-----
#DirectAccessStatic:BEGIN
If ($ResultsCollectionType -eq "DirectAccessStatic")
{
	"[info] User chose Static Data Collection" | WriteTo-StdOut
	#_# $ResultsClientOrServer = Get-DiagInput -Id "DirectAccessClientOrServer"
	#_# DirectAccessCli -or- DirectAccessSrv
	if ($Global:RoleType) {$Script:ResultsClientOrServer = $Global:RoleType} else {
		MenuDiagInput-CliSrv
		DiagInput-ClientServer
	}
	write-host "   ResultsClientOrServer:  $Script:ResultsClientOrServer "
	If ($Script:ResultsClientOrServer -eq "DirectAccessCli")
	{
		"[info] User chose DirectAccess Client for Static Data Collection" | WriteTo-StdOut
		DAClientInfo
		DASharedNetInfo
		DAGeneralInfo
		"[info] DAClientAlerts starting" | WriteTo-StdOut
		DAClientAlerts
	}

	If ($Script:ResultsClientOrServer -eq "DirectAccessSrv")
	{
		"[info] User chose DirectAccess Server for Static Data Collection" | WriteTo-StdOut
		DAServerInfo
		DASharedNetInfo
		DAGeneralInfo
		"[info] DAServerAlerts starting" | WriteTo-StdOut
		DAServerAlerts
	}	
}
#DirectAccessStatic:END



#----------------------------------------
#----- Interactive Data Collection BEGIN
#-----
#DirectAccessInteractive:BEGIN
If ($ResultsCollectionType -eq "DirectAccessInteractive")
{
	"[info] User chose Interactive Data Collection" | WriteTo-StdOut
	"[info] Launching dialog to choose Client or Server." | WriteTo-StdOut	
	#_# $ResultsClientOrServer = Get-DiagInput -Id "DirectAccessClientOrServer"
	#_# DirectAccessCli -or- DirectAccessSrv
	if ($Global:RoleType) {$Script:ResultsClientOrServer = $Global:RoleType} else {
		MenuDiagInput-CliSrv
		DiagInput-ClientServer
	}
	#----------------------------------------
	# DirectAccess Client: Interactive
	#----------------------------------------
	If ($Script:ResultsClientOrServer -eq "DirectAccessCli")
	{
		"[info] User chose DirectAccess Client" | WriteTo-StdOut
		"[info] Prompting user to start tracing." | WriteTo-StdOut	
		#_# $ResultsDirectAccessClientD1 = Get-DiagInput -Id "DirectAccessCliStart"		# Pause dialog
		Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to start tracing. ===`n" -ForegroundColor Green
		do {
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		} until ($x.Character -ieq 's')

		
		#----------------------------------------
		# DirectAccess Client: Start Logging (CAPI, SChannel(Verbose), OTP, NCASvc, and NCSI Eventlogs)
		#----------------------------------------
		#
		#-----Enable CAPI2 logging (added 6/5/2013)
		#Detect CAPI2 logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"
				$capi2OrigStatus = (Get-ItemProperty $capi2RegKeyLocation).EventLogging
				$capi2NewStatus = $capi2OrigStatus

		# Set CAPI2 logging to enabled
			if ($capi2OrigStatus -ne "1")
			{
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable CAPI2 logging by setting registry value
					# reg.exe ; reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled /f /t REG_DWORD /d 0x1
					# pscmdlet; Set-ItemProperty $capi2RegKeyLocation Enabled 1
				
					#enable CAPI2 logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					$capi2NewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}

		
		#-----SCHANNEL EVENTLOG: State and Set to 7 (added 11/1/2013)
		#Detect Schannel logging state
			#reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging 
			"[info] Reading the Schannel EventLogging registry value." | WriteTo-StdOut	
				$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
				$schannelOrigStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
				$schannelNewStatus = $schannelOrigStatus
			"[info] schannelOrigStatus: $schannelOrigStatus" | WriteTo-StdOut	

		# Set SChannel logging to verbose
			if ($schannelOrigStatus -ne "7")
			{
				#reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging /f /t REG_DWORD /d 0x7
				"[info] Setting SChannel EventLogging registry value to 7 for verbose logging" | WriteTo-StdOut
					Set-ItemProperty $schannelRegKeyLocation EventLogging 7
					$schannelNewStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
			}
		
		#
		#-----Enable OTPCredentialProvider event logging (added 5/29/14)
		#Detect OTPCredentialProvider logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
				$otpOrigStatus = (Get-ItemProperty $otpRegKeyLocation).Enabled
				$otpNewStatus = $otpOrigStatus

			# Set OTP logging to enabled
			if ($otpOrigStatus -ne "1")
			{
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable OTP logging by setting registry value
					# reg.exe ; reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled /f /t REG_DWORD /d 0x1
					# pscmdlet; Set-ItemProperty $otpRegKeyLocation Enabled 1
				
					#enable OTP logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					$otpNewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}
			
			#Enabling Ncasvc and NCSI logging
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-Ncasvc/Operational /e:true"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false			
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-NCSI/Operational /e:true"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					
			
		#----------------------------------------
		# DirectAccess Client: Start Logging (Netsh Trace, Netsh WFP, PSR, DNS Cache, Restart IP Helper Service)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{
			#----------Netsh Trace: DirectAccess Scenario: START logging
				"[info] Starting Netsh Trace logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartDesc
				$OutputFileNetshTraceETL = "netshtrace.etl"
				$OutputFileNetshTraceCAB = "netshtrace.cab"
				$CommandToExecute = "cmd.exe /c netsh.exe trace start scenario=DirectAccess tracefile=netshtrace.etl capture=yes"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: START logging
				"[info] Starting Netsh WFP logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartDesc
				$OutputFileWFP = "wfpdiag.cab"
				# For some reason this hangs when running in powershell
					# $CommandToExecute = "cmd.exe /c netsh.exe wfp capture start"
					# RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				# Therefore, I'm using this method to launch WFP logging in the background.
				$ProcessArgs =  " /c netsh.exe wfp capture start"
				BackgroundProcessCreate -Process "cmd.exe" -Arguments $ProcessArgs			
			#----------PSR: Start Problem Steps Recorder
				"[info] Starting problem steps recorder." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartDesc
				$OutputFilePathPSR = join-path $PWD.path "IssueSteps.zip"
				$OutputFilePSR = "IssueSteps.zip"
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr /start /output " + $OutputFilePathPSR + " /maxsc 65 /exitonsave 1"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
				"[info] PSR should be started." | WriteTo-StdOut	
				
			#----------Clearing DNS Cache 
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_DnsClientClearCacheTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_DnsClientClearCacheDesc
				$CommandToExecute = "cmd.exe /c ipconfig /flushdns"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

			
			#----------IP Helper Logging: Enable
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" FileTracingMask -Value 0xffffffff -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" MaxFileSize -Value 0x10000000 -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 1 -force
				
			#----------Restarting the IP Helper service
				# Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_RestartingIpHlpSvcTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_RestartingIpHlpSvcDesc
				# Stop-Service iphlpsvc -Force
				# Start-Service iphlpsvc

				# Notes:
				#  Currently the IP Helper service is having issues when it is restarting. On several occasions, we have seen the IP Helper service fail to restart due to hanging in a STOPPING state.
		}

		#----------------------------------------
		# DirectAccess Client: Start Logging: ETLTraceCollector: OTP
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000)
		{
			#----------OTP: Start OTP logging
			"[info] OTP section: if OTP is enabled, start logging." | WriteTo-StdOut	
			$regkeyOtpCredentialProvider = "HKLM:\SOFTWARE\Policies\Microsoft\OtpCredentialProvider"
			if (Test-Path $regkeyOtpCredentialProvider) 
			{
				if ((Get-ItemProperty -Path $regkeyOtpCredentialProvider)."Enabled" -eq "1")
				{
					#----------OTP: Start OTP logging
						# OTP ETL tracing
							# logman create trace "OTP" -ow -o c:\OTPTracing.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
							"[info] Starting ETL tracing for OTP using XML file." | WriteTo-StdOut	
								$OTP_outfile = "OTP.etl"
								$OTPOutputFileNames = @($OTP_outfile)
								$OTPFileDescriptions = @("OTP")
								$OTPSectionDescriptions = @("OTP Tracing")
								$OTPETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "OTPTrace.XML" -ComponentName "OTP" -OutputFileName $OTPOutputFileNames -DoNotPromptUser
								RunCmD -commandToRun $OTPETL -CollectFiles $false
							"[info] ETL tracing for OTP should be running." | WriteTo-StdOut	
				}
			}
			else
			{
				"[info] OTP is not enabled on this client." | WriteTo-StdOut	
			}
		}
		
		#----------------------------------------
		# DirectAccess Client: Start Logging: ETLTraceCollector: SChannel
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000)
		{			
			#----------SChannel: Start SChannel logging
				"[info] SChannel ETL tracing section" | WriteTo-StdOut
				#Enable Schannel ETL tracing
				# logman -start schannel -p {37d2c3cd-c5d4-4587-8531-4696c44244c8} 0x4000ffff 3 -ets
				"[info] Starting ETL tracing for schannel using XML file." | WriteTo-StdOut	
					$schannel_outfile = "schannel.etl"
					$schannelOutputFileNames = @($SChannel_outfile)
					$schannelFileDescriptions = @("SChannel")
					$schannelSectionDescriptions = @("SChannel Component")
					$schannelDCS = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "schannel.XML" -ComponentName "SChannel" -OutputFileName $SChannelOutputFileNames -DoNotPromptUser
				"[info] ETL tracing for schannel should be running." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Client: Prompt to Stop Logging
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{
			# Pause interaction to stop logging
			"[info] Launching dialog prompting the user to Stop tracing." | WriteTo-StdOut	

			#_# $ResultsDirectAccessCliStop = Get-DiagInput -Id "DirectAccessCliStop"
			Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to stop tracing. ===`n" -ForegroundColor Green
			do {
				$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			} until ($x.Character -ieq 's')
		}

		#----------------------------------------
		# DirectAccess Client: Stop Logging (Netsh Trace, Netsh WFP, PSR)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{	
			#----------Netsh Trace DirectAccess Scenario: STOP logging
				"[info] Stopping Netsh Trace logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe trace stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: STOP logging
				"[info] Stopping Netsh WFP logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe wfp capture stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------PSR: STOP Problem Steps Recorder
				"[info] Stopping problem steps recorder." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopDesc
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr.exe /stop"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
		}

		#----------------------------------------
		# DirectAccess Client: Stop Logging (CAPI2 and Schannel Eventlogs)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{
			#----------------------------------------
			# DirectAccess Client: Stop Logging (CAPI2 and Schannel)
			#----------------------------------------
			#
			#-----CAPI2 EVENTLOG: Set to original state
			"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
			$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"
			if ($capi2OrigStatus -ne "1")
			{
				#disable CAPI2 logging using wevtutil
				$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:false"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				
				#disable CAPI2 logging using the registry
				# Set-ItemProperty -path $capi2RegKeyLocation Enabled $capi2OrigStatus
			}
			
			#----------------------------------------
			# DirectAccess Client: Collect Eventlog (CAPI2)
			#----------------------------------------
			#
			$EventLogNames = "Microsoft-Windows-CAPI2/Operational"
			$Prefix = ""
			$Suffix = "_evt_"
			.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "Certificates Information" -Prefix $Prefix -Suffix $Suffix
			
			#-----SCHANNEL EVENTLOG: Set to original state
			"[info] Setting Schannel Event logging back to original status." | WriteTo-StdOut
			$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
			Set-ItemProperty -path $schannelRegKeyLocation EventLogging $schannelOrigStatus
			
			#
			#-----OTP EVENTLOG: Set to original state
			"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
			$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
			if ($otpOrigStatus -ne "1")
			{
				#disable OTP logging using wevtutil
				$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:false"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				
				#disable OTP logging using the registry
				# Set-ItemProperty -path $capi2RegKeyLocation Enabled $otpOrigStatus
			}
		
			#----------------------------------------
			# Collect Eventlog (OTP)
			#----------------------------------------
			#
			$EventLogNames = "Microsoft-Windows-OtpCredentialProvider/Operational"
			$Prefix = ""
			$Suffix = "_evt_"
			.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "OTP" -Prefix $Prefix -Suffix $Suffix
		}
		
		#----------------------------------------
		# DirectAccess Client: IP Helper Logging: Disable (Added 4/1/14)
		#----------------------------------------
		#
			Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 0 -force
		
		#----------------------------------------
		# DirectAccess Client: Save DNS Client cache using ipconfig /displaydns
		#----------------------------------------
		#
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_SaveDnsClientCacheTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_SaveDnsClientCacheDesc
			$OutputFileDnsClientCache = $Computername + "_DirectAccessClient_DnsClientCache_ipconfig-displaydns.TXT"
			$CommandToExecute = "cmd.exe /c ipconfig /displaydns > $OutputFileDnsClientCache"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			
		#----------------------------------------
		# DirectAccess Client: Stop Logging: ETLTraceCollector: OTP
		#----------------------------------------
		#			
		if ($OSVersion.Build -gt 7000)
		{		
			#----------OTP: Stop OTP logging
			"[info] Stopping OTP ETL logging." | WriteTo-StdOut	
			$regkeyOtpCredentialProvider = "HKLM:\SOFTWARE\Policies\Microsoft\OtpCredentialProvider"
			if (Test-Path $regkeyOtpCredentialProvider) 
			{
				if ((Get-ItemProperty -Path $regkeyOtpCredentialProvider)."Enabled" -eq "1")
				{
					#----------OTP: Stop OTP logging
					# OTP ETL Logging
					# logman stop "OTP" -ets
					"[info] Stopping OTP ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $OTPETL -OutputFileName $OTPOutputFileNames -FileDescription $OTPFileDescriptions -SectionDescription $OTPSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
					"[info] OTP ETL logging should be stopped now." | WriteTo-StdOut			
				}
			}
		}
		
		#----------------------------------------
		# DirectAccess Client: Stop Logging: ETLTraceCollector: Schannel
		#----------------------------------------
		#			
		if ($OSVersion.Build -gt 7000)
		{			
			#-----SCHANNEL ETL Logging
				# logman -stop schannel -ets
				"[info] Stopping Schannel ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SChannelDCS -OutputFileName $SChannelOutputFileNames -FileDescription $SChannelFileDescriptions -SectionDescription $SChannelSectionDescriptions -DoNotPromptUser -DisableRootCauseDetected
				"[info] Schannel ETL logging should be stopped now." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Client: Collect Files
		#----------------------------------------
		#
		#----------Netsh Trace DirectAccess Scenario: Collect logging
			"[info] Collecting Netsh Trace output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectDesc
			$sectionDescription = "Netsh Trace DirectAccess Scenario"
			CollectFiles -filesToCollect $OutputFileNetshTraceETL -fileDescription "Netsh Trace DirectAccess Scenario: ETL" -SectionDescription $sectionDescription
			CollectFiles -filesToCollect $OutputFileNetshTraceCAB -fileDescription "Netsh Trace DirectAccess Scenario: CAB" -SectionDescription $sectionDescription
		#----------Netsh WFP Capture: Collect logging
			"[info] Collecting Netsh WFP output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectDesc
			$sectionDescription = "WFP Tracing"
			CollectFiles -filesToCollect $OutputFileWFP -fileDescription "WFP tracing" -SectionDescription $sectionDescription
		#----------PSR: Collect Problem Steps Recorder output
			"[info] Collecting problem steps recorder output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectDesc
			$sectionDescription = "Problem Steps Recorder (PSR)"
			Start-Sleep 15
			CollectFiles -filesToCollect $OutputFilePSR -fileDescription "PSR logging" -SectionDescription $sectionDescription
			Start-Sleep 15
		#----------Collecting DNS Cache output
			"[info] Collecting DNS cache output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_CollectDnsClientCacheTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_CollectDnsClientCacheDesc
			$sectionDescription = "DNS Client"
			CollectFiles -filesToCollect $OutputFileDnsClientCache -fileDescription "DNS Client cache" -SectionDescription $sectionDescription
		#----------IP Helper Logging: Collect (Added 04/01/14)			
			"[info] Collecting IP Helper log files." | WriteTo-StdOut
			$sectionDescription = "IP Helper service logging"
			$tracingdir = join-path $env:windir tracing
			$OutputFileIpHlpSvcLog = join-path $tracingdir "IpHlpSvc.Log"
			$OutputFileIpHlpSvcOld = join-path $tracingdir "IpHlpSvc.Old" 
			CollectFiles -filesToCollect $OutputFileIpHlpSvcLog -fileDescription "DirectAccess IpHlpSvc Log" -SectionDescription $sectionDescription
			CollectFiles -filesToCollect $OutputFileIpHlpSvcOld -fileDescription "DirectAccess IpHlpSvc Log (Old)" -SectionDescription $sectionDescription		
		#----------NetCfg ETL Logs: Collect (Added 08/12/14)
			$sectionDescription = "NetCfg Logs"
			$OutputDirectory = "$env:windir\inf\netcfg*.etl"
			$OutputFileNetCfgCab = "NetCfgETL.cab"
			CompressCollectFiles -DestinationFileName $OutputFileNetCfgCab -filesToCollect $OutputDirectory -sectionDescription $sectionDescription -fileDescription "NetCfg ETL Logs: CAB"

		#----------------------------------------
		# DirectAccess Client: Static Data Collection
		#----------------------------------------
		if ($true) 
		{
			DAClientInfo
			DASharedNetInfo
		}
		
		#----------------------------------------
		# DirectAccess Client Alerts
		#----------------------------------------
		if ($true) 
		{
			"[info] DAClientAlerts starting" | WriteTo-StdOut
			DAClientAlerts
		}
	} #DirectAccessClient:END
	
	#----------------------------------------
	# DirectAccess Server: Interactive
	#----------------------------------------
	If ($Script:ResultsClientOrServer -eq "DirectAccessSrv")
	{
		"[info] User chose DirectAccess Server" | WriteTo-StdOut
		"[info] DirectAccess Server section" | WriteTo-StdOut
		$sectionDescription = "DirectAccess Diagnostic"
		"[info] Launching dialog prompting the user to Start tracing." | WriteTo-StdOut	
		
		#_# $ResultsDirectAccessClientD1 = Get-DiagInput -Id "DirectAccessSrvStart"		# Pause Dialog
		Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to start tracing. ===`n" -ForegroundColor Green
		do {
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		} until ($x.Character -ieq 's')
		
		#----------------------------------------
		# DirectAccess Server: Start Logging (CAPI and SChanne-Verbose Eventlogs)
		#----------------------------------------
		#

		#-----Enable CAPI2 logging (added 6/5/2013)
		#Detect CAPI2 logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"
				$capi2OrigStatus = (Get-ItemProperty $capi2RegKeyLocation).EventLogging
				$capi2NewStatus = $capi2OrigStatus

		# Set CAPI2 logging to enabled
			if ($capi2OrigStatus -ne "1")
			{
				#reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled /f /t REG_DWORD /d 0x1
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable CAPI2 logging using the registry
					#  Set-ItemProperty $capi2RegKeyLocation Enabled 1
					
					#enable CAPI2 logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
					$capi2NewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}
		
		#-----SCHANNEL EVENTLOG: State and Set to 7 (added 11/1/2013)
		#Detect Schannel logging state
			#reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging 
			"[info] Reading the Schannel EventLogging registry value." | WriteTo-StdOut	
				$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
				$schannelOrigStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
				$schannelNewStatus = $schannelOrigStatus
			"[info] schannelOrigStatus: $schannelOrigStatus" | WriteTo-StdOut	

		# Set SChannel logging to verbose
			if ($schannelOrigStatus -ne "7")
			{
				#reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging /f /t REG_DWORD /d 0x7
				"[info] Setting SChannel EventLogging registry value to 7 for verbose logging" | WriteTo-StdOut
					Set-ItemProperty $schannelRegKeyLocation EventLogging 7
					$schannelNewStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
			}

		#
		#-----Enable OTPCredentialProvider event logging (added 5/29/14)
		#Detect OTPCredentialProvider logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
				$otpOrigStatus = (Get-ItemProperty $otpRegKeyLocation).Enabled
				$otpNewStatus = $otpOrigStatus

			# Set OTP logging to enabled
			if ($otpOrigStatus -ne "1")
			{
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable OTP logging by setting registry value
					# reg.exe ; reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled /f /t REG_DWORD /d 0x1
					# pscmdlet; Set-ItemProperty $otpRegKeyLocation Enabled 1
				
					#enable OTP logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					$otpNewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}

		#Enabling Ncasvc and NCSI logging
		$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-Ncasvc/Operational /e:true"
		RunCmD -commandToRun $CommandToExecute  -CollectFiles $false			
		$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-NCSI/Operational /e:true"
		RunCmD -commandToRun $CommandToExecute  -CollectFiles $false			

		#----------------------------------------
		# DirectAccess Server: Start Logging (Netsh Trace, Netsh WFP, PSR)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{
			#----------Netsh Trace: DirectAccess Scenario: START logging
				"[info] Starting Netsh Trace logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartDesc
				$OutputFileNetshTraceETL = "netshtrace.etl"
				$OutputFileNetshTraceCAB = "netshtrace.cab"
				$CommandToExecute = "cmd.exe /c netsh.exe trace start scenario=DirectAccess tracefile=netshtrace.etl capture=yes"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: START logging
				"[info] Starting Netsh WFP logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartDesc
				$OutputFileWFP = "wfpdiag.cab"
				# For some reason this hangs when running in powershell
					# $CommandToExecute = "cmd.exe /c netsh.exe wfp capture start"
					# RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				# Therefore, I'm using this method to launch WFP logging in the background.
				$ProcessArgs =  " /c netsh.exe wfp capture start"
				BackgroundProcessCreate -Process "cmd.exe" -Arguments $ProcessArgs			
			#----------PSR: Start Problem Steps Recorder
				"[info] Starting problem steps recorder." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartDesc
				$OutputFilePathPSR = join-path $PWD.path "IssueSteps.zip"
				$OutputFilePSR = "IssueSteps.zip"
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr /start /output " + $OutputFilePathPSR + " /maxsc 65 /exitonsave 1"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
			#----------IP Helper Logging: Enable
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" FileTracingMask -Value 0xffffffff -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" MaxFileSize -Value 0x10000000 -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 1 -force
		}


		#----------------------------------------
		# DirectAccess Server: Start Logging: ETLTraceCollector
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000)
		{
			#----------Kerberos: Start SecurityKerberos logging
				# SecurityKerberos ETL tracing
				# logman create trace "SecurityKerberos" -ow -o c:\SecurityKerberos.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
				"[info] Starting ETL tracing for SecurityKerberos using XML file." | WriteTo-StdOut	
					$SecurityKerberos_outfile = "SecurityKerberos.etl"
					$SecurityKerberosOutputFileNames = @($SecurityKerberos_outfile)
					$SecurityKerberosFileDescriptions = @("SecurityKerberos")
					$SecurityKerberosSectionDescriptions = @("SecurityKerberos Tracing")
					$SecurityKerberosETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "SecurityKerberos.XML" -ComponentName "SecurityKerberos" -OutputFileName $SecurityKerberosOutputFileNames -DoNotPromptUser
					# RunCmD -commandToRun $SecurityKerberosETL -CollectFiles $false
				"[info] ETL tracing for SecurityKerberos should be running." | WriteTo-StdOut

			#----------NTLM: Start SecurityNTLM logging
				# SecurityNTLM ETL tracing
				# logman create trace "SecurityNTLM" -ow -o c:\SecurityNTLM.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
				"[info] Starting ETL tracing for SecurityNTLM using XML file." | WriteTo-StdOut	
					$SecurityNTLM_outfile = "SecurityNTLM.etl"
					$SecurityNTLMOutputFileNames = @($SecurityNTLM_outfile)
					$SecurityNTLMFileDescriptions = @("SecurityNTLM")
					$SecurityNTLMSectionDescriptions = @("SecurityNTLM Tracing")
					$SecurityNTLMETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "SecurityNTLM.XML" -ComponentName "SecurityNTLM" -OutputFileName $SecurityNTLMOutputFileNames -DoNotPromptUser
					# RunCmD -commandToRun $SecurityNTLMETL -CollectFiles $false
				"[info] ETL tracing for SecurityNTLM should be running." | WriteTo-StdOut

			#----------OTP: Start OTP logging
				"[info] OTP section: if OTP is enabled, start logging." | WriteTo-StdOut
				$regkeyOtpEnabled = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteAccess\Config\Otp"
				if (Test-Path $regkeyOtpEnabled) 
				{
					if ((Get-ItemProperty -Path $regkeyOtpEnabled)."Enabled" -eq "1")
					{
						"[info] Determining if OTP is enabled" | WriteTo-StdOut	
						$daOTPAuth = get-daotpauthentication
						$daOTPStatus = $daOTPAuth.otpstatus
						if($daOTPStatus -eq "enabled")
						{
							# OTP ETL tracing
							# logman create trace "OTP" -ow -o c:\OTPTracing.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
							"[info] Starting ETL tracing for OTP using XML file." | WriteTo-StdOut	
								$OTP_outfile = "OTP.etl"
								$OTPOutputFileNames = @($OTP_outfile)
								$OTPFileDescriptions = @("OTP")
								$OTPSectionDescriptions = @("OTP Tracing")
								$OTPETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "OTPTrace.XML" -ComponentName "OTP" -OutputFileName $OTPOutputFileNames -DoNotPromptUser
								# RunCmD -commandToRun $OTPETL -CollectFiles $false
							"[info] ETL tracing for OTP should be running." | WriteTo-StdOut	
						}
					}
				}
				else
				{
					"[info] OTP is not enabled on this server." | WriteTo-StdOut	
				}

			#----------------------------------------
			# DirectAccess Server: Start Logging: ETLTraceCollector: SChannel
			#----------------------------------------
			#		
			if ($OSVersion.Build -gt 7000)
			{			
				#----------SChannel: Start SChannel logging
					"[info] SChannel ETL tracing section" | WriteTo-StdOut
					#Enable Schannel ETL tracing
					# logman -start schannel -p {37d2c3cd-c5d4-4587-8531-4696c44244c8} 0x4000ffff 3 -ets
					"[info] Starting ETL tracing for schannel using XML file." | WriteTo-StdOut	
						$schannel_outfile = "schannel.etl"
						$schannelOutputFileNames = @($SChannel_outfile)
						$schannelFileDescriptions = @("SChannel")
						$schannelSectionDescriptions = @("SChannel Component")
						$schannelDCS = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "schannel.XML" -ComponentName "SChannel" -OutputFileName $SChannelOutputFileNames -DoNotPromptUser
					"[info] ETL tracing for schannel should be running." | WriteTo-StdOut
			}
			
			#----------------------------------------
			# DirectAccess Server: Start Logging: ETLTraceCollector: DASrvPSLogging
			#----------------------------------------
			#		
			if ($OSVersion.Build -gt 9000)
			{			
				#----------DASrvPSLogging: Start DASrvPSLogging logging
					"[info] DASrvPSLogging ETL tracing section" | WriteTo-StdOut
					#Enable DASrvPSLogging ETL tracing
						#logman create trace ETWTrace -ow -o c:\ETWTrace.etl -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode 0x2 -max 2048 -ets 
						#logman update trace ETWTrace -p {62DFF3DA-7513-4FCA-BC73-25B111FBB1DB} 0xffffffffffffffff 0xff -ets 
						#logman update trace ETWTrace -p {AAD4C46D-56DE-4F98-BDA2-B5EAEBDD2B04} 0xffffffffffffffff 0xff -ets 
						#
					"[info] Starting ETL tracing for DASrvPSLogging using XML file." | WriteTo-StdOut	
						$DASrvPSLogging_outfile = "DASrvPSLogging.etl"
						$DASrvPSLoggingOutputFileNames = @($DASrvPSLogging_outfile)
						$DASrvPSLoggingFileDescriptions = @("DASrvPSLogging")
						$DASrvPSLoggingSectionDescriptions = @("DASrvPSLogging Section")
						$DASrvPSLoggingDCS = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "DASrvPSLogging.XML" -ComponentName "DASrvPSLogging" -OutputFileName $DASrvPSLoggingOutputFileNames -DoNotPromptUser
					"[info] ETL tracing for DASrvPSLogging should be running." | WriteTo-StdOut
			}
		}
		
		#----------------------------------------
		# DirectAccess Server: Prompt to Stop Logging
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{
			# Pause interaction to stop logging
			#_# $ResultsDirectAccessCliStop = Get-DiagInput -Id "DirectAccessSrvStop"
			Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to stop tracing. ===`n" -ForegroundColor Green
			do {
				$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			} until ($x.Character -ieq 's')
			
			"[info] User clicked Next on the Stop dialog." | WriteTo-StdOut				
		}
		
		#----------------------------------------
		# DirectAccess Server: Stop Logging (Netsh Trace, Netsh WFP, PSR)
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000)
		{
			#----------Netsh Trace DirectAccess Scenario: STOP logging
				"[info] Stopping Netsh Trace logging." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe trace stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: STOP logging
				"[info] Stopping Netsh WFP logging." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe wfp capture stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------PSR: STOP Problem Steps Recorder
				"[info] Stopping problem steps recorder." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopDesc
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr.exe /stop"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
			#----------------------------------------
			# DirectAccess Client: IP Helper Logging: Disable (Added 4/1/14)
			#----------------------------------------
			#
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 0 -force
		}

		#----------------------------------------
		# DirectAccess Server: Stop Logging (CAPI2 and Schannel)
		#----------------------------------------
		#
		#-----CAPI2 EVENTLOG: Set to original state
		"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
		$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"

		if ($capi2OrigStatus -ne "1")
		{
			#disable CAPI2 logging using wevtutil
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:false"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

			#disable CAPI2 logging using the registry
			# Set-ItemProperty -path $capi2RegKeyLocation Enabled $capi2OrigStatus
		}
		#----------------------------------------
		# DirectAccess Server: Collect Eventlog (CAPI2)
		#----------------------------------------
		#
		$EventLogNames = "Microsoft-Windows-CAPI2/Operational"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "Certificates Information" -Prefix $Prefix -Suffix $Suffix		

		#----------------------------------------
		#-----OTP EVENTLOG: Set to original state
		#----------------------------------------
		"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
		$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
		if ($otpOrigStatus -ne "1")
		{
			#disable OTP logging using wevtutil
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:false"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			
			#disable OTP logging using the registry
			# Set-ItemProperty -path $capi2RegKeyLocation Enabled $otpOrigStatus
		}
	
		#----------------------------------------
		# Collect Eventlog (OTP)
		#----------------------------------------
		#
		$EventLogNames = "Microsoft-Windows-OtpCredentialProvider/Operational"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "OTP" -Prefix $Prefix -Suffix $Suffix
	
		#-----SCHANNEL EVENTLOG: Set to original state
		"[info] Setting Schannel Event logging back to original status." | WriteTo-StdOut
		$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
		Set-ItemProperty -path $schannelRegKeyLocation EventLogging $schannelOrigStatus

		#----------------------------------------
		# DirectAccess Server: Stop Logging: ETLTraceCollector
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{
			#----------Kerberos: Stop SecurityKerberos logging
				# SecurityKerberos ETL Logging
				# logman stop "SecurityKerberos" -ets
				"[info] Stopping SecurityKerberos ETL logging." | WriteTo-StdOut
				Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SecurityKerberosETL -OutputFileName $SecurityKerberosOutputFileNames -FileDescription $SecurityKerberosFileDescriptions -SectionDescription $SecurityKerberosSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
				"[info] SecurityKerberos ETL logging should be stopped now." | WriteTo-StdOut

			#----------NTLM: Stop SecurityNTLM logging
				# SecurityNTLM ETL Logging
				# logman stop "SecurityNTLM" -ets
				"[info] Stopping SecurityNTLM ETL logging." | WriteTo-StdOut
				Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SecurityNTLMETL -OutputFileName $SecurityNTLMOutputFileNames -FileDescription $SecurityNTLMFileDescriptions -SectionDescription $SecurityNTLMSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
				"[info] SecurityNTLM ETL logging should be stopped now." | WriteTo-StdOut

			#----------OTP: Stop OTP logging
				"[info] OTP section: if OTP is enabled, stop logging." | WriteTo-StdOut	
				$regkeyOtpEnabled = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteAccess\Config\Otp"
				if (Test-Path $regkeyOtpEnabled) 
				{
					if ((Get-ItemProperty -Path $regkeyOtpEnabled)."Enabled" -eq "1")
					{
						# OTP ETL Logging
						$daOTPAuth = get-daotpauthentication
						$daOTPStatus = $daOTPAuth.otpstatus
						if($daOTPStatus -eq "enabled")
						{
							# OTP ETL Logging
							# logman stop "OTP" -ets
							"[info] Stopping OTP ETL logging." | WriteTo-StdOut
							Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $OTPETL -OutputFileName $OTPOutputFileNames -FileDescription $OTPFileDescriptions -SectionDescription $OTPSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
							"[info] OTP ETL logging should be stopped now." | WriteTo-StdOut			
						}
					}
				}
				else
				{
					"[info] OTP is not enabled on this server." | WriteTo-StdOut
				}
			
			#-----SCHANNEL ETL Logging
				# logman -stop schannel -ets
				"[info] Stopping Schannel ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SChannelDCS -OutputFileName $SChannelOutputFileNames -FileDescription $SChannelFileDescriptions -SectionDescription $SChannelSectionDescriptions -DoNotPromptUser -DisableRootCauseDetected
				"[info] Schannel ETL logging should be stopped now." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Server: Stop Logging: ETLTraceCollector: DASrvPSLogging
		#----------------------------------------
		#			
		if ($OSVersion.Build -gt 9000)
		{			
			#-----DASrvPSLogging ETL Logging
				# logman -stop DASrvPSLogging -ets
				"[info] Stopping DASrvPSLogging ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $DASrvPSLoggingDCS -OutputFileName $DASrvPSLoggingFileNames -FileDescription $DASrvPSLoggingFileDescriptions -SectionDescription $DASrvPSLoggingSectionDescriptions -DoNotPromptUser -DisableRootCauseDetected
				"[info] DASrvPSLogging ETL logging should be stopped now." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Server: Collect Files
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000)
		{
			#----------Netsh Trace DirectAccess Scenario: STOP logging
				"[info] Collecting Netsh Trace output." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectDesc
				$sectionDescription = "Netsh Trace DirectAccess Scenario"
				CollectFiles -filesToCollect $OutputFileNetshTraceETL -fileDescription "Netsh Trace DirectAccess Scenario: ETL" -SectionDescription $sectionDescription
				CollectFiles -filesToCollect $OutputFileNetshTraceCAB -fileDescription "Netsh Trace DirectAccess Scenario: CAB" -SectionDescription $sectionDescription
			#----------Netsh WFP Capture: STOP logging
				"[info] Collecting Netsh WFP output." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectDesc
				$sectionDescription = "WFP Tracing"
				CollectFiles -filesToCollect $OutputFileWFP -fileDescription "WFP tracing" -SectionDescription $sectionDescription
			#----------PSR: STOP Problem Steps Recorder
				"[info] Collecting problem steps recorder output." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectDesc
				$sectionDescription = "Problem Steps Recorder (PSR)"
				Start-Sleep 15
				CollectFiles -filesToCollect $OutputFilePSR -fileDescription "PSR logging" -SectionDescription $sectionDescription
				Start-Sleep 15
			#----------IP Helper Logging: Collect (Added 04/01/14)			
				"[info] Collecting IP Helper log files." | WriteTo-StdOut
				$sectionDescription = "IP Helper service logging"
				$tracingdir = join-path $env:windir tracing
				$OutputFileIpHlpSvcLog = join-path $tracingdir "IpHlpSvc.Log"
				$OutputFileIpHlpSvcOld = join-path $tracingdir "IpHlpSvc.Old" 
				CollectFiles -filesToCollect $OutputFileIpHlpSvcLog -fileDescription "DirectAccess IpHlpSvc Log" -SectionDescription $sectionDescription
				CollectFiles -filesToCollect $OutputFileIpHlpSvcOld -fileDescription "DirectAccess IpHlpSvc Log (Old)" -SectionDescription $sectionDescription

			#----------NetCfg ETL Logs: Collect (Added 08.12.14)
				$sectionDescription = "NetCfg Logs"
				$OutputDirectory = "$env:windir\inf\netcfg*.etl"
				$OutputFileNetCfgCab = "NetCfgETL.cab"
				CompressCollectFiles -DestinationFileName $OutputFileNetCfgCab -filesToCollect $OutputDirectory -sectionDescription $sectionDescription -fileDescription "NetCfg ETL Logs: CAB"
		}

		#----------------------------------------
		# DirectAccess Server: Static Data Collection
		#----------------------------------------
		if ($true) 
		{
			"[info] DirectAccess Server: Static Data Collection" | WriteTo-StdOut
			DAServerInfo
			DASharedNetInfo
		}

		#----------------------------------------
		# DirectAccess Server Alerts
		#----------------------------------------
		if ($true) 
		{
			"[info] DirectAccess Server Alerts" | WriteTo-StdOut
			DAServerAlerts
		}
	} #DirectAccessServer:END
} #DirectAccessInteractive:END


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAV0Z46b3Z+x7bO
# ZZoHXeVQEM57TtFNN0BoN3Iq2h2VqKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFQ0SrLlUbyxaLIZ7Lj3C+fq
# xPRFZw4V3Lr3+hMEXwynMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCvwH7DepaJdNxsMnJaGZ/pcNXeKO8nPO+70tdcsna/b65WUKrqo9Ra
# xznfsrzpZ60ESG4xNBCv8dq+UW1hZnsvvCbS2tx1nthJEyHtf7HaxafUgeusPtIT
# l5UVt1oG4DMBs3zAGOcu2yjjTr5q12aho94jW/kQvyBhvYLzTfokF8rxUIgLEpIP
# 67+jxcXimO+lvcqfnDp4yV8SLpEoNPYWEaOa2O/nrx9rdbsqNnBnQZfhgaGdks0J
# smu3OTyyt0aXDRUdiBHsMLCCCuq0/hvQ8PDD6XbC0CrzOtkn00x8fsyY/dujrY8b
# ubg8EOvG+ozoyCXiAerVFIv6yNvM+qSIoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIOsQKUNU3/cUP/kiLOLHGGTEhsnIQwVfqNwfoqUV5ZRAAgZi3ohQ
# jVsYEzIwMjIwODAxMTMzMDA2LjE4M1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkkD6MCIYDzIwMjIwODAx
# MjAwOTMwWhgPMjAyMjA4MDIyMDA5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaSQPoCAQAwBwIBAAICGMMwBwIBAAICETcwCgIFAOaTknoCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAQ1qtYa2LSfDW+BDUUoOftDZv9w6F7iDLwB+lQzu6X
# QlHIci1LNZMFSSBAkoXbyZbVGdkg1uTIWCGtbVNfd0q1t6sxo90U8Cjg6y7pNU/l
# l3iA2/cvKCIGP1KLb7626OP/8fQ9mqyT96k8fTxa07+kKxqTZ5YOJwX3pm56Z+ml
# wjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEII3dysCeo7urclwYJcli
# 87g3mEipUs4xHjzDHNMYeRJXMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCBM
# /oPrXsFfr+1PchkVxDmLaYZ9+WVo4GT40P2ihJpbTjANBgkqhkiG9w0BAQsFAASC
# AgA4xfGt0wOH+S/V1vg6dU17+okzRz6D1ZS0ar9em7iQcWVETHHF4JeH49Sijsun
# HUeMr7wqOV1/i74I3VJyu+l34wyUw4BMli2QCczwriICENXm7JomTjEnzjO+dkoo
# jlpR3GTZwHOWuKcqUt0PjW5fcmfHmQniq6/jgq97UfapGFVVdIf+zSLvxx3t3hUZ
# 7RRvlhwcK16kE/BLl+jUyo9jaNWjwE/B9vx5RvseB3keQtABknzS4fK9QIpMbSEg
# VVCWhilo+5XvI+Ekv8h6Dgx68w7cFB6d+WoOhEd9ZeqB3SCAQKyTyLMsz1IJOWUj
# aJ2ZP/c8bYN4ilkWjOfjzqD8SmYVbxOF0aHowKaQ6KR/Jt/IUrLnns7fpUlGTp2f
# GeDvt96nnnTKhty6FVfY5hEezjHZJLAUc+CuR9E3odIOE7+EyVm6aO8ThSh2eAOJ
# QWdKxFdyaGpqaCxwlHo0y3tceMVBSkC/jE0bZEYNBjKS7drzk7ss82Fr+aZRFoM0
# aihQUK+4m4bi2AeUe7+LY5ctEQZBvxegZw7IPu+E5RoXKy9/Ezl7q5LHRm3XG4U0
# TgdQD6ze2mks6tAy9XPDZZ/S02HGJpGWLtBUbM/WjV1uAaBSRV/L87/W4OtqfGdZ
# v8Nod87UePa/CDIhXKn05JDInLhPVhQCf+SLBMuaTfSHUg==
# SIG # End signature block
