#************************************************
# DC_HyperVNetworking.ps1
# Version 1.0.04.22.14: Created script.
# Version 1.1.04.26.14: Corrected formatting issues with PowerShell output using format-table
# Version 1.2.05.23.14: Added Get-SCIPAddress; Added Hyper-V registry output (and placed at the top of the script)
# Version 1.3.07.31.14: Moved the "Hyper-V Network Virtualization NAT Configuration" section into its own code block for WS2012R2+. 
# Date: 2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: PS cmdlets
# Called from: Networking Diags
#*******************************************************


Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptVariable


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
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
}



$sectionDescription = "Hyper-V Networking Settings"

#----------Registry
$outputFile = $Computername + "_HyperVNetworking_reg_.TXT"
#grouped registry values together:
#  RegKeys: vmms;
#  RegKeys: vmsmp, smsp, vmsvsf, vmsvsp
#  RegKeys: vmbus, vmbushid, vmbusr
#  RegKeys: vmbusr, vmicguestinterface, vmicheartbeat, vmickvpexchange, vmicrdv, vmicshutdown, vmictimesync, vmicvss

$CurrentVersionKeys = 	"HKLM\SYSTEM\CurrentControlSet\services\vmms",
						"HKLM\SYSTEM\CurrentControlSet\services\vmsmp",
						"HKLM\SYSTEM\CurrentControlSet\services\VMSP",
						"HKLM\SYSTEM\CurrentControlSet\services\VMSVSF",
						"HKLM\SYSTEM\CurrentControlSet\services\VMSVSP",
						"HKLM\SYSTEM\CurrentControlSet\services\vmbus",
						"HKLM\SYSTEM\CurrentControlSet\services\VMBusHID",
						"HKLM\SYSTEM\CurrentControlSet\services\vmbusr",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicguestinterface",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicheartbeat",
						"HKLM\SYSTEM\CurrentControlSet\services\vmickvpexchange",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicrdv",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicshutdown",
						"HKLM\SYSTEM\CurrentControlSet\services\vmictimesync",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicvss"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $outputFile -fileDescription "Hyper-V Registry Keys" -SectionDescription $sectionDescription



# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

$outputFile = $Computername + "_HyperVNetworking_info_pscmdlets.TXT"
"===================================================="	| Out-File -FilePath $OutputFile -append
"Hyper-V Networking Settings Powershell Cmdlets"		| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"Overview"												| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Server Configuration"							| Out-File -FilePath $OutputFile -append
"  1. Get-VMHost"										| Out-File -FilePath $OutputFile -append
"  2. Get-VMHostNumaNode"								| Out-File -FilePath $OutputFile -append
"  3. Get-VMHostNumaNodeStatus"							| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Switch Configuration"							| Out-File -FilePath $OutputFile -append
"  1. Get-VMSwitch *"									| Out-File -FilePath $OutputFile -append
"  2. Get-VMSwitch * | fl"								| Out-File -FilePath $OutputFile -append
#_#"  3. Get-VMSwitchTeam -SwitchName ""vSwitch"" | fl -Property * " | Out-File -FilePath $OutputFile -append
"  3. Get-VMSwitchTeam -EA SilentlyContinue | fl -Property *" | Out-File -FilePath $OutputFile -append
#_#"  4. Get-VMSwitch -Name ""vSwitch"" | Get-VMSwitchExtension | fl -Property * " | Out-File -FilePath $OutputFile -append
"  4. Get-VMSwitch | Get-VMSwitchExtension | fl -Property *" | Out-File -FilePath $OutputFile -append
"  5. Get-VMSystemSwitchExtension | fl -Property * "	| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Adapter Configuration"					| Out-File -FilePath $OutputFile -append
"  1. Get-VMNetworkAdapter -ManagementOS"				| Out-File -FilePath $OutputFile -append
"  2. Get-VMNetworkAdapter -All"						| Out-File -FilePath $OutputFile -append
"  3. Get-VMNetworkAdapter *"							| Out-File -FilePath $OutputFile -append
"  4. Get-VMNetworkAdapter * | fl"						| Out-File -FilePath $OutputFile -append
"  5. Get-VMNetworkAdapter -ManagementOS | fl -Property *"		| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization Configuration"			| Out-File -FilePath $OutputFile -append
"  1. Get-NetVirtualizationCustomerRoute"				| Out-File -FilePath $OutputFile -append
"  2. Get-NetVirtualizationProviderAddress"				| Out-File -FilePath $OutputFile -append
"  3. Get-NetVirtualizationProviderRoute"				| Out-File -FilePath $OutputFile -append
"  4. Get-NetVirtualizationLookupRecord"				| Out-File -FilePath $OutputFile -append
"  4. Get-NetVirtualizationGlobal"						| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization SCVMM Configuration"	| Out-File -FilePath $OutputFile -append
"  1. Get-SCIPAddress"									| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization NAT Configuration [HNV Gateway]" | Out-File -FilePath $OutputFile -append
"  1. Get-NetNat"										| Out-File -FilePath $OutputFile -append
"  2. Get-NetNatGlobal"									| Out-File -FilePath $OutputFile -append
"  3. Get-NetNatSession"								| Out-File -FilePath $OutputFile -append
"  4. Get-NetNatStaticMapping"							| Out-File -FilePath $OutputFile -append
"  5. Get-NetNatExternalAddress"						| Out-File -FilePath $OutputFile -append	
"===================================================="	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append


$vmmsCheck = Test-path "HKLM:\SYSTEM\CurrentControlSet\Services\vmms"
if ($vmmsCheck)
{
	if ((Get-Service "vmms").Status -eq 'Running')
	{
		if ($bn -gt 9000) 
		{
			"[info] Hyper-V Server Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Server Configuration"							| Out-File -FilePath $OutputFile -append	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-VMHost
			runPS "Get-VMHost"		-ft # W8/WS2012, W8.1/WS2012R2	# ft	
			$vmhost = get-vmhost
			runPS "Get-VMHostNumaNode"		-ft # W8/WS2012, W8.1/WS2012R2	# ft
			if ($vmhost.NumaSpanningEnabled -eq $false)
			{
				"NUMA Spanning has been disabled within Hyper-V Settings, running the `"Get-VMHostNumaNodeStatus`" ps cmdlet."		| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append				
				runPS "Get-VMHostNumaNodeStatus"			# W8/WS2012, W8.1/WS2012R2	# ft	
			}
			else
			{
				"------------------------"	| Out-File -FilePath $OutputFile -append
				"Get-VMHostNumaNodeStatus"	| Out-File -FilePath $OutputFile -append
				"------------------------"	| Out-File -FilePath $OutputFile -append
				"NUMA Spanning is NOT enabled. Not running the `"Get-VMHostNumaNodeStatus`" ps cmdlet."	| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append
			}

			
			"[info] Hyper-V Switch Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Switch Configuration"							| Out-File -FilePath $OutputFile -append	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-VMSwitch
			runPS "Get-VMSwitch *"	-ft 							# W8/WS2012, W8.1/WS2012R2	# ft	
			runPS "Get-VMSwitch * | fl"	-ft 						# W8/WS2012, W8.1/WS2012R2	# ft
			#_#runPS "Get-VMSwitchTeam -SwitchName ""vSwitch"" | fl -Property *" #-ft # W8/WS2012, W8.1/WS2012R2
			runPS "Get-VMSwitchTeam -EA SilentlyContinue | fl -Property *"
			#_#runPS "Get-VMSwitch -Name ""vSwitch"" | Get-VMSwitchExtension | fl -Property *"	#-ft # W8/WS2012, W8.1/WS2012R2
			runPS "Get-VMSwitch | Get-VMSwitchExtension | fl -Property *"
			runPS "Get-VMSystemSwitchExtension | fl -Property *" #-ft # W8/WS2012, W8.1/WS2012R2


			"[info] Hyper-V Network Adapter Configuration section."  | WriteTo-StdOut
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Network Adapter Configuration"					| Out-File -FilePath $OutputFile -append
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-VMNetworkAdapter
			runPS "Get-VMNetworkAdapter -ManagementOS"		-ft # W8/WS2012, W8.1/WS2012R2	# ft
			runPS "Get-VMNetworkAdapter -All"				-ft # W8/WS2012, W8.1/WS2012R2	# ft				
			runPS "Get-VMNetworkAdapter *"					-ft # W8/WS2012, W8.1/WS2012R2	# ft	
			runPS "Get-VMNetworkAdapter * | fl"					# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-VMNetworkAdapter -ManagementOS | fl -Property *"	# W8/WS2012, W8.1/WS2012R2	# fl	


			"[info] Hyper-V Network Virtualization Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Network Virtualization Configuration"			| Out-File -FilePath $OutputFile -append
			"===================================================="	| Out-File -FilePath $OutputFile -append		
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-NetVirtualization
			runPS "Get-NetVirtualizationCustomerRoute"			# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-NetVirtualizationProviderAddress"		# W8/WS2012, W8.1/WS2012R2	# fl	
			runPS "Get-NetVirtualizationProviderRoute"			# W8/WS2012, W8.1/WS2012R2	# unknown
			runPS "Get-NetVirtualizationLookupRecord"			# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-NetVirtualizationGlobal"					# W8/WS2012, W8.1/WS2012R2	# fl		#Added 4/26/14


			"[info] Hyper-V Network Virtualization Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Network Virtualization SCVMM Configuration"	| Out-File -FilePath $OutputFile -append
			"===================================================="	| Out-File -FilePath $OutputFile -append		
			"`n"	| Out-File -FilePath $OutputFile -append

			If (Test-path “HKLM:\SYSTEM\CurrentControlSet\Services\SCVMMService”)
			{
				if ($bn -ge 9600) 
				{
					runPS "Get-SCIPAddress"						# W8.1/WS2012R2	# fl
				}
				else
				{
					"This server is not running WS2012 R2. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
				}
			}
			else
			{
				"SCVMM is not installed."					| Out-File -FilePath $OutputFile -append
				"Not running the Get-SCIPAddress pscmdlet."	| Out-File -FilePath $OutputFile -append			
			}			
			"`n"	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
		}
		else
		{
			"This server is not running WS2012 or WS2012 R2. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"The `"Hyper-V Virtual Machine Management`" service is not running. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
	}
}
else
{
	"The `"Hyper-V Virtual Machine Management`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}


"[info] Hyper-V Network Virtualization Configuration section."  | WriteTo-StdOut	
"===================================================="	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization NAT Configuration"		| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append	
"`n"	| Out-File -FilePath $OutputFile -append
#_#if ($bn -ge 9600)
		#Get role, OSVer, hotfix data. #_#
		$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem -ComputerName $ComputerName #_#
		$DomainRole = $cs.domainrole #_#
if (($bn -ge 9600) -and ($DomainRole -ge 2)) #_# not on Win8+,Win10 client
{
	# Hyper-V: Get-NetVirtualization
	runPS "Get-NetNat"						# W8.1/WS2012R2	# unknown		# Added 4/26/14
	runPS "Get-NetNatGlobal"				# W8.1/WS2012R2	# unknown		# Added 4/26/14
	"---------------------------"			| Out-File -FilePath $OutputFile -append
	"Get-NetNatSession"						| Out-File -FilePath $OutputFile -append
	"---------------------------"			| Out-File -FilePath $OutputFile -append
	"Not running Get-NetNatSession currently because of exception."			| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	#runPS "Get-NetNatSession"				# W8.1/WS2012R2	# unknown		# Added 4/26/14 -> commented out because of exception... Need a check in place.
	runPS "Get-NetNatStaticMapping"			# W8.1/WS2012R2	# unknown		# Added 4/26/14
	runPS "Get-NetNatExternalAddress"		# W8.1/WS2012R2	# unknown		# Added 4/26/14
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
}
else
{
	"The Get-NetNat* powershell cmdlets only run on Server WS2012 R2+. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}
CollectFiles -filesToCollect $outputFile -fileDescription "Hyper-V Networking Settings" -SectionDescription $sectionDescription



# SIG # Begin signature block
# MIInnwYJKoZIhvcNAQcCoIInkDCCJ4wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB46E77uuwHi/23
# X+qoLgSXEaK5ex/u67PgRU7Jb4lUMaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGX8wghl7AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHiBo+9bjZ6QDTkT9K6RL/aH
# MJgAiG9RjFfwbiPrFa/nMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCWDcCAgtY56h6i5A6NFIM4VSdxRBMEBQYw4S8wR/Y76SViu+uLB/GP
# jUZSv5AjfkdLCiMyUxeMP21qurB8lL/Ck6NYeXItTCaMUC7mBm6jgNMcMWHmcZu7
# GnBtAmaQD5Wmos3TIlYKc6HNXA3haNI7/SBTT8qiWiL0Zt6AuBgBclqa4nfh54GQ
# LnlWlht//7InMpJTo45vo6e7wCkdIxcAtOuWlYNosCaZHqPZ3Clm+X8HYnQmp9CO
# zeiWGl/kuXmSkLaWhEFNofbpBV1BmX45TeCQH6A6VEN42qbOScZslF8hA2EsuCM5
# sL1j3vDzLcpnFyS2amINvjM2J1dhhC6KoYIXBzCCFwMGCisGAQQBgjcDAwExghbz
# MIIW7wYJKoZIhvcNAQcCoIIW4DCCFtwCAQMxDzANBglghkgBZQMEAgEFADCCAVMG
# CyqGSIb3DQEJEAEEoIIBQgSCAT4wggE6AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAUylPGB0drC4eeE2pZuryk3zdGjVqlYCm9AY2UsR1WvAgZi2xAP
# SfQYETIwMjIwODAxMDc0MDM4LjJaMASAAgH0oIHUpIHRMIHOMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3Bl
# cmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODk3
# QS1FMzU2LTE3MDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2WgghFcMIIHEDCCBPigAwIBAgITMwAAAasJCe+rY9ToqQABAAABqzANBgkqhkiG
# 9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMjAzMDIx
# ODUxMjhaFw0yMzA1MTExODUxMjhaMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVy
# dG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODk3QS1FMzU2LTE3MDEx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDJnUtaOXXoQElLLHC6ssdsJv1oqzVH6pBg
# cpgyLWMxJ6CrZIa3e8DbCbOIPgbjN7gV/NVpztu9JZKwtHtZpg6kLeNtE5m/JcLI
# 0CjOphGjUCH1w66J61Td2sNZcfWwH+1WRAN5BxapemADt5I0Oj37QOIlR19yVb/f
# J7Y5G7asyniTGjVnfHQWgA90QpYjKGo0wxm8mDSk78QYViC8ifFmHSfzQQ6aj80J
# fqcZumWVUngUACDrm2Y1NL36RAsRwubyNRK66mqRvtKAYYTjfoJZVZJTwFmb9or9
# JoIwk4+2DSl+8i9sdk767x1auRjzWuXzW6ct/beXL4omKjH9UWVWXHHa/trwKZOY
# m+WuDvEogID0lMGBqDsG2RtaJx4o9AEzy5IClH4Gj8xX3eSWUm0Zdl4N+O/y41kC
# 0fiowMgAhW9Om6ls7x7UCUzQ/GNI+WNkgZ0gqldszR0lbbOPmlH5FIbCkvhgF0t4
# +V1IGAO0jDaIO+jZ7LOZdNZxF+7Bw3WMpGIc7kCha0+9F1U2Xl9ubUgX8t1WnM2H
# dSUiP/cDhqmxVOdjcq5bANaopsTobLnbOz8aPozt0Y1f5AvgBDqFWlw3Zop7HNz7
# ZQQlYf7IGJ6PQFMpm5UkZnntYMJZ5WSdLohyiPathxYGVjNdMjxuYFbdKa15yRYt
# VsZpoPgR/wIDAQABo4IBNjCCATIwHQYDVR0OBBYEFBRbzvKNXjXEgiEGTL6hn3TS
# /qaqMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYw
# VKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jv
# c29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcB
# AQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSku
# Y3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcN
# AQELBQADggIBAMpLlIE3NSjLMzILB24YI4BBr/3QhxX9G8vfQuOUke+9P7nQjTXq
# pU+tdBIc9d8RhVOh3Ivky1D1J4b1J0rs+8ZIlka7uUY2WZkqJxFb/J6Wt89UL3lH
# 54LcotCXeqpUspKBFSerQ7kdSsPcVPcr7YWVoULP8psjsIfpsbdAvcG3iyfdnq9r
# 3PZctdqRcWwjQyfpkO7+dtIQL63lqmdNhjiYcNEeHNYj9/YjQcxzqM/g7DtLGI8I
# Ws/R672DBMzg9TCXSz1n1BbGf/4k3d48xMpJNNlo52TcyHthDX5kPym5Rlx3knvC
# WKopkxcZeZHjHy1BC4wIdJoUNbywiWdtAcAuDuexIO8jv2LgZ6PuEa1dAg9oKeAT
# tdChVtkkPzIb0Viux24Eugc7e9K5CHklLaO6UZBzKq54bmyE3F3XZMuhrWbJsDN4
# b6l7krTHlNVuTTdxwPMqYzy3f26Jnxsfeh7sPDq37XEL5O7YXTbuCYQMilF1D+3S
# jAiX6znaZYNI9bRNGohPqQ00kFZj8xnswi+NrJcjyVV6buMcRNIaQAq9rmtCx7/y
# wekVeQuAjuDLP6X2pf/xdzvoSWXuYsXr8yjZF128TzmtUfkiK1v6x2TOkSAy0ycU
# xhQzNYUA8mnxrvUv2u7ppL4pYARzcWX5NCGBO0UViXBu6ImPhRncdXLNMIIHcTCC
# BVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMw
# MTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3mi
# y9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+
# Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3
# oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+
# tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0
# hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLN
# ueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZ
# nkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n
# 6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC
# 4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vc
# G9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtF
# tvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEE
# BQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNV
# HQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3
# TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkG
# CSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8E
# BTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRP
# ME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEww
# SgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
# TWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCd
# VX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQ
# dTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnu
# e99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYo
# VSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlC
# GVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZ
# lvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/
# ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtq
# RRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+
# y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgk
# NWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqK
# Oghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs8wggI4AgEBMIH8oYHU
# pIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYD
# VQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMd
# VGhhbGVzIFRTUyBFU046ODk3QS1FMzU2LTE3MDExJTAjBgNVBAMTHE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAFuoev9uFgqO1mc+
# ghFQHi87XJg+oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# DQYJKoZIhvcNAQEFBQACBQDmkWvYMCIYDzIwMjIwODAxMDEwMDA4WhgPMjAyMjA4
# MDIwMTAwMDhaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOaRa9gCAQAwBwIBAAIC
# BtQwBwIBAAICETcwCgIFAOaSvVgCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQABFPqS/n1V3LqoMnckUtsbtCl22gIkw9zJbQp45J93pDbxYHD/uDq0yXuAwKbp
# 00Qm+G7ya2Inyv3oDwlDyOu/jm2o/TOdHLlbR/TcxFBbPEIXkDmxFOrRtOF/wb9H
# KsxBt8mSnadDtIdZOjDLSKyHHCjdyTzG3RZhBwHm+8NUwDGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEA
# AAGrMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIMuPwu8mbGRGMDqhlRbRuJvCou6TB/TVUq64Nxsf
# f7+LMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgDhyv+rCFYBFUlQ9wK75O
# jskCr0cRRysq2lM2zdfwClcwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAasJCe+rY9ToqQABAAABqzAiBCByPkUCh02diHe/7n7yqvw0
# JPnakMtWJJr7DzczpKS9IjANBgkqhkiG9w0BAQsFAASCAgBO4PBz+PBpbeNqSAZ2
# kWWV09vuHZ2xhHM25vcpBimPaU5eTJRh3fIb/RvO2J8f3Fw1c26aa2O8GvV/Jrka
# WekxC+AxzCrjjC2OPTuliHqxCYjqBvUYv+5mN2XdjK3rDILiTO4NF3frPZb923Uc
# BCoswghzjEoukygWEUYclaxb5htkjsYknj7nLp6xIIlgsss3sxhPpc9tXJL4JJqg
# mMKt/JzLD1ltERpG1WzmCI3x/xWEXWU50LM80+J13xyh/OwkNubBJGW3+sZM5TPE
# v5pr/vQc40y9gqrjvKAKL3Nq4M/j7m+iUaL0GvAWtV0ZpzDU1/vuhhSv6ujiJu7R
# wQOYS1ZR5okKtScrxbG/JHAVeFIWzfwqFv7ywvexYOWTnF9JExpbpmw2GwY9WCt8
# 44otDo1CGCcgf5RuqcrwOqrHL+pXYkJgNP3aBHpA6DzrgU7l0sauexxzl7c21BDh
# aedMAL1y3V63HrPkzdmiqvjpGaoc9xdebw0f3yK2JMOI88xou5U3cu1B2A+Wmaud
# c2VnRtY5UaAlv5N3nqBeK8Kezkr5BzGwmJvUx6PFbC2nTZgZ/4tGzTZY8gyBJlv8
# 26w+IJwBgQnGNmj7IxPtqDWjUW/6cry01rWNb21O1ALSn9uu/R0OP6paXmBdPCjR
# fd2Y+8aFnvwiFNbG3zJZROOIlA==
# SIG # End signature block
