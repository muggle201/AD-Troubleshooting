#***************************************************
# DC_InternetExplorer-Component.ps1
# Version 1.0: HKCU and HKLM locations
# Version 1.1.06.07.13: Added "HKU\.DEFAULT" and "HKU\S-1-5-18" locations. [suggestion:johnfern]
# Version 1.2.07.30.14: Added the parsed output of Trusted Sites and Local Intranet to the new _InternetExplorer_Zones.TXT [suggestion:waltere]
# Version 1.3.08.23.14: Added Protected Mode detection for IE Zones. [suggestion:edb]  TFS264121
# Version 1.4.09.04.14: Fixed exception. Corrected syntax for reading registry value by adding "-ErrorAction SilentlyContinue"
# Date: 2009-2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about Internet Explorer (IE)
# Called from: Networking Diagnostics
#****************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

$sectionDescription = "Internet Explorer"
	
Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSInternetExplorer -Status $ScriptVariable.ID_CTSInternetExplorerDescription

#----------Registry
$OutputFile= $Computername + "_InternetExplorer_reg_output.TXT"
$CurrentVersionKeys =	"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "Internet Explorer registry output" -SectionDescription $sectionDescription

$isServerSku = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1
$OutputFile= $Computername + "_InternetExplorer_Zones.TXT"

"===================================================="	| Out-File -FilePath $OutputFile -append
"Internet Explorer Zone Information"					| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"Overview"												| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"   1. IE Enhanced Security Configuration (IE ESC) [Server SKU Only]"		| Out-File -FilePath $OutputFile -append
"   2. IE Protected Mode Configuration for each IE Zone"	| Out-File -FilePath $outputFile -append
"   3. List of Sites in IE Zone2 `"Trusted Sites`""		| Out-File -FilePath $OutputFile -append
"   4. List of Sites in IE Zone1 `"Local Intranet`""	| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append

"====================================================" 	| Out-File -FilePath $outputFile -append
"IE Enhanced Security Configuration (ESC) [Server SKU Only]" 				| Out-File -FilePath $outputFile -append
"====================================================" 	| Out-File -FilePath $outputFile -append
#detect if IE ESC is enabled/disabled for user/admin
if ($isServerSku -eq $true){
	"`n" | Out-File -FilePath $outputFile -append
	# IE ESC is only used on Server SKUs.
	# Detecting if IE Enhanced Security Configuration is Enabled or Disabled
	#  regkey  : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}
	#  regvalue: IsInstalled
	$regkey="HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
	$adminIEESC = (Get-ItemProperty -path $regkey).IsInstalled
	if ($adminIEESC -eq '0'){
		"IE ESC is DISABLED for Admin users." | Out-File -FilePath $outputFile -append
	}
	else{
		"IE ESC is ENABLED for Admin users." | Out-File -FilePath $outputFile -append
	}
	#user
	#  regkey  : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}
	#  regvalue: IsInstalled
	$regkey= "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
	$userIEESC=(Get-ItemProperty -path $regkey).IsInstalled
	if ($userIEESC -eq '0'){
		"IE ESC is DISABLED for non-Admin users." | Out-File -FilePath $outputFile -append
	}
	else{
		"IE ESC is ENABLED for non-Admin users." | Out-File -FilePath $outputFile -append
	}
	"`n`n`n" | Out-File -FilePath $outputFile -append
}
else{
	"IE ESC is only used on Server SKUs. Not checking status." | Out-File -FilePath $outputFile -append
	"`n`n`n" | Out-File -FilePath $outputFile -append
}



#added this section 08.23.14
"====================================================" 	| Out-File -FilePath $outputFile -append
"IE Protected Mode Configuration for each IE Zone" 		| Out-File -FilePath $outputFile -append
"====================================================" 	| Out-File -FilePath $outputFile -append
$zone0 = "Computer"
$zone1 = "Local intranet"
$zone2 = "Trusted sites"
$zone3 = "Internet"
$zone4 = "Restricted sites"
$regkeyZonesHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
$zonesHKCU = Get-ChildItem -path $regkeyZonesHKCU
$regkeyZonesHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
$zonesHKLM = Get-ChildItem -path $regkeyZonesHKLM

# Regvalue 2500 exists by default in HKLM in each zone, but may not exist in HKCU.
for($i=0;$i -le 4;$i++)
{
	if ($i -eq 0) {"IE Protected Mode for Zone0 `"$zone0`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 1) {"IE Protected Mode for Zone1 `"$zone1`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 2) {"IE Protected Mode for Zone2 `"$zone2`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 3) {"IE Protected Mode for Zone3 `"$zone3`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 4) {"IE Protected Mode for Zone4 `"$zone4`":" 	| Out-File -FilePath $outputFile -append }
	$regkeyZoneHKCU = join-path $regkeyZonesHKCU $i
	$regkeyZoneHKLM = join-path $regkeyZonesHKLM $i
	$regvalueHKCU2500Enabled = $false
	$regvalueHKLM2500Enabled = $false

	If (test-path $regkeyZoneHKCU)
	{
		#Moved away from this since it exceptions on W7/WS2008R2:   $regvalueHKCU2500 = (Get-ItemProperty -path $regkeyZoneHKCU).2500
		$regvalueHKCU2500 = Get-ItemProperty -path $regkeyZoneHKCU -name "2500" -ErrorAction SilentlyContinue		
		if ($regvalueHKCU2500 -eq 0){
			#"IE Protected Mode is ENABLED in HKCU. (RegValue 2500 is set to 0.)"
			$regvalueHKCU2500Enabled = $true
		}
		if ($regvalueHKCU2500 -eq 3){
			#"IE Protected Mode is DISABLED in HKCU. (RegValue 2500 is set to 3.)"
			$regvalueHKCU2500Enabled = $false
		}
	}
	If (test-path $regkeyZoneHKLM)
	{
		#Moved away from this since it exceptions on W7/WS2008R2:   $regvalueHKCU2500 = (Get-ItemProperty -path $regkeyZoneHKLM).2500
		$regvalueHKLM2500 = Get-ItemProperty -path $regkeyZoneHKLM -name "2500" -ErrorAction SilentlyContinue
		if ($regvalueHKLM2500 -eq 0){
			#"IE Protected Mode is ENABLED in HKCU. (RegValue 2500 is set to 0.)"
			$regvalueHKLM2500Enabled = $true
		}
		if ($regvalueHKLM2500 -eq 3){
			#"IE Protected Mode is DISABLED in HKCU. (RegValue 2500 is set to 3.)"
			$regvalueHKLM2500Enabled = $false
		}
	}

	If (($regvalueHKCU2500Enabled -eq $true) -and ($regvalueHKLM2500Enabled -eq $true)){
		"  ENABLED (HKCU:enabled; HKLM:enabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $true) -and ($regvalueHKLM2500Enabled -eq $false)){
		"  DISABLED (HKCU:enabled; HKLM:disabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $false) -and ($regvalueHKLM2500Enabled -eq $true)){
		"  ENABLED (HKCU:disabled; HKLM:enabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $false) -and ($regvalueHKLM2500Enabled -eq $false)){
		"  DISABLED (HKCU:disabled; HKLM:disabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
}
"`n`n`n" | Out-File -FilePath $outputFile -append


#Build an array with all registry subkeys of $regkey 
$regkeyZoneMapDomains = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
$regkeyZoneMapEscDomains = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains"
$zoneMapDomains = Get-ChildItem -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
$zoneMapDomainsLength = $zoneMapDomains.length

# Creating psobjects
$ieZoneMapDomainsObj = New-Object psobject
$ieZoneMapEscDomainsObj = New-Object psobject
$ieDomainsTrustedSitesObj = New-Object psobject
$ieEscDomainsTrustedSitesObj = New-Object psobject
$ieDomainLocalIntranetObj = New-Object psobject
$ieEscDomainLocalIntranetObj = New-Object psobject

#Loop through each domain and determine what Zone the domain is in using http or https regvalues
$domainCount=0
$trustedSiteCount=0
$localIntranetCount=0
foreach ($domain in $zoneMapDomains)
{
	$domainCount++
	$domainName = $domain.PSChildName
	
	# Add all domains to $ieZoneMapDomainsObj
	Add-Member -InputObject $ieZoneMapDomainsObj -MemberType NoteProperty -Name "Domain$domainCount" -Value $domainName

	$domainRegkey = $regkeyZoneMapDomains + '\' + $domainName
	$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
	$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
	$domainSubkeys = Get-ChildItem -path $domainRegkey

	if ($domain.SubKeyCount -ge 1){
		foreach ($subkey in $domainSubkeys){
			$subkeyName = $subkey.PSChildName
			$domainRegkey = $regkeyZoneMapDomains + '\' + $domainName + '\' + $subkeyName
			$fullDomainName = $subkeyName + "." + $domainName
			$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
			$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https

			if ($domainHttp -eq 2){
				$trustedSiteCount++
				# Add trusted sites to the $ieDomainsTrustedSitesObj
				Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName
			}			
			if ($domainHttps -eq 2){
				$trustedSiteCount++
				# Add trusted sites to the $ieDomainsTrustedSitesObj
				Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName	
			}

			if ($domainHttp -eq 1){
				$localIntranetCount++
				# Add Local Intranet to the $ieDomainLocalIntranetObj
				Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
			}
			if ($domainHttps -eq 1){
				$localIntranetCount++
				# Add Local Intranet to the $ieDomainLocalIntranetObj
				Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
			}
		}
	}
	else
	{
		$fullDomainName = $domainName
		$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
		$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
		
		if ($domainHttp -eq 2){
			$trustedSiteCount++
			# Add trusted sites to the $ieDomainsTrustedSitesObj
			Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName				
		}
		if ($domainHttps -eq 2){
			$trustedSiteCount++
			# Add trusted sites to the $ieDomainsTrustedSitesObj
			Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName		
		}

		if ($domainHttp -eq 1){
			$localIntranetCount++
			# Add Local Intranet to the $ieDomainLocalIntranetObj
			Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
		}
		if ($domainHttps -eq 1){
			$localIntranetCount++
			# Add Local Intranet to the $ieDomainLocalIntranetObj
			Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
		}	
	}
}

if ($isServerSku -eq $true)
{
	#Loop through each domain and determine what Zone the domain is in using http or https regvalues
	$zoneMapEscDomains = Get-ChildItem -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains"
	$zoneMapEscDomainsLength = $zoneMapEscDomains.length

	$escDomainCount=0
	$trustedSiteCount=0
	$localIntranetCount=0
	if($null -ne $zoneMapEscDomains){ #_#
		foreach ($domain in $zoneMapEscDomains){
			$escDomainCount++
			$domainName = $domain.PSChildName

			# Add domains to $ieZoneMapEscDomainsObj
			Add-Member -InputObject $ieZoneMapEscDomainsObj -MemberType NoteProperty -Name "EscDomain$escDomainCount" -Value $domainName

			$domainRegkey = $regkeyZoneMapEscDomains + '\' + $domainName
			$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
			$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
			$domainSubkeys = Get-ChildItem -path $domainRegkey

			if ($domain.SubKeyCount -ge 1){
				foreach ($subkey in $domainSubkeys){
					$subkeyName = $subkey.PSChildName
					$domainRegkey = $regkeyZoneMapEscDomains + '\' + $domainName + '\' + $subkeyName
					$fullDomainName = $subkeyName + "." + $domainName
					$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
					$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https

					if ($domainHttp -eq 2){
						$trustedSiteCount++
						# Add trusted sites to the $ieEscDomainsTrustedSitesObj
						Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName
					}
					if ($domainHttps -eq 2){
						$trustedSiteCount++
						# Add trusted sites to the $ieEscDomainsTrustedSitesObj
						Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName
					}

					if ($domainHttp -eq 1){
						$localIntranetCount++
						# Add Local Intranet to the $ieEscDomainLocalIntranetObj
						Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
					}
					if ($domainHttps -eq 1){
						$localIntranetCount++
						# Add Local Intranet to the $ieEscDomainLocalIntranetObj
						Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
					}		
				}
			}
			else
			{
				$fullDomainName = $domainName
				$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
				$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
				
				if ($domainHttp -eq 2){
					$trustedSiteCount++
					# Add trusted sites to the $ieEscDomainsTrustedSitesObj
					Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName	
				}
				if ($domainHttps -eq 2){
					$trustedSiteCount++
					# Add trusted sites to the $ieEscDomainsTrustedSitesObj
					Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName	
				}

				if ($domainHttp -eq 1){
					$localIntranetCount++
					# Add Local Intranet to the $ieEscDomainLocalIntranetObj
					Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
				}
				if ($domainHttps -eq 1){
					$localIntranetCount++
					# Add Local Intranet to the $ieEscDomainLocalIntranetObj
					Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
				}		
			}
		}
	}
}



"====================================================" 				| Out-File -FilePath $outputFile -append
"List of Sites in IE Zone2 `"Trusted Sites`""						| Out-File -FilePath $outputFile -append
"====================================================" 				| Out-File -FilePath $outputFile -append
if ($isServerSku -eq $true)
{
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 							| Out-File -FilePath $outputFile -append
	  "Used when IE Enhanced Security Configuration is Disabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieDomainsTrustedSitesObj | Format-List							| Out-File -FilePath $outputFile -append
	"`n" 															| Out-File -FilePath $outputFile -append
	"`n" 															| Out-File -FilePath $outputFile -append
	"`n" 															| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\EscDomains registry location]" 						| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Enabled" 		| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieEscDomainsTrustedSitesObj | Format-List						| Out-File -FilePath $outputFile -append
}
else
{
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 							| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieDomainsTrustedSitesObj | Format-List							| Out-File -FilePath $outputFile -append
}
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append




"====================================================" | Out-File -FilePath $outputFile -append
"List of Sites in IE Zone1 `"Local Intranet`"" | Out-File -FilePath $outputFile -append
"====================================================" | Out-File -FilePath $outputFile -append
if ($isServerSku -eq $true)
{
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 						| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Disabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieDomainLocalIntranetObj | Format-List						| Out-File -FilePath $outputFile -append
	"`n" 														| Out-File -FilePath $outputFile -append
	"`n" 														| Out-File -FilePath $outputFile -append
	"`n" 														| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\EscDomains registry location]" 					| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Enabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieEscDomainLocalIntranetObj | Format-List					| Out-File -FilePath $outputFile -append
}
else
{
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 						| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieDomainLocalIntranetObj | Format-List						| Out-File -FilePath $outputFile -append
}
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append

CollectFiles -sectionDescription $sectionDescription -fileDescription "IE Zones Information (Trusted Sites and Local Intranet)" -filesToCollect $outputFile


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBHHz3taIu5bXPn
# ABUQ2iy1BNK73uB3q8GzR+FGOcVqsKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJteiKfgSiwaM+WZ6QfEbIt0
# ObH3m4pIn8yy+UpyvF7lMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQARq8C9UUvHWwvmJQzhDDVEzwqLb9Pzkd/dFUiehe2qTeLqsjbTrq2C
# iJCQir99AttB1HP0Zru9+6YiETIxZ+YAwVctJx4EAWe62YfUDba8OPyNG8FwRWFX
# 6uW681ZnMiRYhci74CkKGMhN3kwUi2Oh9QLICSITVQIdsDJJPFOPDgavcdjZZGuV
# 8bbBPKKm385XSzcRQApl5N7N+O8FFx1AnE9oiJHlRTFDYpfkq+uKlJOjXhwf4de9
# X/bxWj7nglNiJvzrondg1zhFRZaorjAxad39RGQ0UHpr2Axu0mSLQWNREFn/NsFa
# iHB/alcAUf1Banr1rg1F6HwgHnjSxilIoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDwlE+nIOGQ6WPTYayot4/doMSiKZML814P6wg6GZ6knAgZi3nXH
# vIgYEzIwMjIwODA4MDkxNTE5LjE2MVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QTI0MC00QjgyLTEzMEUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY16VS54dJkqtwABAAABjTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDVaFw0yMzAxMjYxOTI3NDVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkEyNDAt
# NEI4Mi0xMzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2jRILZg+O6U7dLcuwBPM
# B+0tJUz0wHLqJ5f7KJXQsTzWToADUMYV4xVZnp9mPTWojUJ/l3O4XqegLDNduFAO
# bcitrLyY5HDsxAfUG1/2YilcSkSP6CcMqWfsSwULGX5zlsVKHJ7tvwg26y6eLklU
# dFMpiq294T4uJQdXd5O7mFy0vVkaGPGxNWLbZxKNzqKtFnWQ7jMtZ05XvafkIWZr
# NTFv8GGpAlHtRsZ1A8KDo6IDSGVNZZXbQs+fOwMOGp/Bzod8f1YI8Gb2oN/mx2cc
# vdGr9la55QZeVsM7LfTaEPQxbgAcLgWDlIPcmTzcBksEzLOQsSpBzsqPaWI9ykVw
# 5ofmrkFKMbpQT5EMki2suJoVM5xGgdZWnt/tz00xubPSKFi4B4IMFUB9mcANUq9c
# HaLsHbDJ+AUsVO0qnVjwzXPYJeR7C/B8X0Ul6UkIdplZmncQZSBK3yZQy+oGsuJK
# XFAq3BlxT6kDuhYYvO7itLrPeY0knut1rKkxom+ui6vCdthCfnAiyknyRC2lknqz
# z8x1mDkQ5Q6Ox9p6/lduFupSJMtgsCPN9fIvrfppMDFIvRoULsHOdLJjrRli8co5
# M+vZmf20oTxYuXzM0tbRurEJycB5ZMbwznsFHymOkgyx8OeFnXV3car45uejI1B1
# iqUDbeSNxnvczuOhcpzwackCAwEAAaOCATYwggEyMB0GA1UdDgQWBBR4zJFuh59G
# wpTuSju4STcflihmkzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQA1r3Oz0lEq3VvpdFlh3YBxc4hnYkALyYPDa9FO
# 4XgqwkBm8Lsb+lK3tbGGgpi6QJbK3iM3BK0ObBcwRaJVCxGLGtr6Jz9hRumRyF8o
# 4n2y3YiKv4olBxNjFShSGc9E29JmVjBmLgmfjRqPc/2rD25q4ow4uA3rc9ekiauf
# gGhcSAdek/l+kASbzohOt/5z2+IlgT4e3auSUzt2GAKfKZB02ZDGWKKeCY3pELj1
# tuh6yfrOJPPInO4ZZLW3vgKavtL8e6FJZyJoDFMewJ59oEL+AK3e2M2I4IFE9n6L
# VS8bS9UbMUMvrAlXN5ZM2I8GdHB9TbfI17Wm/9Uf4qu588PJN7vCJj9s+KxZqXc5
# sGScLgqiPqIbbNTE+/AEZ/eTixc9YLgTyMqakZI59wGqjrONQSY7u0VEDkEE6ikz
# +FSFRKKzpySb0WTgMvWxsLvbnN8ACmISPnBHYZoGssPAL7foGGKFLdABTQC2PX19
# WjrfyrshHdiqSlCspqIGBTxRaHtyPMro3B/26gPfCl3MC3rC3NGq4xGnIHDZGSiz
# UmGg8TkQAloVdU5dJ1v910gjxaxaUraGhP8IttE0RWnU5XRp/sGaNmDcMwbyHuSp
# aFsn3Q21OzitP4BnN5tprHangAC7joe4zmLnmRnAiUc9sRqQ2bmsMAvUpsO8nlOF
# miM1LzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QTI0MC00QjgyLTEzMEUxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAIBzlZM9TRND4PgtpLWQZkSPYVcJoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmmr/pMCIYDzIwMjIwODA4
# MDY0OTEzWhgPMjAyMjA4MDkwNjQ5MTNaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaav+kCAQAwBwIBAAICAWEwBwIBAAICEYAwCgIFAOacEWkCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQBjXUPlTZ05vrI+FIPkaJD67x5CEYCOMqCF/shkIQNZ
# lA5UWPHM87QCwSqRHf18G1J0ro4Z7hqmR+LGEc6xrzH4clgWvAK+n85N2dHJ+G7O
# xc4CxtbvaCP26rTUsv6Rvj5w37GOKcFw0g+2WzW9yJQ3IDpKWA/lxS56z5Jpboqi
# LTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjXpVLnh0mSq3AAEAAAGNMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIJIIc6qX6OUQf/NLxWQc
# 78uxLQlxhj4tHJMqBHDMUrQwMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# npYRM/odXkDAnzf2udL569W8cfGTgwVuenQ8ttIYzX8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY16VS54dJkqtwABAAABjTAiBCDN
# BOqadVolAphwy0ZX9D6+oRaG75H02g+3nu5oVmRWdDANBgkqhkiG9w0BAQsFAASC
# AgApqHX6fsq1+EglURNmCIqJ1pH5Rc742DFSl4tYppqbIRXeLDVsMnVeuC3Z4DaE
# 2VBKfG9UN02HdV+ojgFyvFcWiPs0bSUkBve3LLbrYbsFruHOakjF5rOgE0cWBIxk
# S6MNUSqKUeV39UpB4fl6y7e94dib6wR0dgBqZUCXf0XAuIaa7t5x6SRJfy4PvQsW
# COVSf6IPIwEibOOtVTbr9OK4pZetgj/FrEaVM74tkZlNeCgqffWPA30mjnHBSb0/
# tWNOTFLQKw0/HqSexmHiFGJd1frd9X+4Sl4QlCczV7mOKRq4d7GfVOW0FThQIDOQ
# sq3LTEK0eolbtd+lQiAEogX3+svzWlYShL8lvKYyqppav7GdjfQVFi38ycb6ezZY
# g+qSL5Py1t58o9LXRUHcfbQkPYibrjybO3HVtNIq4wQ3/qaLZaQhUkbtbiAYjsOw
# 2E+ECCE7SL6ZSqSnf8Sz7+skxEaC7+CXcuVTSBIym447U71FojiDKJKek8STxRRv
# WywUjgvqtvKoVjjAsjPtuws6hs8pSajRrqBhloiRfoy6B7IubxI1E6SnGtfUDxw7
# PnCkEqvye/wVjM/9T1Na+vrqhyvgdV3mfh4VxXAU2LnOINoIDlRY5z3OxOMjhqNU
# 7tvq2gGC/VKHNqTLgRlin9AIKbwqAHXGs+toLADMg6s2NA==
# SIG # End signature block
