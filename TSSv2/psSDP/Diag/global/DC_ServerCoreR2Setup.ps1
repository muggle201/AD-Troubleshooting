Import-LocalizedData -BindingVariable Strings

Function GetWin32OSFromRemoteSystem([string] $MachineName)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("[GetWin32OSFromRemoteSystem] Error contacting " + $MachineName)
		continue
	}
	
	#Obtain OS From Remote Machine and return the WMI class.
	#If error communicating, return the exeption error code instead of WMI class
	$Error.Clear()	
	$OS = Get-CimInstance -Class Win32_OperatingSystem -ComputerName $MachineName
	
	if ($Error.Count -gt 0)
	{
		Return $Error[0].Exception.ErrorCode
	} 
	else 
	{
		return $OS
	}
}

trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

do
{
	do
	{
		#_#$RemoteServerCore = get-diaginput -id "BrowseServerCore"
		$RemoteServerCore = Read-Host 'please supply Remote-Server-Name: ' #_#
	} while (($RemoteServerCore[0] -eq 0) -or ($null -eq $RemoteServerCore[0]))

	$Error.Clear()

	#_#$RemoteServerCore = $RemoteServerCore[0].ToUpper()
	$RemoteServerCore = $RemoteServerCore.ToUpper() #_#

	Write-DiagProgress -Activity ($Strings.ID_EPSConnectingTo -replace("%MACHINE%", $RemoteServerCore)) -Status $Strings.ID_EPSConnectingToDesc

	$RemoteMachineOS = GetWin32OSFromRemoteSystem $RemoteServerCore
	
	if ($RemoteMachineOS -isnot [wmi])
	{
		if ($Error[0].Exception.ErrorCode -eq -2147023174) #The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
		{
			get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"=$Strings.ID_EPSConnectingRCPError}
		} 
		else 
		{
			get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"= $Error[0].Exception.Message}
		}
		
		$Error.Clear()
	}
	else
	{
		$Error.Clear()
		if ($RemoteMachineOS.BuildNumber -gt 7000)
		{
			$Error.Clear()
			
			#Now connect to machine to see if it is a Cluster
			$RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteServerCore)
	
			if ($Error.Count -eq 0)
			{
				$RemoteNodesKey = $RemoteReg.OpenSubKey("Cluster\Nodes")
				
				if ($RemoteNodesKey.SubKeyCount -gt 0)
				{
					$ClusterName = $RemoteReg.OpenSubKey("Cluster", $false).GetValue("ClusterName").ToUpper()
					
					$Choices = @()
					
					foreach ($SubKey in $RemoteNodesKey.GetSubKeyNames())
					{
						$NodeMachineName = $RemoteReg.OpenSubKey("Cluster\Nodes\$SubKey", $false).GetValue("NodeName").ToUpper()
						
						if ($NodeMachineName -ne $RemoteServerCore) 
						{
							$ExtensionPoint = ""
						} else {
							#Set the machine indicated by customer the default
							$ExtensionPoint = "<Default/>"
						}

						$Choices += @{"Name"=$NodeMachineName;"Value"=$NodeMachineName;"Description"=$NodeMachineName;"ExtensionPoint"=$ExtensionPoint}
						
					}

					$TroubleshootingNodeNames = @()
					
					if ($Choices.Count -gt 0)
					{
						do
						{
							$TroubleshootingNodeNames = Get-DiagInput -Id SelectServerCoreClusterNodes -Parameter @{"Cluster"=$ClusterName; "Machine"=$RemoteServerCore} -Choice $Choices
							
						} while ($TroubleshootingNodeNames.Count -eq 0)

						if (($TroubleshootingNodeNames[0] -ne 0) -and ($TroubleshootingNodeNames.Count -ne 0))
						{
							if ($TroubleshootingNodeNames -contains "All")
							{
								foreach ($MachinName in $ClusterValues)
								{
									$MachineNames = $MachinName.Value
								}
							}
							else 
							{
								$MachineNames = $TroubleshootingNodeNames
							}
							
							Return $MachineNames

						}
					}
					else 
					{
						get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$NodeName; "Error"=$Strings.ID_EPSSelectNodesUnableObtainNames}
					}
				}
				else
				{
					#Machine is not a cluster node
					return $RemoteServerCore
				}
			}
			else
			{
				get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"= $Error[0].Exception.Message}
			}
		}
		else
		{
			get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"=$Strings.ID_EPSSelectNodesNotSupported.Replace("%Machine%",$NodeName).Replace("%OSName%",$RemoteMachineOS.Caption)}
		}
	}
} while ($true)


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCABapXTBig6C87s
# /6giffvn+iLsE5pENBNUhQCIPTHrWqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOeU7pPxF5WB4WxiKr5BnZKA
# MyKtOXCzcxeU4nGWSL0xMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB1Vpm7whrfgF2nXetWADGXupS4BJCmWHtK1Cwa5aXdZ0dk/SSur8tL
# xJfaLPEKYTNseN6XE2sK4zC+kH+GQGSjLL2D6eE/KimnQq1jGHlWRCo71vF27oVi
# x6zrz5S6p7qfRh/xpKeJW41cxzm0QNXM2L7j7DcoKX9yrdeif+yhl3kDEncQv2+7
# kyJtiv03r45T6Izyxhcuctb8yBQh0gcLEbbXfQ6nPdg26InwRWrVj8Fg8d7Qa7LF
# lQ6vxtOSp5gJMRXxyG+kldaMQ15ziHN4lzw8oJwZcspLTQQG/qi46jCAieHAa9cV
# vX9NiuNS28nQEA1h/KHDG+dM/Cm/sVKioYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILBckX3FEZBUHIOWS86cqrw8HrSgrwKglae9Pex54awfAgZiz/Wr
# 8t0YEzIwMjIwODAxMDc1MDU5LjE2NlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMt
# RTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGcD6ZNYdKeSygAAQAAAZwwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE5WhcNMjMwMjI4MTkwNTE5WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDbUioMGV1JFj+s612s02mKu23KPUNs71OjDeJGtxkT
# F9rSWTiuA8XgYkAAi/5+2Ff7Ck7JcKQ9H/XD1OKwg1/bH3E1qO1z8XRy0PlpGhmy
# ilgE7KsOvW8PIZCf243KdldgOrxrL8HKiQodOwStyT5lLWYpMsuT2fH8k8oihje4
# TlpWiFPaCKLnFDaAB0Ccy6vIdtHjYB1Ie3iOZPisquL+vNdCx7gOhB8iiTmTdsU8
# OSUpC8tBTeTIYPzmhaxQZd4moNk6qeCJyi7fiW4fyXdHrZ3otmgxxa5pXz5pUUr+
# cEjV+cwIYBMkaY5kHM9c6dEGkgHn0ZDJvdt/54FOdSG61WwHh4+evUhwvXaB4LCM
# ZIdCt5acOfNvtDjV3CHyFOp5AU/qgAwGftHU9brv4EUwcuteEAKH46NufE20l/Wj
# lNUh7gAvt2zKMjO4zXRxCUTh/prBQwXJiUZeFSrEXiOfkuvSlBniyAYYZp5kOnax
# fCKdGYjvr4QLA93vQJ6p2Ox3IHvOdCPaCr8LsKVcFpyp8MEhhJTM+1LwqHJqFDF5
# O1Z9mjbYvm3R9vPhkG+RDLKoTpr7mTgkaTljd9xvm94Obp8BD9Hk4mPi51mtgLiu
# N8/6aZVESVZXtvSuNkD5DnIJQerIy5jaRKW/W2rCe9ngNDJadS7R96GGRl7IIE37
# lwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFLtpCWdTXY5dtddkspy+oxjCA/qyMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAKcAKqYjGEczTWMs9z0m7Yo23sgqVF3LyK6gOMz7TCHAJN+FvbvZkQ53Vkvr
# ZUd1sE6a9ToGldcJnOmBc6iuhBlpvdN1BLBRO8QSTD1433VTj4XCQd737wND1+eq
# KG3BdjrzbDksEwfG4v57PgrN/T7s7PkEjUGXfIgFQQkr8TQi+/HZZ9kRlNccgeAC
# qlfb4uGPxn5sdhQPoxdMvmC3qG9DONJ5UsS9KtO+bey+ohUTDa9LvEToc4Qzy5fu
# Hj2H1JsmCaKG78nXpfWpwBLBxZYSpfml29onN8jcG7KD8nGSS/76PDlb2GMQsvv+
# Ra0JgL6FtGRGgYmHCpM6zVrf4V/a+SoHcC+tcdGYk2aKU5KOlv+fFE3n024V+z54
# tDAKR9z78rejdCBWqfvy5cBUQ9c5+3unHD08BEp7qP2rgpoD856vNDgEwO77n7EW
# T76nl/IyrbK2kjbHLzUMphFpXKnV1fYWJI2+E/0LHvXFGGqF4OvMBRxbrJVn03T2
# Dy5db6s5TzJzSaQvCrXYqA4HKvstQWkqkpvBHTX8M09+/vyRbVXNxrPdeXw6oD2Q
# 4DksykCFfn8N2j2LdixE9wG5iilv69dzsvHIN/g9A9+thkAQCVb9DUSOTaMIGgsO
# qDYFjhT6ze9lkhHHGv/EEIkxj9l6S4hqUQyWerFkaUWDXcnZMIIHcTCCBVmgAwIB
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
# IEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAzdlp6t3ws/bnErbm9c0M+9dvU0Cg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRhcAwIhgPMjAyMjA4MDEwNjUwNDBaGA8yMDIyMDgwMjA2NTA0MFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGFwAIBADAKAgEAAgIfrQIB/zAHAgEA
# AgIRuDAKAgUA5pLXQAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAIsM1ZbJ
# +1+9+rEPRHXyncQ8aXRtTzMaJe6TkMiljXcl8r6EfHTQ8uj5lUA6mnhjxgd4upXy
# phtjxD1mcGLFxLiBnVeTf4ZcSM0q6eIYIprfpd2G+TAnXh90xh5h//OJGACnGoxE
# /GqoUNZG0ed6Qf4LPicY1mgVETib8frum6LzMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGcD6ZNYdKeSygAAQAAAZwwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQguhCiM8BQN8+k80IMtEzKwZeGZ3dTL+TNUR16vLN7I40wgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCA3D0WFII0syjoRd/XeEIG0WUIKzzuy
# 6P6hORrb0nqmvDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnA+mTWHSnksoAAEAAAGcMCIEINgYywu7xnPeesMF/5y9/Sc/fFz+Lesq
# +y5RGEfTZowXMA0GCSqGSIb3DQEBCwUABIICAAntMLqehcjQU1SEDAhnpK7GWkLj
# uJ44L6LissNMYtQSROwhiTCVxuKS9N4Qz9ZWpkFTGFgn4BMnCs0MYG1jEzRAWZER
# +bNxR1+BPGs5Eawt3IGp4uB0Loe2hbjLWvhX2rO5FWkyBehYearR/7i7TAsQhkQ8
# DTEVcBbVR52rh/Jn2/TVYdGym2nMr6rDAm1Mbl6cDjzeFMWKNLF3k3+7/vn4tmD+
# HacWZS7K7WpOQz90JaBJJzIg2d+dfkaDpKbruQNfIKLtF3w1XDxdtsuqTWy3OlWB
# cQMPJNcYrm4S/nzFq8xiVNI7p+KaVcQF998/x9vYj89wt9CV7oMVqUCuQpGslv/k
# 5BVo9XT5vLvsrMkEFaljejF6nzq6DrZ7VZJk6f9VaB9v/sJx4sRlMYvY0DFjsq3e
# 4Q/p0StRjNgw8/lBDnXF+A896RkHly/ijjvChuSLoyvaFCMvxuoQCLPQUQBbxgpb
# Kcn1Af2DKmAKr+fHkpYVH9FOdE/fpX9QNmDJR0aqD6jSmdcX6NSQKyW4fyZQonOn
# oC2SaedtwpKV/GUfVR56PRrnvjC3Fof26iQzLvT4S/UBJpokUvT0UFL0Yg3+fBr1
# 0wH3gVAlZpDjh47EubMopTyn736rzlO7eLgkMZDPr3AWYEd0ms7Zvs7fP/EBqip5
# 4Q+4vRu6LOjmRBRu
# SIG # End signature block
