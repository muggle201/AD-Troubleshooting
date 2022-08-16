# Copyright and License https://github.com/Microsoft/busiotools/blob/master/LICENSE
# Script: GetBluetoothRadioInfo.ps1
#region ::::: Script Input PARAMETERS :::::
[CmdletBinding()]param(
 [Parameter(Mandatory=$true, Position=0)] [String] $DataPath
)
$ScriptVer="1.01"	#Date: 2021-05-13


function Get-BluetoothRadioInfo
# SYNOPSIS: collect BluetoothRadio Info
{
	$devices = Get-PnpDevice -Class Bluetooth -EA SilentlyContinue |Where-Object InstanceId -notlike "BTH*"
	if ($null -ne $devices) {
		$radios = New-Object System.Collections.ArrayList
		foreach ($device in $devices)
		{   
			$radio = New-Object PSObject
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "InstanceId" -Value $device.InstanceId
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioAddress'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "MAC" -Value $(-join ($property.Data |  ForEach-Object { "{0:X2}" -f $_ } ))
			$radios.Add($radio) | Out-Null

			# Driver Info
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverDesc'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "DriverDescription" -Value $property.Data
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "DriverVersion" -Value $property.Data

			# Radio Roles
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioIsCentralRoleSupported'
			$isCentralRole = [boolean]($property.Data)
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioIsPeripheralRoleSupported'
			$isPeripheralRole = [boolean]($property.Data)
			if ($isCentralRole -And $isPeripheralRole) { 
				$role = "Both" 
			} elseif ($isCentralRole) {
				$role = "Central"
			} elseif ($isPeripheral) {
				$role = "Peripheral"
			} else {
				$role = "None"
			}
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "LERole" -Value $role

			# Radio Secure Connections
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioAreBRSecureConnectionsSupported'
			$isBR = [boolean]($property.Data)
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioAreLESecureConnectionsSupported'
			$isLE = [boolean]($property.Data)
			if ($isBR -And $isLE) { 
				$role = "Both" 
			} elseif ($isBR) {
				$role = "BR"
			} elseif ($isLE) {
				$role = "LE"
			} else {
				$role = "None"
			}
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "SecureConnections" -Value $role
			
			# Error Recovery
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 14'
			$supportedTypes = $property.Data
			if ($supportedTypes -eq 0)
			{
				Add-Member -InputObject $radio -MemberType NoteProperty -Name "ErrorRecovery" -Value "None"
			} elseif ($supportedTypes -band 1 -shl 0)
			{
				Add-Member -InputObject $radio -MemberType NoteProperty -Name "ErrorRecovery" -Value "FLDR"
			} elseif ($supportedTypes -band 1 -shl 1)
			{
				Add-Member -InputObject $radio -MemberType NoteProperty -Name "ErrorRecovery" -Value "PLDR"
			}
			
			# Proximal Connections
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 13'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "ProximalConnections" -Value ([boolean]($property.Data))
			
			# Key Size Enforcement
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 15'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "KeySizeEnforcement" -Value ([boolean]($property.Data))

			# Extended Advertising
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 16'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "ExtendedAdvertising" -Value ([boolean]($property.Data))
			
			# LE2MPhy
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 18'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "LE2MPhy" -Value ([boolean]($property.Data))

			# LECodedPhy
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 19'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "LECodedPhy" -Value ([boolean]($property.Data))
			
		}
		$radios | Format-Table -autosize -Wrap -Property *
	}
} # end of function Get-BluetoothRadioInfo

#region ::::: MAIN ::::
$InfoFileName = $dataPath + '\' + $env:COMPUTERNAME + '_BluetoothRadioInfo.txt'
Get-BluetoothRadioInfo |Out-File $InfoFileName -Width 500
#endregion ::::: MAIN :::::
# SIG # Begin signature block
# MIInuQYJKoZIhvcNAQcCoIInqjCCJ6YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9z1ABWzZKXlfL
# YgqSdXzkW8gnqIW7gnkKzwHuU1v/EaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZjjCCGYoCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg2XF7BWgK
# BbFyLc2jFqE5yyhQk1VwcjSjPUqyxozFK8kwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAGDHVqCxFReMe3WfrexYGhUOmm/mMS+keWFyD8nEal
# ely0xLa+cgCR22TRIa7mM+bJfn5o6ZsClmR4F0wwnh59TST5UeOAUH15ZI2/w7Iq
# Vwg3pDGfv0507lWQTOI/q18AJ8OnVfwsmtHkra/EX0OfaEzTlG1trA13KQ9i8qXR
# 7GmJpoCNOypW2ppXbIy2nZDcXeGHRtiM7GCc+EQMh6hrh7/fElMlQS6AMrjdD1Wr
# ktGWX2EGQwzkqEOmBJlZDkYvz5yCO/PajFG7q3hAz3izJG6KRf1+di7uXOSJ6Qi2
# /i5y9U/k+foNBOHZzizT9dmoALe4ySdJualPXomsMDploYIXGDCCFxQGCisGAQQB
# gjcDAwExghcEMIIXAAYJKoZIhvcNAQcCoIIW8TCCFu0CAQMxDzANBglghkgBZQME
# AgEFADCCAVgGCyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIAj0/I7MEazul+Ea9vkL/9LYPeZkaAWg1H63aZXs
# 6MQ9AgZi3mIrNjoYEjIwMjIwODE2MDkyMDM5LjcxWjAEgAIB9KCB2KSB1TCB0jEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWlj
# cm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjoyQUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCEWgwggcUMIIE/KADAgECAhMzAAABhnjlGYn4JEvM
# AAEAAAGGMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMB4XDTIxMTAyODE5MjczOVoXDTIzMDEyNjE5MjczOVowgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MkFENC00QjkyLUZBMDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDAjcbZam/o
# HgiMB+uB8mmd0849g7Vh3z6+V+gjExbeB0INP7Mhtp+DXik67S3R6RRDHrSns9p0
# fg6Oeo0gTWrqV0f2e2PWAh2Xgerit0QdNnokV0TbgNJtWiqpH5HgjDjDcY9t9zZD
# eR/LIXKP4M6GYJbD8VmJNVOVPht16PIBbqv8mfh+vfEuNu+EhNq2vfpXLLOBDRjh
# avvcfeBRwuNi7SqIe60MNvr6n7IMEaYoXOc5bzBW3sP67ZUQmgTomUrQSlUtm6x1
# LOF5y5TAlfFva7KABleWxr98eXBb1ieUGowcn6Kb0e4rlfjHz/kHl2S4ihfmVYaM
# UxsPYDou78+ZQHiErQIXkbVhpS0GswTvcMAqTKmTtISbcGUlfBj8atWhdZhQYQfJ
# +uQuTCzRGgQymggSB5tk0qqNHKdEmBHh88IqsSHASJNMBzgNcZyLgcc6brgRDWD9
# IMcwWogpVLGhRuQZt0o0oeGZqG4isDLjB72zutkmyS95lhmIOa0C0G3+BCiPFtnW
# 870LXVK2GSuaSRMwtB/1wPOVUQF67oqYdfZLN7qCCd7cjhzL/khQucdneszhmklz
# SzYqkYsdpWsRDLjH+YCfjJph+B4fcwQBaRWPL+pMOHpwMIX+DLPdNpAO28WcArvQ
# uq1sS8E90Gl4Ib+GT2XSVpjPCLLIZj8eowIDAQABo4IBNjCCATIwHQYDVR0OBBYE
# FBm2o0UD72Z0S7+HfdSEcw3rCFwuMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBAMPuZ6Eljd9McoLiGP7AFYHznji5
# omIwwgeeEr041MztWtpNjPHRT9NwsnqDHDW1HMzm67ySzAk2Uc2ntF52wCLC+JVB
# lX0AvwhtlEslPA16ELCT4FVxjaCHdkZmbHy5q09mtG57KGFNMPY+8VUut/CHaWIM
# b90Q80gdMqPv0OURw8hag4JSnunQ5EzBD3mRVqJulfz2m+OE+XYWbQIE7eldcmDR
# vJ2lDl0MNO/+pvT5ZgX+81URT8ygwRCqVRZa5cQJOrHpNrIm4snq5TsrlDJORD+X
# bgiEaMPN/kARk6sg1jORZXI19Q6kjGcqxZME3aKOln9O6fmquaj280gNPSWhuCe6
# Vp7Xs1oQ72iIQkkfW1Dfnd2G5GL4DTQ9HvzWJiXMXklTUOsR8TI3HwJaARGL3Qsq
# xiCFkEIONDcOImN9Rkuo414esl9yaHPn9t+bz5oBpQ+lkV4/SDQiid3pc2ThiJht
# Y8Wih9zQvBypIAu24gDLPp/d35RplmynjVTiEIigaPqGgMi5Tzf1uj+Zn8CARLAb
# EhezSBlToD7aohR7rRB0D3r3BZLO5wo6KyeD0cJJksXV2pzdBRrCvQLRTjXvzgqj
# 29yQAbdqTBi5UZyzqEz9KoSGh72MfB7henzUKtMHWX34Qh26QJs/STLPHRZnO156
# IM3mt2KJBH2YEm6WMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTAN
# BgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDi
# vbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5G
# awcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUm
# ZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjks
# UZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvr
# g0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31B
# mkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PR
# c6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRR
# RuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSR
# lJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflS
# xIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHd
# MIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSa
# voKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYD
# VR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjR
# PZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNy
# bDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0G
# CSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHix
# BpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjY
# Ni6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe5
# 3Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BU
# hUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QM
# vOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1A
# PMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsN
# n6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFs
# c/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue1
# 0CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6g
# MTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm
# 8qGCAtcwggJAAgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0
# aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyQUQ0LTRCOTIt
# RkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEB
# MAcGBSsOAwIaAxUAAa7YNHNaQqWOZfJJfWSiscvh8yeggYMwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOalOAwwIhgP
# MjAyMjA4MTYwNTI0MjhaGA8yMDIyMDgxNzA1MjQyOFowdzA9BgorBgEEAYRZCgQB
# MS8wLTAKAgUA5qU4DAIBADAKAgEAAgIBYwIB/zAHAgEAAgIRMjAKAgUA5qaJjAIB
# ADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQow
# CAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAIJ6gEOziwVkAjH+Buuj0HZB991Z
# 5qX+XBj1V3NOaUlmFrk3jDQwh1usGvjJMDvNcKnxdqgWeIcnR6tfYC4lB4yumKUP
# oa7+cuwNeg81k6aG1hmGMkL5d2yJ8uM2RJjn+d93L33ciClFJ1JpAX3QPvil6p9X
# IMiIYGCn/gy6oQTjMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAGGeOUZifgkS8wAAQAAAYYwDQYJYIZIAWUDBAIBBQCgggFK
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg/DL7
# 7a7cwuAy5AEA81Klh5N5J2DWqo2hb9aNM2nQRFowgfoGCyqGSIb3DQEJEAIvMYHq
# MIHnMIHkMIG9BCAamYjgsiwIVMaJjJ9EBHubsVraC7FU0jDXuZwCKrxCfjCBmDCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABhnjlGYn4JEvM
# AAEAAAGGMCIEIBvoFDeBW+V48MXHL5vY6hTMu4KoxIvpDhULYVdk7E+dMA0GCSqG
# SIb3DQEBCwUABIICABN8ePv49HAktL10zjJ3SeSsxsI2Um6OXzvGp7dGIg19gJvA
# OS48FMj080pVYZYAJqFSnuc9iewQ9xmaJUjhp1Y3rxiHdjb7Z1eS+r3RszJ18Lrs
# J/zB8ZqdR/FfWQJbdCC42vR3LujMD+taOB56A+T9bASM7VvCiVeYR9C+1aKiYCQF
# fkaHuI4m9BtoUSqfDW5M5rLBr+Kr31De0f8S9IaTbJvdYTu13HFTtf0CduKUNQ0k
# LjC2snYKhm0iZdt1dK13AruR119dimDj0hgryVBi3F7jQiiM5JDMwCTUqHcIpUG7
# 9pyXrPMvYY0p9lkHXjA8k/qkFdnMeSzMXljT2zQrLG5w7jeDE6ncY8CiM9kY1nBu
# TFrZMrZHcBPYW/rVD/lhpabde1zg1XvO79MRPK9LkHaa8gFHdAgDFv/CBkuNeS5q
# ruLSHlrSa7hpMT31BK8XS3lwLXzDaXxGpew/OSolGPo2+EN4M+tbL6da/hK7Rn24
# Dqczy4IW2TzgRsPxWL6E6KN4Xff5o81DBctZussuN0LMCzS9rnimeiT7rLsOzcGf
# SIP2D5AYiNe3w1RpYnsEhfyAS0fEs1kpfthYMgf077ex3cIN9VjsfqNsOn2/lMrZ
# L+hPdGuhfBCNBsfO+cyVDPPOtSFERafZqfGwxFpjHNitMvBz9s9w7ChIJ7Ww
# SIG # End signature block
