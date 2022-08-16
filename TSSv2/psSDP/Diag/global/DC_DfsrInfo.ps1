#************************************************
# DC_DfsrInfo.ps1
# Version 1.2.0
# Date: 4/19/2010
# By Craig Landis (clandis@microsoft.com)
#************************************************
# 2019-03-17 WalterE added Trap #_# nneds check for DFSrDiag.exe / OSversion?

function MenuDiagInput-CollectDFSR

{
    Write-Host -ForegroundColor Yellow 	"============AD Collect DFSR Information =============="
    Write-Host "1: Collect All"
    Write-Host "2: Collect All But Health-Reports"
    Write-Host "3: Collect Minimal"
	Write-Host "q: Press Q  or Enter to skip"
}

If ((Get-CimInstance -query "Select ProductType from Win32_OperatingSystem").ProductType -ne 1) {

	$DFSRkey = "HKLM:\SYSTEM\CurrentControlSet\Services\DFSR"
            
	If (Test-Path $DFSRkey) { 

		Import-LocalizedData -BindingVariable DfsrInfoStrings -FileName DC_DfsrInfo -UICulture en-us
			
		Write-DiagProgress -Activity $DfsrInfoStrings.ID_DfsrInfo -Status $DfsrInfoStrings.ID_DfsrInfoObtaining

		$sectionDescription = "DFSR Miscellaneous"

		$OutputFile = "DFSR__Progress.txt"

		#_#$CollectDFSRInformation_Answer = get-diaginput -id "CollectDFSRInformation"
		MenuDiagInput-CollectDFSR
        $Selection = Read-Host "Choose the DFSR Information level"
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DFSR Selection: $Selection" -shortformat
		switch ($Selection)
		{
			1 {$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt"}
			2 {$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports"}
			3 {$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports /nodbguids /nodebuglogs"}
			'q' {}
		}
		<#
		switch ($CollectDFSRInformation_Answer) 
				{
					"CollectAll" 
					{
						$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt"
					}
					"CollectAllButHealthReports" 
					{
						$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports"
					}
					"CollectMinimal" 
					{
						$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports /nodbguids /nodebuglogs"
					}
				}
		#>

		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription "Progress Log"

		CollectFiles -filesToCollect "Dfsr*.log" -fileDescription "DFSR Current Log File" -sectionDescription "DFSR Debug Log Files" -renameOutput $false
		CollectFiles -filesToCollect "Dfsr*.gz" -fileDescription "DFSR Previous Log file" -sectionDescription "DFSR Debug Log Files" -renameOutput $false
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_ConflictAndDeleted.xls") -fileDescription "DFSR Conflicts and Deletes" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Events_Last_72_Hours.xls") -fileDescription "DFSR Events Last 3 Days" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_File_Versions.txt") -fileDescription "DFSR File Versions" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Hotfixes.txt") -fileDescription "DFSR Hotfixes" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Info.txt") -fileDescription "DFSR Configuration Information" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Performance_Data.txt") -fileDescription "DFSR Performance Data" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_DBGUIDs.txt") -fileDescription "DFSR Database GUIDs" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_DfsrMachineConfig.XML") -fileDescription "XML File" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_RegKey_DFSR.txt") -fileDescription "DFSR Registry Key" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_RegKey_TCPIP.txt") -fileDescription "TCPIP Registry Key" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Replica*.xml") -fileDescription "XML File" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Volume*.xml") -fileDescription "XML File" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Dfsmgmt*.log") -fileDescription "DFS Management Trace Log" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_FSRM_File_Screens.txt") -fileDescription "FSRM File Screens" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_FSRM_Quotas.txt") -fileDescription "FSRM Quotas" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect "*HealthReport*" -fileDescription "Health Report" -sectionDescription "DFSR Health Reports"

	}
}

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}



# SIG # Begin signature block
# MIIjhwYJKoZIhvcNAQcCoIIjeDCCI3QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDNRzgjjPaVUM9T
# 3MaMqpzI7jUajFKhFiA13TSSpsR7+6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXDCCFVgCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQglYVhIzGu
# JBwcHsf9kH/7kmmHSQseC/nMEplD2De/yG8wOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBALLx6ohGVfEXnU/U144xLZpQddJk/wKSEM9yar6CnDtUBLmC9vaTy5nd
# sYzvqWYs3FaLQnFJ9mfuKEL5K/TsCLrhEdq5UdimLMkqyrUpm81+/tUV+riNc+Qg
# /27ujk8TPcVEoDh999PIMkaUt4twlFfsVhjnbjwJtUrI+naw4OyubIiFHWyLlbdo
# eFj4lVZeG+H19nodL+wQV5SI8h0NI8S0SM2b0geYUUNfCzqAFYxRZ4eOBfrp7ooh
# i6yPPjJI3jdPlXNax/to9kj9i9Ju2btAB+tQ8KqR4dfTyp8O8OOCiuD/2XA5zsrw
# wLKawGkra1ujU4vRVZ82tCGoof1V1SahghLwMIIS7AYKKwYBBAGCNwMDATGCEtww
# ghLYBgkqhkiG9w0BBwKgghLJMIISxQIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVAYL
# KoZIhvcNAQkQAQSgggFDBIIBPzCCATsCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgbxUDCO7DHrTppyhfp/PWCbGH+nswwTyYYjLLOoM5CYYCBmGB++Yl
# TBgSMjAyMTExMTExNjUzMzUuNDRaMASAAgH0oIHUpIHRMIHOMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3Bl
# cmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODk3
# QS1FMzU2LTE3MDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2Wggg5EMIIE9TCCA92gAwIBAgITMwAAAWAHIPCSSNq+6wAAAAABYDANBgkqhkiG
# 9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTAxMTQx
# OTAyMjBaFw0yMjA0MTExOTAyMjBaMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVy
# dG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODk3QS1FMzU2LTE3MDEx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0MYAc0PLGzPFSMz4JjfU1pFrNpPEtQmVM
# jefEi8y1t9efK2WfzuJevBm+EpBP4gVEpOMlXrASjlaJ2yy95wMCF5rGIZ+QUdEV
# zyPVy4s81arJVIBz80z0bTLWbvo7coAqYeTH6rgYmv0qdB44+5RA6zR0fwv9f8Qm
# mckKYCEe5QESSGkVYecvlqm6pm1LBSKBeVB8MMyRSaTl8WLQNLlrq2iqXQlMwM4e
# sJCmYDJEa1z9xP8OXLOFO3GImI2URpZtxq/ryYJMk7CltzgYk7ZGlv3o7aVvkuqb
# vzXs1xagM8Lkg43iCJjjnhGr5QPTvVaQnsaNc+lQqadBG9/dOLoTAgMBAAGjggEb
# MIIBFzAdBgNVHQ4EFgQUp5se+LeoF+Ca4XUyCXV80Ou+H2MwHwYDVR0jBBgwFoAU
# 1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIw
# MTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0w
# Ny0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAQEAFTSYCJs6BaaJUHVPJ2HXF+8kpShD9+faoOUP0hae3uI+
# XQNVfpLL5inWQdY4Y7AbNiJjTiLcjWNrtjcI2uCTcRX/tsvyk3D/BhPex/KIK/XP
# lW9bhxe4LZ3txfL579Am+/SuJm4YuktECIaj3CPHN+lKnj8CjC5t9ifrzvcLiltj
# SvL/WwOYELvdgI+rn+wBgLjWByIdImaJPm3LiaWDyimNZ70thGtYM5hfCf4qz2OD
# FvL+P4GnpCaLH5HOoG6JmuMNYBQxioCob+7ZU9fud7hxkdk0tajGHjcBnxrY4k8U
# NQZUBGYm5OzxXwnvikYU0Uwkbc1p0oNzRBNMtqi51DCCBnEwggRZoAMCAQICCmEJ
# gSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1
# NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF++18
# aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRDDNdN
# uDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSxz5NM
# ksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2K
# Qk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16HgcsOmZ
# zTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQ
# BgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqFbVUw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCBkjCB
# jwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAd
# AEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQALiAd
# MA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F
# 4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GASinbM
# QEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mB
# ZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWOM7ti
# X5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4pm3S
# 4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45V3ai
# caoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x4QDf
# 5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEegPsb
# iSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKnQqLJ
# zxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB
# 0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvTX4/e
# dIhJEqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQ
# dWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODk3QS1FMzU2LTE3
# MDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAPsyknR1i0TcyJcqh1cV2YCp2dCioIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDlN67TMCIYDzIw
# MjExMTExMTkwMTM5WhgPMjAyMTExMTIxOTAxMzlaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOU3rtMCAQAwCgIBAAICJKgCAf8wBwIBAAICEXcwCgIFAOU5AFMCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQB9iRM8ddKWCUDwpk2dkV2sU8riAl5B
# yd7tfaYJ62+3BVZ+cO+6ADF7KhPYuty2b4ha5hNy+qP18qgEtU0o0FyMK3BJNjR1
# y9WLZEVKLj6OuXq1NskbvbQH7cdTTnmIPNtLXP78d0UUI25FRpSEopaR+6Nhun2E
# iwB/mxE1p1ILtTGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABYAcg8JJI2r7rAAAAAAFgMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGWUcFXN
# HpiRaAl5tjr3qgincfOtnHGpuEfDcJ8X3icwMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgAhKjvaNzLpdbRaevHuoryn6V0v+PXBcJ4l5I96iwZbkwgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAWAHIPCSSNq+6wAA
# AAABYDAiBCD/+W9FFgDN4VBLijRIykK8Vgg4kkGg0FX4nGM3UiAI5TANBgkqhkiG
# 9w0BAQsFAASCAQCGH9jB0W0kNJYqk7vWBqtAl4KXL+Ra4Q1DDvniU5qBgyeWc7sA
# 7piMd6InRulFsBk7KcYUi9JzNwuNnBqDKDdBeRtjOw+2qoO10LYCe42tpg/YEGs2
# 122c3Yyd72At+RFDZ3mOVrLJNunR2ROrx1lhXJ3wjAwm0QJ39uZVPFwz0BK+4DmH
# Fr7vChT7g3VhAgr+K1zq8m5nRvJfh2htnZ+hz6hPxLsgqri6Izr8AVhgUI5yZ795
# gJhVfAFJiUY7F56uOOpTrMos0WK7ksqn6hXBBLdYQv6EnGaGEhh0XUlszlmIzVyC
# gvIl2ZgsZbR2pnexJOrQg9QkFIy196slxsZh
# SIG # End signature block
