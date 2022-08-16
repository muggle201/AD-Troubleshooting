<#
File: TSSv2_UEX_WVD.psm1

.SYNOPSIS
   UEX Scenarios helper module for Managemen
   Collect WMI log and settings
   Collect Printing log and settings
   Collect WinRM log and settings
   Collect Task log and settings


.DESCRIPTION
   Collect WMI log and settings and save them to WMI log folder
   Collect Printing log and settings and save them to printing log folder
   Collect WinRM log and settings and save them to WinRM log folder
   Collect Task log and settings and save them to Task log folder

.NOTES  
   Authors    : Gianni Bragante, Luc Talpe, Ryutaro Hayashi and Milan Milosavljevic
   Requires   : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDateUEX_WVD
#>

<# latest changes
  2022.05.12.0 [we] #_# This .psm1 module seems not to be used at all, tests should be done in TSSv2_DEV.psm1. Reason: -Help or -Find -outputs should not show all the test-only functions
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7 or Win11+
#>

$global:TssVerDateUEX_WVD= "2021.11.10.0"

<#
#region Switches
# Normal trace -> data will be collected in a sign
$TEST_TEST1Providers = @(
    '{CC85922F-DB41-11D2-9244-006008269001}' # LSA
    '{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
)

$TEST_TEST2Providers = @(
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' # NTLM
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
)

# Normal trace with multi etl files
$TEST_TEST3Providers = @(
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}!NTLM'
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}!schannel'
)

$TEST_TEST4Providers = @(
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
)

$TEST_TEST5Providers = @(
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' # NTLM
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
)


#endregion Switches


#region Scenarios

# Scenario trace
Switch (FwGetProductTypeFromReg)
{
    "WinNT" {
        $TEST_ETWTracingSwitchesStatus = [Ordered]@{
            'TEST_TEST1' = $true
            'TEST_TEST2' = $true
            'TEST_TEST3' = $true   # Multi etl file trace
            'TEST_TEST4' = $true   # Single trace
            'TEST_TEST5' = $False  # Disabled trace
            'UEX_Task' = $True     # Outside of this module
        }
    }
    "ServerNT" {
        $TEST_ETWTracingSwitchesStatus = [Ordered]@{
            'TEST_TEST1' = $true
            'TEST_TEST2' = $true
        }
    }
    "LanmanNT" {
        $TEST_ETWTracingSwitchesStatus = [Ordered]@{
            'TEST_TEST1' = $true
            'TEST_TEST2' = $true
        }
    }
    Default {
        $TEST_ETWTracingSwitchesStatus = [Ordered]@{
            'TEST_TEST1' = $true
            'TEST_TEST2' = $true
        }
    }
}
#endregion Scenarios


#region Functions

### Data Collection
function CollectTEST_TEST1Log
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    LogInfo "This is message from LogInfo()."
    LogInfo "This is message from LogInfo() with color." "Blue"
    LogWarn "This is message from LogWarn()."
    LogWarn "This is message from LogWarn() with color." "Cyan"
    LogError "This is message from LogError()."
    LogError "This is message from LogError() with color." "DarkCyan"
    LogDebug "This is message from LogDebug()."
    LogDebug "This is message from LogDebug() with color." "DarkRed"
    EndFunc $MyInvocation.MyCommand.Name
}

### Diag function
function RunTEST_TEST1Diag
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

### Pre-Start / Post-Stop function for trace
function TEST_TEST1PreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

function TEST_TEST1PostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

### Pre-Start / Post-Stop function for scenario trace
function TESTScenarioPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

function TESTScenarioPostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
#endregion Functions


Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
#>
# SIG # Begin signature block
# MIInqAYJKoZIhvcNAQcCoIInmTCCJ5UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBmr0Acl3aiceZA
# 3y7N/k2Awm3vnRSN2P35TPKmjkGioaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZfTCCGXkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgNebQeQQE
# xlsqjrE9o7TwvPLUwuBFjfrBZJ5WumGLbJowQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAmuYk3nCUBjoEaTYc7VrQ9oIe7nU+ktRxwhgfU0040
# JJpYRgWY1skM341L6wQvGL/gFwnce3CHbKgv4vFP+Lr5JtSCbAzf31EMA9rhFJqe
# e1UwxHGvJTbngjlJd/eioH4diN7/jaZ5feJfT/RZ9TSRPlrauF1IROArvfCAsBwH
# 5JQC69vavNMy7hXemJsGmn3wo6Gk2knp4dP1rLWHOPJsi3glrTuSbiMPGBKlVGLr
# JO3AS1zPuRtFDJXCfSfgh8zMfyBdcbvozQyL1UyYddrYj1hbFqQJ1hQy6SA1yQb2
# 2NzauMu1B6m86yiCkoqeESjE4QVwzK6RKiHNpnylAMi7oYIXBzCCFwMGCisGAQQB
# gjcDAwExghbzMIIW7wYJKoZIhvcNAQcCoIIW4DCCFtwCAQMxDzANBglghkgBZQME
# AgEFADCCAVMGCyqGSIb3DQEJEAEEoIIBQgSCAT4wggE6AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEINbY1LVRy1JQ60dbwUbSvLQ9aaE2JdNCXBZ/a29o
# +NYuAgZi2sEF02QYETIwMjIwODE2MDkxODEwLjJaMASAAgH0oIHUpIHRMIHOMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNy
# b3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046QzRCRC1FMzdGLTVGRkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2WgghFcMIIHEDCCBPigAwIBAgITMwAAAaP7mrOOe4ZDTwABAAAB
# ozANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0yMjAzMDIxODUxMTZaFw0yMzA1MTExODUxMTZaMIHOMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0
# aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QzRCRC1F
# MzdGLTVGRkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDvvU3Ky3sqCnAqi2zbc+zb
# diWz9UxM8zIYvOIEumCyOwhenVUgOSNWxQh3MOmRdnhfEImn9KNl0l3/46ebIJlG
# LTGxouJ3gLVkjSucobeIskIQcZ9EyEKhfjYrIgcVvnoTGFhGxSPu3EnV/3VsPv2P
# PzLvbqt1wiuT9hvmYm1cDlR/efiIkxp5qHMVoHbNKpQaWta2IN25fF1XuS9qk1Ji
# Qb50Kcdm1K7u9Jbdvx6FOWwWyygIQj6ccuJ5rK3Tkdxr+FG3wJraUJ7T++fDUT4Y
# NWwAh9OhZb2yMj/P7kbN8dt9t3WmhqSUGEKGaQAYOtqxQ0yePntOrbfsW376fDPZ
# aPGtWoH8WUNaSE9VZyXWjvfIFjIjFuuXXhVIlEflp4EFX79oC7L+qO/jnKc8ukR2
# SJulhBmfSwbee9TXwrMec9CJb6+kszdEG2liUyyFm18G1FSmHm61xFRTMoblRkB3
# rGQflcFd/OoWKJzMbNI7zPBqTnMdMS8spuNlwPfVUqbLor0yYOKPGtQAiW0wVRaB
# AN1axUmMznUOr818a8cOov09d/JvlxfsirQBJ4aflHgDIZcO4z/fRAJYBlJdCpHA
# Y02E8/oxMj4Cmna1NaH+aBYv6vWA5a1b/R+CbFXvBhzDpD0zaAeNNvI/PDhHuNug
# bH3Fy5ItKYT6e4q1tAG0XQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFFBR+7M8Jgix
# z00vQaNoqy5yY4uqMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAFry3qdpl8OorgcRrtD7LLZlyOYC5oD5EykJ44GZ
# bKHoqbLWvaJLtDE1cZR1XXHQWxXFRzC0UZFBSJHyp2nJcpeXso9N8Hg+m/6VHxcg
# 2QfAGaRlF4U2CzUfD3qTOsg+oPtBNZx9DIThqBOlxbn5G5+niHTUxrlsAXhK9gzY
# hoQxpcGlB+RC894bbsjMligIGBdvAuIssoWHb5RvVTeiZwuJnPxCLedAQh6fGUAJ
# Oxwt0TpbYNYLuTYxmklXYrGouTiVn+nubGEHQwTWClyXYh3otTeyvi+bNb1fgund
# 07BffgDaYqAQwDhpxUmLeD/rrVtdYt+4iyy2/duqQi+C8vvhlNMJc2H5+59tkckJ
# rw9daMomR4ZkbLAwarAPp7wlbX5x9fNw3+aAQVbJM2XCU1IwsWmoAyuwKgekANx+
# 5f9khXnqn1/w7XZXuAfrz1eJatQgrNANSwfZZs0tL8aEQ7rGPNA0ItdCt0n2StYc
# smo/WvKW2RtAbAadjcHOMbTgxHgU1qAMxfZKOFendPbhRaSay6FfnvHCVP4U9/kp
# Vu3Z6+XbWL84h06Wbrkb+ClOhdzkMzaR3+3AS6VikV0YxmHVZwBm/Dc1usFk42Yz
# AjXQhRu6ZCizDhnajwxXX5PhGBOUUhvcsUu+nD316kSlbSWUnCBeuHo512xSLOW4
# fCsBMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs8wggI4
# AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046QzRCRC1FMzdGLTVGRkMxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAB5f
# 6V5CzAGz2qQsGvhl3N0pQw0ToIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmpYtYMCIYDzIwMjIwODE2MDcxOTUy
# WhgPMjAyMjA4MTcwNzE5NTJaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOali1gC
# AQAwBwIBAAICGFEwBwIBAAICEUUwCgIFAOam3NgCAQAwNgYKKwYBBAGEWQoEAjEo
# MCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG
# 9w0BAQUFAAOBgQA9IW3gGHPMMugT1qN4lb2+72n9wbTNCivjwvA3p4pbgJqeDheP
# u9VUv4oolDvhORXlTWawbtg6G0FTLWSnG+9oIRM19zE4LHT7d9PEYvNtaMVgGcRM
# 3lelP7zWzv79owdr/oBYSWEMMPg0jFXWn9eWMaXBiKoKUKM4fjnjEsBB2DGCBA0w
# ggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABo/ua
# s457hkNPAAEAAAGjMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIOKI4I8w/XW7IpwSVgiuxaQMm4lm
# fSA+tzNwhdwrLeA5MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgjPi4sAZx
# zDKDnf7IG2mMacLxCZURGZf6Uz5Jc+nrjf4wgZgwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaP7mrOOe4ZDTwABAAABozAiBCB1g7rhSWYg
# 5+6QH9CRqpbB5OFFuwTQw7r0iBRAaprUEzANBgkqhkiG9w0BAQsFAASCAgCvmUhR
# Tz+ETtXQqu+AQbryYSoAlZLEHh7u6uva8qVW+jotxdLvefPCSFOgYr84my3uYYx/
# rphX/mGUPvKvrVTEwIsXHCKU07bNBd9P79Or5pCs0VCEkeohNRLsavK8XDNReWXl
# 9vfBXgyJEaOtarw0kB1/ze6oTnPEyji3u49TNOCQAUgJv8VcKmDfATzHJVXWz00l
# vgt4KyG2GGOZkZuyAi4l/xQ/WW/TNTvNwmd3NVn/oEtqxJvYUYN6SdsjLEzA7HYq
# TMm4rcm1/Fe5dxDMYsMq0PkeNjvVRBdjY/V6Mmqb7QzM5S7bOL4jvEE+6UGE0uCp
# MAn4AZsSi9hJN0cGMBIljSS9xBVRrWi7mU6XyZXHjcSHCvx6UP+qjSIqomAIMiQe
# J7q+a/GsFclMKNBFBNyIu11wwT3SaELmWVLWzG3bEakIneUoNyUJhX5w0reqUS3t
# ofmmkZXckE2QN6HWY5Cfz8pTl/Uj6VRARv8MopNX8BxXfpN2X0TZ61PlzIoUgFBZ
# DYxm96NmDBbI1tnv0FCfkT5y38QvXYb4dWLpN1Qc3kImpa0wraCibcSu0AqAjNoC
# AxZbFIdQNW9zfCRaimvarMc3cKyXcqo8S11V15qFWFSkZbUbHotxhRNFii/3kJuH
# 8EsC5pd73JKlNd6TwKufxOJ1+WBPhq5cO77qUQ==
# SIG # End signature block
