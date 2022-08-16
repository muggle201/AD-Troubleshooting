# Name tss_FindUserBadPwdAttempts.ps1

<# 
.SYNOPSIS
	Script to find sAMAccountName, pwdLastSet, lockoutTime, DC, lastLogon, logonCount, badPwdCount, badPasswordTime for a username.

.DESCRIPTION
	Script to assist in troubleshooting accounts experiencing bad password attempts. 
	It can also be used to investigate how accounts get locked out in Active Directory. 
	The script finds the values of the sAMAccountName, pwdLastSet, lockoutTime, lastLogon, 
	logonCount, badPwdCount, and badPasswordTime attributes for a specified user. 
	The last 4 attributes are not replicated, so a different value is saved on every domain controller in the domain. 
	A separate line of output is generated for each domain controller. 
	The script prompts for either the distingished name or the sAMAccountName of an account.

.PARAMETER UserName
 Please enter the user sAMAccountName or distinguished name
	
.PARAMETER DataPath
 This switch determines the path for output files
 

.EXAMPLE
 .\tss_FindUserBadPwdAttempts.ps1 -UserName "User1" -DataPath "C:\MS_DATA" 
 Example 1: find sAMAccountName,pwdLastSet,lockoutTime,DC,lastLogon,logonCount,badPwdCount,badPasswordTime for User1
	
.LINK
	https://gallery.technet.microsoft.com/Troubleshoot-Account-Bad-4bf47940
	https://microsoft.sharepoint.com/teams/HybridIdentityPOD/_layouts/15/Doc.aspx?sourcedoc={5bec59af-bf31-4073-9111-a63486fcdf0c}&action=view&wd=target%28Account%20Lockouts.one%7C9a46c4f5-38af-4648-93f2-8a976a91c463%2FWorkflow%20Account%20Lockout%20Data%20Collection%20-%20Reactive%7Cdc03d719-fff5-4bdf-b46e-15456c2521f1%2F%29
#>

# PowerShell Version 1 
# Author: Richard L. Mueller
# Version 1.0 - October 6, 2015
# Version 1.1 - 2020.03.25 WalterE

[CmdletBinding()]
PARAM (
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Enter user sAMAccountName or distinguished name')]
	[string]$UserName
	,
	[string]$DataPath = (Split-Path $MyInvocation.MyCommand.Path -Parent)
)

#_#write-host "count: $($Args.Count)"
# Check for parameter identifying the object.
<#
If ($Args.Count -eq 1)
{
    $UserName = $Args[0]
}
#>
If (-not $UserName)
{
    $UserName = Read-Host "[FindUserBadPwd] Enter user sAMAccountName or distinguished name"
}

$outfile = $DataPath+"\"+$env:COMPUTERNAME+"_BadPwdAttempts.txt"

# Setup the DirectorySearcher object.
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.PageSize = 200
$Searcher.SearchScope = "subtree"
$Domain = New-Object System.DirectoryServices.DirectoryEntry
$BaseDN = $Domain.distinguishedName

If ($UserName -Like "*,*")
{
    $Searcher.Filter = "(distinguishedName=$UserName)"
}
Else
{
    $Searcher.Filter = "(sAMAccountName=$UserName)"
}

# Check for existence of the user object on any DC.
$Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$BaseDN"
$Check = $Searcher.FindOne()
If (-Not $Check)
{
    Write-Host "ERROR: User $UserName not found" -foregroundcolor red
	"$(Get-Date -format "yyyyMMdd_HHmmss") ERROR: User $UserName not found" | Out-File -FilePath $outfile 
    Break
}

# Specify the attribute values to retrieve.
$Searcher.PropertiesToLoad.Add("distinguishedName") > $Null
$Searcher.PropertiesToLoad.Add("sAMAccountName") > $Null
$Searcher.PropertiesToLoad.Add("badPwdCount") > $Null
$Searcher.PropertiesToLoad.Add("badPasswordTime") > $Null
$Searcher.PropertiesToLoad.Add("lockoutTime") > $Null
$Searcher.PropertiesToLoad.Add("logonCount") > $Null
$Searcher.PropertiesToLoad.Add("lastLogon") > $Null
$Searcher.PropertiesToLoad.Add("pwdLastSet") > $Null

$D = [system.directoryservices.activedirectory.Domain]::GetCurrentDomain()
$PDC= $D.PdcRoleOwner

# Output a heading line.
"sAMAccountName,pwdLastSet,lockoutTime,DC,lastLogon,logonCount,badPwdCount,badPasswordTime" | Out-File -FilePath $outfile 

Write-Host "$(Get-Date -format "yyyyMMdd_HHmmss") Query every domain controller in the domain. Please be patient..."
ForEach ($DC In $D.DomainControllers)
{
    $Server = $DC.Name
    $Result = $Null
    # Identify the DC with the PDC Emulator role.
    If ($Server -eq $PDC) {$ServerName = "$Server (PDCe)"}
    Else {$ServerName = $Server}
    # Specify the DC and domain in the Base of the query.
    $Base = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$Server/$BaseDN"
    $Searcher.SearchRoot = $Base
    $Result = $Searcher.FindOne()
    If ($Result)
    {
        # Retrieve the values.
        $DN = $Result.Properties.Item("distinguishedName")
        $NTName = $Result.Properties.Item("sAMAccountName")
        $BadCount = $Result.Properties.Item("badPwdCount")
        $LogonCount = $Result.Properties.Item("logonCount")
        $Time = $Result.Properties.Item("badPasswordTime")
        $Last = $Result.Properties.Item("lastLogon")
        $Pwd = $Result.Properties.Item("pwdLastSet")
        $Lock = $Result.Properties.Item("lockoutTime")
        # Convert LargeInteger values into datetime values in the local time zone.
        If ($Time.Count -eq 0) {$BadTime = "Never"}
        Else
        {
            If ($Time.Item(0) -eq 0) {$BadTime = "Never"}
            Else {$BadTime = ([DateTime]$Time.Item(0)).AddYears(1600).ToLocalTime()}
        }
        If ($Last.Count -eq 0) {$LastLogon = "Never"}
        Else
        {
            If ($Last.Item(0) -eq 0) {$LastLogon = "Never"}
            Else {$LastLogon = ([DateTime]$Last.Item(0)).AddYears(1600).ToLocalTime()}
        }
        If ($Pwd.Count -eq 0) {$PwdLastSet = "Never"}
        Else
        {
            If ($Pwd.Item(0) -eq 0) {$PwdLastSet = "Never"}
            Else {$PwdLastSet = ([DateTime]$Pwd.Item(0)).AddYears(1600).ToLocalTime()}
        }
        If ($Lock.Count -eq 0) {$Lockout = "Never"}
        Else
        {
            If ($Lock.Item(0) -eq 0) {$Lockout = "Never"}
            Else {$Lockout = ([DateTime]$Lock.Item(0)).AddYears(1600).ToLocalTime()}
        }
        # Output in comma delimited format.
        "$NTName,$PwdLastSet,$Lockout,$ServerName,$LastLogon,$LogonCount,$BadCount,$BadTime" | Out-File -FilePath $outfile -Append
    }
    Else
    {
        Write-Host "ERROR: Failed to connect to DC $Server" -foregroundcolor red -backgroundcolor black
		"ERROR: Failed to connect to DC $Server" | Out-File -FilePath $outfile -Append
        ",,,$ServerName,,,," | Out-File -FilePath $outfile -Append
    }
}

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "$(Get-Date -UFormat "%R:%S") Done, result in $outfile"

# SIG # Begin signature block
# MIInugYJKoZIhvcNAQcCoIInqzCCJ6cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBbM03tEPPhj6F
# XqO4TJ/LXceK13qnnPT+6KuX4OVBGaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZjzCCGYsCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgijv89noA
# TA5kJk/3PfLyh0Q6rzQhi4cJbGaEG7fjHtIwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCXGuCYTLSwb9QI5aqqBhhEPH5Wf4urKZRVkE4VUmox
# TkOq3mpEXaAELhA26DEVoDmv5v9j5b7Ss/8C4e3sbrhVd/hu7wVT7yokvy9/1ULJ
# TJziMzM36qZU5T6s2YmA2gByDetcv0K9dwTmmdhVGbZccIZACLEnhZT/JATWqdX4
# WxmqLnbnbgarL36n2wZOkJqBOSDkRgRfDBleGYgWvewr6gY7rTKQZlNbzooDpfz6
# zEmOSXL0vYWLIP7Np5m9SILG3QZbgpMBfZeYrfbVYJmtlpVf4zHu+vcm8SfEGN0C
# LtjjEWlP9ly3xh66omsF9rXUikDoBfn/f4vjxRUMR+QYoYIXGTCCFxUGCisGAQQB
# gjcDAwExghcFMIIXAQYJKoZIhvcNAQcCoIIW8jCCFu4CAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIMKtojWMAKkcyeBoMOa3Nzr1SYuensa7SrSrcdYI
# kerbAgZi3ozruwYYEzIwMjIwODE2MDkyMDExLjcxOFowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghFoMIIHFDCCBPygAwIBAgITMwAAAYo+OI3SDgL6
# 6AABAAABijANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMTEwMjgxOTI3NDJaFw0yMzAxMjYxOTI3NDJaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjE3OUUtNEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/+ut6GD
# AyAZvegBhagWd0GoqT8lFHMepoWNOLPPEEoLuya4X3n+K14FvlZwFmKwqap6B+6E
# kITSjkecTSB6QRA4kivdJydlLvKrg8udtBu67LKyjQqwRzDQTRhECxpU30tdBE/A
# eyP95k7qndhIu/OpT4QGyGJUiMDlmZAiDPY5FJkitUgGvwMBHwogJz8FVEBFnViA
# URTJ4kBDiU6ppbv4PI97+vQhpspDK+83gayaiRC3gNTGy3iOie6Psl03cvYIiFcA
# JRP4O0RkeFlv/SQoomz3JtsMd9ooS/XO0vSN9h2DVKONMjaFOgnN5Rk5iCqwmn6q
# sme+haoR/TrCBS0zXjXsWTgkljUBtt17UBbW8RL+9LNw3cjPJ8EYRglMNXCYLM6G
# zCDXEvE9T//sAv+k1c84tmoiZDZBqBgr/SvL+gVsOz3EoDZQ26qTa1bEn/npxMmX
# ctoZSe8SRDqgK0JUWhjKXgnyaOADEB+FtfIi+jdcUJbpPtAL4kWvVSRKipVv8MEu
# YRLexXEDEBi+V4tfKApZhE4ga0p+QCiawHLBZNoj3UQNzM5QVmGai3MnQFbZkhqb
# UDypo9vaWEeVeO35JfdLWjwRgvMX3VKZL57d7jmRjiVlluXjZFLx+rhJL7JYVptO
# PtF1MAtMYlp6OugnOpG+4W4MGHqj7YYfP0UCAwEAAaOCATYwggEyMB0GA1UdDgQW
# BBQj2kPY/WwZ1Jeup0lHhD4xkGkkAzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQDF9MESsPXDeRtfFo1f575iPfF9
# ARWbeuuNfM583IfTxfzZf2dv/me3DNi/KcNNEnR1TKbZtG7Lsg0cy/pKIEQOJG2f
# YaWwIIKYwuyDJI2Q4kVi5mzbV/0C5+vQQsQcCvfsM8K5X2ffifJi7tqeG0r58Cjg
# we7xBYvguPmjUNxwTWvEjZIPfpjVUoaPCl6qqs0eFUb7bcLhzTEEYBnAj8MENhiP
# 5IJd4Pp5lFqHTtpec67YFmGuO/uIA/TjPBfctM5kUI+uzfyh/yIdtDNtkIz+e/xm
# XSFhiQER0uBjRobQZV6c+0TNtvRNLayU4u7Eekd7OaDXzQR0RuWGaSiwtN6Xc/Po
# NP0rezG6Ovcyow1qMoUkUEQ7qqD0Qq8QFwK0DKCdZSJtyBKMBpjUYCnNUZbYvTTW
# m4DXK5RYgf23bVBJW4Xo5w490HHo4TjWNqz17PqPyMCTnM8HcAqTnPeME0dPYvbd
# wzDMgbumydbJaq/06FImkJ7KXs9jxqDiE2PTeYnaj82n6Q//PqbHuxxJmwQO4fzd
# OgVqAEkG1XDmppVKW/rJxBN3IxyVr6QP9chY2MYVa0bbACI2dvU+R2QJlE5AjoMK
# y68WI1pmFT3JKBrracpy6HUjGrtV+/1U52brrElClVy5Fb8+UZWZLp82cuCztJMM
# SqW+kP5zyVBSvLM+4DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUw
# DQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhv
# cml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg
# 4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aO
# RmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41
# JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5
# LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL
# 64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9
# QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj
# 0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqE
# UUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0
# kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435
# UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB
# 3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTE
# mr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwG
# A1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNV
# HSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNV
# HQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo
# 0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29m
# dC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5j
# cmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDAN
# BgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4
# sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th54
# 2DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRX
# ud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBew
# VIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0
# DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+Cljd
# QDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFr
# DZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFh
# bHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7n
# tdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+
# oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6Fw
# ZvKhggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTc5RS00QkIw
# LTgyNDYxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoB
# ATAHBgUrDgMCGgMVAIDw82OvG1MFBB2n/4weVqpzV8ShoIGDMIGApH4wfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmpWKWMCIY
# DzIwMjIwODE2MDgyNTU4WhgPMjAyMjA4MTcwODI1NThaMHcwPQYKKwYBBAGEWQoE
# ATEvMC0wCgIFAOalYpYCAQAwCgIBAAICDpwCAf8wBwIBAAICKM4wCgIFAOamtBYC
# AQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEK
# MAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCxsU/RbJSmPmEwxrKNgJ+PqeyW
# kgZRD7gHu4xlBhvzK0rUgcbJ2be0HzYbVpVH9PL0lS0z0grFroIutS46l9MLD2gv
# JnkkMPD56LzMCZ5aYqqWeu3j7453HW/QoOXwpGiwOolYg/+jzRk0XdLAgFN8HFIK
# lcepDNQJk9BTGoNZLTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABij44jdIOAvroAAEAAAGKMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIBHV
# B3flFHciGs2HDmCQLwwKHgeJcxIAxZqHOytmxwRAMIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQg9L3gq3XfSr5+879/MPgxtZCFBoTtEeQ4foCSOU1UKb0wgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYo+OI3SDgL6
# 6AABAAABijAiBCBlTTGALcO1kGIPi9mJKdOzeG6COAAINhhKCEUsoUp56TANBgkq
# hkiG9w0BAQsFAASCAgAu4xrNI5fjenb7lEH5bAXB9QUPkPeEGwTStnJH6RmrPMxT
# k0Vr7HpFms7Nym1FUaVstk88AxXvihd+sKVTUWrat/x1NMg5GHSSftmTtyRn9ABI
# FCJgEFsImuyN6jyisbxY+Zkb43CSZUGsi1q3dHgidzyPS4NWonYbFaolumOl76fS
# nSQtm5Y9TiojMWxQsCN0dvSGoVdqhkiP2+r+KJsgGnhfdn7Bo2ubwW7pffzaXGhe
# nd0honFHewtdUbYV20IPKkbiml0Hc6xCO8W4kML834Yz8Se/K6leUK49yF9zH6N3
# uoj0pteIVUnXx2PdNkqj9FcmRX29dG3ZDcKQnFA5C8l51v30FtcdmwGtqwBYNh+8
# 1z+pN+HsceBQS7US5qIxmouvxXf//QDzx7cxqo8DUyGn4DJRzxuBf62Aq5bU4oNd
# KyWLcylffUpS9CY3GGhcxf3wUe2tm1eWBV2E5mGBVUyZKKq7iJwwtvFKMgx3jhPQ
# sDwYlPx6jqhMZA1Psx9lxaF3Q7twXNr60BhTUBLpn8JcDJIgcctDwu1K3qyx1JxI
# TU/6HhKFIEz5niaiW0r6jRGwKGTN5SgZoiBAGqF7YAZV0ad3/Rur/LEjs6DjwuId
# EeWB7QUCtvzzqwQsZOUqYGFNdjsnWS1VeTiIhp3OC+Vf0apRjQ8PeWiQ/YijJQ==
# SIG # End signature block
