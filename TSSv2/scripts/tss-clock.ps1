Param (
    [Parameter(Mandatory=$False)]
    [switch]$noTopMost # Usually this is used with RDS/AVD scenario.
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework  # We load WPF for DPI awareness
[xml]$Xaml= @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window"></Window>
"@
$Reader= (New-Object System.Xml.XmlNodeReader $Xaml)
$Window= [Windows.Markup.XamlReader]::Load($Reader)
$IsHighDPI = $False

$LogPixels = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI" -ErrorAction Ignore).LogPixels
If($Null -ne $LogPixels -and $LogPixels -ge 144){
    $IsHighDPI = $True
}

###           ###
### Functions ###
###           ###
Function UpdateTimeLabel{
    $Date = Get-Date -Format "yyyy/MM/dd"
    $Time = Get-Date -Format "HH:mm:ss"
    $DateLabel.Text = "$Date`n$Time"
}

###             ###
### Window Form ###
###             ###
$Form = New-Object System.Windows.Forms.Form
If($IsHighDPI){
    $FormHight=380
    $FormWidth=400
}Else{
    $FormHight=255
    $FormWidth=300
}
$Form.Size = New-Object System.Drawing.Size($FormWidth,$FormHight)

# Titile bar
$Form.Text = "TSS Clock"
$Form.FormBorderStyle = 3 # FixedDialog
If(!$noTopMost.IsPresent){
    $Form.Topmost = $True		# keep TSS clock Topmost
}
# Color. Set Windows 11 color style.
$Form.BackColor = "#E8F1F8"

# Window position
$Form.StartPosition = 0 # FormStartPosition.Manual
$Screens = [System.Windows.Forms.Screen]::AllScreens
$Left = $Screens.WorkingArea.Width * 0.05
$Top = $Screens.WorkingArea.Height * 0.1
$Form.Location = New-Object System.Drawing.Point($Left,$Top)

###       ###
### Label ###
###       ###
If($IsHighDPI){
    $DateLabelPosition = 140
}Else{
    $DateLabelPosition = 70
}
# Date
$DateLabel = New-Object System.Windows.Forms.Label
$DateLabel.AutoSize = $False
$DateLabel.Size = New-Object System.Drawing.size($FormWidth,$DateLabelPosition)
$DateLabel.Font = New-Object System.Drawing.Font("Segoe UI",20)
$DateLabel.ForeColor = "#0078D4"
$DateLabel.TextAlign = 32 # MiddleCenter

# Computer/User/Session
If($IsHighDPI){
    $InfoLabelPosition = 140
    $InfoLabelSize = 130
}Else{
    $InfoLabelPosition = 80
    $InfoLabelSize = 100
}
$InfoLabel = New-Object System.Windows.Forms.Label
$InfoLabel.AutoSize = $False
$InfoLabel.Location = New-Object System.Drawing.Point(25,$InfoLabelPosition)
$InfoLabel.Size = New-Object System.Drawing.size($FormWidth,$InfoLabelSize)
$InfoLabel.Font = New-Object System.Drawing.Font("Segoe UI",10)
$InfoLabel.ForeColor = "#281E5D"
$SessionID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
# Issue#334 - add Timezone info to clock display
#we# If($PSVersionTable.PSVersion.Major -le 4){ # PowerShell 4.0
If(($PSVersionTable.PSVersion.Major -le 4) -or ($global:OSBuild -le 9600)){ # PowerShell 4.0 / #we# Get-TimeZone fails on Srv2012R2 with PS v5.0 
    $TimeZone = [System.TimeZoneInfo]::Local.DisplayName
}Else{
    $TimeZone = (Get-TimeZone).DisplayName
}
$InfoLabel.Text = "Computer: $ENV:COMPUTERNAME`nUser: $ENV:USERNAME`nSession: $SessionID`nTZ: $TimeZone"

# Footer
If($IsHighDPI){
    $FooterLabelPosition = 260
    $FooterLabelSize = 70
}Else{
    $FooterLabelPosition = 170
    $FooterLabelSize = 50
}
$FooterLabel = New-Object System.Windows.Forms.Label
$FooterLabel.AutoSize = $False
$FooterLabel.Location = New-Object System.Drawing.Point(0,$FooterLabelPosition)
$FooterLabel.Size = New-Object System.Drawing.size($FormWidth,$FooterLabelSize)
$FooterLabel.Font = New-Object System.Drawing.Font("Segoe UI",9)
$FooterLabel.Text = "PLEASE do NOT close this window `nor any TSS related windows OPENED!"
$FooterLabel.BackColor = "#1F456E"
$FooterLabel.ForeColor = "#FFFFFF"
$FooterLabel.TextAlign = 32 # MiddleCenter

UpdateTimeLabel # Set $DateLabel.Text

###       ###
### Timer ###
###       ###

# Update clock using Timer with 1 sec interval.
$Timer = New-Object System.Windows.Forms.Timer
$Timer.Interval = 1000
$DisplayedTime = "(Get-Date -Format `"yyyy/MM/dd`")`n(Get-Date -Format `"HH:mm:ss`")"
$UpdateTime = {UpdateTimeLabel} # Call UpdateTimeLabel()
$Timer.Add_Tick($UpdateTime)
$Timer.Enabled = $True

# We are all set. Add components and show the window.
$Form.Controls.Add($FooterLabel)
$Form.Controls.Add($InfoLabel)
$Form.Controls.Add($DateLabel)
$Form.Add_Shown({$Form.Activate()})
$Ret = $Form.ShowDialog()  # Script stops here.

# Release instances.
$DateLabel.Dispose()
$InfoLabel.Dispose()
$FooterLabel.Dispose()
$Form.Close()
$Form.Dispose()

# SIG # Begin signature block
# MIIntQYJKoZIhvcNAQcCoIInpjCCJ6ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBHERS6hAAxCpJ6
# 4vb15QGUDjI4cG2gcW1GORjvV4k99qCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZijCCGYYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgwV0bfTWM
# oFPBNb+h3TSIvqRzZ1La+Vh18eVOowdYbYYwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBjrsimlMiVwA58fqZp9QcQiRF4i5gayVKjvNmqxKKE
# aRFjudDRz4Nm1pWwQZPTIY5cUOr4YQIXZvZzQcgwcG/wY2inlh8nN4XKlAUpXjXj
# j96ijMA1Ast8RDCDmhOWGw7b6gBkItwWsJ+amJHf0RVe/xnq2xpm2qd/47h0KC72
# OR3gXVUhfFFhkdt1OMylQ349x1bpD3sWWuOs2lh18fSKHPLrlyvj7vVgVlLubm3w
# rHXK4IsOIIcl0Y8cdrpPXBZCDokKRwZY2cFrJfmmYfywDfV6EilifA6s34OMVmJ+
# FOKS7a6z+LoF9FINgjTHf+Sow0sXRiPhWmNjMCrVoWBnoYIXFDCCFxAGCisGAQQB
# gjcDAwExghcAMIIW/AYJKoZIhvcNAQcCoIIW7TCCFukCAQMxDzANBglghkgBZQME
# AgEFADCCAVcGCyqGSIb3DQEJEAEEoIIBRgSCAUIwggE+AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIBr9agnvd4lKcTVOnDCPWMBwNBCL19zWi2M+Ba6X
# mgoAAgZi3n9zZQAYETIwMjIwODE2MDkyMDExLjdaMASAAgH0oIHYpIHVMIHSMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNy
# b3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRZTCCBxQwggT8oAMCAQICEzMAAAGOWdtGAKgQlMwA
# AQAAAY4wDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjExMDI4MTkyNzQ1WhcNMjMwMTI2MTkyNzQ1WjCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKojAqujjMy2
# ucK7XH+wX/X9Vl1vZKamzgc4Dyb2hi62Ru7cIMKk0Vn9RZI6SSgThuUDyEcu2uiB
# VQMtFvrQWhV+CJ+A2wX9rRrm8mPfoUVPoUXsDyR+QmDr6T4e+xXxjOt/jpcEV6eW
# BEerQtFkSp95q8lqbeAsAA7hr9Cw9kI54YYLUVYnbIg55/fmi4zLjWqVIbLRqgq+
# yXEGbdGaz1B1v06kycpnlNXqoDaKxG03nelEMi2k1QJoVzUFwwoX2udup1u0UOy+
# LV1/S3NKILogkpD5buXazQOjTPM/lF0DgB8VXyEF5ovmN0ldoa9nXMW8vZ5U82L3
# +GQ6+VqXMLe7U3USCYm1x7F1jCq5js4pYhg06C8d+Gv3LWRODTi55aykFjfWRvjs
# ec0WqytRIUoWoTNLkDYW+gSY6d/nNHjczBSdqi2ag6dv92JeUPuJPjAxy04qT+lQ
# XcXHVX3eJoK1U8d2nzuSjX4DJ4Bhn4UmsBq2kVtvBIayzrKZiMYovdhO7453CdrX
# I4SwowQK1aT4d3GRuYN2VcuYogGqA2rMKTYJzBQCuVJ9a3ivjBYT4vYjJ71D8LUw
# wybeWBA+QwE95gVMaeUB97e0YWcACTS1i7aU3hhe7m/NbEimL9mq3WswHvVy0tdL
# VdqDj63J4hic5V1u1T78akDcXvJQgwNtAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU
# 7EH5M/YE+ODf+RvLzR2snqfmleQwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
# JTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr
# BgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEANVCvccyHk5SoUmy59G3pEeYGIemw
# dV0KZbgqggNebJGd+1IpWhScPPhpJQy85TYUj9pjojs1cgqvJJKap31HNNWWgXs0
# MYO+6nr49ojMoN/WCX3ogiIcWDhboMHqWKzzvDJQf6Lnv1YSIg29XjWE5T0pr96W
# pbILZK29KKNBdLlpl+BEFRikaNFBDbWXrVSMWtCfQ6VHY0Fj3hIfXBDPkYBNuucO
# VgFW/ljcdIloheIk2wpq1mlRDl/dnTagZvW09VO5xsDeQsoKTQIBGmJ60zMdTeAI
# 8TmwAgzeQ3bxpbvztA3zFlXOqpOoigxQulqV0EpDJa5VyCPzYaftPp6FOrXxKRyi
# 7e32JvaH+Yv0KJnAsKP3pIjgo2JLad/d6L6AtTtri7Wy5zFZROa2gSwTUmyDWekC
# 8YgONZV51VSyMw4oVC/DFPQjLxuLHW4ZNhV/M767D+T3gSMNX2npzGbs9Fd1FwrV
# OTpMeX5oqFooi2UgotZY2sV/gRMEIopwovrxOfW02CORW7kfLQ7hi4lbvyUqVRV6
# 81jD9ip9dbAiwBhI6iWFJjtbUWNvSnex3CI9p4kgdD0Dgo2JZwp8sJw4p6ktQl70
# bIrI1ZUtUaeE5rpLPqRsYjBsxefM3G/oaBSsjjbi92/rYMUwM97BdwVV/bpPTORf
# jhKHsi8hny3pDQIwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0G
# CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9
# uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZr
# BxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk
# 2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxR
# nOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uD
# RedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGa
# RnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fz
# pk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG
# 4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGU
# lNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLE
# hReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0w
# ggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+
# gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNV
# HSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9
# lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3Js
# MFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJ
# KoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEG
# k5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2
# LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7nd
# n/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSF
# QrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy8
# 7JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8
# x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2f
# pCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz
# /gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQ
# KBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAx
# M328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGby
# oYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRp
# b25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1E
# MjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQA9YivqT04R6oKWucbD5omK7llbjKCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5qVVMTAiGA8y
# MDIyMDgxNjA3Mjg0OVoYDzIwMjIwODE3MDcyODQ5WjB0MDoGCisGAQQBhFkKBAEx
# LDAqMAoCBQDmpVUxAgEAMAcCAQACAg6pMAcCAQACAhFHMAoCBQDmpqaxAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAcataZ5yuzeyfAiMNEnVQw02uoR7eouZ6
# WAEucHFpHXpbQKS4EUL264kd/tNBlidrc+NDfoUL11VcMxrQgYEy2dvgsP8rW5Dk
# ALDD60kMb9liQTHF2Crgf8X2oxVG8nSNCoiM5Fu3JLeOeksCakIYJCjS8/WmUn8t
# 2HfuEfW0l3UxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAY5Z20YAqBCUzAABAAABjjANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBtvRkmyih4
# MgNlh638fYoyUEawF0sxWLoPpB6gzkC7DjCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIL0FjyE74oGlLlefn/5VrNwV2cCf5dZn/snpbuZ15sQlMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGOWdtGAKgQlMwAAQAA
# AY4wIgQg9fVEB7DZJDl5wloxN5NOS0o5x+8sQ3H+hXAxRpLHJWcwDQYJKoZIhvcN
# AQELBQAEggIAD/6+KSE1w6k0cg6F8UKjMkNRsMr/oshYK5562DzmENHQCQPlyFLy
# dDOLqwP0XpjBQWHC7OE8QBaBuT/ffbyQDkTksOEVqt3ssQk2uyDNeUDoaTC0u4L3
# knKIL6pTmXmm5Mp1Pkp56u6oF3Ga0bMLJtCi63rFDLAOE+9PnX8FzeQ2TXG4kfSm
# ex7CcZ7p1haYX8qcYL2hiD1FFtwfjpUnHot+swXtyslOdEiap8iXRsuWrreUG7h5
# pKeoY8IIvJqzU1jxc/pwsDzS0a3NcmRLmVrWr1/y2iBc0k97s608WHTMLHZ9vmQI
# xDoHfd/3a4+98iFNmuJWA25hImww/SVFuqItlxlh8Rkn2BAWGnoJ+oF8JtqJcVfL
# dyZ8u4IXiRCZ4BiHSI5ptyGEV68GWNRUnoDi7WZSWoC3ygtnqfQ6sLtRyg98whu4
# 3nRw5GYowZp4Y3iSCFgbvGDDVY9jmna2BujcN7bdP008mrbpOPhZIk/CnFYgETk/
# J7dkZpWmS2KdsSAvlxXxv5aD8GcZglJV1t5FTTPJ5P5qCVe5P74wUO3yMldp8Nr2
# 3zSqqkYd1ydmYthhY6DMFxlbtnYOutgWGvr2u6ckCHNp3AzkN4wNeKLmOiXfKNJO
# fXZztDPRpm3aYPIDjw/jzU8mps3BaMjV0wZMx7GPRxDhlQ9ib5KX0nE=
# SIG # End signature block
