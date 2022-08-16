param( 
  [string]$DataPath,
  [switch]$AcceptEula,
  [switch]$NoDumps = $false
)

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking
$toolName = "Print-Collect"
$version = $toolName + " 2021-Dec-08"
# maintained by Marius Porcolean (maporcol) using Gianni Bragante's (gbrag) framework

Deny-IfNotAdmin

# Initialize some global variables & output folder
$resName = "$($ToolName -replace "Collect","Results")-" + $env:computername + "-" + $(get-date -f yyyyMMdd_HHmmss)
# Check if a destination folder was explicitly requested
if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    $answer = Read-Host "The destination folder ${DataPath} does not exist. Do you want to create it now? y/n"
    if ($answer -eq 'y') {
      New-Item -ItemType "directory" -Path $DataPath -Force
    }
    else {
      exit
    }
  }
  $global:resDir = $DataPath + "\" + $resName
}
else {
  $global:resDir = $global:Root + "\" + $resName
}
New-Item -ItemType "directory" -Path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"
$global:RdrOut = " >>""" + $global:outfile + """"
$global:RdrErr = " 2>>""" + $global:errfile + """"
# $fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
# $OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) / 10

Write-Log $version

# License Agreement
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eula = ShowEULAIfNeeded $ToolName 2
}
else {
  $eula = ShowEULAIfNeeded $ToolName 0
  if ($eula -ne "Yes") {
    Write-Log "EULA declined, exiting"
    exit
  }
}
Write-Log "EULA accepted, continuing"

# Collect dumps if not disabled
if ($NoDumps) {
  Write-Log "We have the NoDumps flag, skipping collection of process dumps."
}
else {
  Write-Log "Collecting dump of the Spooler service"
  $pidSpooler = FindServicePid "Spooler"
  if ($pidSpooler) {
    CreateProcDump $pidSpooler $global:resDir "spoolsv"
  }

  Write-Log "Collecing the dumps of splwow64 if they exist"
  $list = get-process -Name "splwow64" -ErrorAction SilentlyContinue 2>>$global:errfile
  if (($list | Measure-Object).count -gt 0) {
    foreach ($proc in $list) {
      Write-Log ("Found splwow64.exe with PID " + $proc.Id)
      CreateProcDump $proc.Id $global:resDir "splwow64-$($proc.Id)"
    }
  }
  else {
    Write-Log "No splwow64 process found"
  }

  Write-Log "Collecing the dumps of PrintIsolationHost.exe processes"
  $list = get-process -Name "PrintIsolationHost.exe" -ErrorAction SilentlyContinue 2>>$global:errfile
  if (($list | Measure-Object).count -gt 0) {
    foreach ($proc in $list) {
      Write-Log ("Found PrintIsolationHost.exe with PID " + $proc.Id)
      CreateProcDump $proc.Id $global:resDir "PrintIsolationHost-$($proc.Id)"
    }
  }
  else {
    Write-Log "No PrintIsolationHost.exe process found"
  }
}

# Export relevant User registry settings
Export-RegistryKey -KeyPath "HKCU:\Printers" -DestinationFile "User-printer-connections.reg.txt"
Export-RegistryKey -KeyPath "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Devices" -DestinationFile "User-devices.reg.txt"
Export-RegistryKey -KeyPath "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts" -DestinationFile "User-printer-ports.reg.txt"

# Export relevant Machine registry settings
Export-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print" -DestinationFile "Print-main.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -DestinationFile "Print-policies.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\System\CurrentControlSet\Control\Print" -DestinationFile "Print-service.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\System\CurrentControlSet\Enum\USBPRINT" -DestinationFile "Print-enum-usbprint.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\PRINTENUM" -DestinationFile "Print-enum-swd-printenum.reg.txt"

# Get any KIR overrides configured on this device
Export-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides" -DestinationFile "KIR-Overrides.reg.txt"

# Export relevant event logs
Export-EventLog -LogName "Application"
Export-EventLog -LogName "System"
Export-EventLog -LogName "Microsoft-Windows-PrintService/Operational"
Export-EventLog -LogName "Microsoft-Windows-PrintService/Admin"
Export-EventLog -LogName "Microsoft-Windows-DeviceSetupManager/Admin"
Export-EventLog -LogName "Microsoft-Windows-DeviceSetupManager/Operational"

# Get some additional information (Spooler service config, setupapi, netstat, ipconfig, gpresult)
Write-Log "Exporting setupapi.dev.log"
Copy-Item "C:\Windows\INF\setupapi.dev.log" -Destination $global:resDir
Invoke-CustomCommand -Command "sc.exe queryex spooler" -DestinationFile "Spooler_ServiceConfig.txt"
Invoke-CustomCommand -Command "netstat -anob" -DestinationFile "netstat.txt"
Invoke-CustomCommand -Command "ipconfig /all" -DestinationFile "ipconfig.txt"
# Notice that for gpresult /h we don't specify a Destinationfile, because it has a dedicated output file
# no need to redirect the console output stream, which in this case doesn't work anyway
Invoke-CustomCommand -Command "gpresult /h ""${global:resDir}\gpresult.html"""
Invoke-CustomCommand -Command "gpresult /r" -DestinationFile "gpresult.txt"
Invoke-CustomCommand -Command "driverquery /v" -DestinationFile "drivers.txt"

# Check version of some relevant print-related files
FileVersion -Filepath ($env:windir + "\System32\localspl.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\spoolsv.exe") -Log $true
FileVersion -Filepath ($env:windir + "\system32\win32spl.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\spoolss.dll") -Log $true 
FileVersion -Filepath ($env:windir + "\system32\PrintIsolationProxy.dll") -Log $true 
FileVersion -Filepath ($env:windir + "\system32\winspool.drv") -Log $true 

# Get running processes
Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime = @{e = { $_.CreationDate.ToString("yyyyMMdd HH:mm:ss") }; n = "Start time" }
  $Owner = @{N = "User"; E = { (GetOwnerCim($_)) } }
}
else {
  $StartTime = @{n = 'StartTime'; e = { $_.ConvertToDateTime($_.CreationDate) } }
  $Owner = @{N = "User"; E = { (GetOwnerWmi($_)) } }
}

if ($proc) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e = { $_.ProcessId }; Label = "PID" }, @{e = { $_.ParentProcessId }; n = "Parent" }, Name,
  @{N = "WorkingSet"; E = { "{0:N0}" -f ($_.WorkingSetSize / 1kb) }; a = "right" },
  @{e = { [DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss") }; n = "UserTime" }, @{e = { [DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss") }; n = "KernelTime" },
  @{N = "Threads"; E = { $_.ThreadCount } }, @{N = "Handles"; E = { ($_.HandleCount) } }, $StartTime, $Owner, CommandLine |
  Out-String -Width 500 | Out-File -FilePath ($global:resDir + "\processes.txt")

  Write-Log "Retrieving file version of running binaries"
  $binlist = $proc | Group-Object -Property ExecutablePath
  foreach ($file in $binlist) {
    if ($file.Name) {
      FileVersion -Filepath ($file.name) -Log $true
    }
  }

  Write-Log "Collecting services details"
  $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

  if ($svc) {
    $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode, State, Name, PathName, StartName |
    Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\services.txt")
  }

  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")
}
else {
  $proc = Get-Process | Where-Object { $_.Name -ne "Idle" }
  $proc | Format-Table -AutoSize -property id, name, @{N = "WorkingSet"; E = { "{0:N0}" -f ($_.workingset / 1kb) }; a = "right" },
  @{N = "VM Size"; E = { "{0:N0}" -f ($_.VirtualMemorySize / 1kb) }; a = "right" },
  @{N = "Proc time"; E = { ($_.TotalProcessorTime.ToString().substring(0, 8)) } }, @{N = "Threads"; E = { $_.threads.count } },
  @{N = "Handles"; E = { ($_.HandleCount) } }, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
  Write-Log "Exiting since WMI is not working"
}

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File $global:resDir\hotfixes.txt
# SIG # Begin signature block
# MIInngYJKoZIhvcNAQcCoIInjzCCJ4sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKLAuUo0eP1Ee5
# GvIm+aHkSHslQdLi4GOj0j8Bbaus7qCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZczCCGW8CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLIsUNvze
# b+0RzbxL8P3vl+BiYNXAX1QEflbkmGMCaHEwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBOnRXsPS8PQxU+xQIfX66HhgqnA2TcWIp2SFTX6hCo
# zrNvwE5J/3F1LGyCbMeSqKUnmJpO+qNZ+AqxcsYcjcAkhMehFyV/NB2DPWReBgGs
# f0d3g2tkp+psHV0MiVudzgKMCh5SrmH5dUI+/k+Jeti6LW3x0ky0mtGHktEIdeE8
# 74JHee9V0+1w36CjwMnPhDbho5aqkfV6zf6HrKXgdm/+ZUjSAl8YvI3Lax/KhwMh
# RbPr3MihGjQ4ol3EUm+bLeBu5OaFVG7UBA1B9YGiORo7yaren123QizyxGom/WV9
# pCZCyxuL4upnDpCJBABgtoR0vQz5J00P0M2AJRKHxlkWoYIW/TCCFvkGCisGAQQB
# gjcDAwExghbpMIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIKmjOKArUTC2J3ad88g0iw2K4zmjvyBAk7f6I5nD
# 0DoXAgZi1V2RmwwYEzIwMjIwODE2MDkyMDEyLjc5NFowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQICEzMAAAGg6buMuw6i0XoAAQAAAaAw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjExMjAyMTkwNTIzWhcNMjMwMjI4MTkwNTIzWjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEy
# NUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/2uIOaHGdAOj2YvhhI6C8iFAq7wrl
# /5WpPjj0fEHCi6Ivx/I02Jss/HVhkfGTMGttR5jRhhrJXydWDnOmzRU3B4G525T7
# pwkFNFBXumM/98l5k0U2XiaZ+bulXHe54x6uj/6v5VGFv+0Hh1dyjGUTPaREwS7x
# 98Te5tFHEimPa+AsG2mM+n9NwfQRjd1LiECbcCZFkgwbliQ/akiMr1tZmjkDbxtu
# 2aQcXjEfDna8JH+wZmfdu0X7k6dJ5WGRFwzZiLOJW4QhAEpeh2c1mmbtAfBnhSPN
# +E5yULfpfTT2wX8RbH6XfAg6sZx8896xq0+gUD9mHy8ZtpdEeE1ZA0HgByDW2rJC
# bTAJAht71B7Rz2pPQmg5R3+vSCri8BecSB+Z8mwYL3uOS3R6beUBJ7iE4rPS9WC1
# w1fZR7K44ZSme2dI+O9/nhgb3MLYgm6zx3HhtLoGhGVPL+WoDkMnt93IGoO6kNBC
# M2X+Cs22ql2tPjkIRyxwxF6RsXh/QHnhKJgBzfO+e84I3TYbI0i29zATL6yHOv5s
# Es1zaNMih27IwfWg4Q7+40L7e68uC6yD8EUEpaD2s2T59NhSauTzCEnAp5YrSscc
# 9MQVIi7g+5GAdC8pCv+0iRa7QIvalU+9lWgkyABU/niFHWPjyGoB4x3Kzo3tXB6a
# C3yZ/dTRXpJnaQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFHK5LlDYKU6RuJFsFC9E
# zwthjNDoMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
# BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQELBQADggIBADF9xgKr+N+slAmlbcEqQBlpL5PfBMqcLkS6ySeGJjG+LKX3
# Wov5pygrhKftXZ90NYWUftIZpzdYs4ehR5RlaE3eYubWlcNlwsKkcrGSDJKawbbD
# GfvO4h/1L13sg66hPib67mG96CAqRVF0c5MA1wiKjjl/5gfrbdNLHgtREQ8zCpbK
# 4+66l1Fd0up9mxcOEEphhJr8U3whwFwoK+QJ/kxWogGtfDiaq6RyoFWhP8uKSLVD
# V+MTETHZb3p2OwnBWE1W6071XDKdxRkN/pAEZ15E1LJNv9iYo1l1P/RdF+IzpMLG
# DAf/PlVvTUw3VrH9uaqbYr+rRxti+bM3ab1wv9v3xRLc+wPoniSxW2p69DN4Wo96
# IDFZIkLR+HcWCiqHVwFXngkCUfdMe3xmvOIXYRkTK0P6wPLfC+Os7oeVReMj2TA1
# QMMkgZ+rhPO07iW7N57zABvMiHJQdHRMeK3FBgR4faEvTjUAdKRQkKFV82uE7w0U
# MnseJfX7ELDY9T4aWx2qwEqam9l7GHX4A2Zm0nn1oaa/YxczJ7gIVERSGSOWLwEM
# xcFqBGPm9QSQ7ogMBn5WHwkdTTkmanBb/Z2cDpxBxd1vOjyIm4BOFlLjB4pivClO
# 2ZksWKH7qBYloYa07U1O3C8jtbzGUdHyLCaVGBV8DfD5h8eOnyjraBG7PNNZMIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4
# oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
# IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAEwa4jWjacbOYU++9
# 5ydJ7hSCi5iggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOalbKowIhgPMjAyMjA4MTYwOTA4NThaGA8yMDIyMDgx
# NzA5MDg1OFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5qVsqgIBADAHAgEAAgIC
# qjAHAgEAAgISNDAKAgUA5qa+KgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AJPBOwaAVXauBfyDb/+vSfH3SD+kt30zCCacO+4qoTw04TYK4nltF1AdvrI5JH4h
# 7XGJauX+k34HNFrrguLXbSLuAQhqp54YT0yRiBPb5jjW/y0cBoXpAkHuTbB9/mla
# piCyYMZ4xAVmA0Sb7TduzV1Mcwv9qUXjCD3K3qFbvxGzMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGg6buMuw6i0XoAAQAA
# AaAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgnqwASPbhIjDA1xx+0CG3ETkSiaYdlplv5gLZbA8S
# gAswgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAvR4o8aGUEIhIt3REvsx0+
# svnM6Wiaga5SPaK4g6+00zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABoOm7jLsOotF6AAEAAAGgMCIEIAuAna2pIvX/CLQJV2beVqmu
# bqHGVRUpN34kUtZMGa84MA0GCSqGSIb3DQEBCwUABIICADZy14XCNqOYT6ydPfTF
# u2+UZHaXKYY41SQkmRkmTzCLqW9PmCvjpPL/sZkIBNr9mTjxUUH51mwCy+/Vm00v
# o1WfvFGQkJPB+fayoMeVYgfMAPTYwmd11jNnHDMjSCs+eKM1ElV0R3dO9UCSfY+5
# ohw9XhTuf9qLBovEgAoawc/vuVLUfSPH/ZkbHnZKlF7MtcLLHQ6QLnu87sAcUg3c
# S8uxcfrFF3EuitrHs18nAIZ59JBSbdM9jYT8gJI4hZgHPqbkcKNj+50plh5JgncD
# sLaebes4sxIP4MPDXCFjmKP8E+Rj0qH77g12lpCzWIe0YhUKGCdY46eR1OViDRC8
# jtJX0HXwEqkiF7FjiaKXDmNYdJW8MI4xU5n2yVWq/qfy6hnzIiQtdRJhbnLQc37t
# Turip8gJILfz/1i7LwoHVO4QwunK0b6Z0h4tgrn1ID5qScdnEnMuIlfLTMmKU6Pv
# BBauglwOUD0bPJS+GjVBMrCGL2oMG6qaPi5AdqLTLWs2vt/91tHF30g201jjcr1G
# 1pT4OWa516h/cAVkKK0lCuP3xp4qagYCDbo3MmV92q2frUXeGNho/V/xOC3+kUHD
# dllDSljW3eiu2gE2FjKDPwnVXrEuTrNMWcLIHu3RrPwSlWiBhVyjMapLBdJY33Oe
# h+WEOPUqgL2kh5VSldWlm22P
# SIG # End signature block
