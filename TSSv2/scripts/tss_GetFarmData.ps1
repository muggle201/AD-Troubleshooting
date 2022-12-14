# Script: tss_GetFarmData.ps1
# from https://microsoft.sharepoint.com/teams/css-rds/SitePages/getfarmdata.aspx?xsdata=MDN8MDF8fDRhNGUxOTM4NmE3ZTQ0ODliNWJlMWQ2MDdmYjgwMjU2fDcyZjk4OGJmODZmMTQxYWY5MWFiMmQ3Y2QwMTFkYjQ3fDF8MHw2Mzc3NzU4NTEyODY0MjIxMDZ8R29vZHxWR1ZoYlhOVFpXTjFjbWwwZVZObGNuWnBZMlY4ZXlKV0lqb2lNQzR3TGpBd01EQWlMQ0pRSWpvaVYybHVNeklpTENKQlRpSTZJazkwYUdWeUlpd2lWMVFpT2pFeGZRPT0%3D&sdata=ZzVWUFZRZXQvWUMwa3VWbzZpeStmNHhRN2VDMTlVd1NjdkthNUNIWkYyUT0%3D&ovuser=72f988bf-86f1-41af-91ab-2d7cd011db47%2Cwaltere%40microsoft.com&OR=Teams-HL&CT=1642008472926
# addon to tss RDSsrv

#region ::::: Script Input PARAMETERS :::::
[CmdletBinding()]param(
 [Parameter(Mandatory=$False, Position=0)] [String] $DataPath
)
$ScriptVer="1.00"	#Date: 2022-01-12


Import-Module remotedesktop


#Get Servers of the farm:
$servers = Get-RDServer

$BrokerServers = @()
$WebAccessServers = @()
$RDSHostServers = @()
$GatewayServers = @()

foreach ($server in $servers)
{
	switch ($server.Roles)
	{
	"RDS-CONNECTION-BROKER" {$BrokerServers += $server.Server}
	"RDS-WEB-ACCESS" {$WebAccessServers += $server.Server}
	"RDS-RD-SERVER" {$RDSHostServers += $server.Server}
	"RDS-GATEWAY" {$GatewayServers += $server.Server}
	}
}
"Machines involved in the deployment : " + $servers.Count
"	-Broker(s) : " + $BrokerServers.Count
foreach ($BrokerServer in $BrokerServers)
		{
		"		" +	$BrokerServer
$ServicesStatus = Get-WmiObject -ComputerName $BrokerServer -Query "Select * from Win32_Service where Name='rdms' or Name='tssdis' or Name='tscpubrpc'"
        foreach ($stat in $ServicesStatus)
        {
        "		      - " + $stat.Name + " service is " + $stat.State
        }

		}
" "	
"	-RDS Host(s) : " + $RDSHostServers.Count
foreach ($RDSHostServer in $RDSHostServers)
		{
		"		" +	$RDSHostServer
$ServicesStatus = Get-WmiObject -ComputerName $RDSHostServer -Query "Select * from Win32_Service where Name='TermService'"
        foreach ($stat in $ServicesStatus)
        {
        "		      - " + $stat.Name +  "service is " + $stat.State
        }
		}
" " 
"	-Web Access Server(s) : " + $WebAccessServers.Count
foreach ($WebAccessServer in $WebAccessServers)
		{
		"		" +	$WebAccessServer
		}
" " 	
"	-Gateway server(s) : " + $GatewayServers.Count
foreach ($GatewayServer in $GatewayServers)
		{
		"		" +	$GatewayServer

$ServicesStatus = Get-WmiObject -ComputerName $GatewayServer -Query "Select * from Win32_Service where Name='TSGateway'"
        foreach ($stat in $ServicesStatus)
        {
        "		      - " + $stat.Name + " service is " + $stat.State
        }
		}
" "

#Get active broker server.
$ActiveBroker = Invoke-WmiMethod -Path ROOT\cimv2\rdms:Win32_RDMSEnvironment -Name GetActiveServer
$ConnectionBroker = $ActiveBroker.ServerName
"ActiveManagementServer (broker) : " +	$ActiveBroker.ServerName
" "

# Deployment Properties  TODO ##############
##########
"Deployment details : "
# Is Broker configured in High Availability?
$HighAvailabilityBroker = Get-RDConnectionBrokerHighAvailability
$BoolHighAvail = $false
If ($null -eq $HighAvailabilityBroker)
{
	$BoolHighAvail = $false
	"	Is Connection Broker configured for High Availability : " + $BoolHighAvail
}
else
{
	$BoolHighAvail = $true
	"	Is Connection Broker configured for High Availability : " + $BoolHighAvail
	"		- Client Access Name (Round Robin DNS) : " + $HighAvailabilityBroker.ClientAccessName
	"		- DatabaseConnectionString : " + $HighAvailabilityBroker.DatabaseConnectionString
    "		- DatabaseSecondaryConnectionString : " + $HighAvailabilityBroker.DatabaseSecondaryConnectionString
	"		- DatabaseFilePath : " + $HighAvailabilityBroker.DatabaseFilePath
}

#Gateway Configuration
$GatewayConfig = Get-RDDeploymentGatewayConfiguration -ConnectionBroker $ConnectionBroker
"	Gateway Mode : " + $GatewayConfig.GatewayMode
if ($GatewayConfig.GatewayMode -eq "custom")
{
"		- LogonMethod : " + $GatewayConfig.LogonMethod   
"		- GatewayExternalFQDN : " + $GatewayConfig.GatewayExternalFQDN
"		- GatewayBypassLocal : " + $GatewayConfig.BypassLocal
"		- GatewayUseCachedCredentials : " + $GatewayConfig.UseCachedCredentials

}

# RD Licencing
$LicencingConfig = Get-RDLicenseConfiguration -ConnectionBroker $ConnectionBroker
"	Licencing Mode : " + $LicencingConfig.Mode
if ($LicencingConfig.Mode -ne "NotConfigured")
{
"		- Licencing Server(s) : " + $LicencingConfig.LicenseServer.Count
foreach ($licserver in $LicencingConfig.LicenseServer)
{
"		       - Licencing Server : " + $licserver
}

}
# RD Web Access
"	Web Access Server(s) : " + $WebAccessServers.Count
foreach ($WebAccessServer in $WebAccessServers)
{
"	     - Name : " + $WebAccessServer
"	     - Url : " + "https://" + $WebAccessServer + "/rdweb"
}

# Certificates
#Get-ChildItem -Path cert:\LocalMachine\my -Recurse | Format-Table -Property DnsNameList, EnhancedKeyUsageList, NotAfter, SendAsTrustedIssuer
"	Certificates "
$certificates = Get-RDCertificate -ConnectionBroker $ConnectionBroker
foreach ($certificate in $certificates)
{
"		- Role : " + $certificate.Role
"			- Level : " + $certificate.Level
"			- Expires on : " + $certificate.ExpiresOn
"			- Issued To : " + $certificate.IssuedTo
"			- Issued By : " + $certificate.IssuedBy
"			- Thumbprint : " + $certificate.Thumbprint
"			- Subject : " + $certificate.Subject
"			- Subject Alternate Name : " + $certificate.SubjectAlternateName

}
" "

#RDS Collections
$collectionnames = Get-RDSessionCollection 
$client = $null
$connection = $null
$loadbalancing = $null 
$Security = $null
$UserGroup = $null
$UserProfileDisks = $null

"RDS Collections : "
foreach ($Collection in $collectionnames)
{
	$CollectionName = $Collection.CollectionName
	"	Collection : " +  $CollectionName	
	"		Resource Type : " + $Collection.ResourceType
	if ($Collection.ResourceType -eq "RemoteApp programs")
	{
		"			Remote Apps : "
		$remoteapps = Get-RDRemoteApp -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		foreach ($remoteapp in $remoteapps)
		{
			"			- DisplayName : " + $remoteapp.DisplayName
			"				- Alias : " + $remoteapp.Alias
			"				- FilePath : " + $remoteapp.FilePath
			"				- Show In WebAccess : " + $remoteapp.ShowInWebAccess
			"				- CommandLineSetting : " + $remoteapp.CommandLineSetting
			"				- RequiredCommandLine : " + $remoteapp.RequiredCommandLine
			"				- UserGroups : " + $remoteapp.UserGroups
		}		
	}

#       $rdshServers		
		$rdshservers = Get-RDSessionHost -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		"		Servers in that collection : "
		foreach ($rdshServer in $rdshservers)
		{		
			"			- SessionHost : " + $rdshServer.SessionHost			
			"				- NewConnectionAllowed : " + $rdshServer.NewConnectionAllowed			
		}		
		
		$client = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Client 
		"		Client Settings : " 
		"			- MaxRedirectedMonitors : " + $client.MaxRedirectedMonitors
		"			- RDEasyPrintDriverEnabled : " + $client.RDEasyPrintDriverEnabled
		"			- ClientPrinterRedirected : " + $client.ClientPrinterRedirected
		"			- ClientPrinterAsDefault : " + $client.ClientPrinterAsDefault
		"			- ClientDeviceRedirectionOptions : " + $client.ClientDeviceRedirectionOptions
		" "
		
		$connection = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Connection
		"		Connection Settings : " 
		"			- DisconnectedSessionLimitMin : " + $connection.DisconnectedSessionLimitMin
		"			- BrokenConnectionAction : " + $connection.BrokenConnectionAction
		"			- TemporaryFoldersDeletedOnExit : " + $connection.TemporaryFoldersDeletedOnExit
		"			- AutomaticReconnectionEnabled : " + $connection.AutomaticReconnectionEnabled
		"			- ActiveSessionLimitMin : " + $connection.ActiveSessionLimitMin
		"			- IdleSessionLimitMin : " + $connection.IdleSessionLimitMin
		" "
		
		$loadbalancing = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -LoadBalancing
		"		Load Balancing Settings : " 
		foreach ($SessHost in $loadbalancing)
		{
		"			- SessionHost : " + $SessHost.SessionHost
		"				- RelativeWeight : " + $SessHost.RelativeWeight
		"				- SessionLimit : " + $SessHost.SessionLimit
		}
		" "
		
		$Security = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Security
		"		Security Settings : " 
		"			- AuthenticateUsingNLA : " + $Security.AuthenticateUsingNLA
		"			- EncryptionLevel : " + $Security.EncryptionLevel
		"			- SecurityLayer : " + $Security.SecurityLayer
		" "
		
		$UserGroup = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserGroup 
		"		User Group Settings : "
		"			- UserGroup  : " + $UserGroup.UserGroup 
		" "
		
		$UserProfileDisks = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserProfileDisk
		"		User Profile Disk Settings : "
		"			- EnableUserProfileDisk : " + $UserProfileDisks.EnableUserProfileDisk
		"			- MaxUserProfileDiskSizeGB : " + $UserProfileDisks.MaxUserProfileDiskSizeGB
		"			- DiskPath : " + $UserProfileDisks.DiskPath                 
		"			- ExcludeFilePath : " + $UserProfileDisks.ExcludeFilePath
		"			- ExcludeFolderPath : " + $UserProfileDisks.ExcludeFolderPath
		"			- IncludeFilePath : " + $UserProfileDisks.IncludeFilePath
		"			- IncludeFolderPath : " + $UserProfileDisks.IncludeFolderPath
		" "
				
		$usersConnected = Get-RDUserSession -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		"		Users connected to this collection : " 
		foreach ($userconnected in $usersConnected)
		{
		"			User : " + $userConnected.DomainName + "\" + $userConnected.UserName
		"				- HostServer : " + $userConnected.HostServer
		"				- UnifiedSessionID : " + $userConnected.UnifiedSessionID
		}
		" "	 	
    }


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCWEhKoBksWIeEl
# jSvC9xPcH4cRlhpSa8aO9dzLXKkBAaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZdjCCGXICAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgW5Amfjq3
# zSY7qaKY2Znho+5bP1T2wuTuZ4eTUh6SdfkwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCT9vtjdcbXsEcAFPA51cIffQvxhGKSugWYKkYfnPYj
# CCJ6Ob9kI1Rx5NnNd+GFcz53S95fjid4U+SfR8Wmlgvxx5KyIzGIUDkyzdE1/ddO
# fGkneNDo2PEgh27+j2kr6xI0hihjBHOdwZpMHC0hoQZj3oxwh2YcYukK9Vy8nT9H
# NJOXWSea3ybAZdLNeM3VTkzfcxrI7loM3B0jI1plYuhzihv6+HXuXw64OuJwG0qV
# JJtfC4ymU2XCaKH7ZNXR8/iTQphrtie2aFGNZDdEJfkAhgC6j9h65Ym23wyFFCMv
# gLLeGMimXK/iOHwLdrOosZv0bcn7i27/eOhsKqO+KzoToYIXADCCFvwGCisGAQQB
# gjcDAwExghbsMIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIC9QseRgWjZyK+3ogDMy2+r6+4xHu4mG8UMPiuMS
# e6UOAgZi2BBtdlYYEzIwMjIwODE2MDkyMDEyLjkwNlowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkVBQ0UtRTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRVzCCBwwwggT0oAMCAQICEzMAAAGawHWixCFtPoUAAQAAAZow
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjExMjAyMTkwNTE3WhcNMjMwMjI4MTkwNTE3WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5
# MUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDacgasKiu3ZGEU/mr6A5t9oXAgbsCJ
# q0NnOu+54zZPt9Y/trEHSTlpE2n4jua4VnadE4sf2Ng8xfUxDQPO4Vb/3UHhhdHi
# CnLoUIsW3wtE2OPzHFhAcUNzxuSpk667om4o/GcaPlwiIN4ZdDxSOz6ojSNT9azs
# KXwQFAcu4c9tsvXiul99sifC3s2dEEJ0/BhyHiJAwscU4N2nm1UDf4uMAfC1B7SB
# QZL30ssPyiUjU7gIijr1IRlBAdBYmiyR0F7RJvzy+diwjm0Isj3f8bsVIq9gZkUW
# xxFkKZLfByleEo4BMmRMZE9+AfTprQne6mcjtVAdBLRKXvXjLSXPR6h54pttsShK
# aV3IP6Dp6bXRf2Gb2CfdVSxty3HHAUyZXuFwguIV2OW3gF3kFQK3uL6QZvN8a6KB
# 0hto06V98Otey1OTOvn1mRnAvVu4Wj8f1dc+9cOPdPgtFz4cd37mRRPEkAdX2Yae
# TgpcNExa+jCbOSN++VtNScxwu4AjPoTfQjuQ+L1p8SMZfggT8khaXaWWZ9vLvO7P
# IwIZ4b2SK3/XmWpk0AmaTha5QG0fu5uvd4YZ/xLuI/kiwHWcTykviAZOlwkrnsoY
# ZJJ03RsIAWv6UHnYjAI8G3UgCFFlAm0nguQ3rIX54pmujS83lgrm1YqbL2Lrlhmi
# 98Mk2ktCHCXKRwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFF+2nlnwnNtR6aVZvQqV
# yK02K9FwMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
# BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQELBQADggIBAAATu4fMRtRH20+nNzGAXFxdXEpRPTfbM0LJDeNe4QCxj0FM
# +wrJdu6UKrM2wQuO31UDcQ4nrUJBe81N6W2RvEa8xNXjbO0qzNitwUfOVLeZp6HV
# GcNTtYEMAvK9k//0daBFxbp04BzMaIyaHRy7y/K/zZ9ckEw7jF9VsJqlrwqkx9Hq
# I/IBsCpJdlTtKBl/+LRbD8tWvw6FDrSkv/IDiKcarPE0BU6//bFXvZ5/h7diE13d
# qv5DPU5Kn499HvUOAcHG31gr/TJPEftqqK40dfpB+1bBPSzAef58rJxRJXNJ661G
# bOZ5e64EuyIQv0Vo5ZptaWZiftQ5pgmztaZCuNIIvxPHCyvIAjmSfRuX7Uyke0k2
# 9rSTruRsBVIsifG39gldsbyjOvkDN7S3pJtTwJV0ToC4VWg00kpunk72PORup31a
# hW99fU3jxBh2fHjiefjZUa08d/nQQdLWCzadttpkZvCgH/dc8Mts2CwrcxCPZ5p9
# VuGcqyFhK2I6PS0POnMuf70R3lrl5Y87dO8f4Kv83bkhq5g+IrY5KvLcIEER5kt5
# uuorpWzJmBNGB+62OVNMz92YJFl/Lt+NvkGFTuGZy96TLMPdLcrNSpPGV5qHqnHl
# r/wUz9UAViTKJArvSbvk/siU7mi29oqRxb0ahB4oYVPNuv7ccHTBGqNNGol4MIIH
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
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4
# oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
# IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAbquMnUCam/m7Ox1
# Uv/GNs1jmu+ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOalfgwwIhgPMjAyMjA4MTYxMDIzMDhaGA8yMDIyMDgx
# NzEwMjMwOFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5qV+DAIBADAKAgEAAgIC
# iAIB/zAHAgEAAgIRrjAKAgUA5qbPjAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBABApa0/bi5NyowH+jm1/Xw5ROTxa01LwHiQxtgGmrRWB/tRCeMC2M1iPExLC
# pRogGXQ+vA2RcBkg+u6JAjUniKdZmnVLMfr4Z2xTj4DOk9b1J2DctoK6fYesRxUK
# zS9FWUeSLijtkvXzuI7GHmLU2WbKIRtI0aziz69or0OO57Z6MYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGawHWixCFtPoUA
# AQAAAZowDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQg093j7Zdit0v/NyTyju5igHFe0e0ySHPHvssK
# w6HaaWswgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJi
# L539Lx+nsr/NFVTnKFX030iNYDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABmsB1osQhbT6FAAEAAAGaMCIEIHi4zgoapLg6e7lIoGZc
# T5UI7j4EtOdnLriJSRmAtVLUMA0GCSqGSIb3DQEBCwUABIICACO+sc458DFcVBJH
# aXqtM/Z+weveA7jUf142llMKVexWqFEmKlIDeV/rwy8yHm913TU+S+qlOUU6m03E
# iHzpCgwl66F8REDPiPPgH/9TUV7fKEKq1gdqYeOaInWY6m2DylXeWGLYG72Hveas
# n6IAXe8D9KRyrYjDQyXYd79WlAQcGRqRl9M0IDASFar8DDkL60Awj0GFAIU8s+Fo
# Ij4OQUUq2L8p5WMw+DnN4Z7RWhpXS2s7ffg7FcJyeGkj8NS0rl6JWPI6sBD3kqgL
# dSBpaGZigQ2T1nbL3hTkFGO9xnKr41oTLKR42VWVgCmksh4hcIk2bOdh6lUDLK8u
# 85N1xE2D6Qalmpvw6FOBVne+fAC/RSt4q9/L+XJxr09QGnHN0rX6QI6VDwmz+H4L
# 5wDMxvrvzJEUnK6oHlZe8k2HRyJGrYPB89gE0jj6xqWNQmKiWEF+s2fsTpO71XKP
# X9NeIoMLcFlFfqgRpItUD37rVDL5jwim+4pm+2ApDJG8nqgLT6rYYqkr4Yw/DPYz
# lJycjFSbEOlzjs085JKUnP69a/WhWG2qdGrcYzX8fey3WbIoK2bUi3KIHcJTcnGG
# 9CHgxAKHBffxrDtUimpH5EyuZTGmXOefQIYyqxX5wpDBdfHx3ZGKijiX5TSS2dGX
# ocSa3QXr3pDUu7DIvnrFsKJF/221
# SIG # End signature block
