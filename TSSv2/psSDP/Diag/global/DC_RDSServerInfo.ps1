#************************************************
# DC_RDSServerInfo.ps1
# Version 1.0.0
# Date: 21-01-2012
# Author: Daniel Grund - dgrund@microsoft.com
# Description: 
#	This script gets the RDS config and
#   checks vital signs to inform user.
# 1.0.0 Beta release / 2021-03-30 Waltere #_#
#************************************************
PARAM(
	[string] $TargetHost = "localhost",
   	[string] $RootCause = "",
   	[object] $RDSobject = $null,
	[array]  $OutputFileName
)
# globals and function definitions for RDS
$OutputFolder = $PWD.Path 
Import-LocalizedData -BindingVariable RDSSDPStrings -FileName DC_RDSServerInfo -UICulture en-us
$bIsRDSSH = $false
$bIsRDSGW = $false
$bIsRDSCB = $false
$bIsRDSLS = $false
$RCNum = 0

Trap [Exception]  #_#
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}
	
. ./DC_RDSHelper.ps1 $RDSHelper $RDSSDPStrings
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSWMIGet
Copy-Item .\RDS.xslt (join-path $pwd.path "result\RDS.xslt")
#[array]$OutputFileName+= $OutputFolder + "\" + "RDS.xslt"

#test for validity of the target end point
$OS = Get-CimInstance -Class win32_operatingsystem -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate 
$Computer = Get-CimInstance -Class win32_ComputerSystem -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate  
if (($null -ne $Computer) -and (($TargetHost -ne $Computer.DNSHostName) -or ( $TargetHost -eq $Computer.DNSHostName + "." + $Computer.Domain)))
{
    $TargetHost = $Computer.DNSHostName.ToUpper()
}



$RDSobject = FilterWMIObject (Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
$RDSGateWay = FilterWMIObject (Get-CimInstance -Class Win32_TSGatewayServer -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate -EA SilentlyContinue) #_# -EA
$RDSCB = FilterWMIObject (Get-CimInstance -Class Win32_SessionDirectoryServer -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate -EA SilentlyContinue) #_# -EA
$RDSLS = FilterWMIObject (Get-CimInstance -Class Win32_TSLicenseServer -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate -EA SilentlyContinue) #_# -EA
$Error.Clear()
if ($null -eq $OS) 
{
	ReportError -RCNum $RCNum -RootCause $RDSSDPStrings.ID_RDSWMIGetError -Solution $RDSSDPStrings.ID_RDSWMIGetSolution
	exit
}

if ($null -ne $RDSCB)
{
	"RDSCB " | WriteTo-StdOut
	$bIsRDSCB = $true
	$OutputFileName = SaveAsXml $RDSCB  ($TargetHost + "_Win32_SessionDirectoryServer.xml") $OutputFileName

	#start multi system
	# skip this for now, enable after further testing
	if($false) # remove for enable
	{		   # remove for enable
	$TargetHost_Temp = $TargetHost  # calling ourself will break targethost, saving it.
    $RDSCBCluster = Get-CimInstance -Class Win32_SessionDirectoryCluster -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
    $ConnectionBroker = New-Object RDSHelper+ConnectionBroker
	$ConnectionBroker.ConnectionBrokerName = $TargetHost_Temp
	
	foreach( $Cluster in $RDSCBCluster)
    {
		$Collection = New-Object RDSHelper+Collection
		$Collection.CollectionName = $Cluster.ClusterName
	
        $Query = "Select * from Win32_SessionDirectoryServer where ClusterName='" + $Cluster.ClusterName + "'" 
	    $RDSCBClusterEnum = Get-CimInstance -Query $Query -Namespace root\cimv2 -Authentication PacketPrivacy -Impersonation Impersonate
		$Collection.CollectionServers = $RDSCBClusterEnum.ServerName
        $ConnectionBroker.Collections += $Collection
    }
	# Treeview for the server list , don't show if there are no collections
	if($ConnectionBroker.Collections.Count -gt 0)
	{
		$objTreeView = CreateTreeViewUI -ConnectionBroker $ConnectionBroker
		# Get all the servers that were checked in the UI
		$ServersToCollect = GetNodesChecked -objTreeView $objTreeView -ServersToCollect $ServersToCollect
		# Get report logs from each server
		foreach($Server in $ServersToCollect)
		{
			. ./DC_RDSServerInfo.ps1 -TargetHost $Server
		}
	}
	$TargetHost = $TargetHost_Temp # restore targethost when we come back
	} # remove for enable
	#end multi system
	. ./DC_RDSCB.ps1 -TargetHost $TargetHost -RDSobject $RDSobject -OutputFileName $OutputFileName -OS $OS -bIsRDSCB $bIsRDSCB
}
 
if ($null -ne $RDSobject)
{
	
	if($RDSobject.TerminalServerMode -eq "1") {$bIsRDSSH = $true}
	"RDSSH" + $bIsRDSSH| WriteTo-StdOut
    $OutputFileName = SaveAsXml $RDSobject  ($TargetHost + "_Win32_TerminalServiceSetting.xml") $OutputFileName
	. ./DC_RDSSH.ps1 -TargetHost $TargetHost -RDSobject $RDSobject -OutputFileName $OutputFileName -OS $OS -bIsRDSSH $bIsRDSSH
}

if ($null -ne $RDSGateWay)
{
	"RDSGateWay" | WriteTo-StdOut
	$bIsRDSGW = $true
	. ./DC_RDSGW.ps1 $TargetHost $RDSobject $OutputFileName $OS $RDSSDPStrings $bIsRDSGW
}



if ($null -ne $RDSLS)
{
	"RDSLS" | WriteTo-StdOut
	$bIsRDSLS = $true
	$OutputFileName = SaveAsXml $RDSLS  ($TargetHost + "_Win32_TSLicenseServer.xml") $OutputFileName
	. ./DC_RDSLS.ps1 $TargetHost $RDSobject $OutputFileName $OS $RDSSDPStrings $bIsRDSLS
}

#get All RDS eventlogs
. ./DC_RDSEventLog.ps1 $TargetHost $RDSSDPStrings $OutputFolder  #_# . .\

#get IIS information
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSIIS
. ./DC_RDSRDWeb.ps1 $TargetHost $OutputFileName  #_# . .\

#get all the info we can get from RDS powershell plugin !! Only if we have RDS components and if we have powershell V2
#if (($host.version.Major -ge 2) -and (($bIsRDSSH -eq $true) -or ($bIsRDSGW -eq $true) -or ($bIsRDSCB -eq $true) -or ($bIsRDSLS -eq $true)))
#{
#	Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSPowerShell
#	. ./DC_RDSPowerInfo.ps1 $TargetHost $OutputFileName $RDSSDPStrings
#}

# get the RDMSDeploymentUI
$File = $Env:windir + "\Logs\RDMSDeploymentUI.txt"
if(Test-Path $File )
{
	$OutputFileName += $File
}
#get the RDMSUI-trace.log
$File = $Env:temp + "\RDMSUI-trace.log"
if(Test-Path $File )
{
	$OutputFileName += $File
}

#collect our files !!!
$sectionDescription = "RDS specific files"
[array]$RDPFiles = $null
if ($OutputFileName -is [array])
	{
		ForEach ($OutputFile in $OutputFileName)
		{
			$fileDescription = $OutputFile.Substring($OutputFile.LastIndexOf('_')+1, ($OutputFile.LastIndexOf('.')-$OutputFile.LastIndexOf('_')-1))
			if ($OutputFile.Substring($OutputFile.Length -4, 4) -eq ".xml")
			{
				CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFile)) -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity Debug
			}elseif($OutputFile.Substring($OutputFile.Length -4, 4) -eq ".rdp")
			{
				[array]$RDPFiles += $OutputFile
			}
			else
			{
				CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFile)) -fileDescription $fileDescription -sectionDescription $sectionDescription 
			}
			
			Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status ($RDSSDPStrings.ID_RDSSaved + " " + $OutputFile)
		}
		if($RDPFiles -ne "")
		{
			$RDPFiles = ($RDPFiles | ForEach-Object {([System.IO.Path]::Combine( $OutputFolder,$_))})
			CompressCollectFiles -filesToCollect $RDPFiles -DestinationFileName "RDSRdpFiles.zip" -renameOutput $false  -fileDescription "Compressed collected RDP files" -sectionDescription $sectionDescription 
		}
	}
	else
	{
		CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFileName)) -fileDescription $FileDescription -sectionDescription $sectionDescription
	}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAUmfnIL5MASaTT
# YfKyvX0no2EVlppo+5LKOZadkDxLDaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILqIv7nkwKlxOWP0DuG+NeqT
# tjOUAdDOM7dgsDNfpLXEMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBVzO+yb0oX25dKbx5oB7VoP8E4H0ErdMDgDlpRsRU6zMnbLWfFZZEE
# Ax4FVr+CCzZ5Vcz/BdKv/xWpogPz6jzVrK4oD1vPFv90NV5yXFKD2dCT1OBjNFK8
# zghJzptxnbc00HcNvJOu6qAyRGnmSz+VI3EobN8bq6gV5i/wEB7Rr4p4liLZfjNC
# /g3j8+PfT3gKPDu+Br3PuRmUFWUC/djTAzyEyxceZt6tL6ybmnLDi3rT36NkiRv2
# pemNWmcAH1p05PvVkrbeb0n23HsslrPhf0tW1s0WBqfd1ENrUrEklIK8j000kBo+
# 7g8hjzlQ9IozLRSDJ6kI8bAGOaWhJil0oYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGpj3FH6ij8eNjZxjesqE9p5HlNi/sSV4fi8lG+51OKYAgZi3mQf
# Ht8YEzIwMjIwODAxMDc1MDI5LjU3MlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYwBl2JHNnZmOwABAAABjDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDRaFw0yMzAxMjYxOTI3NDRaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjg2REYt
# NEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA00hoTKET+SGsayw+9BFd
# m+uZ+kvEPGLd5sF8XlT3Uy4YGqT86+Dr8G3k6q/lRagixRKvn+g2AFRL9VuZqC1u
# Tva7dZN9ChiotHHFmyyQZPalXdJTC8nKIrbgTMXAwh/mbhnmoaxsI9jGlivYgi5G
# NOE7u6TV4UOtnVP8iohTUfNMKhZaJdzmWDjhWC7LjPXIham9QhRkVzrkxfJKc59A
# saGD3PviRkgHoGxfpdWHPPaW8iiEHjc4PDmCKluW3J+IdU38H+MkKPmekC7GtRTL
# XKBCuWKXS8TjZY/wkNczWNEo+l5J3OZdHeVigxpzCneskZfcHXxrCX2hue7qJvWr
# ksFStkZbOG7IYmafYMQrZGull72PnS1oIdQdYnR5/ngcvSQb11GQ0kNMDziKsSd+
# 5ifUaYbJLZ0XExNV4qLXCS65Dj+8FygCjtNvkDiB5Hs9I7K9zxZsUb7fKKSGEZ9y
# A0JgTWbcAPCYPtuAHVJ8UKaT967pJm7+r3hgce38VU39speeHHgaCS4vXrelTLiU
# MAl0Otk5ncKQKc2kGnvuwP2RCS3kEEFAxonwLn8pyedyreZTbBMQBqf1o3kj0ilO
# J7/f/P3c1rnaYO01GDJomv7otpb5z+1hrSoIs8u+6eruJKCTihd0i/8bc67AKF76
# wpWuvW9BhbUMTsWkww4r42cCAwEAAaOCATYwggEyMB0GA1UdDgQWBBSWzlOGqYIh
# YIh5Vp0+iMrdQItSIzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDXaMVFWMIJqdblQZK6oks7cdCUwePAmmEIedsy
# usgUMIQlQqajfCP9iG58yOFSRx2k59j2hABSZBxFmbkVjwhYEC1yJPQm9464gUz5
# G+uOW51i8ueeeB3h2i+DmoWNKNSulINyfSGgW6PCDCiRqO3qn8KYVzLzoemfPir/
# UVx5CAgVcEDAMtxbRrTHXBABXyCa6aQ3+jukWB5aQzLw6qhHhz7HIOU9q/Q9Y2Nn
# VBKPfzIlwPjb2NrQGfQnXTssfFD98OpRHq07ZUx21g4ps8V33hSSkJ2uDwhtp5Vt
# FGnF+AxzFBlCvc33LPTmXsczly6+yQgARwmNHeNA262WqLLJM84Iz8OS1VfE1N6y
# YCkLjg81+zGXsjvMGmjBliyxZwXWGWJmsovB6T6h1GrfmvMKudOE92D67SR3zT3D
# dA5JwL9TAzX8Uhi0aGYtn5uNUDFbxIozIRMpLVpP/YOLng+r2v8s8lyWv0afjwZY
# HBJ64MWVNxHcaNtjzkYtQjdZ5bhyka6dX+DtQD9bh3zji0SlrfVDILxEb6Ojyqtf
# Gj7iWZvJrb4AqIVgHQaDzguixES9ietFikHff6p97C5qobTTbKwN0AEP3q5teyI9
# NIOVlJl0gi5Ibd58Hif3JLO6vp+5yHXjoSL/MlhFmvGtaYmQwD7KzTm9uADF4BzP
# /mx2vzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODZERi00QkJDLTkzMzUxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVADSi8hTrq/Q8oppweGyuZLNEJq/VoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkXQnMCIYDzIwMjIwODAx
# MDUzNTM1WhgPMjAyMjA4MDIwNTM1MzVaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRdCcCAQAwBwIBAAICGM0wBwIBAAICEU8wCgIFAOaSxacCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCIsY9Ly+6K9S9Shp4oRSoLWJ00XRTLqUH0YK7lKobW
# 8eWfIrppdWOIf4H7BnWoO0/tMJJHgeSrJisS6vnLflRO/4yJ/OiGy6tcxoTZPfeS
# K5q/F4NEIboNLCDhW8RxBTAI4Hor5tEA4Y4BdGmZl++3Tly7aywliLfU/qiVJvKi
# VjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjAGXYkc2dmY7AAEAAAGMMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIOoaiUflq2MERoGydRbR
# sHbsugHBsMrUCBFxKMH7ER9xMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# 1a2L+BUqkM8Gf8TmIQWdgeKTTrYXIwOofOuJiBiYaZ4wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYwBl2JHNnZmOwABAAABjDAiBCBY
# eC4LEStKyRogWYCSryzBcOErikzXGGVi2RsI7tYWwzANBgkqhkiG9w0BAQsFAASC
# AgCpSzEKI6e6avxFU/gUWcMO6Vml4dm7+OugmHw2oWgRYdRw2elx7/ty/zbTMk8f
# cPhvoSaw2r9Y6jlSPRt1QgpWbaK7GzaXKSsKFLhsalSQcqPT2n4Lbzs+9wXMWDt4
# bogitduAMrK0cPo8sg9dvhhjTwgO8q024DNhUu8NIMdTlfz+y8fXPg0QaWflpSMT
# AjeyjdhstZWT5AzXQF4dkAv1Y3Fphaz5mUYyeT9YxbMHTjLNSExQ6727x9nbH7RF
# Ve3W26kZn1UCs96/4K9+Ergs4lwgaX0TekbrVcxE4+VrTx8PNjU8PdBvPIcD2YfW
# eUJq9MX05z6yaWudlUIBAr6IjJ5OsE+MGB4eTa29Rn9mlMDmao9Fb3JPQf+hcnm9
# a6jFdXoZCG7+iiEMgTjw40vucPVRnvQ7CFOUl9QHWa6E7nsZksT89bISJi7fB9Xf
# afJZZXvzKyOtszgOrKJwezCHmL6La69RK32QJm/vts/k2h1ixyfWLtI88lo+H7Hd
# GUBzeoW30g/yjKoZojNFDMSal/Nes+p2mIQ0E/T8nzC/CavZ1QQYgLUgYvafnD5H
# QdCvU91VatSiSiiGumWpALqDwu0xzEUb8tl3j4XnigPKqrQk+PfO+dlze2lNKoXF
# AhAy58cjmem23xK4SQYFbwKYS94XRgHhBhKcbGbXJ5Y5Qw==
# SIG # End signature block
