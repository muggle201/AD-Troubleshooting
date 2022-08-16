# Name: tss_update-script.ps1 for TSSv2

<# 
.SYNOPSIS
	Script to [auto-]update TSSv2 to latest version or download latest zip from CesdiagTools/GitHub.

.DESCRIPTION
	Script will search on "https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/releases/tag" for latest TSSv2 version
	If local version does not match the remote CesdiagTools/GitHub version, it will download and replace TSSv2 with latest version
	Script gets the current version from $global:TssVerDate or by running ".\TSSv2 -ver" and compares to version 'https://cesdiagtools.blob.core.windows.net/windows/TSSv2.ver'.

.PARAMETER tss_action
	choose action from allowed values: "Download" or "Update" or "Version"
		Download	= download latest CesdiagTools/GitHub version
		Update		= update current local version
		Version		= decide based on local version, try AutoUpdate if local version is lower than CesdiagTools/GitHub version
	Ex: -tss_action "Download"
	
.PARAMETER tss_file
	Specify filename from allowed values: "TSSv2.zip" , "TSSv2_ttd.zip" , "TSSv2_diff.zip" or "TSSv2Lite.zip"
	Ex: -tss_file "TSSv2.zip"
	
.PARAMETER TSS_path
	Specify the local path where TSSv2.ps1 is located.
	Ex: -TSS_path "C:\TSSv2"

.PARAMETER UpdMode
	Specify the mode: 
		Online  = complete package (TSSv2.zip) from aka.ms/getTSS
		Full    = complete package (TSSv2.zip) from CesdiagTools/GitHub
		Quick   = differential package only (TSSv2_diff.zip): replace only TSSv2.ps1, TSSv2_[POD].psm1 and config\tss_config.cfg files; will not update \BIN* folders
		Force   = run a Full update, regardless of current installed version

.PARAMETER tss_arch
	Specify the System Architecture.
	Allowed values:
		x64 - For 64-bit systems
		x86 - For 32-bit systems
	Ex: -tss_arch "x64"

.EXAMPLE
	.\tss_update-script.ps1 -tss_action "Update" -TSS_path "C:\TSSv2" -tss_file "TSSv2.zip"
	Example 1: Update TSSv2 in folder C:\TSSv2
	
.LINK
	https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/releases/tag
	Public Download: TSSv2:    https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip -or- https://aka.ms/getTSSv2 or aka.ms/getTSS
#>


param(
	[ValidateSet("download","update","version")]
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose from: download|update|version')]
	[string]$tss_action 	= "download"
	,
	[string]$TSS_path 		= (Split-Path $MyInvocation.MyCommand.Path -Parent | Split-Path -Parent),
	[ValidateSet("Online","Full","Quick","Force","Lite")]
	[string]$UpdMode 		= "Online"
	,
	$verOnline
	,
	[ValidateSet("TSSv2.zip","TSSv2_diff.zip","TSSv2Lite.zip","TSSv2_ttd.zip")]
	[string]$tss_file 		= "TSSv2.zip"
	,
	[ValidateSet("x64","x86")]
	[string]$tss_arch 		= "x64",
	[string]$CentralStore	= "",								# updating from Central Enterprise Store
	[switch]$AutoUpd		= $False,							# 
	[switch]$UseExitCode 	= $true								# This will cause the script to bail out after the error is logged if an error occurs.
)

#region  ::::: [Variables] -----------------------------------------------------------#
$updScriptVersion	= "2022.05.22"
$UpdLogfile 		= $TSS_path + "\_tss_Update-Log.txt"
$script:ChkFailed	= $FALSE
$invocation 		= (Get-Variable MyInvocation).Value
$ScriptGrandParentPath 	= $MyInvocation.MyCommand.Path | Split-Path -Parent | Split-Path -Parent
$scriptName 		= $invocation.MyCommand.Name
if ($UpdMode -match 'Online') {
	$TssReleaseServer = "cesdiagtools.blob.core.windows.net"
	$tss_release_url  = "https://cesdiagtools.blob.core.windows.net/windows"
} else {
	$TssReleaseServer = "api.Github.com"
	$tss_release_url  = "https://api.github.com/repos/walter-1/TSSv2/releases"
}
$NumExecutable = (Get-ChildItem "$global:ScriptFolder\BIN\" -Name "*.exe" -ErrorAction Ignore).count 
If($NumExecutable -lt 20){
	$LiteMode=$True
}Else{
	$LiteMode=$False
}
#endregion  ::::: [Variables] --------------------------------------------------------#

$ScriptBeginTimeStamp = Get-Date

# Check if last "\" was provided in $TSS_path, if it was not, add it
if (-not $TSS_path.EndsWith("\")){
	$TSS_path = $TSS_path + "\"
}

#region  ::::: [Functions] -----------------------------------------------------------#
function ExitWithCode ($Ecode) {
	# set ErrorLevel to be picked up by invoking CMD script
	if ( $UseExitCode ) {
		Write-Verbose "[Update] Return Code: $Ecode"
		#error.clear()	# clear script errors
		exit $Ecode
		}
}

function get_local_tss_version {
	<#
	.SYNOPSIS
		Function returns current or LKG TSSv2 version locally from "$TSSv2_ps1_script -ver" command.
	#>
	param($type="current")
	switch ($type) {
        "current"  	{ $TSSv2_ps1_script = "TSSv2.ps1" }
        "LKG" 		{ $TSSv2_ps1_script = "TSSv2-LKG.ps1" }
	}
	if ( -not (Test-Path $TSSv2_ps1_script)) {
		$TSSv2_ps1_script = "TSSv2.ps1"
	}  
	Get-Content ..\$TSSv2_ps1_script | Where-Object {$_ -match 'global:TssVerDate ='} | ForEach-Object { $v2version=($_ -Split '\s+')[3] }
	$TSSv2version = $v2version.Replace("""","")
	Write-verbose "[get_local_tss_version] TSSv2version= $TSSv2version"
	return [version]$TSSv2version
}

function get_latest_tss_version {
	<#
	.SYNOPSIS
		Function will get latest version from CesdiagTools/GitHub Release page
	.LINK
		https://github.com/CSS-Windows/WindowsDiag/tree/master/ALL/TSS
		https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip
	#>
	if ($UpdMode -match 'Online') {
		return $verOnline # = TSSv2.ver
	} else {
		# GitHub: Get web content and convert from JSON
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		try { $web_content = Invoke-WebRequest -Uri $tss_release_url -UseBasicParsing | ConvertFrom-Json } catch { "`n*** Failure during TSSv2 update. Exception Message:`n $($_.Exception.Message)" | Out-File $UpdLogfile -Append }
		if ($web_content.tag_name) {
			[version]$expected_latest_tss_version = $web_content.tag_name.replace("v","")
			write-verbose "$UpdateSource Version of '$tss_release_url': --> $expected_latest_tss_version"
			return $expected_latest_tss_version
		}
		else 
		{ Write-Host -ForegroundColor Red "[ERROR] cannot securely access $TssReleaseServer. Please download https://aka.ms/getTSS"
			"`n $ScriptBeginTimeStamp [ERROR] cannot securely access $TssReleaseServer. Please download https://aka.ms/getTSS" | Out-File $UpdLogfile -Append
			$script:ChkFailed=$TRUE
			return 2022.0.0.0
		}
	}
}

function DownloadFileFromGitHubRelease {
	param(
		$action = "download", 
		$file, 
		$installedTSSver)
	# Download latest TSSv2 release from CesdiagTools/GitHub
	$repo = "walter-1/TSSv2"
	$releases = "https://api.github.com/repos/$repo/releases"
	#Determining latest release , Set TLS to 1.2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	$tag = (Invoke-WebRequest $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
	$downloadURL = "https://github.com/$repo/releases/download/$tag/$file"
	Write-Verbose "downloadURL: $downloadURL"
	$name = $file.Split(".")[0]
	$zip = "$name-$tag.zip"
	$TmpDir = "$name-$tag"
	Write-Verbose "Name: $name - Zip: $zip - Dir: $TmpDir - Tag/version: $tag"
	
	#_# faster Start-BitsTransfer $downloadURL -Destination $zip # is not allowed for GitHub
	Write-Host ".. Secure download of latest release: $downloadURL"
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest $downloadURL -OutFile $zip

	if ($action -match "download") {
		Write-Host -ForegroundColor Green "[Info] Downloaded version to folder: $TSS_path`scripts\$tss_file"
		}
	if ($action -match "update") {
		#save current script and expand
		Write-Host "... saving a copy of current installed TSSv2.ps1 to $($TSS_path + "TSSv2.ps1_v" + $installedTSSver)"
		Copy-Item ($TSS_path + "TSSv2.ps1") ($TSS_path + "TSSv2.ps1_v" + $installedTSSver) -Force -ErrorAction SilentlyContinue
		Write-Host "... saving a copy of current \config\tss_config.cfg to $($TSS_path + "config\tss_config.cfg_backup")"
		Copy-Item ($TSS_path + "config\tss_config.cfg") ($TSS_path + "config\tss_config.cfg_backup") -Force -ErrorAction SilentlyContinue
		Write-Host "[Expand-Archive] Extracting release files from $zip"
		Expand-Archive  -Path $zip -DestinationPath $ENV:temp\$TmpDir -Force
		Write-Host ".. Cleaning up .."
		Write-Verbose "Cleaning up target dir: Remove-Item $name -Recurse"
		Write-Verbose "Copying from temp dir: $ENV:temp\$TmpDir to target dir: $TSS_path"
		Copy-Item $ENV:temp\$TmpDir\* -Destination $TSS_path -Recurse -Force
		Write-Verbose "Removing temp file: $zip and folder $TmpDir"
		Remove-Item $zip -Force
		Write-Verbose "Remove-Item $ENV:temp\$TmpDir -Recurse"
		Remove-Item $ENV:temp\$TmpDir -Recurse -Force -ErrorAction SilentlyContinue
		Write-Host -ForegroundColor Gray "[Info] Updated with latest TSSv2 version $script:expectedVersion"
	}
}

function DownloadTssZipFromCesdiagRelease {
	param(
		$file	# TSSv2.zip or TSSv2Lite.zip
	)
	switch ($file) {
        "TSSv2.zip"  	{ $downloadURL = $tss_release_url + "/TSSv2.zip" }
        "TSSv2Lite.zip" { $downloadURL = $tss_release_url + "/TSSv2Lite.zip"  }
	}
	
	# faster Start-BitsTransfer
	Write-Host ".. Secure download of latest release: $downloadURL"
	Start-BitsTransfer $downloadURL -Destination "$ENV:temp\TSSv2_download.zip"
	#save current script and expand
	Write-Host "... saving a copy of current installed TSSv2.ps1 to $($TSS_path + "TSSv2.ps1_v" + $installedTSSver)"
	Copy-Item ($TSS_path + "TSSv2.ps1") ($TSS_path + "TSSv2.ps1_v" + $installedTSSver) -Force -ErrorAction SilentlyContinue
	Write-Host "... saving a copy of current \config\tss_config.cfg to $($TSS_path + "config\tss_config.cfg_backup")"
	Copy-Item ($TSS_path + "config\tss_config.cfg") ($TSS_path + "config\tss_config.cfg_backup") -Force -ErrorAction SilentlyContinue
	Write-Host "[Expand-Archive] Extracting release files from $ENV:temp\TSSv2_download.zip"
	expand-archive -LiteralPath "$ENV:temp\TSSv2_download.zip" -DestinationPath $TSS_path -force
	#ToDo
}
#endregion  ::::: [Functions] --------------------------------------------------------#


#region  ::::: [MAIN] ----------------------------------------------------------------#
# detect OS version and SKU # Note: gwmi / Get-WmiObject is no more supportd in PS v7 -> use Get-CimInstance
If($Host.Version.Major -ge 7){
	[Reflection.Assembly]::LoadWithPartialName("System.ServiceProcess.servicecontroller") | Out-Null
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
} else {$wmiOSVersion = Get-WmiObject -Namespace "root\cimv2" -Class Win32_OperatingSystem}
[int]$bn = [int]$wmiOSVersion.BuildNumber
#Write-verbose "installed-version: $(get_local_tss_version current) - Build: $bn"
$installedTSSver = New-Object System.Version([version]$(get_local_tss_version "current"))
Write-verbose "installedTSSver: $installedTSSver"

## :: Criteria to use Quick vs. Online update: Quick if UpdMode = Quick; Online = if updates in xray or psSDP are needed, ...
# Choose download file based on $UpdMode (and current installed TSSv2 build)
If($LiteMode) {$tss_file = "TSSv2Lite.zip"} else {$tss_file = "TSSv2.zip" }
switch ($UpdMode) {
        "Quick"	{ 	$tss_file = "TSSv2_diff.zip"
					$UpdateSource= "GitHub"}
        "Lite"	{ 	$tss_file = "TSSv2Lite.zip"
					$UpdateSource= "GitHub"}
		"Online"{ 	#$tss_file = "TSSv2.zip"
					$UpdateSource= "CesdiagTools"}
#		"Force" { 	$tss_file = "TSSv2.zip" }	# always perform a Full update
        default	{ 	$tss_file = "TSSv2.zip"
					$UpdateSource= "CesdiagTools"}
}
		
# Check for Internet connectivity // Test-NetConnection does not work for Win7
$checkConn = FwTestConnWebSite $TssReleaseServer -ErrorAction SilentlyContinue
if ( $checkConn -eq "True") {
	# Determine which edition we need, ? based on existence of .\x64\TTTracer.exe # + ToDo Lite based on existence/number of *.exe in \BIN folder
	if ($UpdMode -Notmatch "Online") {
		$script:expectedVersion = New-Object System.Version(get_latest_tss_version)
	}
	if ("$($script:expectedVersion)" -eq "0.0") { Write-Verbose "Bail out: $script:expectedVersion"; ExitWithCode 20}
	# Check if TSSv2 exists in $TSS_path
	if (-not (Test-Path ($TSS_path + "TSSv2.ps1"))){
		Write-Host -ForegroundColor Red "[Warning] TSSv2.ps1 could not be located in $TSS_path"
		DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
	}

	if (Test-Path ($TSS_path + "TSSv2.ps1")){
		if ($UpdMode -match "Online") {
			DownloadTssZipFromCesdiagRelease -File "TSSv2.zip"
		}
		elseif ($UpdMode -match "Force") {	# update regardless of current local version
		Write-Host -ForegroundColor Cyan "[Forced update:] to latest version $script:expectedVersion from $UpdateSource`n"
		 if (Test-Path ($TSS_path + "x64\TTTracer.exe")) { Write-Host -ForegroundColor Yellow "[note:] This procedure will not refresh iDNA part"}
									DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
		} else {
			Write-Host "[Info] checking current version $installedTSSver in $TSS_path against latest released $UpdateSource version $script:expectedVersion."
			if ($($installedTSSver.CompareTo($script:expectedVersion)) -eq 0) { 		# If versions match, display message
				"`n [Info] Latest TSSv2 version $script:expectedVersion is installed. " | Out-File $UpdLogfile -Append
				Write-Host -ForegroundColor Cyan "[Info] Latest TSSv2 version $script:expectedVersion is installed.`n"}
			elseif ($($installedTSSver.CompareTo($script:expectedVersion)) -lt 0) {	# if installed current version is lower than latest $UpdateSource Release version
				"`n [Action: $tss_action -[Warning] Actually installed TSSv2 version $installedTSSver is outdated] " | Out-File $UpdLogfile -Append
				Write-Host -ForegroundColor red "[Warning] Actually installed TSSv2 version $installedTSSver is outdated"
				Write-Host "[Info] Expected latest TSSv2 version on $($UpdateSource) = $script:expectedVersion"
				Write-Host -ForegroundColor yellow "[Warning] ** Update will overwrite customized configuration, latest \config\tss_config.cfg is preserved in \config\tss_config.cfg_backup. ** "
				switch($tss_action)
					{
					"download"		{ 	Write-Host "[download:] latest $tss_file"
										DownloadFileFromGitHubRelease "download" $tss_file $installedTSSver
									}
					"update"		{ 	Write-Host "[update:] to latest version $script:expectedVersion from $UpdateSource " 
										 if (Test-Path ($TSS_path + "x64\TTTracer.exe")) { Write-Host -ForegroundColor Yellow "[note:] This procedure will not refresh iDNA/TTD part"}
										DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
									}
					"version"		{ 	Write-Host -background darkRed "[version:] installed TSSv2 version is outdated, please run 'TSS Update', trying AutoUpate" # or answer next question with 'Yes'"
										Write-Host -ForegroundColor Cyan "[Info] running AutoUpdate now... (to avoid updates, append TSSv2 switch 'noUpdate')"
										DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
									}
					}
					"`n [Action: $tss_action - OK] " | Out-File $UpdLogfile -Append
			}
			else {	# if installed current version is greater than latest CesdiagTools/GitHub Release version
				if ($script:ChkFailed) {Write-Host -ForegroundColor Gray "[Info] Version check failed! Expected version on $($UpdateSource) = $script:expectedVersion. Please download https://aka.ms/getTSS `n"}
				Write-Verbose "Match: Current installed TSSv2 version:  $installedTSSver"
				Write-Verbose "Expected latest TSSv2 version on $($UpdateSource) = $script:expectedVersion"
			}
		}
	}
} else {
	Write-Host -ForegroundColor Red "[failed update] Missing secure internet connection to $TssReleaseServer. Please download https://aka.ms/getTSS `n"
							"`n [failed update] Missing secure internet connection to $TssReleaseServer. Please download https://aka.ms/getTSS `n" | Out-File $UpdLogfile -Append
}

$ScriptEndTimeStamp = Get-Date
$Duration = $(New-TimeSpan -Start $ScriptBeginTimeStamp -End $ScriptEndTimeStamp)

Write-Host -ForegroundColor Black -background gray "[Info] Script $scriptName v$updScriptVersion execution finished. Duration: $Duration"
if ($AutoUpd) { Write-Host -ForegroundColor Yellow  "[AutoUpdate done] .. Please repeat your TSSv2 command now."}
#endregion  ::::: [MAIN] -------------------------------------------------------------#

#region  ::::: [ToDo] ----------------------------------------------------------------#
<# 
 ToDo: 
 - save any CX changed file like \config\tss_config.cfg into a [backup_v...] subfolder with prev. version, --> easy restoration, if there is no schema change
	see "...saving a copy of installed TSSv2.ps1  ..."
 - allow TSSv2 to update from CX Central Enterprise store \\server\share\tss defined in \config\tss_config.cfg, if update from CesdiagTools/GitHub fails
 
- Implement a scheduled task for periodic update check
Example one-line command: schtasks.exe /Create /SC DAILY /MO 1 /TN "tss Updater" /TR "powershell \path\to\script\get-latest-tss.ps1 -TSS_path 'path\to\where\tss\is' -tss_arch 'x64'" /ST 12:00 /F
	[/SC DAILY]: Run daily
	[/MO 1]: Every Day
	[/TN "tss Updater"]: Task Name
	[/TR "powershell \path\to\script\get-latest-tss.ps1 -TSS_path 'path\to\where\tss\is' -tss_arch 'x64'"]: Command to run
	[/ST 12:00]: Run at 12 PM
	[/F]: Force update
#>
#endregion  ::::: [ToDo] ----------------------------------------------------------------#


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAHV1UR+bltZ7oG
# MurUO5GjiHaD6TWRKHeGwSzLImmu7qCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQguZTU+ubB
# wN4NI+ZiZEwH5oxq06+rqfKm8yiOfiNrymUwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAXYLZiOcedALXOb6YDkIq6eRqsGBka90k4IYdlvqks
# MOS0BA+IgySFLVe7qc9b4xRacxh8BKOyB6Qm9MAg9XVHLwpAhbdeWqeUM6Tp0cpH
# F0FNVROBzpjf+q0/Drr8G0/7/jVsV4xFKWlqyMbf8MmFSWQq0kLB9vRfthWuj7s0
# qNBIkiIUJZh13G5zHinPmE6RVuzVw/+dGOZXpx5Oo1UODVM7D4ZHucxsgJoKcQfb
# JB7iPa5YU9+jl7U+KQMcHfq+EFZVEKjMZvPRfdOESkz3dYJeW1D+l4XJVymirbxB
# cUb42YcorxnKiWeN+2qQCH2J3Y8Bpu32Jaiz0eJJYrAKoYIXADCCFvwGCisGAQQB
# gjcDAwExghbsMIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIFkp0+3bQUmp8aG4RecUAgRb3yppjyKfLAWmYUM9
# vw8kAgZi2BBtdlAYEzIwMjIwODE2MDkyMDEyLjY0OFowBIACAfSggdCkgc0wgcox
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
# CRABBDAvBgkqhkiG9w0BCQQxIgQgeBNaA0wamrc+XsYBqX+NSlw+kDKx0pAo4At+
# xvJO2zQwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJi
# L539Lx+nsr/NFVTnKFX030iNYDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABmsB1osQhbT6FAAEAAAGaMCIEIHi4zgoapLg6e7lIoGZc
# T5UI7j4EtOdnLriJSRmAtVLUMA0GCSqGSIb3DQEBCwUABIICAFo5Z32MMY3QtUjI
# z8A12OnvUPZQ4iEd2vtpKhB41Fzx7AzfQWM3DjE4g5X2t15TV5IrZY5HK4Y7ai0w
# SawcFy/aeyHfcGKgW7d9m4jf9zZ1HqqwXaFxHRA75tCYkc5Qv79uC7Dg02xHdyuP
# ucpFHpPv44vvFADtzo5Fyb6BQ5HOpmUaCvGNUicJLsnBISGOKVIojror0uoeWTJ8
# woTP7BHOxJHi1FtmujTXNLXeb378u6z/dfer4rLylsEfu9l4G7zhV92o4xEabRWH
# 0RsD26X+P5M+e71VkE4LkahKfenyzI+cGmOJB1UWyGeoFEFNscAu5WMD/VLYKlpQ
# SomWkVOMZDBidnNY1cgyLqjZIGqam9PuEvelz1LJQwTX+lvZEmv/KTRgPJ2quWIA
# HEwRM/lHcXdiKlRavTEdRtBw2aEyRJK4FqCCvoVNnfV8wDkqhUhGdN0WlWtIcM6v
# ISVa8ziEwohkr6YyxvGuVLvl3sX9SjASB96nptUIyvj1fmAj3zwqQS+GbNZrruJ1
# wIUyl4Cq9MgeNJxPIg1WfDkJm4X4lLH8w0eXXTZGYqhA5WwImGs9wART4yNSaDRI
# alx0Uk2yhbKn5fVRj8GqPDtN9A5BvZwFd/EDkpDYOTZb2+//OEF/jfotN0rJKGqg
# +ldBLIrpglc01pWGmFgFR8bbSQbi
# SIG # End signature block
