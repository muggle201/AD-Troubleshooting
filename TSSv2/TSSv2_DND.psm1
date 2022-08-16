<#
.SYNOPSIS
   DND module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows DND components
   Add any custom tracing functinaliy for tracing DND components
   For Developers:
   1. Switch test: .\TSSv2.ps1 -Start -DND_TEST1
   2. Scenario test: .\TSSv2.ps1 -start -Scenario DND_MyScenarioTest

.NOTES
   Authors    : cleng; sabieler
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDateDND

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	DND https://internal.support.services.microsoft.com/en-us/help/4643331
#>

<# latest changes
  2022.08.01.0 [we] _NET: add var $PublicSymSrv to make PSScriptAnalyzer happy
  2022.07.25.1 [sb] #_# added new function to retrieve AppLocker policy
  2022.07.25.0 [sb] #_# added info from storage cmdLets
  2022.07.11.0 [sb] #_# enabled _NETBASIC
  2022.07.04.0 [sb] #_# Get-DNDSetupLogs, moving back to robocopy to leverage filters
  2022.07.01.0 [sb] #_# FwCopyFiles, changed wildcard usage from "*.*"" to "*"
  2022.06.29.0 [sb] #_# Get-DNDWindowsUpdateInfo, fixed typo
  2022.06.28.1 [sb] #_# CollectDND_WULogsLog, fixed typo
  2022.06.28.0 [sb] #_# Get-DNDMiscInfo, reg_Drivers.hiv no longer overwrites reg_Components.hiv
  2022.06.21.1 [sb] #_# Get-DNDEventLogs, exclude archived event logs, Get-DNDWindowsUpdateInfo added 1607 detection logic
  2022.06.21.0 [sb] #_# Get-DNDCbsPnpInfo, re-added files
  2022.06.20.0 [sb] #_# [Get-DNDDeploymentLogs] fixed output filename
  2022.06.17.0 [sb] #_# [Get-DNDEnergyInfo] change output for system power report to Powercfg-systempowerreport.html
  2022.06.06.0 [we] #_# [DND_WUlogs] fix msinfo/systeminfo
  2022.06.03.0 [we] #_# fix While loop in [Get-DNDMiscInfo], use FW function FwGet-SummaryVbsLog
  2022.05.31.0 [we] #_# replaced LogMessage .. with LogInfo/LogDebug; replaced some code with FW functions i.e. using FwExportFileVerToCsv
	FYI: RunCommands will mirror each commandline in output file, if last item separated by space ' ' is a output file-name; FW functions have better error handling
  2022.05.25.0 [sb] #_# DND_SETUPReport, enhanced configuration granularity through tss_config.cfg
  2022.05.24.3 [sb] #_# DND_SETUPReport, replaced  [System.ServiceProcess.ServiceControllerStatus] with [System.ServiceProcess.ServiceStartMode]
  2022.05.24.2 [sb] #_# DND_SETUPReport, added try block to Get-DNDWindowsUpdateInfo
  2022.05.24.1 [sb] #_# DND_SETUPReport, added abnormal sleepstudy ETLs
  2022.05.24.0 [sb] #_# DND_SETUPReport, minor changes in Get-DNDNetworkBasic
  2022.04.13.0 [cl] #_# DND_SETUPLog and DND_WULogs  replaced WMIC with Get-CimInstance
  2022.03.14.0 [sb] #_# DND_SETUPReport, adding extra logging to Get-DNDEventLogs
  2022.02.21.0 [sb] #_# DND_SETUPReport, adding pattern to servicing state query
  2022.02.16.0 [sb] #_# DND_SETUPReport, removed function placeholder
  2022.02.15.0 [sb] #_# DND_SETUPReport, added servicing scenario "-Scenario DND_ServicingProcmon"
  2022.02.09.1 [sb] #_# DND_SETUPReport, added function Get-DNDRFLCheckPrereqs
  2022.02.09.0 [sb] #_# DND_SETUPReport, fixed bug in Get-DNDWindowsUpdateInfo
  2022.02.06.0 [we] #_# added description for DND_SETUPReport in framework
  2022.02.03.1 [sb] #_# DND_SETUPReport, split network functions into Get-DNDNetworkBasic and Get-DNDNetworkSetup
  2022.02.03.0 [sb] #_# DND_SETUPReport, check if wuauserv is disabled before querying it to prevent runtime exception
  2022.02.02.0 [sb] #_# DND_SETUPReport, removed duplicate collection of reg_SoftwareProctectionPlatform.txt, fixed typo and moved collection from Get-DNDMiscInfo into Get-DNDActivationState
  2022.02.01.0 [sb] #_# DND_SETUPReport, added parameters to tss_config.cfg and use them to be more flexible
  2022.01.26.1 [sb] #_# DND_SETUPReport, disabled progress display from Test-NetConnection
  2022.01.26.0 [sb] #_# DND_SETUPReport, added hours to runtime calculation
  2022.01.20.0 [sb] #_# DND_SETUPReport, added connection test to public symbol server msdl.microsoft.com to prevent long running Get-WindowsUpdateLog cmdLet
  2022.01.07.2 [sb] #_# DND_SETUPReport, removed xray overwrite to have telemetry working
  2022.01.07.1 [sb] #_# DND_WULogs, added noBasicLog to global parameter array to skip basic log collection, ($global:ParameterArray += "noBasicLog")
  2022.01.07.0 [sb] #_# DND_SETUPReport, added noBasicLog to global parameter array to skip basic log collection, ($global:ParameterArray += "noBasicLog")
  2022.01.05.0 [sb] #_# typo in "Token Activation" section and output certutil info into new text file.
  2022.01.04.0 [sb] #_# added storage cmdLets for Windows 8 and higher
  2022.01.02.0 [we] #_# _NET: moved NET_ '_WinUpd' to _DND, https://microsoft.ghe.com/css-windows/WindowsCSSToolsDevRep/pull/394
  2021.12.23.0 [sb] #_# split up DND_SETUPReport  collection into functions in preparation of different log collection purposes or scenarios
  2021.12.20.0 [sb] #_# surface log collection: removed unneeded closing brace, escaped pipeline variable
  2021.12.02.1 [sb] #_# migrating common CMD commands to use TSSv2 framework functions (section: activation, directory listing, surface, slow processing)
  2021.12.02.0 [sb] #_# added cidiag to scenario "-DND_CodeIntegrity", example: .\TSSv2.ps1 -Start -DND_CodeIntegrity -noBasicLog -noUpdate
  2021.11.30.0 [sb] #_# migrating common CMD commands to use TSSv2 framework functions (section: network)
  2021.11.27.0 [cl] #_# added variuos taracing GUIDs
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
  2021.03.23.0 [cl] #_# initial version of TSSv2 DND module
#>

$global:TssVerDateDND = "2022.08.011.2"

$PublicSymSrv = "msdl.microsoft.com"
#region Switches
<#
# Normal trace -> data will be collected in a sign
$DND_TEST1Providers = @(
    '{CC85922F-DB41-11D2-9244-006008269001}' # LSA
    '{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
)

$DND_TEST2Providers = @(
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' # NTLM
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
)

# Normal trace with multi etl files
$DND_TEST3Providers = @(
    '{98BF1CD3-583E-4926-95EE-A61BF3F46470}!CertCli'
    '{6A71D062-9AFE-4F35-AD08-52134F85DFB9}!CertificationAuthority'
)
#>

$DND_WUProviders = @(
    '{0b7a6f19-47c4-454e-8c5c-e868d637e4d8}' # WUTraceLogging
    '{9906081d-e45a-4f41-a53f-2ac2e0225de1}' # SIHTraceLoggingProviderGuid
    '{5251FD36-A05A-4033-ADAD-FA409644E282}' # SIHTraceLoggingSessionGuid
    '{D48679EB-8AA3-4138-BE24-F1648C874E49}' # SoftwareUpdateClientTelemetry
)

$DND_CBSProviders = @(
    '{5fc48aed-2eb8-4cd4-9c87-54700c4b7b26}' # CbsServicingProvider
    '{bd12f3b8-fc40-4a61-a307-b7a013a069c1}' # Microsoft-Windows-Servicing
    '{34c6b9f6-c1cf-4fe5-a133-df6cb085ec67}' # CBSTRACEGUID
)

$DND_CodeIntegrityProviders = @(
    '{DDD9464F-84F5-4536-9F80-03E9D3254E5B}' # MicrosoftWindowsCodeIntegrityTraceLoggingProvider
    '{2e1eb30a-c39f-453f-b25f-74e14862f946}' # MicrosoftWindowsCodeIntegrityAuditTraceLoggingProvider
    '{4EE76BD8-3CF4-44a0-A0AC-3937643E37A3}' # Microsoft-Windows-CodeIntegrity
    '{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
    '{382B5E24-181E-417F-A8D6-2155F749E724}' # Microsoft.Windows.ShellExecute
    '{072665fb-8953-5a85-931d-d06aeab3d109}' # Microsoft.Windows.ProcessLifetimeManager
)

$DND_PNPProviders = @(
    '{63aeffcd-648e-5fc0-b4e7-a39a4e6612f8}' # Microsoft.Windows.InfRemove
    '{2E5950B2-1F5D-4A52-8D1F-4E656C915F57}' # Microsoft.Windows.PNP.DeviceManager
    '{F52E9EE1-03D4-4DB3-B2D4-1CDD01C65582}' # PnpInstall
    '{9C205A39-1250-487D-ABD7-E831C6290539}' # Microsoft-Windows-Kernel-PnP
    '{8c8ebb7e-a4b7-4336-bddb-4a0aea0f535a}' # Microsoft.Windows.Sysprep.PnP
    '{0e0fe12b-e926-44d2-8cf1-8a62a6d44036}' # Microsoft.Windows.DriverStore
    '{139299bb-9394-5058-dd33-9422e5903fc3}' # Microsoft.Windows.SetupApi
    '{a23bd382-12ab-4f02-a0d7-273153f8b65a}' # Microsoft.Windows.DriverInstall
    '{059a2460-1077-4446-bdeb-5221de48b9e4}' # Microsoft.Windows.DriverStore.DriverPackage
    '{96F4A050-7E31-453C-88BE-9634F4E02139}' # Microsoft-Windows-UserPnp
    '{A676B545-4CFB-4306-A067-502D9A0F2220}' # PlugPlay
    '{84051b98-f508-4e54-82fa-8865c697c3b1}' # Microsoft-Windows-PnPMgrTriggerProvider
    '{96F4A050-7E31-453C-88BE-9634F4E02139}' # Microsoft-Windows-UserPnp
    '{D5EBB80C-4407-45E4-A87A-015F6AF60B41}' # Microsoft-Windows-Kernel-PnPConfig
    '{FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}' # claspnp
    '{F5D05B38-80A6-4653-825D-C414E4AB3C68}' # Microsoft-Windows-StorDiag
    '{5590bf8b-9781-5d78-961f-5bb8b21fbaf6}' # Microsoft.Windows.Storage.Classpnp
)

$DND_TPMProviders = @(
    '{1B6B0772-251B-4D42-917D-FACA166BC059}' # TPM
    '{3A8D6942-B034-48E2-B314-F69C2B4655A3}' # TpmCtlGuid
    '{470baa67-2d7f-4c9c-8bf4-b1b3226f7b17}' # Microsoft.Tpm.ProvisioningTask
    '{7D5387B0-CBE0-11DA-A94D-0800200C9A66}' # Microsoft-Windows-TPM-WMI
    '{84FF4863-8173-5F91-9E83-B4C3B38042D5}' # Microsoft.Tpm.Drv_20
    '{6FCC5608-58C2-56AE-5ACD-B2A70F6323CF}' # Microsoft.Tpm.Drv_12
    '{61D3C72E-6B1B-454C-A34D-B39EB95B8D99}' # Microsoft.Tpm.Tbs
)
#endregion Switches


#region Scenarios

# Scenario trace
<#
Switch (FwGetProductTypeFromReg)
{
    "WinNT" {
        $DND_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
            'DND_TEST1' = $true
            'DND_TEST2' = $true
            'DND_TEST3' = $true   # Multi files
            'UEX_Task' = $True   # Outside of this module
        }
    }
    "ServerNT" {
        $DND_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
            'DND_TEST1' = $true
            'DND_TEST2' = $true
        }
    }
    "LanmanNT" {
        $DND_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
            'DND_TEST1' = $true
            'DND_TEST2' = $true
        }
    }
    Default {
        $DND_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
            'DND_TEST1' = $true
            'DND_TEST2' = $true
        }
    }
}
#>

$DND_ServicingProviders = @( # all Providers need to be defined already above
	$DND_CBSProviders
	$DND_PNPProviders
	$DND_WUProviders
)
#endregion --- ETW component trace Providers ---

$DND_Servicing_ETWTracingSwitchesStatus = [Ordered]@{
    'DND_Servicing' = $True
    'Procmon' = $True
    'noBasicLog' = $True
    'CollectComponentLog' = $True
}
#endregion Scenarios

#region Functions
# [we] _NET: moved NET_ '_WinUpd' to _DND, #394
function CollectDND_WinUpdLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting 'Get-WindowsUpdateLog -LogPath WindowsUpdate.log'"
	$Commands = @(
		"Set-Alias Out-Default Out-Null"
		"Get-WindowsUpdateLog -LogPath $PrefixCn`WindowsUpdate.log"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

########## CollectLog Function ############
#For CopyLogs.cmd
Function CollectDND_WULogsLog
{
    EnterFunc $MyInvocation.MyCommand.Name
	# do we run elevated?
    if (!(FwIsElevated) -or ($Host.Name -match "ISE Host"))
    {
		if ($Host.Name -match "ISE Host")
        {
			LogInfo "Exiting on ISE Host." "Red"
		}
		LogInfo 'This script needs to run from elevated command/PowerShell prompt.' "Red"
        return
    }

    # Skipping unneccessary basic log collection and xray
    $global:ParameterArray += "noBasicLog"

    $_tempdir= "$LogFolder\WU_Logs$LogSuffix"
    FwCreateLogFolder $_tempdir
    $_prefix="$_tempdir\$Env:COMPUTERNAME" + "_"
    $_robocopy_log=$_prefix+'robocopy.log'
    $_line='--------------------------------------------------------------------------------------------------------'
    $_errorfile= $_prefix+'Errorout.txt'
    # use tss_config.cfg to modify these parameters on the fly as you need them
    # Flush Windows Update logs by stopping services before copying...usually not needed.
    $_flush_logs=0

    $_WUETLPATH="$Env:windir\Logs\WindowsUpdate"
    $_SIHETLPATH="$Env:windir\Logs\SIH"
    $_WUOLDETLPATH="$Env:windir.old\Windows\Logs\WindowsUpdate"
    $_OLDPROGRAMDATA="$Env:windir.old\ProgramData"
    $_robocopy_log="$_tempdir\robocopy.log"
    $_OLDLOCALAPPDATA="$Env:windir.old\" + "$Env:localappdata".Substring(2)

    # OS Version checks
    $_major = [environment]::OSVersion.Version.Major
    $_minor = [environment]::OSVersion.Version.Minor
    $_build = [environment]::OSVersion.Version.Build

    LogInfo ("[OS] Version: $_major.$_minor.$_build")

    $_WIN8_OR_LATER = $false
    $_WINBLUE_OR_LATER = $false

    if ([int]$_major -ge 7)
    {
        $_WIN8_OR_LATER = $true
        $_WINBLUE_OR_LATER = $true
    }
    elseif ([int]$_major -eq 6)
    {
        if([int]$_minor -ge 2) { $_WIN8_OR_LATER = $true}
        if([int]$_minor -ge 3) { $_WINBLUE_OR_LATER = $true}
    }

	# starting MsInfo early
	FwGetMsInfo32 "nfo" -Subfolder "WU_Logs$LogSuffix"
	FwGetSysInfo -Subfolder "WU_Logs$LogSuffix"

    Write-Output "-------------------------------------------"
    Write-Output "Copying logs ..."
    Write-Output "-------------------------------------------"
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\windowsupdate.log", "$($_prefix)WindowsUpdate.log"),
		@("$Env:windir\SoftwareDistribution\ReportingEvents.log", "$($_prefix)WindowsUpdate_ReportingEvents.log"),
		@("$Env:localappdata\microsoft\windows\windowsupdate.log", "$($_prefix)WindowsUpdatePerUser.log"),
		@("$Env:windir\windowsupdate (1).log", "$($_prefix)WindowsUpdate(1).log"),
		@("$Env:windir.old\Windows\windowsupdate.log", "$($_prefix)Old.WindowsUpdate.log"),
		@("$Env:windir.old\Windows\SoftwareDistribution\ReportingEvents.log", "$($_prefix)Old.ReportingEvents.log"),
		@("$_OLDLOCALAPPDATA\microsoft\windows\windowsupdate.log", "$($_prefix)Old.WindowsUpdatePerUser.log"),
		@("$Env:windir\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833\TokenRetrieval.log", "$($_prefix)WindowsUpdate_TokenRetrieval.log")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False

    # -------------------------------------------------------------
    # CBS & PNP logs
	$Commands = @(
		"robocopy.exe `"$Env:windir\logs\cbs`" 	$_tempdir *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
		"robocopy.exe `"$Env:windir\logs\cbs`" 	$_tempdir *.cab /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
		"robocopy.exe `"$Env:windir\logs\dpx`" 	$_tempdir *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
		"robocopy.exe `"$Env:windir\inf`" 		$_tempdir *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
		"robocopy.exe `"$Env:windir\WinSxS`" 	$_tempdir poqexec.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
		"robocopy.exe `"$Env:windir\WinSxS`" 	$_tempdir pending.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
		"robocopy.exe `"$Env:windir\servicing\sessions`" $_tempdir sessions.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
	)
	RunCommands "CBS_PNP" $Commands -ThrowException:$False -ShowMessage:$True

    # UUP logs and action list xmls
    robocopy "$Env:windir\SoftwareDistribution\Download" "$_tempdir\UUP" *.log *.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log

    # -------------------------------------------------------------
    # Windows Store logs.
    cmd /r Copy "$Env:temp\winstore.log" "$_tempdir\winstore-Broker.log" /y >$null 2>&1
    robocopy "$Env:userprofile\AppData\Local\Packages\WinStore_cw5n1h2txyewy\AC\Temp" "$_tempdir winstore.log" /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null

    # -------------------------------------------------------------
    # WU ETLs for Win10+

    # Older build has ETL in windir
    if (test-path -path "$Env:windir\windowsupdate.etl")
    {
      # windowsupdate.etl is not flushed until service is stopped.
      $LogPrefixFlushLogs = "FlushLogs"
      LogInfo ("[$LogPrefixFlushLogs] Flushing USO/WU logs")
      $CommandsFlushLogs = @(
          "Stop-Service -Name usosvc"
          "Stop-Service -Name wuauserv"
      )
      RunCommands $LogPrefixFlushLogs $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True

      robocopy "$Env:windir" $_tempdir windowsupdate.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    }

    # Newer build has multiple ETLs
    if (test-path -path $_WUETLPATH)
    {
        $LogPrefixFlushLogs = "FlushLogs"
        LogInfo ("[$LogPrefixFlushLogs] Flushing USO/WU logs")
        $CommandsFlushLogs = @(
            "Stop-Service -Name usosvc"
            "Stop-Service -Name wuauserv"
		)
		RunCommands $LogPrefixFlushLogs $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True

        robocopy $_WUETLPATH $_tempdir *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    }

	# Copy SIH ETLs
	if (test-path -path $_SIHETLPATH)
	{
		robocopy $_SIHETLPATH $_tempdir *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
	}

	# Verbose Logging redirects WU ETL to systemdrive
	if (test-path -path "$Env:systemdrive\windowsupdateverbose.etl")
	{
		# windowsupdateverbose.etl is not flushed until service is stopped.
		$LogPrefixFlushLogs = "FlushLogs"
		LogInfo ("[$LogPrefixFlushLogs] Flushing USO/WU logs")
		$CommandsFlushLogs = @(
			"Stop-Service -Name usosvc"
			"Stop-Service -Name wuauserv"
		)
		RunCommands $LogPrefixFlushLogs $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True

		robocopy $Env:systemdrive $_tempdir windowsupdateverbose.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
	}

    Write-Output "-------------------------------------------"
    Write-Output "Copying upgrade logs"
    Write-Output "-------------------------------------------"
    cmd /r mkdir "$_tempdir\UpgradeSetup" >$null 2>&1
    cmd /r mkdir "$_tempdir\UpgradeSetup\NewOS" >$null 2>&1
    cmd /r mkdir "$_tempdir\UpgradeSetup\UpgradeAdvisor" >$null 2>&1

    robocopy "$Env:systemdrive\Windows10Upgrade" "$_tempdir\UpgradeSetup\UpgradeAdvisor" Upgrader_default.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\Windows10Upgrade "$_tempdir\UpgradeSetup\UpgradeAdvisor" Upgrader_win10.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy "$Env:systemdrive\$GetCurrent\logs" "$_tempdir\UpgradeSetup\UpgradeAdvisor" *.* /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy "$Env:windir\logs\mosetup" "$_tempdir\UpgradeSetup" *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    cmd /r Copy "$Env:windir.old\windows\logs\mosetup\*.log" "$_tempdir\UpgradeSetup\bluebox_windowsold.log" /y >$null 2>&1
    robocopy "$Env:windir\Panther\NewOS" "$_tempdir\UpgradeSetup\NewOS" *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy "$Env:windir\Panther\NewOS" "$_tempdir\UpgradeSetup\NewOS" miglog.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy "$Env:windir\Panther" "$_tempdir\UpgradeSetup" *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy "$Env:windir\Panther" "$_tempdir\UpgradeSetup" miglog.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    cmd /r Copy "$Env:systemdrive\`$Windows.~BT\Sources\Panther\setupact.log" "$_tempdir\UpgradeSetup\setupact_tildabt.log" /y >$null 2>&1
    cmd /r Copy "$Env:systemdrive\`$Windows.~BT\Sources\Panther\setuperr.log" "$_tempdir\UpgradeSetup\setuperr_tildabt.log" /y >$null 2>&1
    cmd /r Copy "$Env:systemdrive\`$Windows.~BT\Sources\Panther\miglog.xml" "$_tempdir\UpgradeSetup\miglog_tildabt.xml" /y >$null 2>&1
    if (test-path -path "$Env:systemdrive\`$Windows.~BT\Sources\Rollback")
    {
        robocopy "$Env:systemdrive\`$Windows.~BT\Sources\Rollback" "$_tempdir\UpgradeSetup\Rollback" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
    }
    if (test-path -path "$Env:windir\Panther\NewOS")
    {
        robocopy "$Env:windir\Panther\NewOS" "$_tempdir\UpgradeSetup\PantherNewOS" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
    }

    # Copying the datastore file
    if (test-path -path "$Env:windir\softwaredistribution\datastore\datastore.edb")
    {
      Write-Output "Copying WU datastore ..."
      Stop-Service -Name usosvc >$null 2>&1
      Stop-Service -Name wuauserv >$null 2>&1
      robocopy "$Env:windir\softwaredistribution\datastore" $_tempdir DataStore.edb /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    }

    # Also copy ETLs pre-upgrade
    if (test-path -path $_WUOLDETLPATH)
    {
      robocopy $_WUOLDETLPATH "$_tempdir\Windows.old\WU" *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    }

    # -------------------------------------------------------------
    # Copy DISM Logs and DISM output
    robocopy "$Env:windir\logs\dism" $_tempdir * /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    dism /online /get-packages /format:table > $_tempdir\DISM_GetPackages.txt
    dism /online /get-features /format:table > $_tempdir\DISM_GetFeatures.txt

    # -------------------------------------------------------------
    # MUSE logs for Win10+
    if($null -ne (Get-Service -Name usosvc -ErrorAction SilentlyContinue))
    {
      Write-Output "Copying MUSE logs ..."
      Stop-Service -Name usosvc >$null 2>&1
      robocopy "$Env:programdata\UsoPrivate\UpdateStore" "$_tempdir\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
      robocopy "$Env:programdata\USOShared\Logs" "$_tempdir\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
      SCHTASKS /query /v /TN \Microsoft\Windows\UpdateOrchestrator\ > "$_tempdir\MUSE\updatetaskschedules.txt"

      robocopy "$_OLDPROGRAMDATA\USOPrivate\UpdateStore" "$_tempdir\Windows.old\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
      robocopy "$_OLDPROGRAMDATA%\USOShared\Logs" "$_tempdir\Windows.old\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
    }

        # -------------------------------------------------------------
    # DO logs for Win10+
	Get-DNDDoLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs

    # -------------------------------------------------------------
    # WU BVT logs.
    cmd /r mkdir $_tempdir\BVT >$null 2>&1
    robocopy $Env:systemdrive\wubvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\dcatebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\wuappxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\wuuxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\wuauebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\WUE2ETest  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\taef\wubvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\taef\wuappxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\taef\wuuxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\taef\wuauebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\taef\WUE2ETest  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy $Env:systemdrive\taef\WUE2ETest  $_tempdir\BVT *.wtl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null

    Write-Output "-------------------------------------------"
    Write-Output "Copying token cache and license store ..."
    Write-Output "-------------------------------------------"
    robocopy "$Env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\WSLicense" $_tempdir tokens.dat /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
    robocopy "$Env:windir\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833" $_tempdir 117CAB2D-82B1-4B5A-A08C-4D62DBEE7782.cache /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null

    Write-Output "-------------------------------------------"
    Write-Output "Copying event logs ..."
    Write-Output "-------------------------------------------"
    cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx" $_tempdir /y >$null 2>&1
    cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx" $_tempdir /y >$null 2>&1
    cmd /r Copy "$Env:windir\System32\winevt\Logs\Application.evtx" $_tempdir /y >$null 2>&1
    cmd /r Copy "$Env:windir\System32\winevt\Logs\System.evtx" $_tempdir /y >$null 2>&1
    cmd /r Copy "$Env:windir\System32\Winevt\Logs\*AppX*.evtx" $_tempdir /y >$null 2>&1
    cmd /r Copy "$Env:windir\System32\Winevt\Logs\Microsoft-WS-Licensing%4Admin.evtx"  $_tempdir /y >$null 2>&1
    cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-Kernel-PnP%4Configuration.evtx" $_tempdir /y >$null 2>&1
    cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-Store%4Operational.evtx" $_tempdir /y >$null 2>&1

    Write-Output "-------------------------------------------"
    Write-Output "Logging registry ..."
    Write-Output "-------------------------------------------"
    $RegKeysMiscInfoExport = @(
		('HKLM:Software\Microsoft\Windows\CurrentVersion\WindowsUpdate', "$($_prefix)reg_wu.txt"),
		('HKLM:Software\Policies\Microsoft\Windows\WindowsUpdate', "$($_prefix)reg_wupolicy.txt"),
		('HKLM:SYSTEM\CurrentControlSet\Control\MUI\UILanguages', "$($_prefix)reg_langpack.txt"),
		('HKLM:Software\Policies\Microsoft\WindowsStore', "$($_prefix)reg_StorePolicy.txt"),
		('HKLM:Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate', "$($_prefix)reg_StoreWUApproval.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\FirmwareResources', "$($_prefix)reg_FirmwareResources.txt"),
		('HKLM:Software\Microsoft\WindowsSelfhost', "$($_prefix)reg_WindowsSelfhost.txt"),
		('HKLM:Software\Microsoft\WindowsUpdate', "$($_prefix)reg_wuhandlers.txt"),
		('HKLM:Software\Microsoft\Windows\CurrentVersion\Appx', "$($_prefix)reg_appx.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\Superfetch', "$($_prefix)reg_superfetch.txt"),
		('HKLM:Software\Setup', "$($_prefix)reg_Setup.txt"),
		('HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', "$($_prefix)reg_peruser_wupolicy.txt"),
		('HKLM:Software\Microsoft\PolicyManager\current\device\Update', "$($_prefix)reg_wupolicy_mdm.txt"),
		('HKLM:Software\Microsoft\WindowsUpdate\UX\Settings', "$($_prefix)reg_wupolicy_ux.txt"),
		('HKLM:Software\Microsoft\Windows\CurrentVersion\WaaSAssessment', "$($_prefix)reg_WaasAssessment.txt"),
        ('HKLM:Software\Microsoft\sih', "$($_prefix)reg_sih.txt")
    )
    FwExportRegistry "MiscInfo" $RegKeysMiscInfoExport -RealExport $true

    $RegKeysMiscInfoProperty = @(
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'BuildLab', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'UBR', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel', 'Version', "$($_prefix)reg_AppModelVersion.txt")
    )
    FwExportRegistry "MiscInfo" $RegKeysMiscInfoProperty

    Write-Output "-------------------------------------------"
    Write-Output "Collecting other stuffs ..."
    Write-Output "-------------------------------------------"
    Write-Output "Getting networking configs ..."
    $Commands = @(
		"ipconfig /all | Out-File -Append $($_prefix)ipconfig.txt"
		"cmd /r netsh winhttp show proxy | Out-File -Append $($_prefix)winhttp_proxy.txt"
		"cmd /r Copy `"$Env:windir\System32\drivers\etc\hosts`" `"$($_prefix)hosts_file.txt`" /y"
    )
    RunCommands "Network_config" $Commands -ThrowException:$False -ShowMessage:$True

    Write-Output "Getting directory lists ..."
    $Commands = @(
		"cmd /r Dir $Env:windir\SoftwareDistribution /s  | Out-File -Append $($_prefix)dir_softwaredistribution.txt"
		"cmd /r Dir $Env:windir\SoftwareDistribution /ah | Out-File -Append $($_prefix)dir_softwaredistribution_hidden.txt"
    )
    RunCommands "directory_lists" $Commands -ThrowException:$False -ShowMessage:$True

    Write-Output "Getting app list ..."
    if ($_WIN8_OR_LATER -eq $true)
    {
        try { Import-Module appx;get-appxpackage -allusers | Out-File -FilePath $_tempdir\GetAppxPackage.log }
        catch { LogException "Get-Appxpackage failed" $_ }
    }
    if ($_WINBLUE_OR_LATER -eq $true)
    {
        try { Get-Appxpackage -packagetype bundle | Out-File -FilePath $_tempdir\GetAppxPackageBundle.log }
        catch { LogException "Get-Appxpackage failed" $_ }
    }
    Write-Output "Getting download list ..."
    bitsadmin /list /allusers /verbose > $_tempdir\bitsadmin.log

    Write-Output "Getting certificate list ..."
    certutil -store root > $_tempdir\certs.txt 2>&1

    Write-Output "Getting installed update list ..."
    $Commands = @(
		"Get-CimInstance -ClassName win32_quickfixengineering | Out-File -Append $($_prefix)InstalledUpdates.log"
		"sc.exe query wuauserv | Out-File -Append $($_prefix)wuauserv-state.txt"
		"SCHTASKS /query /v /TN \Microsoft\Windows\WindowsUpdate\ | Out-File -Append $($_prefix)WUScheduledTasks.log"
    )
    RunCommands "installed_update" $Commands -ThrowException:$False -ShowMessage:$True

    Write-Output "-------------------------------------------"
    Write-Output "Collecting file versions ..."
    Write-Output "-------------------------------------------"

    $binaries = @("wuaext.dll", "wuapi.dll", "wuaueng.dll", "wucltux.dll", "wudriver.dll", "wups.dll", "wups2.dll", "wusettingsprovider.dll", "wushareduxresources.dll", "wuwebv.dll", "wuapp.exe", "wuauclt.exe", "storewuauth.dll", "wuuhext.dll", "wuuhmobile.dll", "wuau.dll", "wuautoappupdate.dll")
    foreach($file in $binaries)
    {
		FwFileVersion -Filepath ("$Env:windir\system32\$file") | Out-File -FilePath ($_prefix+"FilesVersion.txt") -Append
	}

    $muis = @("wuapi.dll.mui", "wuaueng.dll.mui", "wucltux.dll.mui", "wusettingsprovider.dll.mui", "wushareduxresources.dll.mui")
    foreach($file in $muis)
    {
		FwFileVersion -Filepath ("$Env:windir\system32\en-US\$file") | Out-File -FilePath ($_prefix+"FilesVersion.txt") -Append
	}

    # end
    Write-Output "-------------------------------------------"
    Write-Output "Restarting services ..."
    Write-Output "-------------------------------------------"
	$Commands = @(
		"Start-Service -Name dosvc"
		"Start-Service -Name usosvc"
		"Start-Service -Name wuauserv"
	)
	RunCommands "Restart_services" $Commands -ThrowException:$False -ShowMessage:$True

	FwWaitForProcess $global:msinfo32NFO 300
    Write-Output "-------------------------------------------"
    Write-Output "Finished DND_WUlogs!"
    Write-Output "-------------------------------------------"

    EndFunc $MyInvocation.MyCommand.Name
}

#For SetupReport
Function CollectDND_SETUPReportLog
{
    EnterFunc $MyInvocation.MyCommand.Name
    # Skipping unneccessary basic log collection and xray
    $global:ParameterArray += "noBasicLog"

    # do we run elevated?
    if (!(FwIsElevated) -or ($Host.Name -match "ISE Host"))
    {
		if ($Host.Name -match "ISE Host")
        {
			LogInfo "Exiting on ISE Host." "Red"
		}
		LogInfo 'This script needs to run from elevated command/PowerShell prompt.' "Red"
        return
    }

    $_tempdir= "$LogFolder\Setup_Report$LogSuffix"
	FwCreateLogFolder $_tempdir
    $_prefix="$_tempdir\$Env:COMPUTERNAME" + "_"
    $_robocopy_log=$_prefix+'robocopy.log'

    #$_BatchDir= convert-path .
    $_line='--------------------------------------------------------------------------------------------------------'
    $_errorfile= $_prefix+'Errorout.txt'

    # use tss_config.cfg to modify these parameters on the fly as you need them
    # Flush Windows Update logs by stopping services before copying...usually not needed.
    $_flush_logs=0
    # $global:DND_SETUPReport_FlushLogs set in tss_config.cfg?
    if (($DND_SETUPReport_FlushLogs -eq '0') -or ($DND_SETUPReport_FlushLogs -eq '1')) {$_flush_logs = $DND_SETUPReport_FlushLogs}

    # collect datastore
    $_DATASTORE=0
    # $global:DND_SETUPReport_DATASTORE
    if (($DND_SETUPReport_DATASTORE -eq '0') -or ($DND_SETUPReport_DATASTORE -eq '1')) {$_DATASTORE = $DND_SETUPReport_DATASTORE}

    # Gather upgrade logs.
    $_UPGRADE=1
    #$global:DND_SETUPReport_UPGRADE
    if (($DND_SETUPReport_UPGRADE -eq '0') -or ($DND_SETUPReport_UPGRADE -eq '1')) {$_UPGRADE = $DND_SETUPReport_UPGRADE}

    # DXDiag isn't usually needed.
    $_DXDIAG=0
    #$global:DND_SETUPReport_DXDIAG
    if (($DND_SETUPReport_DXDIAG -eq '0') -or ($DND_SETUPReport_DXDIAG -eq '1')) {$_DXDIAG = $DND_SETUPReport_DXDIAG}

    # Get WinSxS and .Net file version info - Supported on systems with PowerShell 4+
    $_GETWINSXS=0
    #$global:DND_SETUPReport_GETWINSXS
    if (($DND_SETUPReport_GETWINSXS -eq '0') -or ($DND_SETUPReport_GETWINSXS -eq '1')) {$_GETWINSXS = $DND_SETUPReport_GETWINSXS}

    # Get App Compat info
    $_APPCOMPAT=0
    #$global:DND_SETUPReport_APPCOMPAT
    if (($DND_SETUPReport_APPCOMPAT -eq '0') -or ($DND_SETUPReport_APPCOMPAT -eq '1')) {$_APPCOMPAT = $DND_SETUPReport_APPCOMPAT}

    # Get Detail Power info
    $_POWERCFG=0
    #$global:DND_SETUPReport_POWERCFG
    if (($DND_SETUPReport_POWERCFG -eq '0') -or ($DND_SETUPReport_POWERCFG -eq '1')) {$_POWERCFG = $DND_SETUPReport_POWERCFG}

    # Get mimimum info
    $_Min=0
    #$global:DND_SETUPReport_Min
    if (($DND_SETUPReport_Min -eq '0') -or ($DND_SETUPReport_Min -eq '1')) {$_Min = $DND_SETUPReport_Min}

    # Get max info
    $_Max=0  #changed this to get max info
    #$global:DND_SETUPReport_Max
    if (($DND_SETUPReport_Max -eq '0') -or ($DND_SETUPReport_Max -eq '1')) {$_Max = $DND_SETUPReport_Max}

    # Surface Device
    $_SURFACE=0
    #$global:DND_SETUPReport_Surface
    if (($DND_SETUPReport_Surface -eq '0') -or ($DND_SETUPReport_Surface -eq '1')) {$_SURFACE = $DND_SETUPReport_Surface}

    $_Summary=1 # enabled by default ot collect system summary
    #$global:DND_SETUPReport_Summary
    if (($DND_SETUPReport_Summary -eq '0') -or ($DND_SETUPReport_Summary -eq '1')) {$_Summary = $DND_SETUPReport_Summary}

    # detailed network info
    $_NETDETAIL=0
    #$global:DND_SETUPReport_NETDETAIL
    if (($DND_SETUPReport_NETDETAIL -eq '0') -or ($DND_SETUPReport_NETDETAIL -eq '1')) {$_NETDETAIL = $DND_SETUPReport_NETDETAIL}

    # collect RFLcheck prereqs (ChkSym.ps1 still missing)
    $_RFLCHECK=1
    #$global:DND_SETUPReport_RFLCHECK
    if (($DND_SETUPReport_RFLCHECK -eq '0') -or ($DND_SETUPReport_RFLCHECK -eq '1')) {$_RFLCHECK = $DND_SETUPReport_RFLCHECK}

    # detailed Windows Update info
    $_WU=1
    #$global:DND_SETUPReport_WU
    if (($DND_SETUPReport_WU -eq '0') -or ($DND_SETUPReport_WU -eq '1')) {$_WU = $DND_SETUPReport_WU}

    # detailed CBS and PNP info
    $_CBSPNP=1
    #$global:DND_SETUPReport_CBSPNP
    if (($DND_SETUPReport_CBSPNP -eq '0') -or ($DND_SETUPReport_CBSPNP -eq '1')) {$_CBSPNP = $DND_SETUPReport_CBSPNP}

    # collect and export event logs
    $_EVTX=1
    #$global:DND_SETUPReport_EVTX
    if (($DND_SETUPReport_EVTX -eq '0') -or ($DND_SETUPReport_EVTX -eq '1')) {$_EVTX = $DND_SETUPReport_EVTX}

    # collect permissions and policies
    $_PERMPOL=1
    #$global:DND_SETUPReport_PERMPOL
    if (($DND_SETUPReport_PERMPOL -eq '0') -or ($DND_SETUPReport_PERMPOL -eq '1')) {$_PERMPOL = $DND_SETUPReport_PERMPOL}

    # get activation state
    $_ACTIVATION=1
    #$global:DND_SETUPReport_ACTIVATION
    if (($DND_SETUPReport_ACTIVATION -eq '0') -or ($DND_SETUPReport_ACTIVATION -eq '1')) {$_ACTIVATION = $DND_SETUPReport_ACTIVATION}

    # get Bitlocker info
    $_BITLOCKER=1
    #$global:DND_SETUPReport_BITLOCKER
    if (($DND_SETUPReport_BITLOCKER -eq '0') -or ($DND_SETUPReport_BITLOCKER -eq '1')) {$_BITLOCKER = $DND_SETUPReport_BITLOCKER}

    # get directory info
    $_DIR=1
    #$global:DND_SETUPReport_DIR
    if (($DND_SETUPReport_DIR -eq '0') -or ($DND_SETUPReport_DIR -eq '1')) {$_DIR = $DND_SETUPReport_DIR}

    # get slow processing servicing info
    $_SLOW=1
    #$global:DND_SETUPReport_SLOW
    if (($DND_SETUPReport_SLOW -eq '0') -or ($DND_SETUPReport_SLOW -eq '1')) {$_SLOW = $DND_SETUPReport_SLOW}

    # get slow processing servicing info
    $_PERF=1
    #$global:DND_SETUPReport_PERF
    if (($DND_SETUPReport_PERF -eq '0') -or ($DND_SETUPReport_PERF -eq '1')) {$_PERF = $DND_SETUPReport_PERF}

    # get slow processing servicing info
    $_DO=1
    #$global:DND_SETUPReport_DO
    if (($DND_SETUPReport_DO -eq '0') -or ($DND_SETUPReport_DO -eq '1')) {$_DO = $DND_SETUPReport_DO}

    # get slow processing servicing info
    $_TWS=1
    #$global:DND_SETUPReport_TWS
    if (($DND_SETUPReport_TWS -eq '0') -or ($DND_SETUPReport_TWS -eq '1')) {$_TWS = $DND_SETUPReport_TWS}

    # get slow processing servicing info
    $_PROCESS=1
    #$global:DND_SETUPReport_PROCESS
    if (($DND_SETUPReport_PROCESS -eq '0') -or ($DND_SETUPReport_PROCESS -eq '1')) {$_PROCESS = $DND_SETUPReport_PROCESS}

    # get slow processing servicing info
    $_STORAGE=1
    #$global:DND_SETUPReport_STORAGE
    if (($DND_SETUPReport_STORAGE -eq '0') -or ($DND_SETUPReport_STORAGE -eq '1')) {$_STORAGE = $DND_SETUPReport_STORAGE}

    # get slow processing servicing info
    $_MISC=1
    #$global:DND_SETUPReport_MISC
    if (($DND_SETUPReport_MISC -eq '0') -or ($DND_SETUPReport_MISC -eq '1')) {$_MISC = $DND_SETUPReport_MISC}

    # basic network info
    $_NETBASIC=1
    #$global:DND_SETUPReport_NETBASIC
    if (($DND_SETUPReport_NETBASIC -eq '0') -or ($DND_SETUPReport_NETBASIC -eq '1')) {$_NETBASIC = $DND_SETUPReport_NETBASIC}

    # get slow processing servicing info
    $_DEFENDER=1
    #$global:DND_SETUPReport_DEFENDER
    if (($DND_SETUPReport_DEFENDER -eq '0') -or ($DND_SETUPReport_DEFENDER -eq '1')) {$_DEFENDER = $DND_SETUPReport_DEFENDER}

    # get general file version info
    $_FILEVERSION=1
    #$global:DND_SETUPReport_FILEVERSION
    if (($DND_SETUPReport_FILEVERSION -eq '0') -or ($DND_SETUPReport_FILEVERSION -eq '1')) {$_FILEVERSION = $DND_SETUPReport_FILEVERSION}

    # get general file version info
    $_APPLOCKER=1
    #$global:DND_SETUPReport_APPLOCKER
    if (($DND_SETUPReport_APPLOCKER -eq '0') -or ($DND_SETUPReport_APPLOCKER -eq '1')) {$_APPLOCKER = $DND_SETUPReport_APPLOCKER}

    # get activation ONLY state
    $_ACTONLY=0
    #$global:DND_SETUPReport_ACTONLY
    if (($DND_SETUPReport_ACTONLY -eq '0') -or ($DND_SETUPReport_ACTONLY -eq '1')) {$_ACTONLY = $DND_SETUPReport_ACTONLY}
    if ($_ACTONLY -eq 1 )
    {
        $_ACTIVATION=1
        $_APPCOMPAT=0
        $_APPLOCKER=0
        $_BITLOCKER=0
        $_CBSPNP=0
        $_DATASTORE=0
        $_DEFENDER=0
        $_DIR=0
        $_DO=0
        $_DXDIAG=0
        $_EVTX=1
        $_flush_logs=0
        $_FILEVERSION=0
        $_GETWINSXS=0
        $_Max=0
        $_Min=0
        $_MISC=0
        $_NETBASIC=0
        $_NETDETAIL=0
        $_PERF=0
        $_PERMPOL=0
        $_POWERCFG=0
        $_PROCESS=0
        $_RFLCHECK=0
        $_SLOW=0
        $_STORAGE=0
        $_Summary=1
        $_SURFACE=0
        $_TWS=0
        $_UPGRADE=0
        $_WU=0
    }

    # Get MBAM info
    $_MBAM_SYSTEM=0

    $DND_SETUPReport_Start = (Get-Date)
    LogInfo ("[DND_SETUPReport] Starting...")

    # ----- Setup initial stuff
    # OS Version checks
    $_major = [environment]::OSVersion.Version.Major
    $_minor = [environment]::OSVersion.Version.Minor
    $_build = [environment]::OSVersion.Version.Build

    LogInfo ("[OS] Version: $_major.$_minor.$_build")

    $_WIN8_OR_LATER = 0
    $_WINBLUE_OR_LATER = 0
    $_WIN10 = 0
    $_WIN10_1607 = 0

    if ([int]$_major -eq 10)  { $_Win10 = 1}
    if (([int]$_major -eq 10) -and ([int]$_build -eq 14393)) { $_WIN10_1607 = 1}
    if ([int]$_major -ge 7)
    {
        $_WIN8_OR_LATER = 1
        $_WINBLUE_OR_LATER = 1
    }
    elseif ([int]$_major -eq 6)
    {
        if([int]$_minor -ge 2) { $_WIN8_OR_LATER = 1}
        if([int]$_minor -ge 3) { $_WINBLUE_OR_LATER = 1}
    }

    $_PS4ormore=0
    #$_PS5=0
    # - Get Powershell version in a file
    if(($PSVersionTable.PSVersion).Major -ge 4) {$_PS4ormore=1}
    #if(($PSVersionTable.PSVersion).Major -eq 5) {$_PS5=1}

    # =================================================================================================================================================
    # Section For things that need to be started early
    # - Write script version info to MiscInfo
    Write-Output "TssVerDateDND: $global:TssVerDateDND" | Out-File -FilePath ($_prefix+"MiscInfo.txt")
    # - Now lets setup Error output file header
    Write-Output $_line | Out-File -FilePath ($_prefix+"MiscInfo.txt") -Append
    #Write-Output "Beginning error recording" | Out-File -FilePath ($_prefix+"MiscInfo.txt") -Append
    #Write-Output $_line | Out-File -FilePath ($_prefix+"MiscInfo.txt") -Append
    $date = Get-Date
    Write-Output ("Starting at----------------------------------------------  $date") | Out-File -FilePath ($_prefix+"MiscInfo.txt") -Append
    # =================================================================================================================================================
    # New logic flow with functions

    # Determine if Surface by seeing if manufacturer is Microsoft
    $_manufacturer = (Get-CimInstance -Class:Win32_ComputerSystem).Manufacturer
    $_isVirtual = (Get-CimInstance -Class:Win32_ComputerSystem).Model.Contains("Virtual")
    if ((($_manufacturer -eq "microsoft") -or ($_manufacturer -eq "microsoft corporation")) -and ($_isVirtual -ne $true)) {$_SURFACE = 1}
    if (($_SURFACE -eq 1) -and ($_ACTONLY -ne 1)) { $_POWERCFG=1 }
    if ($_SURFACE -eq 1)
    {
        # call function SurfaceInfo
        Get-DNDSurfaceInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    if (($_DXDIAG -eq 1)) {
        # call function dxdiag
        Get-DNDDxDiag $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # - App Compat check
    if (($_APPCOMPAT -eq 1) -or ($_Max -eq 1))
    #------------------AppcompatFunc--------------------------
    {
        # call function appcompat info
        Get-DNDAppCompatInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }
# #we-test#
    # call function Windows Update
    if ($_WU -eq 1)
    {
        Get-DNDWindowsUpdateInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # Get Datastore if set
    if ($_DATASTORE -eq 1)
    {
        Get-DNDDatastore $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # call function general file info
    if (($_PS4ormore -eq 1) -and ($_FILEVERSION -eq 1))
    {
        Get-DNDGeneralFileVersionInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    if ($_GETWINSXS -eq 1) {$_WINSXSVER=1}
    if ($_PS4ormore -ne 1) {$_WINSXSVER=0}
    if ($_WINSXSVER -eq 1)
    {
        # call function WinSxS version info
        Get-DNDWinSxSVersionInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }
#> #we-test
    # call function CBS and PNP
    if ($_CBSPNP -eq 1)
    {
        Get-DNDCbsPnpInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }
# #we-test#
    if($_WIN8_OR_LATER -eq 1)
    {
        If ((Test-Path "$Env:SystemRoot\system32\appxdeploymentserver.dll") -and ($_TWS -eq 1))
        {
            # call function store info
            Get-DNDStoreInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }

        # call function delivery optimization logs
        if ($_DO -eq 1)
        {
            Get-DNDDoLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }
    }

    if (($_UPGRADE -eq 1) -or ($_Max -eq 1))
    {
        # Windows Setup/Upgrade logs
        if($_UPGRADE -eq 1)
        {
            # call function upgrade logs
            Get-DNDSetupLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        } # End Windows Setup/Upgrade logs

        # call function PBR logs
        Get-DNDPbrLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs

        # call function deployment logs
        Get-DNDDeploymentLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs

        # -------------------------------Removed as we should never need---------------------------
        # Write-Output -------------------------------------------
        # Write-Output Copying token cache and license store ...
        # Write-Output -------------------------------------------
        # cmd /r Copy $Env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\WSLicense\tokens.dat $_tempdir /y
        # cmd /r Copy $Env:windir\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833\117CAB2D-82B1-4B5A-A08C-4D62DBEE7782.cache $_tempdir /y
        # ------------------------------Removed--------------------------
        #################### END OF FUNCTION SETUPFunc ####################
    }

    # call function event logs
    if ($_EVTX -eq 1)
    {
        Get-DNDEventLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # call function PermissionsAndPolicies
    if ($_PERMPOL -eq 1)
    {
        Get-DNDPermissionsAndPolicies $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # call function BitlockerInfo
    if ($_BITLOCKER -eq 1)
    {
        Get-DNDBitlockerInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # call function ReliabilitySummary
    if (($_Summary -eq 1)  -or ($_Max -eq 1)) {
        Get-DNDReliabilitySummary $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # call function ActivationState
    if ($_ACTIVATION -eq 1)
    {
        Get-DNDActivationState $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # call function DirInfo
    if ($_DIR -eq 1)
    {
        Get-DNDDirInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    if (($_POWERCFG -eq 1) -or ($_Max -eq 1))
    {
        #call function EnergyInfo
        Get-DNDEnergyInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    if ($_Min -ne 1)
    {
        # call function StorageInfo
        if ($_STORAGE -eq 1)
        {
            Get-DNDStorageInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }

        # call function ProcessInfo
        if ($_PROCESS -eq 1)
        {
            Get-DNDProcessInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }
#> #we-test#
        # call function MiscInfo
        if ($_MISC -eq 1)
        {
            Get-DNDMiscInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }
# #we-test#
        # call function NetworkSetup
        if ($_NETBASIC -eq 1)
        {
            Get-DNDNetworkBasic $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }

        if ($_NETDETAIL -eq 1)
        {
            # call function NetworkSetup
            Get-DNDNetworkSetup $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }
    }

    if ($_WIN10 -eq 1)
    {
        # call function defender info
        if ($_DEFENDER -eq 1)
        {
            Get-DNDDefenderInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }
    }

    if (Test-Path $Env:windir\Minidump) {
        # call funciton minidumps
        Get-DNDMiniDumps $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # call function SlowProcessing
    if ($_SLOW -eq 1)
    {
        Get-DNDSlowProcessing $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    LogInfo ("[DND_SETUPReport] Finalizing.")

    # LEAVE THIS HERE AT END OF FILE AND RUN EVEN ON MIN OUTPUT
    # call function 15 sec perfmon
    if ($_PERF -eq 1)
    {
        Get-DNDGeneralPerfmon $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    if ($_RFLCHECK -eq 1)
    {
        # call function RFLcheck prereqs
        Get-DNDRFLCheckPrereqs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    }

    # Windows 10 1607 or higher
    if ([int]$_build -ge 14393) {
        # call function applocker function
        if ($_APPLOCKER -eq 1)
        {
            # call function applocker prereqs
            Get-DNDAppLocker $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
        }
    }

#> #we-test#
    # ---------------------------------------------------------------------------------------------
    # Section Wait for slow things to finish
    if (-not(Test-Path -path ($_prefix+'gpresult.htm'))){
		if ($global:GPresultHTM) {
        Write-Output 'Waiting  30 seconds for background processing(GPresult) to complete'
        # Only wait 30 seconds. If still not complete ignore.
        #Timeout /T 30 /nobreak
		FwWaitForProcess $global:GPresultHTM 30
		}
    }

    $DND_SETUPReport_End = (Get-Date)
    $DND_SETUPReport_Runtime = (new-TimeSpan -Start $DND_SETUPReport_Start -End $DND_SETUPReport_End)
    $DND_SETUPReport_hours = $DND_SETUPReport_Runtime.Hours
    $DND_SETUPReport_minutes = $DND_SETUPReport_Runtime.Minutes
    $DND_SETUPReport_seconds = $DND_SETUPReport_Runtime.Seconds
    LogInfo "[DND_SETUPReport] Overall duration: $DND_SETUPReport_hours hours, $DND_SETUPReport_minutes minutes and $DND_SETUPReport_seconds seconds" "Gray"
    <#
    Write-Output "`n`n   Files saved in $_tempdir"
    Write-Output '** Please zip up the folder and upload to workspace'
    Write-Output "Please manually delete the report directory $_tempdir"
    # in case user run the script from explorer, keep the console open
    #pause
    Write-Output "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    #>
    EndFunc $MyInvocation.MyCommand.Name
}
###END DND_SETUPReport

#################### FUNCTION DXDIAGFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDDxDiag
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    $LogPrefixDXDiag = "DXDiag"
    $CommandsDXDiag = @(
        "dxdiag /t `"$($_prefix)DxDiag.txt`""
    )
    RunCommands $LogPrefixDXDiag $CommandsDXDiag -ThrowException:$False -ShowMessage:$True
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION DXDIAGFunc ####################

#################### FUNCTION APPCOMPATINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDAppCompatInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    # Section for App Compat Info  Only run if flag set
    # Exporting App Compat Info related registry keys
    $LogPrefixAppCompatInfo = "AppCompatInfo"
    FwCreateFolder $_tempdir\Appcompat
    LogInfo ("[$LogPrefixAppCompatInfo] Exporting registries.")
    $RegKeysAppCompatInfo = @(
        ('HKCU:SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$_tempdir\Appcompat\reg_CurrentUser-AppCompatFlags.txt"),
        ('HKCU:SOFTWARE', "$_tempdir\Appcompat\reg_CurrentUser-Software.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$_tempdir\Appcompat\reg_LocalMachine-AppCompatFlags.txt"),
        ('HKLM:SOFTWARE\ODBC', "$_tempdir\Appcompat\reg_ODBC-Drivers.txt"),
        ('HKLM:SOFTWARE\WOW6432Node\ODBC', "$_tempdir\Appcompat\reg_ODBC-WOW6432Node-Drivers.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Installer', "$_tempdir\Appcompat\reg_WindowsInstaller.txt")
    )
    FwExportRegistry $LogPrefixAppCompatInfo $RegKeysAppCompatInfo -RealExport $true

    $CommandsAppCompatInfo = @(
        "REG SAVE HKLM\SOFTWARE $_tempdir\Appcompat\reg_LocalMachine-Software.hiv /Y"
        "cmd /r Dir /a /s /r `"C:\Program Files (x86)`"| Out-File -Append $_tempdir\Appcompat\dir_ProgramFiles_x86.txt"
        "cmd /r Dir /a /s /r `"C:\Program Files`"| Out-File -Append $_tempdir\Appcompat\dir_ProgramFiles.txt"
        "cmd /r Dir /a /s /r `"C:\Program Files (Arm)`"| Out-File -Append $_tempdir\Appcompat\dir_ProgramFiles_Arm.txt"
        "cmd /r Dir /a /s /r $Env:WinDir\fonts  | Out-File -Append $_tempdir\Appcompat\dir_Fonts.txt"
        "xcopy.exe `"$Env:windir\System32\Winevt\Logs\*compatibility*.evtx`" `"$_tempdir\Appcompat`" /Y /H"
        "xcopy.exe `"$Env:windir\System32\Winevt\Logs\*inventory*.evtx`" `"$_tempdir\Appcompat`" /Y /H"
        "xcopy.exe `"$Env:windir\System32\Winevt\Logs\*program-telemetry*.evtx`" `"$_tempdir\Appcompat`" /Y /H"
        "xcopy.exe `"$Env:windir\AppPatch\CompatAdmin.log`" `"$_tempdir\Appcompat\Apppatch-CompatAdmin.log`" /Y /H"
        "xcopy.exe `"$Env:windir\AppPatch64\CompatAdmin.log`" `"$_tempdir\Appcompat\Apppatch64-CompatAdmin.log`" /Y /H"
    )
    RunCommands $LogPrefixAppCompatInfo $CommandsAppCompatInfo -ThrowException:$False -ShowMessage:$True

    # - Powershell for font info
    [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-File -FilePath "$_tempdir\Appcompat\FontInfo1.txt"
    (New-Object System.Drawing.Text.InstalledFontCollection).Families  | Out-File -Append -FilePath "$_tempdir\Appcompat\FontInfo1.txt"
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts' | Out-File -FilePath "$_tempdir\Appcompat\FontInfo2.txt"
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION APPCOMPATINFOFunc ####################

#################### FUNCTION WINDOWSUPDATEFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDWindowsUpdateInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    # SECTION - Windows Update
	$_OLDLOCALAPPDATA="$Env:windir.old" + "$Env:localappdata".Substring(2)
    # Put everything except ETL's in the main folder
    $LogPrefixWU = "WU"
    LogInfo ("[$LogPrefixWU] Getting Windows Update info")
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\windowsupdate.log", "$($_prefix)WindowsUpdate.log"),
		@("$Env:windir\SoftwareDistribution\ReportingEvents.log", "$($_prefix)WindowsUpdate_ReportingEvents.log"),
		@("$Env:localappdata\microsoft\windows\windowsupdate.log", "$($_prefix)WindowsUpdatePerUser.log"),
		@("$Env:windir\windowsupdate (1).log", "$($_prefix)WindowsUpdate(1).log"),
		@("$Env:windir.old\Windows\windowsupdate.log", "$($_prefix)Old.WindowsUpdate.log"),
		@("$Env:windir.old\Windows\SoftwareDistribution\ReportingEvents.log", "$($_prefix)Old.ReportingEvents.log"),
		@("$_OLDLOCALAPPDATA\microsoft\windows\windowsupdate.log", "$($_prefix)Old.WindowsUpdatePerUser.log"),
		@("$Env:windir\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833\TokenRetrieval.log", "$($_prefix)WindowsUpdate_TokenRetrieval.log"),
        @("$Env:systemdrive\WindowsUpdateVerbose.etl", "$($_prefix)WindowsUpdateVerbose.etl")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False

    $CommandsWU = @(
        "cmd /r Dir $Env:windir\SoftwareDistribution /a /s /r | Out-File -Append $($_prefix)WindowsUpdate_dir_softwaredistribution.txt"
        "bitsadmin /list /allusers /verbose | Out-File -Append $($_prefix)bitsadmin.log"
        "SCHTASKS /query /v /TN \Microsoft\Windows\WindowsUpdate\ | Out-File -Append $($_prefix)WindowsUpdate_ScheduledTasks.log"
        "reg save HKLM\SOFTWARE\Microsoft\sih `"$($_prefix)reg_SIH.hiv`""
    )
    RunCommands $LogPrefixWU $CommandsWU -ThrowException:$False -ShowMessage:$True

    LogInfo ("[$LogPrefixWU] Export by querying registry keys.")
    # FwExportRegistry is using the /s (recursive) switch by default and appends to an existing file
    $RegKeysWU = @(
        ('HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', "$($_prefix)WindowsUpdate_reg_wupolicy.txt"),
        ('HKLM:SOFTWARE\Microsoft\PolicyManager\current\device\Update', "$($_prefix)WindowsUpdate_reg_wupolicy-mdm.txt"),
        ('HKLM:SOFTWARE\Microsoft\sih', "$($_prefix)reg_SIH.txt"),
        ('HKLM:Software\microsoft\windows\currentversion\oobe', "$($_prefix)reg_oobe.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate', "$($_prefix)WindowsUpdate_reg_wu.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Wosc\Client\Persistent\ClientState', "$($_prefix)WindowsUpdate_reg_Onesettings.txt"),
        ('HKLM:SOFTWARE\Microsoft\WindowsSelfHost\OneSettings', "$($_prefix)WindowsUpdate_reg_Onesettings.txt"),
        ('HKLM:SOFTWARE\Microsoft\WindowsUpdate', "$($_prefix)WindowsUpdate_reg_wuhandlers.txt")
    )
    FwExportRegistry $LogPrefixWU $RegKeysWU

    # UUP logs and action list xmls
    # robocopy $Env:windir\SoftwareDistribution\Download $_tempdir\UUP *.log *.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log

    # WU ETLs for Win10+
    $_WUETLPATH="$Env:windir\Logs\WindowsUpdate"
    if (Test-Path $_WUETLPATH)
    {
        if ($_WIN10_1607 -eq 1) {
            LogInfo ("[$LogPrefixWU] Public symbol server: Trying to connect.")
            # temporarily save $ProgressPreference
            $OriginalProgressPreference = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
            $pubsymsrvcon = Test-NetConnection -ComputerName $PublicSymSrv -CommonTCPPort HTTP -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            # reset $ProgressPreference
            $Global:ProgressPreference = $OriginalProgressPreference

            if (($false -eq ($pubsymsrvcon).TcpTestSucceeded))
            {
                LogInfo ("[$LogPrefixWU] Public symbol server: Connection failed.")
                Write-Output "Public symbol server: Wasn't able to connect to msdl.microsoft.com." | Out-File -FilePath ($_prefix+"WindowsUpdateETL_PublicSymbolsFailed.log") -Append
                Write-Output "Please convert ETL files from logs\WindowsUpdate instead." | Out-File -FilePath ($_prefix+"WindowsUpdateETL_PublicSymbolsFailed.log") -Append
                Write-Output "Use a internet connected Windows Server 2016 to convert logs with Get-WindowsUpdateLog." | Out-File -FilePath ($_prefix+"WindowsUpdateETL_PublicSymbolsFailed.log") -Append
                Write-Output $_line  | Out-File -FilePath ($_prefix+"WindowsUpdateETL_PublicSymbols.log") -Append
                $pubsymsrvcon | Out-File -FilePath ($_prefix+"WindowsUpdateETL_PublicSymbols.log") -Append
            }
        }

        if ($_FLUSH_LOGS -eq 1)
        {
            LogInfo ("[$LogPrefixWU] Flushing USO/WU logs.")
            $CommandsFlushLogs = @(
                "Stop-Service -Name usosvc"
                "Stop-Service -Name wuauserv"
            )
            RunCommands $LogPrefixWU $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True
        }

        # only run if public symbol server is reachable
        if ($true -eq ($pubsymsrvcon).TcpTestSucceeded)
        {
            LogInfo ("[$LogPrefixWU] Public symbol server: Connected.")
            LogInfo ("[$LogPrefixWU] Getting Windows Update log.")
            # Suppress script output by using a job
            $WULogsJobLog = "$($_prefix)WindowsUpdateETL_Converted.log"
            $WULogsJob = Start-Job -ScriptBlock {Get-WindowsUpdateLog -Log $args} -ArgumentList $WULogsJobLog
            $WULogsJob | Wait-Job | Remove-Job
            #  robocopy "$Env:systemdrive\ $_tempdir\$_WINDOWSUPDATE WindowsUpdateVerbose.etl" /W:1 /R:1 /NP /LOG+:$_robocopy_log
        }
        elseif ($_WIN10_1607 -eq 0)
        {
            LogInfo ("[$LogPrefixWU] Getting Windows Update log.")
            # Suppress script output by using a job
            $WULogsJobLog = "$($_prefix)WindowsUpdateETL_Converted.log"
            $WULogsJob = Start-Job -ScriptBlock {Get-WindowsUpdateLog -Log $args} -ArgumentList $WULogsJobLog
            $WULogsJob | Wait-Job | Remove-Job
        }
    }

    if ($_PS4ormore -eq 1)
    {
        # Begin Windows Update file versions-----------------------------------
        LogInfo ("[$LogPrefixWU] Getting Windows Update file versions.")
        $binaries = @("wuaext.dll", "wuapi.dll", "wuaueng.dll", "wucltux.dll", "wudriver.dll", "wups.dll", "wups2.dll", "wusettingsprovider.dll", "wushareduxresources.dll", "wuwebv.dll", "wuapp.exe", "wuauclt.exe", "storewuauth.dll", "wuuhext.dll", "wuuhmobile.dll", "wuau.dll", "wuautoappupdate.dll")
        foreach($file in $binaries)
        {
            if(test-path "$env:windir\system32\$file")
            {
            $version = (Get-Command "$env:windir\system32\$file").FileVersionInfo
            Write-Output "$file : $($version.FileMajorPart).$($version.FileMinorPart).$($version.FileBuildPart).$($version.FilePrivatePart)" | Out-File -FilePath ($_prefix+"WindowsUpdate_FileVersions.log") -Append
            }
        }

        $muis = @("wuapi.dll.mui", "wuaueng.dll.mui", "wucltux.dll.mui", "wusettingsprovider.dll.mui", "wushareduxresources.dll.mui")
        foreach($file in $muis)
        {
            if(test-path "$env:windir\system32\en-US\$file")
            {
            $version = (Get-Command "$env:windir\system32\en-US\$file").FileVersionInfo
            Write-Output "$file : $($version.FileMajorPart).$($version.FileMinorPart).$($version.FileBuildPart).$($version.FilePrivatePart)" | Out-File -FilePath ($_prefix+"WindowsUpdate_FileVersions.log") -Append
            }
        }
        # End Windows Update file versions--------------------------------
    }

    # -------------------------------------------------------------
    # MUSE logs for Win10+
    if($null -ne (Get-Service -Name usosvc -ErrorAction SilentlyContinue))
    {
        $LogPrefixUSO = "USO"
        if ($_FLUSH_LOGS -eq 1)
        {
            LogInfo ("[$LogPrefixUSO] Flushing USO logs.")
            $CommandsFlushLogs = @(
                "Stop-Service -Name usosvc"
            )
            RunCommands $LogPrefixUSO $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True
        }

        $_OLDPROGRAMDATA="$Env:windir.old\ProgramData"
        FwCreateFolder $_tempdir\MUSE
        if(Test-Path "$Env:windir.old") { FwCreateFolder $_tempdir\Windows.old }
        LogInfo ("[$LogPrefixUSO] Copying USO logs.")
        $CommandsUSO = @(
            "SCHTASKS /query /v /TN \Microsoft\Windows\UpdateOrchestrator\| Out-File -Append $_tempdir\MUSE\updatetaskschedules.txt"
		)
		if(Test-Path "$Env:programdata\UsoPrivate\UpdateStore") {$CommandsUSO += @("robocopy `"$Env:programdata\UsoPrivate\UpdateStore`" `"$_tempdir\MUSE`" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null")}
		if(Test-Path "$Env:programdata\USOShared\Logs") 			{$CommandsUSO += @("robocopy `"$Env:programdata\USOShared\Logs`" `"$_tempdir\MUSE`" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null")}
		if(Test-Path "$_OLDPROGRAMDATA\USOPrivate\UpdateStore") {$CommandsUSO += @("robocopy `"$_OLDPROGRAMDATA\USOPrivate\UpdateStore`" `"$_tempdir\Windows.old\MUSE`" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null")}
		if(Test-Path "$_OLDPROGRAMDATA\USOShared\Logs") 			{$CommandsUSO += @("robocopy `"$_OLDPROGRAMDATA\USOShared\Logs`" `"$_tempdir\Windows.old\MUSE`" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null")}
        RunCommands $LogPrefixUSO $CommandsUSO -ThrowException:$False -ShowMessage:$True
    }

    # Also copying ETLs pre-upgrade to see history
    $_WUOLDETLPATH= "$Env:windir.old\Windows\Logs\WindowsUpdate"
    IF (Test-Path -path $_WUOLDETLPATH)
    {
        $LogPrefixWUOld = "WUOld"
        LogInfo ("[$LogPrefixWUOld] Copying ETLs pre-upgrade.")
        $CommandsWUOld = @(
            "robocopy `"$_WUOLDETLPATH`" `"$_tempdir\Windows.old\WU`" *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null"
        )
        RunCommands $LogPrefixWUOld $CommandsWUOld -ThrowException:$False -ShowMessage:$True
    }

    LogInfo ("[$LogPrefixWU] Getting Installed Updates.")
    Get-CimInstance -ClassName win32_quickfixengineering | Out-File -FilePath "$($_prefix)Hotfix-WMIC.txt"
    # Get update id list with wmic, replaced
    # wmic qfe list full /format:texttable >> ($_prefix+"Hotfix-WMIC.txt") 2>> $_errorfile
    Write-Output $_line  | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt")
    Write-Output "This file contains the summary output of Windows Update history and full output of Windows Update history" | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
    Write-Output $_line | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
    Write-Output ("`n" + $_line) | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append

    # check if wuauserv is disabled to prevent exception during log collection
    if ((Get-Service wuauserv).StartType -ne [System.ServiceProcess.ServiceStartMode]::Disabled)
    {
        try
        {
            # Get Windows Update History info - Summary First
            LogInfo ("[$LogPrefixWU] Getting Update History - summary.")
            Write-Output "Windows Update history Summary" | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
            Write-Output "Operation 1=Installation 2=Uninstallation 3=Other" | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
            Write-Output $_line | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
            $Session = New-Object -ComObject "Microsoft.Update.Session"
            $Searcher = $Session.CreateUpdateSearcher()
            $historyCount = $Searcher.GetTotalHistoryCount()
            if($historyCount -gt 0) { $null = $Searcher.QueryHistory(0, $historyCount) | Select-Object Date, Operation, Title | Out-File ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append}

            # Get Windows Update History Info - All fields
            LogInfo ("[$LogPrefixWU] Getting Update History - all.")
            Write-Output ("`n" + $_line) | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
            Write-Output "Get all fields in Windows Update database" | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
            Write-Output $_line | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
            $Session = New-Object -ComObject "Microsoft.Update.Session"
            $Searcher = $Session.CreateUpdateSearcher()
            $historyCount = $Searcher.GetTotalHistoryCount()
            if($historyCount -gt 0) { $null = $Searcher.QueryHistory(0, $historyCount) | Select-Object * | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append }

            # Get Windows Update Configuration info
            LogInfo ("[$LogPrefixWU] Getting configuration info.")
            $MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
            $MUSM.Services | Select-Object Name, IsDefaultAUService, OffersWindowsUpdates | Out-File -FilePath ($_prefix+"WindowsUpdateConfiguration.txt") 2>> $_errorfile
            Write-Output $_line | Out-File -FilePath ($_prefix+"WindowsUpdateConfiguration.txt") -Append
            Write-Output "         Now get all data" | Out-File -FilePath ($_prefix+"WindowsUpdateConfiguration.txt") -Append
            Write-Output $_line | Out-File -FilePath ($_prefix+"WindowsUpdateConfiguration.txt") -Append
            $MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
            $MUSM.Services | Out-File -FilePath ($_prefix+"WindowsUpdateConfiguration.txt") -Append 2>> $_errorfile
        }
        catch { LogException "Getting Update History - summary failed." $_ }
    }
    else
    {
        LogInfo ("[$LogPrefixWU] Getting Update History - skipped (wuauserv disabled).")
        Write-Output "Windows Update history Summary" | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase.txt") -Append
        Write-Output "Skipped, because service wuauserv is disabled." | Out-File -FilePath ($_prefix+"Hotfix-WindowsUpdateDatabase_SKIPPED.txt") -Append

        LogInfo ("[$LogPrefixWU] Getting configuration info - skipped (wuauserv disabled).")
        Write-Output "Skipped, because service wuauserv is disabled." | Out-File -FilePath ($_prefix+"WindowsUpdateConfiguration_SKIPPED.txt") -Append
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION WINDOWSUPDATEFunc ####################

#################### FUNCTION DATASTOREFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDDatastore
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefixWU = "WU"
    FwCreateFolder $_tempdir\datastore
    LogInfo ("[$LogPrefixWU] Copying datastore.")
    $CommandsDatastore = @(
        "Stop-Service -Name wuauserv"
        "xcopy.exe `"$Env:windir\softwaredistribution\datastore\*.*`" `"$_tempdir\datastore`" /Y /H"
    )
    RunCommands $LogPrefixWU $CommandsDatastore -ThrowException:$False -ShowMessage:$True
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION DATASTOREFunc ####################

#################### FUNCTION FILEVERSIONINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDGeneralFileVersionInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
	FwGetMsInfo32 -Subfolder "Setup_Report$LogSuffix"
	FwGetWhoAmI -Subfolder "Setup_Report$LogSuffix"
	FwGetSysInfo -Subfolder "Setup_Report$LogSuffix"

	$global:GPresultHTM = Start-Process -FilePath 'gpresult' -ArgumentList "/H $($_prefix)GPResult.htm" -PassThru

    # SECTION for general file version info
    LogInfo "[GeneralInfo] Getting general file version info. Please be patient... " "cyan"
	FwFileVersion -Filepath ("$env:windir\system32\wbem\wbemcore.dll") | Out-File -FilePath ($_prefix+"FilesVersion.csv") -Append
	FwExportFileVerToCsv "system32" "DLL","EXE","SYS" -Subfolder "Setup_Report$LogSuffix"
    # Now get syswow64 files if on 64bit Windows
    if(Test-Path "$Env:windir\syswow64\comctl32.dll"){
		FwExportFileVerToCsv "SysWOW64" "DLL","EXE","SYS" -Subfolder "Setup_Report$LogSuffix"
    }
	#FwWaitForProcess $global:msinfo32NFO 300
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION FILEVERSIONINFOFunc ####################


#################### FUNCTION WINSXSINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDWinSxSVersionInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
		LogInfo "[FwExportFileVerToCsv] Getting general fileversion info. Please be patient... " "cyan"
		FwExportFileVerToCsv "WinSxS" "DLL","EXE","SYS" -Subfolder "Setup_Report$LogSuffix"
		FwExportFileVerToCsv "Microsoft.NET" "DLL" -Subfolder "Setup_Report$LogSuffix"
		# Begin Reference Assemblies DLL File Versions-----------------------------------
		#FwExportFileVerToCsv "$Env:programfiles\Reference Assemblies" "DLL" -Subfolder "Setup_Report$LogSuffix"
        LogInfo ("[$LogPrefixWinSxS] Getting Reference Assemblies files version info.")
        Get-ChildItem -Path "$Env:programfiles\Reference Assemblies" -Filter *.dll -Recurse -ea 0 | foreach-object {
            [pscustomobject]@{
				Name = $_.FullName;
				Version = $_.VersionInfo.FileVersion;
				DateModified = $_.LastWriteTime;
				Length = $_.length;
				CompanyName = $_.VersionInfo.CompanyName;
				FileDescription = $_.VersionInfo.FileDescription;
            }
        } | export-csv -notypeinformation -path ($_prefix+"File_Versions_Reference_Assemblies.csv") 2>> $_errorfile
        # End Reference Assemblies DLL File Versions--------------------------------
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION WINSXSINFOFunc ####################

#################### FUNCTION CBSPNPINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDCbsPnpInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # SECTION CBS & PNP info, components hive, SideBySide hive, Iemain.log
    $LogPrefixCBS = "CBS"
    LogInfo ("[$LogPrefixCBS] Getting CBS and servicing info.")

    Try {
		LogInfo "[$LogPrefixCBS] waiting max 50 sec to succeed on copy $Env:windir\system32\config\components" "Gray"
		$StopWait = $False
		$attempt = 0
		While (($StopWait -eq $False) -and ($attempt -lt 10)) {
			$attempt +=1
			$Result = (cmd /r copy "$Env:windir\system32\config\components" "$($_prefix)reg_Components.hiv" 2>&1)
			if ($Result -match '1 file') {$StopWait = $True; LogInfo "[$LogPrefixCBS] - Result: $Result (@attempt=$attempt)" "Green" } else {$StopWait = $False ; LogErrorFile "[$LogPrefixCBS] waiting +5 sec  - Result: $Result (@attempt=$attempt)"; Start-Sleep -Milliseconds 5000}
		}
		if ($Result -match '0 file') {LogInfo "[$LogPrefixCBS] - Result: $Result (@attempt=$attempt) - copy $Env:windir\system32\config\components FAILED after $attempt attempts" "Magenta"}
	} catch { LogException "[$LogPrefixCBS] copying $Env:windir\system32\config\components failed" $_ }

    # Copy logs
    $CommandsCBS = @(
        "robocopy `"$Env:windir\logs`" `"$_tempdir\logs`" /W:1 /R:1 /NP /E /XD PowerShell /LOG+:$_robocopy_log /S | Out-Null"
        "robocopy `"$Env:windir\System32\LogFiles\setupcln`" `"$_tempdir\System32-Logfiles\setupcln`" /W:1 /R:1 /NP /E /LOG+:$_robocopy_log /S | Out-Null"
        "robocopy `"$Env:windir\System32\LogFiles\wmi`" `"$_tempdir\System32-Logfiles\wmi`" /W:1 /R:1 /NP /E /LOG+:$_robocopy_log /S | Out-Null"
#        "xcopy `"$Env:windir\servicing\sessions\*.*`" `"$_tempdir\logs\cbs\Sessions`" /y /h"
        "dism /english /online /Get-TargetEditions | Out-File -Append $($_prefix)dism_EditionInfo.txt"
        "cmd /r Dir `"$Env:windir\WinSxS\temp`" /s /a /r | Out-File -Append $($_prefix)dir_WinSxSTEMP.txt"
        "cmd /r Dir `"$Env:windir\WinSxS`" /s /a /r | Out-File -Append $($_prefix)dir_WinSxS.txt"
        "cmd /r Dir `"$Env:windir\servicing\*.*`" /s /a /r | Out-File -Append $($_prefix)dir_servicing.txt"
        "cmd /r Dir `"$Env:windir\system32\dism\*.*`" /s /a /r | Out-File -Append $($_prefix)dir_dism.txt"
        "dism /english /online /Get-Packages /Format:Table | Out-File -Append $($_prefix)dism_GetPackages.txt"
        "dism /english /online /Get-Packages | Out-File -Append $($_prefix)dism_GetPackages.txt"
        "dism /english /online /Cleanup-Image /CheckHealth | Out-File -Append $($_prefix)dism_CheckHealth.txt"
        "dism /english /online /Get-Features /Format:Table | Out-File -Append $($_prefix)dism_GetFeatures.txt"
        "dism /english /online /Get-Intl | Out-File -Append $($_prefix)dism_GetInternationalSettings.txt"
        "dism /english /online /Get-Capabilities /Format:Table | Out-File -Append $($_prefix)dism_GetCapabilities.txt"
        "dism /english /online /Get-CurrentEdition | Out-File -Append $($_prefix)dism_EditionInfo.txt"
#        "cmd /r Copy `"$Env:windir\system32\config\components`" `"$($_prefix)reg_Components.hiv`""
        )
        RunCommands $LogPrefixCBS $CommandsCBS -ThrowException:$False -ShowMessage:$True

    FwCreateFolder $_tempdir\logs\CBS\sessions
    $SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\iemain.log", "$_tempdir"),
		@("$Env:windir\inf\*.log", "$_tempdir\logs\cbs"),
		@("$Env:windir\inf\*.log", "$_tempdir\logs\cbs"),
		@("$Env:windir\WinSxS\poqexec.log", "$_tempdir\logs\cbs"),
		@("$Env:windir\WinSxS\pending.xml", "$_tempdir\logs\cbs"),
		@("$Env:windir\servicing\sessions\*.xml", "$_tempdir\logs\cbs\sessions"),
		@("$Env:windir\Logs\MoSetup\UpdateAgent.log", "$_tempdir\logs\cbs"),
		@("$Env:windir\temp\lpksetup.log", "$_tempdir\logs\cbs\lpksetup.log")
		#@("$Env:windir\system32\config\components", "$($_prefix)reg_Components.hiv")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False

    # Powershell way Get-CimInstance Win32_OptionalFeature | Foreach {Write-host( "Name:{0}, InstallState:{1}" -f $_.Name,($_.InstallState -replace 1, "Installed" -replace 2, "Disabled" -replace 3, "Absent"))}

    LogInfo ("[$LogPrefixCBS] Getting packages info.")
# #we-test#
	dism /online /Get-Packages | ForEach-Object {
        if ( $_ -match 'Package Identity')
        {
            $DismPackage = $_.substring(19)
            dism /online /get-packageinfo /packagename:$DismPackage
        }
    } | Out-File -FilePath ($_prefix+"dism_GetPackages.txt") -Append 2>> $_errorfile
	LogDebug "[$LogPrefixCBS] done Getting packages info "

    # Dump out any servicing packages not in current state of 80 (superseded) or 112 (Installed)
    # Build header for output file
    LogInfo ("[$LogPrefixCBS] Getting CBS packages status.")
    Write-Output 'CBS servicing states, as seen on https://docs.microsoft.com/en-us/archive/blogs/tip_of_the_day/tip-of-the-day-cbs-servicing-states-chart-refresher' | Out-File -FilePath ($_prefix+"Servicing_PackageState.txt")
    Write-Output 'This will list any packages not in a state of 80 (superseded) or 112 (Installed)' | Out-File -FilePath ($_prefix+"Servicing_PackageState.txt") -Append
    Write-Output "If blank then none were found" | Out-File -FilePath ($_prefix+"Servicing_PackageState.txt") -Append
    Write-Output $_line | Out-File -FilePath ($_prefix+"Servicing_PackageState.txt") -Append
    # Build PS script
    $regPATH = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
    $brokenUpdates = Get-ChildItem -PATH $regPATH -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Rollup|ServicingStack" } #matches any Cumulative Update or Monthly Rollup
    $brokenUpdates | Get-ItemProperty | Where-Object { $_.CurrentState -ne "80" -and $_.CurrentState -ne "112"} | Select-Object @{N='Cumulative/rollup package(s) in broken state'; E={$_.PSChildName};} | Format-Table -Wrap -AutoSize | Out-File -FilePath ($_prefix+"Servicing_PackageState.txt") -Append
    $brokenUpdates = Get-ChildItem -PATH $regPATH -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Package_for_KB[0-9]{7}~31bf3856ad364e35' } #matches any standalone KBs
    $brokenUpdates | Get-ItemProperty | Where-Object { $_.CurrentState -ne "80" -and $_.CurrentState -ne "112"} | Select-Object @{N='Standalone package(s) in broken state'; E={$_.PSChildName};} | Format-Table -Wrap -AutoSize | Out-File -FilePath ($_prefix+"Servicing_PackageState.txt") -Append

    # ----------------------------------------------------------------------
    # Now do a converted poqexec if it exist
    if (Test-Path "$_tempdir\logs\cbs\poqexec.log")
    {
        LogInfo ("[$LogPrefixCBS] Collecting poqexec info.")
        $OutputFile = "$_tempdir\logs\CBS\poqexec_Converted.log"
        Set-Content -Path $OutputFile -Value "poqexec.log with FileTime converted to Date and Time"
        Add-Content -Path $OutputFile -Value ""
        Add-Content -Path $OutputFile -Value "Date       Time     Entry"
        $poqexeclog = "$_tempdir\logs\CBS\poqexec.log"
        $ProcessingData = Get-Content $poqexeclog
        $ProcessingData | ForEach-Object {
            $ProcessingLine = $_
            [Int64]$DateString = '0x'+$ProcessingLine.substring(0,15)
            $ConvertedDate = [DateTime]::FromFileTime($DateString)
            Add-Content -Path $OutputFile -Value $ConvertedDate`t$ProcessingLine
        }
    }

    if (Test-Path "$env:windir\servicing\Sessions\Sessions.xml")
    {
        try {
            LogInfo ("[$LogPrefixCBS] Scanning for problematic sessions.")
            [xml]$data = Get-Content "$env:windir\servicing\Sessions\Sessions.xml"
            $sessionobj = @()
            foreach ($session in $data.sessions.session) {
                if (($session.status -ne '0x0') -and ($session.status -ne '0x800f0816') -and ($session.status -ne '0x800f0841')) {
                    $sessionobj += [PsCustomObject]@{
                        Date = $session.started
                        Id = $session.tasks.phase.package.id
                        KB = $session.tasks.phase.package.name
                        Targetstate = $session.tasks.phase.package.targetState
                        Status = $session.status
                        Client = $session.client
                    }
                }
            }
            if (0 -ne $sessionobj.Count) { $sessionobj | Sort-Object Date | Format-Table -Property * -AutoSize | Out-File "C:\MS_DATA\CBS_sessions_xml_sum.txt" }
            elseif (0 -eq $sessionobj.Count) { Write-Output "No problem sessions found." | Out-File "C:\MS_DATA\CBS_sessions_xml_sum.txt" }
        }
        # catch "The input document has exceeded a limit set by MaxCharactersInDocument.")
        catch { LogException "[$LogPrefixCBS] sessions.xml" $_ }
    }

    if ($_Win10 -eq 1)
    {
        $LogPrefixPnpState = "PNP"
        LogInfo ("[$LogPrefixPnpState] Getting PNP info.")
        $CommandsPNP = @(
            "pnputil.exe /export-pnpstate `"$($_prefix)drivers_pnpstate.pnp`""
            "driverquery /si | Out-File -Append $($_prefix)Driver_signing.txt"
        )
        RunCommands $LogPrefixPnpState $CommandsPNP -ThrowException:$False -ShowMessage:$True
    }
#> #we-test#
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION CBSPNPINFOFunc ####################

#################### FUNCTION STOREINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDStoreInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # Section Windows Store info
    # Only run if Appx Server exist
    If (Test-Path "$Env:SystemRoot\system32\appxdeploymentserver.dll")
    {
        $_WINSTORE='Winstore'
        $LogPrefixTWS = "TWS"
        FwCreateFolder $_tempdir\$_WINSTORE
        LogInfo ("[$LogPrefixTWS] Getting Windows Store/Appx data.")
        $RegKeysTWS = @(
            ('HKLM:SOFTWARE\Policies\Microsoft\WindowsStore', "$_tempdir\$_WINSTORE\reg_StorePolicy.txt"),
            ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Appx', "$_tempdir\$_WINSTORE\reg_appx.txt")
        )
        FwExportRegistry $LogPrefixTWS $RegKeysTWS -RealExport $true
        #"REG SAVE HKLM\SOFTWARE $_tempdir\Appcompat\reg_LocalMachine-Software.hiv /Y"
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("$Env:temp\winstore.log", "$_tempdir\$_WINSTORE\winstore-Broker.log"),
			@("$Env:userprofile\AppData\Local\Packages\WinStore_cw5n1h2txyewy\AC\Temp\winstore.log", "$_tempdir\$_WINSTORE")
		)
		FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
        try { Import-module appx;get-appxpackage -allusers | Out-File -FilePath "$_tempdir\$_WINSTORE\GetAppxPackage.log" }
        catch { LogException "Get-Appxpackage failed" $_ }
        if($_WINBLUE_OR_LATER -eq 1)
        {
            try { Get-Appxpackage -packagetype bundle | Out-File -FilePath "$_tempdir\$_WINSTORE\GetAppxPackageBundle.log" }
            catch { LogException "Get-Appxpackage failed" $_ }
            dism /english /online /Get-ProvisionedAppxPackages > "$_tempdir\$_WINSTORE\Dism_GetAppxProvisioned.log" 2>> $_errorfile
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION STOREINFOFunc ####################

#################### FUNCTION DOLOGSFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDDoLogs
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # Section Delivery Optimizaton logs and powershell for Win10+
    $LogPrefixDO = "DOSVC"
    if ($null -ne (Get-Service -Name dosvc -ErrorAction SilentlyContinue)) {
        if ($_FLUSH_LOGS -eq 1) {
            LogInfo ("[$LogPrefixDO] Flushing DO/USO/WU logs.")
            $CommandsFlushLogs = @(
                "Stop-Service -Name dosvc"
                "Stop-Service -Name usosvc"
                "Stop-Service -Name wuauserv"
            )
			RunCommands $LogPrefixDO $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True
        }
        FwCreateFolder $_tempdir\logs\DOSVC
        LogInfo ("[$LogPrefixDO] Getting DeliveryOptimization logs.")
        $CommandsDOSVC = @(
            "robocopy `"$Env:windir\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs`" `"$_tempdir\logs\dosvc`" *.log *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null"
            "robocopy `"$Env:windir\SoftwareDistribution\DeliveryOptimization\SavedLogs`" `"$_tempdir\logs\dosvc`" *.log *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null"
        )
        RunCommands $LogPrefixDO $CommandsDOSVC -ThrowException:$False -ShowMessage:$True

        LogInfo ("[$LogPrefixDO] Getting DeliveryOptimization registry.")
        $RegKeysDOSVC = @(
            ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization')
        )
        FwExportRegToOneFile $LogPrefixDO $RegKeysDOSVC "$_tempdir\logs\dosvc\registry_DeliveryOptimization.txt"

        LogInfo ("[$LogPrefixDO] Getting DeliveryOptimization perf data.")
		$outfile = "$_tempdir\logs\dosvc\DeliveryOptimization_info.txt"
		$Commands = @(
			"Get-DeliveryOptimizationPerfSnap	| Out-File -Append $outfile"
			"Get-DeliveryOptimizationStatus		| Out-File -Append $outfile"
		)
		RunCommands "MDT" $Commands -ThrowException:$False -ShowMessage:$True
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION DOLOGSFunc ####################


#################### FUNCTION SETUPLOGSFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDSetupLogs
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefixSetup = "Setup"
    $LogPrefixUpgrade = "IPU"
    $LogPrefixPBR = "PBR"
    FwCreateFolder $_tempdir\UpgradeSetup
    if (Test-Path "$Env:windir\Panther") {FwCreateFolder $_tempdir\UpgradeSetup\win_Panther }
    if (Test-Path "$Env:windir\system32\sysprep\panther") { FwCreateFolder $_tempdir\UpgradeSetup\sysprep_Panther }
    if (Test-Path "$Env:windir\setup\") { FwCreateFolder $_tempdir\UpgradeSetup\win_Setup }

    LogInfo ("[$LogPrefixSetup] Copying Windows Setup / Feature Update logs.")
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\logs\mosetup\bluebox.log", "$_tempdir\UpgradeSetup\"),
		@("$Env:windir.old\windows\logs\mosetup\bluebox.log", "$_tempdir\UpgradeSetup\bluebox_windowsold.log"),
		@("$Env:windir.old\windows\logs\mosetup\UpdateAgent.log", "$_tempdir\UpgradeSetup\UpdateAgent_windowsold.log"),
		@("$Env:windir\Panther\*", "$_tempdir\UpgradeSetup\win_Panther"),
		@("$Env:windir\system32\sysprep\panther\*", "$_tempdir\UpgradeSetup\sysprep_Panther"),
		@("$Env:windir\setup\*", "$_tempdir\UpgradeSetup\win_Setup"),
        @("$Env:windir\setupact.log", "$_tempdir\UpgradeSetup\setupact-windows.log"),
        @("$Env:windir\System32\LogFiles\setupcln\setupact.log", "$_tempdir\UpgradeSetup\setupact-setupcln.log")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False

	"$Env:systemdrive","D:" | ForEach-Object {
		if (Test-Path "$_\`$Windows.~BT")
		{
			LogInfo ("[$LogPrefixUpgrade] Found `"$_\`$Windows.~BT`".")
			FwCreateFolder $_tempdir\UpgradeSetup\~bt_Panther
			FwCreateFolder $_tempdir\UpgradeSetup\~bt_Rollback
			LogInfo ("[$LogPrefixUpgrade] Copying Feature Update logs.")
			<#
            $SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
			$SourceDestinationPaths = @(
				@("$_\`$Windows.~BT\Sources\Panther\*", "$_tempdir\UpgradeSetup\~bt_Panther"),
				@("$_\`$Windows.~BT\Sources\Rollback\*", "$_tempdir\UpgradeSetup\~bt_Rollback")
				#@("$Env:windir\system32\security\logs", "$_tempdir\security")
			)
			FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
			#>

			$CommandsUpgrade = @(
				#"xcopy /s /e /c `"$Env:systemdrive\`$Windows.~BT\Sources\Panther\*.*`" `"$_tempdir\UpgradeSetup\~bt_Panther`" /y"
				#"xcopy /s /e /c `"$Env:systemdrive\`$Windows.~BT\Sources\Rollback\*.*`" `"$_tempdir\UpgradeSetup\~bt_Rollback`" /y"
                "robocopy `'$Env:systemdrive\`$Windows.~BT\Sources\Panther`' `"$_tempdir\UpgradeSetup\~bt_Panther`" /S /COPY:DT /XF *.esd *.wim *.dll *.sdi *.mui *.png *.ttf /LOG+:$_robocopy_log /S | Out-Null"
                "robocopy `'$Env:systemdrive\`$Windows.~BT\Sources\Rollback`' `"$_tempdir\UpgradeSetup\~bt_Rollback`" /S /COPY:DT /XF *.esd *.wim *.dll *.sdi *.mui *.png *.ttf /LOG+:$_robocopy_log /S | Out-Null"
				"cmd /r Dir /a /s /r '$_\`$Windows.~BT`' | Out-File -Append $_tempdir\UpgradeSetup\Dir_WindowsBT.txt"
				"robocopy.exe `"$Env:windir\system32\security\logs`" `"$_tempdir\security`" /W:1 /R:1 /NP /E /LOG+:$_robocopy_log /S | Out-Null"
			)
			RunCommands $LogPrefixUpgrade $CommandsUpgrade -ThrowException:$False -ShowMessage:$True
		}
	}

    if (Test-Path "$Env:UserProfile\Local Settings\Application Data\Microsoft\WebSetup\Panther") {
        $LogPrefixWebSetup = "WebSetup"
        FwCreateFolder $_tempdir\UpgradeSetup\WebSetup-Panther
        LogInfo ("[$LogPrefixWebSetup] Copying WebSetup logs.")
        $CommandsWebSetup = @(
            "robocopy `"$Env:UserProfile\Local Settings\Application Data\Microsoft\WebSetup\Panther`" `"$_tempdir\UpgradeSetup\WebSetup-Panther`" *.* /MIR /XF *.png *.js *.tmp *.exe"
        )
        RunCommands $LogPrefixWebSetup $CommandsWebSetup -ThrowException:$False -ShowMessage:$True
    }

    if (Test-Path "$Env:UserProfile\Local Settings\Application Data\Microsoft\WebSetup\Panther") {
        FwCreateFolder $_tempdir\UpgradeSetup\PurchaseWindowsLicense
        LogInfo ("[PurchWinLic] Copying PurchaseWindowsLicense logs.")
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("$Env:LocalAppdata\microsoft\Microsoft\Windows\PurchaseWindowsLicense\PurchaseWindowsLicense.log", "$_tempdir\UpgradeSetup\PurchaseWindowsLicense")
		)
		FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
    }

    if (Test-Path "$Env:UserProfile\Local Settings\Application Data\Microsoft\WebSetup\Panther") {
        FwCreateFolder $_tempdir\UpgradeSetup\WindowsAnytimeUpgrade
        LogInfo ("[AnyUpgr] Copying Anytime Upgrade logs.")
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("$Env:LocalAppdata\microsoft\Microsoft\Windows\Windows Anytime Upgrade\upgrade.log", "$_tempdir\UpgradeSetup\WindowsAnytimeUpgrade")
		)
		FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION SETUPLOGSFunc ####################

##################### FUNCTION PBRLOGSFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDPBRLogs
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # - Get Sysrest logs for PBR issues
    if (Test-Path "C:\`$SysReset\Logs")
    {
        $LogPrefixSysReset = "SysReset"
        FwCreateFolder $_tempdir\UpgradeSetup\Sysreset
        LogInfo ("[$LogPrefixSysReset] Copying SysReset logs.")
        $CommandsSysReset = @(
            "xcopy /s /e /c `"c:\`$SysReset\Logs\*.*`" `"$_tempdir\UpgradeSetup\Sysreset`""
        )
        RunCommands $LogPrefixSysReset $CommandsSysReset -ThrowException:$False -ShowMessage:$True
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION PBRLOGSFunc ####################

#################### FUNCTION DEPLOYMENTLOGSFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDDeploymentLogs
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # MDT logs
    if (Test-Path "$Env:systemroot\temp\deploymentlogs")
    {
		FwCreateFolder $_tempdir\UpgradeSetup\deployment_logs
    }
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:systemroot\temp\deploymentlogs\*.*", "$_tempdir\UpgradeSetup\deployment_logs"),
		@("$Env:systemdrive\minint\*.*", "$_tempdir\UpgradeSetup\minint"),
		@("$Env:temp\smstslog\smsts.log", "$_tempdir\UpgradeSetup\curentusertemp-smsts.log"),
		@("$Env:systemdrive\users\administrator\appdata\local\temp\smstslog\smsts.log", "$_tempdir\UpgradeSetup\admintemp-smsts.log")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
    # Windows Recovery Environment (Windows RE) and system reset configuration
	$Commands = @(
		"ReAgentc.exe /info | Out-File -Append $($_prefix)ReAgentc.txt"
	)
    RunCommands "MDT" $Commands -ThrowException:$False -ShowMessage:$True
    # ========================================================================================================================
    # Section WDS
    If (Test-Path $Env:windir\system32\wdsutil.exe)
    {
    $LogPrefixWDS = "WDS"
    FwCreateFolder $_tempdir\WDS
    LogInfo ("[$LogPrefixWDS] Getting WDS info.")
    $CommandsWDS = @(
        "xcopy `"$Env:windir\System32\winevt\Logs\*deployment-services*.*`" `"$_tempdir\WDS`" /Y /H"
        "WDSUTIL /get-server /show:all /detailed | Out-File -Append $_tempdir\WDS\WDS-Get-Server.txt"
        "WDSUTIL /get-transportserver /show:config | Out-File -Append $_tempdir\WDS\WDS-Get-Transportserver.txt"
    )
    RunCommands $LogPrefixWDS $CommandsWDS -ThrowException:$False -ShowMessage:$True
    }

    # -----------------------------------------------------------------------------
    # Get some SCCM logs and other data if they exist
    if(Test-Path "$Env:windir\ccm\logs\ccmexec.log")
    {
    $LogPrefixSCCM = "SCCM"
    FwCreateFolder $_tempdir\SCCM
    LogInfo ("[$LogPrefixSCCM] Copying MININT logs.")
    $CommandsSCCM = @(
        "xcopy `"$Env:windir\ccm\logs\*.*`" `"$_tempdir\sccm`" /y /s /e /c"
        "Get-CimInstance -Namespace `"root\ccm\Policy\Machine\ActualConfig`" -Class CCM_SoftwareUpdatesClientConfig | Out-File -Append $_tempdir\sccm\SoftwareUpdatesClientConfig.txt"
    )
    RunCommands $LogPrefixSCCM $CommandsSCCM -ThrowException:$False -ShowMessage:$True
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION DEPLOYMENTLOGSFunc ####################

#################### FUNCTION PERMISSIONSANDPOLICIESFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDPermissionsAndPolicies
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # Section Policies and Permissions
    $LogPrefixPermPol = "PermPol"
    LogInfo ("[$LogPrefixPermPol] Permissions and Policies section.")
	$outfile = "$($_prefix)File_Icacls_Permissions.txt"
    $CommandsPermPol = @(
        "icacls C:\			| Out-File -Append $outfile"
        "icacls C:\windows	| Out-File -Append $outfile"
        "icacls C:\windows\serviceProfiles /t | Out-File -Append $outfile"
        "secedit /export /cfg `"$($_prefix)User_Rights.txt`""
        "xcopy /s /e /c /i `"$Env:windir\system32\CodeIntegrity\*.*`" `"$_tempdir\CodeIntegrity`" /y"
    )
    RunCommands $LogPrefixPermPol $CommandsPermPol -ThrowException:$False -ShowMessage:$True

    LogInfo ("[$LogPrefixPermPol] Querying registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    $RegKeysPermPol = @(
        ('HKCU:Software\Policies', "$($_prefix)reg_Policies.txt"),
        ('HKLM:Software\Policies', "$($_prefix)reg_Policies.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies', "$($_prefix)reg_Policies.txt"),
        ('HKLM:System\CurrentControlSet\Policies', "$($_prefix)reg_Policies.txt")
    )
    FwExportRegistry $LogPrefixPermPol $RegKeysPermPol

    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION PERMISSIONSANDPOLICIESFunc ####################

#################### FUNCTION STORAGEFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDStorageInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # Section Storage and Device info
    $LogPrefixStorage = "Storage"
    LogInfo ("[$LogPrefixStorage] Getting Storage and Device info.")
    $CommandsStorage = @(
        "Fltmc.exe Filters | Out-File -Append $($_prefix)Fltmc.txt"
        "Fltmc.exe Instances | Out-File -Append $($_prefix)Fltmc.txt"
        "Fltmc.exe Volumes | Out-File -Append $($_prefix)Fltmc.txt"
        "vssadmin.exe list volumes | Out-File -Append $($_prefix)VSSAdmin.txt"
        "vssadmin.exe list writers | Out-File -Append $($_prefix)VSSAdmin.txt"
        "vssadmin.exe list providers | Out-File -Append $($_prefix)VSSAdmin.txt"
        "vssadmin.exe list shadows | Out-File -Append $($_prefix)VSSAdmin.txt"
        "vssadmin.exe list shadowstorage | Out-File -Append $($_prefix)VSSAdmin.txt"
        "reg.exe save `"HKLM\System\MountedDevices`" `"$($_prefix)reg_MountedDevices.hiv`""
    )
     RunCommands $LogPrefixStorage $CommandsStorage -ThrowException:$False -ShowMessage:$True

    LogInfo ("[$LogPrefixStorage] Querying registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    $RegKeysStorage = @(
        ('HKCU:Software\Policies', "$($_prefix)reg_Policies.txt"),
        ('HKLM:System\MountedDevices', "$($_prefix)reg_MountedDevices.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Services\iScsiPrt', "$($_prefix)reg_iSCSI.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Enum', "$($_prefix)reg_Enum.txt")
    )
    FwExportRegistry $LogPrefixStorage $RegKeysStorage

    if ($_WIN8_OR_LATER -eq 1)
    {
        Write-Output "EFI system partition GUID: c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  | Out-File -FilePath ($_prefix+"Storage.txt") -append
        Write-Output "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/set-id"  | Out-File -FilePath ($_prefix+"Storage.txt") -append
        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage.txt") -append

        LogInfo ("[$LogPrefixStorage] Get capacity and free space.")
        $diskobj = @()
        Get-CIMInstance Win32_Volume -Filter "DriveType='3'" | ForEach-Object {
            $volobj = $_
            $parobj = Get-Partition | Where-Object { $_.AccessPaths -contains $volobj.DeviceID }
            if ( $parobj ) {
                $efi = $null
                if ($parObj.GptType -match '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}') { $efi = $true }
                $diskobj += [pscustomobject][ordered]@{
                    DiskID = $([string]$($parobj.DiskNumber) + "-" + [string]$($parobj.PartitionNumber)) -as [string]
                    Mountpoint = $volobj.Name
                    Letter = $volobj.DriveLetter
                    Label = $volobj.Label
                    FileSystem = $volobj.FileSystem
                    'Capacity(GB)' = ([Math]::Round(($volobj.Capacity / 1GB),2))
                    'FreeSpace(GB)' = ([Math]::Round(($volobj.FreeSpace / 1GB),2))
                    'Free(%)' = ([Math]::Round(((($volobj.FreeSpace / 1GB)/($volobj.Capacity / 1GB)) * 100),0))
                    Type = $parObj.Type
                    GptType = $parObj.GptType
                    EFI = $efi
                    'Boot' = $VolObj.BootVolume
                    Active = $parObj.IsActive
                }
            }
        }
        $diskobj | Sort-Object DiskID | Format-Table -Property * -AutoSize | Out-String -Width 4096 | Out-File -FilePath ($_prefix+"Storage.txt") -append

        LogInfo ("[$LogPrefixStorage] Get volume and partition info.")
        Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } | ForEach-Object {
            $volobj = $_
            $parobj = Get-Partition | Where-Object { $_.AccessPaths -contains $volobj.Path }
            if ( $parobj ) {
                if ($($volobj.FileSystemLabel) -ne '')
                {
                    Write-Output "------ volume $($volobj.FileSystemLabel), partition #$($parobj.PartitionNumber), disk #$($parobj.DiskNumber) -------"  | Out-File -FilePath ($_prefix+"Storage.txt") -append
                }
                else
                {
                    Write-Output "------ volume (no label), partition #$($parobj.PartitionNumber), disk #$($parobj.DiskNumber) -------"  | Out-File -FilePath ($_prefix+"Storage.txt") -append
                }
                $volobj | Select-Object -Property * | Out-File -FilePath ($_prefix+"Storage.txt") -append
                Write-Output "------ partition #$($parobj.PartitionNumber), disk #$($parobj.DiskNumber) -------"  | Out-File -FilePath ($_prefix+"Storage.txt") -append
                $parobj | Select-Object -Property * | Out-File -FilePath ($_prefix+"Storage.txt") -append
            }
        }

        LogInfo ("[$LogPrefixStorage] Get powershell storage cmdLets info.")
        Get-Disk | Out-File -FilePath ($_prefix+'Storage_get-disk.txt')
        Write-Output "------ Get disk objects -------"  | Out-File -FilePath ($_prefix+"Storage_get-disk.txt") -append
        Get-Disk | Select-Object * | Out-File -FilePath ($_prefix+'Storage_get-disk.txt') -append
        Get-PhysicalDisk | Out-File -FilePath ($_prefix+'Storage_get-physicaldisk.txt')
        Write-Output "------ Get physical disk objects -------"  | Out-File -FilePath ($_prefix+"Storage_get-physicaldisk.txt") -append
        Get-PhysicalDisk | Select-Object * | Out-File -FilePath ($_prefix+'Storage_get-physicaldisk.txt') -append
        Get-VirtualDisk | Out-File -FilePath ($_prefix+'Storage_get-virtualdisk.txt')
        Write-Output "------ Get virtual disk objects -------"  | Out-File -FilePath ($_prefix+"Storage_get-virtualdisk.txt") -append
        Get-VirtualDisk | Select-Object * | Out-File -FilePath ($_prefix+'Storage_get-virtualdisk.txt') -append
        Get-Partition | Out-File -FilePath ($_prefix+'Storage_get-partition.txt')
        Write-Output "------ Get partition objects -------"  | Out-File -FilePath ($_prefix+"Storage_get-partition.txt") -append
        Get-Partition | Select-Object * | Out-File -FilePath ($_prefix+'Storage_get-partition.txt') -append
        Get-Volume | Out-File -FilePath ($_prefix+'Storage_get-volume.txt')
        Write-Output "------ Get volume objects -------"  | Out-File -FilePath ($_prefix+"Storage_get-volume.txt") -append
        Get-Volume | Select-Object * | Out-File -FilePath ($_prefix+'Storage_get-volume.txt') -append

        LogInfo ("[$LogPrefixStorage] Get WMI storage info.")
        Get-CimInstance Win32_DiskDrive | Out-File -FilePath ($_prefix+'Storage_Win32_DiskDrive.txt')
        Get-CimInstance Win32_DiskPartition | Out-File -FilePath ($_prefix+'Storage_Win32_DiskPartition.txt')
        Get-CimInstance Win32_LogicalDiskToPartition | Out-File -FilePath ($_prefix+'Storage_Win32_LogicalDiskToPartition.txt')
        Get-CimInstance Win32_LogicalDisk  | Out-File -FilePath ($_prefix+'Storage_Win32_LogicalDisk.txt')
        Get-CimInstance Win32_Volume | Out-File -FilePath ($_prefix+'Storage_Win32_Volume.txt')

        LogInfo ("[$LogPrefixStorage] Get disk health.")
        # Begin Disk Info script-----------------------------------
        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage_Reliability.txt") -append
        Write-Output "------ Get disk health -------"  | Out-File -FilePath ($_prefix+"Storage_Reliability.txt") -append
        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage_Reliability.txt") -append

        LogInfo ("[$LogPrefixStorage] Get disk reliability.")
        $Pdisk= Get-PhysicalDisk
        ForEach ( $LDisk in $PDisk )
        {
            $LDisk.FriendlyName | Out-File -FilePath ($_prefix+"Storage_Reliability.txt") -append
            $LDisk.HealthStatus | Out-File -FilePath ($_prefix+"Storage_Reliability.txt") -append
            # performance: ~24 sec.
            # $LDisk | Get-StorageReliabilityCounter | Select-Object * | Format-List | Out-File -FilePath ($_prefix+"Storage_Reliability.txt") -append
            Write-Output "==================" | Out-File -FilePath ($_prefix+"Storage_Reliability.txt") -append
        }
        # End Disk Info--------------------------------

        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage.txt") -append
        Write-Output "------ Get physical disk info -------"  | Out-File -FilePath ($_prefix+"Storage.txt") -append
        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage.txt") -append
        Get-PhysicalDisk | Select-Object * | Out-File -FilePath ($_prefix+"Storage.txt") -append
    }
    else
    {

        LogInfo ("[$LogPrefixStorage] Build diskpart script.")
        # - Diskpart info
        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage_diskpart.txt") -append
        Write-Output "------ Get disk info using diskpart -------" | Out-File -FilePath ($_prefix+"Storage_diskpart.txt") -append
        Write-Output "------ Note that a failure finding a disk in the command file will end the query so there will be error at the end of the output -------" | Out-File -FilePath ($_prefix+"Storage_diskpart.txt") -append
        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage_diskpart.txt") -append

        # - Build the command file
        Write-Output "list disk" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII
        Write-Output "select disk 0" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "list volume" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "list partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select partition 1" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select partition 2" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select partition 3" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "list volume" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select volume 1" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail volume" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select volume 2" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail volume" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select disk 1" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "list partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select partition 1" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select partition 2" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "select partition 3" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        Write-Output "detail partition" | Out-File -FilePath ($_prefix+"pscommand.txt") -Encoding ASCII -Append
        # - Done building command file

        LogInfo ("[$LogPrefixStorage] Running diskpart to retrieve info.")
        diskpart /s ($_prefix+"pscommand.txt") >> ($_prefix+"Storage_diskpart.txt") 2>> $_errorfile
        Write-Output $_line | Out-File -FilePath ($_prefix+"Storage_diskpart.txt") -append
        Remove-Item ($_prefix+"pscommand.txt") -Force
    }
    LogInfo ("[$LogPrefixStorage] End Storage and Device info.")

    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION STORAGEINFOFunc ####################

#################### FUNCTION PROCESSINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDProcessInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # replaced wmic
    #"wmic process get * /format:texttable  > $($_prefix)Process_and_Service_info.txt"

    # Section Running process info
    LogInfo ("[Process] Getting process info.")
	$outFile = "$($_prefix)Process_and_Service_Tasklist.txt"
    $Commands = @(
        "tasklist /svc /fo list | Out-File -Append $outFile"
	)
	RunCommands "Process" $Commands -ThrowException:$False -ShowMessage:$True
	$outFile = "$($_prefix)Process_and_Service_info.txt"
	$Commands = @(
        "Get-CimInstance Win32_Process | ft ProcessId,Name,HandleCount,WorkingSetSize,VirtualSize,CommandLine | Out-File -Append $outFile"
    )
    RunCommands "Process" $Commands -ThrowException:$False -ShowMessage:$True
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION PROCESSINFOFunc ####################

#################### FUNCTION BITLOCKERINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDBitlockerInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    $_MBAM_SYSTEM=0

    # Section Bitlocker and MBAM
    $LogPrefixBitlocker = "Bitlocker"
    LogInfo ("[$LogPrefixBitlocker] Querying registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    $RegKeysBitlocker = @(
        ('HKLM:SOFTWARE\Policies\Microsoft\FVE', "$($_prefix)Bitlocker_MBAM-Reg.txt"),
        ('HKLM:SOFTWARE\Policies\Microsoft\TPM', "$($_prefix)Bitlocker_MBAM-Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\BitLockerCsp', "$($_prefix)Bitlocker_MBAM-Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\MBAM', "$($_prefix)Bitlocker_MBAM-Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\MBAMPersistent', "$($_prefix)Bitlocker_MBAM-Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\MBAM Server', "$($_prefix)Bitlocker_MBAM-Reg.txt")
    )
    FwExportRegistry $LogPrefixBitlocker $RegKeysBitlocker

    LogInfo ("[$LogPrefixBitlocker] Getting Bitlocker and MBAM info.")
    if (Test-Path $Env:windir\system32\manage-bde.exe)
    {
        LogInfo ("[$LogPrefixBitlocker] ManageBDE info.")
        $CommandsBitlocker = @(
            "manage-bde -status | Out-File -Append $($_prefix)Bitlocker_ManageBDE.txt"
            "manage-bde -protectors c: -get | Out-File -Append $($_prefix)Bitlocker_ManageBDE.txt"
        )
        RunCommands $LogPrefixBitlocker $CommandsBitlocker -ThrowException:$False -ShowMessage:$True
    }

    if (Test-Path "$Env:ProgramFiles\Microsoft\MDOP MBAM\mbamagent.exe") {Get-CimInstance -class mbam_volume -namespace root\microsoft\mbam | Out-File -Append ($_prefix+"Bitlocker_MBAM-WMINamespace.txt")}
    if ($_PS4ormore -eq 1)
    {
        try { Get-Tpm | Out-File -Append ($_prefix+"Bitlocker_Get-TPM.txt") }
        catch { LogException "Get-Tpm failed" $_}
    }

    if (Test-Path "$Env:windir\system32\tpmtool.exe")
    {
        $LogPrefixTPM = "TPM"
        LogInfo ("[$LogPrefixTPM] Getting TPM info.")
        FwCreateFolder $_tempdir\tpmtool
        $CommandsTPM = @(
            "tpmtool getdeviceinformation | Out-File -Append $_tempdir\tpmtool\getdeviceinformation.txt"
            "tpmtool gatherlogs `"$_tempdir\tpmtool`""
            "tpmtool parsetcglogs | Out-File -Append $_tempdir\tpmtool\parsetcglogs.txt"
        )
        RunCommands $LogPrefixTPM $CommandsTPM -ThrowException:$False -ShowMessage:$True
    }
    else
    {
        LogWarn ("[$LogPrefixTPM] TPM not present.")
    }

    # Check for MBAM
    if((Test-Path -path "HKLM:\SOFTWARE\Microsoft\MBAM Server") -or (Test-Path -path "HKLM:\SOFTWARE\Microsoft\MBAM")) { $_MBAM_SYSTEM = 1 }

    # - If MBAM server then gather this
    if($_MBAM_SYSTEM -eq 1)
    {
        LogInfo ("[MBAM] Getting MBAM server info.")
		$outFile = "$($_prefix)Bitlocker-MBAM_Info.txt"
        $MBAM = @(
            "Get-MbamCMIntegration							| Out-File -Append $outFile"
            "Get-MbamReport									| Out-File -Append $outFile"
            "Get-MbamWebApplication -AdministratorPortal	| Out-File -Append $outFile"
            "Get-MbamWebApplication -AgentService			| Out-File -Append $outFile"
            "Get-MbamWebApplication -SelfServicePortal		| Out-File -Append $outFile"
        )
        RunCommands "MBAM" $MBAM -ThrowException:$False -ShowMessage:$True
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION BITLOCKERINFOFunc ####################

#################### FUNCTION RELIABILITYSUMMARYFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDReliabilitySummary
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    #Use good old SummaryReliability.vbs
    if ($_Summary -eq 1) {
		FwGet-SummaryVbsLog -Subfolder "Setup_Report$LogSuffix"
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION RELIABILITYSUMMARYFunc ####################

#################### FUNCTION ACTIVATIONSTATEFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDActivationState
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # Get Licensing info
    LogInfo ("[Activation] Getting licensing info.")
	$outFile = "$($_prefix)KMSActivation.txt"
    $Activation = @(
        "nslookup -type=all _vlmcs._tcp		| Out-File -Append $outFile"
        "licensingdiag.exe -report `"$($_prefix)lic_diag.txt`" -log `"$($_prefix)lic_logs.cab`""
        "icacls c:\windows\system32\spp /t	| Out-File -Append $($_prefix)File_Icacls_Permissions_SPP.txt"
    )
    RunCommands "Activation" $Activation -ThrowException:$False -ShowMessage:$True

	FwGetDSregCmd -Subfolder "Setup_Report$LogSuffix"

    LogInfo ("[Activation] slmgr section.")
    $slmgr = @(
        "cscript.exe //Nologo `"$Env:windir\system32\slmgr.vbs`" /dlv		| Out-File -Append $outFile"
        "cscript.exe //Nologo `"$Env:windir\system32\slmgr.vbs`" /dlv all	| Out-File -Append $outFile"
        "cscript.exe //Nologo `"$Env:windir\System32\slmgr.vbs`" /ao-list	| Out-File -Append $outFile"
        "Get-CimInstance -Class SoftwareLicensingService					| Out-File -Append $outFile"
    )
    RunCommands "Activation" $slmgr -ThrowException:$False -ShowMessage:$True

    # Token Activation
    LogInfo ("[Activation] Token section.")
	$outFile = "$($_prefix)Token_ACT.txt"
    $Commands = @(
        "Cscript.exe //Nologo `"$Env:windir\system32\slmgr.vbs`" /dlv | Out-File -Append $outFile"
        "Cscript.exe //Nologo `"$Env:windir\system32\slmgr.vbs`" /lil | Out-File -Append $outFile"
        "Cscript.exe //Nologo `"$Env:windir\system32\slmgr.vbs`" /ltc | Out-File -Append $outFile"
	)
	RunCommands "Activation" $Commands -ThrowException:$False -ShowMessage:$True
	$outFile = "$($_prefix)Token_ACT_CERT.txt"
	$Commands = @(
        "Certutil -store ca		| Out-File -Append $outFile"
        "Certutil -store my		| Out-File -Append $outFile"
        "Certutil -store root	| Out-File -Append $outFile"
    )
    RunCommands "Activation" $Commands -ThrowException:$False -ShowMessage:$True

    LogInfo ("[Activation] Querying registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    $RegKeysActivation = @(
        ('HKLM:SYSTEM\WPA', "$($_prefix)reg_System-wpa.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform', "$($_prefix)reg_SoftwareProtectionPlatform.txt"),
        ('HKU:\S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform', "$($_prefix)reg_SoftwareProtectionPlatform.txt")
    )
    FwExportRegistry "Activation" $RegKeysActivation

    # Office token activation
    LogInfo ("[Activation] Getting Office Token info.")
    Write-Output "`n`nGetting Office Token Info" | Out-File -Append ($_prefix+"Token_ACT.txt")
    if (Test-Path "C:\program files (x86)\microsoft office\office14\ospp.vbs")
    {
        Write-Output "Checking for Office14 x86`n$_line" | Out-File -Append ($_prefix+"Token_ACT.txt")
        Cscript.exe "c:\program files (x86)\microsoft office\office14\ospp.vbs" /dtokils >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
        Cscript.exe "c:\program files (x86)\microsoft office\office14\ospp.vbs" /dtokcerts >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
    }

    If (Test-Path "c:\program files\microsoft office\office14\ospp.vbs")
    {
        Write-Output "Checking for Office14 x64`n$_line" | Out-File -Append ($_prefix+"Token_ACT.txt")
        Cscript.exe "c:\program files\microsoft office\office14\ospp.vbs" /dtokils >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
        Cscript.exe "c:\program files\microsoft office\office14\ospp.vbs" /dtokcerts >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
    }

    If (Test-Path "c:\program files (x86)\microsoft office\office15\ospp.vbs")
    {
        Write-Output "Checking for Office15 x86`n$_line" | Out-File -Append ($_prefix+"Token_ACT.txt")
        Cscript.exe "c:\program files (x86)\microsoft office\office15\ospp.vbs" /dtokils >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
        Cscript.exe "c:\program files (x86)\microsoft office\office15\ospp.vbs" /dtokcerts >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
    }

    If (Test-Path "c:\program files\microsoft office\office15\ospp.vbs")
    {
        Write-Output "Checking for Office15 x64`n$_line" | Out-File -Append ($_prefix+"Token_ACT.txt")
        Cscript.exe "c:\program files\microsoft office\office15\ospp.vbs" /dtokils >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
        Cscript.exe "c:\program files\microsoft office\office15\ospp.vbs" /dtokcerts >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
    }

    If (Test-Path "c:\program files (x86)\microsoft office\office16\ospp.vbs")
    {
        Write-Output "Checking for Office16 x86`n$_line" | Out-File -Append ($_prefix+"Token_ACT.txt")
        Cscript.exe "c:\program files (x86)\microsoft office\office16\ospp.vbs" /dtokils >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
        Cscript.exe "c:\program files (x86)\microsoft office\office16\ospp.vbs" /dtokcerts >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
    }

    If (Test-Path "c:\program files\microsoft office\office16\ospp.vbs")
    {
        Write-Output "Checking for Office16 x64`n$_line" | Out-File -Append ($_prefix+"Token_ACT.txt")
        Cscript.exe "c:\program files\microsoft office\office16\ospp.vbs" /dtokils >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
        Cscript.exe "c:\program files\microsoft office\office16\ospp.vbs" /dtokcerts >> ($_prefix+"Token_ACT.txt") 2>> $_errorfile
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION ACTIVATIONSTATEFunc ####################

#################### FUNCTION DIRINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDDirInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefixDIR = "DIR"
    LogInfo ("[$LogPrefixDIR] Getting Directory Listing of Key Files.")
    $Commands = @(
        "cmd /r Dir /a /r C:\ 								| Out-File -Append $($_prefix)dir_driveroot.txt"
        "cmd /r Dir /a /s /r $Env:windir\system32\drivers	| Out-File -Append $($_prefix)dir_win32-drivers.txt"
        "cmd /r Dir /a /s /r $Env:temp						| Out-File -Append $($_prefix)dir_temp.txt"
        "cmd /r Dir /a /s /r $Env:windir\temp				| Out-File -Append $($_prefix)dir_temp.txt"
        "cmd /r Dir /a /s /r $Env:windir\inf				| Out-File -Append $($_prefix)dir_INF.txt"
        "cmd /r Dir /a /s /r $Env:windir\system32\catroot	| Out-File -Append $($_prefix)dir_catroot.txt"
        "cmd /r Dir /a /s /r $Env:windir\system32\catroot2	| Out-File -Append $($_prefix)dir_catroot.txt"
        "cmd /r Dir /a /s /r $Env:windir\system32\config\*.* | Out-File -Append $($_prefix)dir_registry_list.txt"  # Get registry size info including Config and profile info
        "cmd /r Dir /a /s /r c:\users\ntuser.dat			| Out-File -Append $($_prefix)dir_registry_list.txt"
    )
	if (Test-Path d:\) {$Commands += "cmd /r Dir /a /r D:\	| Out-File -Append $($_prefix)dir_driveroot.txt"}
	if (Test-Path e:\) { $Commands += "cmd /r Dir /a /r E:\	| Out-File -Append $($_prefix)dir_driveroot.txt"}
	if (Test-Path "$Env:windir\boot") {$Commands += "cmd /r Dir /a /s /r C:\windows\boot | Out-File -Append $($_prefix)dir_boot.txt"}
	if (Test-Path "$Env:windir\LiveKernelReports") {$Commands += "cmd /r Dir /a /s /r C:\Windows\LiveKernelReports | Out-File -Append $($_prefix)dir_LiveKernelReports.txt"}
	if (Test-Path "$Env:windir\system32\driverstore\filerepository") { $Commands += "cmd /r Dir /a /s /r $Env:windir\system32\driverstore\filerepository | Out-File -Append $($_prefix)dir_win32-driverstore.txt"}
	if (Test-Path "$Env:windir\systemapps") {$Commands += "cmd /r Dir /a /s /r $Env:windir\systemapps | Out-File -Append $($_prefix)dir_systemapps.txt"}
    RunCommands $LogPrefixDIR $Commands -ThrowException:$False -ShowMessage:$True
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION DIRINFOFunc ####################


#################### FUNCTION ENERGYINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDEnergyInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # - Generate detail battery, sleep and power info.
    # - Only run if flag set
    $LogPrefixPowerCfg = "PowerCfg"
    LogInfo ("[$LogPrefixPowerCfg] Power Config section.")
    LogInfo ("[$LogPrefixPowerCfg] Getting Powercfg Config and Sleep info.")
    If (Test-Path $Env:windir\system32\sleepstudy\*abnormal*) { FwCreateFolder $_tempdir\sleepstudy }
    $CommandsPowerCfg = @(
		"powercfg /batteryreport /duration 14 /output $($_prefix)Powercfg-batteryreport.html"
		"powercfg /sleepstudy /duration 14 /output $($_prefix)Powercfg-sleepstudy.html"
		"powercfg /energy /output $($_prefix)Powercfg-energy.html"
		"powercfg /srumutil /output $($_prefix)Powercfg-srumdbout.xml /xml"
		"powercfg /SYSTEMSLEEPDIAGNOSTICS /OUTPUT $($_prefix)Powercfg-system-sleep-diagnostics.html"
		"powercfg /SYSTEMPOWERREPORT /OUTPUT $($_prefix)Powercfg-systempowerreport.html"
		"xcopy /chrky $Env:windir\system32\sleepstudy\*abnormal*.etl $_tempdir\sleepstudy\"
    )
    RunCommands $LogPrefixPowerCfg $CommandsPowerCfg -ThrowException:$False -ShowMessage:$True
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION ENERGYINFOFunc ####################

#################### FUNCTION SURFACEINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDSurfaceInfo
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # - Microsoft Surface Specific info.
    # - Drivers
    $LogPrefixSurface = "Surface"
    LogInfo ("[$LogPrefixSurface] Surface section.")
    $Surface = @(
		"Get-CimInstance Win32_PnPSignedDriver | Select-Object devicename,driverversion,HardwareID | Where-Object {`$_.devicename -like `"*intel*`" -or `$_.devicename -like `"*surface*`" -or `$_.devicename -like `"*Nvidia*`" -or `$_.devicename -like `"*microsoft*`" -or `$_.devicename -like `"*marvel*`" -or `$_.devicename -like `"*qualcomm*`" -or `$_.devicename -like `"*realtek*`"} | Sort-object -property devicename | Export-Csv -path $($_prefix)Surface_drivers.csv"
    )
    RunCommands $LogPrefixSurface $Surface -ThrowException:$False -ShowMessage:$True

    # - Registry keys
    LogInfo ("[$LogPrefixSurface] Querying registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    $RegKeysSurface = @(
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF\Services\SurfaceDockFwUpdate', "$($_prefix)Surface_Registry.txt"),
        ('HKLM:SOFTWARE\Microsoft\Surface\OSImage', "$($_prefix)Surface_Registry.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\Power', "$($_prefix)Surface_Registry.txt")
    )
    FwExportRegistry $LogPrefixSurface $RegKeysSurface
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION SURFACEINFOFunc ####################

#################### FUNCTION EVENTLOGSFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDEventLogs
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # - Get all event logs and convert some if getevents script is available
    $LogPrefixEventLogs = "Events"
    FwCreateFolder $_tempdir\eventlogs
    LogInfo ("[$LogPrefixEventLogs] Getting event logs.")
    $CommandsEventLogs = @(
		"robocopy.exe `"$Env:windir\system32\winevt\logs`" `"$_tempdir\eventlogs`" /W:1 /R:1 /NP /E /XF Archive*.evtx /LOG+:$_robocopy_log /S | Out-Null"
    )
    RunCommands $LogPrefixEventLogs $CommandsEventLogs -ThrowException:$False -ShowMessage:$True

    #Use good old GetEvents.vbs
    $ExclusionList = ''
    # Long list
    # $EventLogNames = "System","Application","Setup","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-Setup/Analytic","General Logging","HardwareEvents","Microsoft-Windows-Crashdump/Operational","Microsoft-Windows-Dism-Api/Analytic","Microsoft-Windows-EventLog-WMIProvider/Debug","Microsoft-Windows-EventLog/Analytic","Microsoft-Windows-EventLog/Debug","Microsoft-Windows-Store/Operational","Microsoft-Windows-Store/Operational","Microsoft-Client-Licensing-Platform/Admin","Microsoft-Client-Licensing-Platform/Admin"
    # Short list
    $EventLogNames = "System","Application","Setup","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-TaskScheduler/Operational"#,"Microsoft-Windows-Store/Operational","Microsoft-Client-Licensing-Platform/Admin"
    $Days = ''
    $OutputFormatCMD = "/TXT /CSV"
    $EventLogAdvisorXMLCMD = ''
    $Query=$null
    $Suffix=$null
    $DisplayToAdd = ''
    $LogPrefixSDP = "psSDP"
    If (Test-Path -Path "$Scriptfolder\psSDP\Diag\global\GetEvents.vbs") {
    Try {
        LogInfo "[$LogPrefixSDP] GetEvents.vbs starting..."
        Push-Location -Path "$Scriptfolder\psSDP\Diag\global"
        ForEach ($EventLogName in $EventLogNames) {
            $CommandsVerifyEventLogs = @(
        		"wevtutil gl `"$EventLogName`""
            )
            RunCommands $LogPrefixSDP $CommandsVerifyEventLogs -ThrowException:$False -ShowMessage:$True

            if ($LASTEXITCODE -eq 0) {
                if ($ExclusionList -notcontains $EventLogName) {
                    $CommandToExecute = "cscript.exe //e:vbscript $Scriptfolder\psSDP\Diag\global\GetEvents.vbs `"$EventLogName`" /channel $Days $OutputFormatCMD $EventLogAdvisorXMLCMD `"$_tempdir`" /noextended $Query $_prefix $Suffix"
                    LogInfo "[$LogPrefixSDP] GetEvents.vbs Exporting event log: `"$EventLogName`""
                    Invoke-Expression -Command $CommandToExecute >$null 2>> $_errorfile
                }
            }

            if ($LASTEXITCODE -eq '15007') {
                LogWarn "[$LogPrefixSDP] GetEvents.vbs the specified channel could not be found: `"$EventLogName`""
            }
        }
    } Catch { LogException "An Exception happend in GetEvents.VBS" $_ }
    Pop-Location
    LogInfo "[$LogPrefixSDP] GetEvents.vbs event log export completed"
    }
    Else { LogInfo "[$LogPrefixSDP] GetEvents.vbs not found - skipping..." }

    <#
    #Use built-in TSSv2 function FwExportEventLogWithTXTFormat
    FwExportEventLogWithTXTFormat System ($_tempdir)
    FwExportEventLogWithTXTFormat Application $_tempdir
    FwExportEventLogWithTXTFormat Setup $_tempdir
    FwExportEventLogWithTXTFormat Microsoft-Windows-WMI-Activity/Operational $_tempdir
    FwExportEventLogWithTXTFormat Microsoft-Windows-TaskScheduler/Operational $_tempdir
    FwExportEventLogWithTXTFormat Microsoft-Windows-Store/Operational $_tempdir
    FwExportEventLogWithTXTFormat Microsoft-Client-Licensing-Platform/Admin $_tempdir
    #>
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION EVENTLOGSFunc ####################

#################### FUNCTION MISCINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDMiscInfo {
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    #$LogPrefixMiscInfo = "MiscInfo"
    LogInfo ("[MiscInfo] Native export registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    # removed reg_CurrentVersion_Windows* due to performance when running recursively (~3 minutes)
    # added non-recursive in $CommandsMiscInfo
    # ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', "$($_prefix)reg_CurrentVersion_Windows_NT.txt"),
    # ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion', "$($_prefix)reg_CurrentVersion_Windows.txt")
# #we-test#
    $RegKeysMiscInfoExport = @(
        ('HKLM:SYSTEM\CurrentControlSet\Control\FirmwareResources', "$($_prefix)reg_FirmwareResources.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\MUI\UILanguages', "$($_prefix)reg_langpack.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Services', "$($_prefix)reg_services.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$($_prefix)reg_LocalMachine-AppCompatFlags.txt")
    )
    FwExportRegistry "MiscInfo" $RegKeysMiscInfoExport -RealExport $true

    LogInfo ("[MiscInfo] Export registry properties.")
    # FwExportRegistry property values
    $RegKeysMiscInfoProperty = @(
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'BuildLab', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'UBR', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName', "$($_prefix)reg_BuildInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel', 'Version', "$($_prefix)reg_AppModelVersion.txt")
    )
    FwExportRegistry "MiscInfo" $RegKeysMiscInfoProperty

    LogInfo ("[MiscInfo] Export by querying registry keys.")
    # FwExportRegistry is using the /s (recursive) switch by default and appends to an existing file
    $RegKeysMiscInfoQuery = @(
        ('HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP', "$($_prefix)reg_.NET-Setup.txt"),
        ('HKLM:SOFTWARE\Microsoft\PolicyManager', "$($_prefix)reg_PolicyManager.txt"),
        ('HKLM:SOFTWARE\Microsoft\SQMClient', "$($_prefix)reg_SQMClient.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', "$($_prefix)reg_ProfileList.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Superfetch', "$($_prefix)reg_superfetch.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost', "$($_prefix)reg_SVCHost.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones', "$($_prefix)reg_TimeZone.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication', "$($_prefix)reg_Software_Authentication.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp', "$($_prefix)reg_SecurityInfo.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad', "$($_prefix)reg_Startup.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability', "$($_prefix)reg_Relibility.txt"),
        ('HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Run', "$($_prefix)reg_Startup.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce', "$($_prefix)reg_Startup.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE', "$($_prefix)reg_Setup.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State', "$($_prefix)reg_Setup.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\Sysprep', "$($_prefix)reg_Setup.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\SysPrepExternal', "$($_prefix)reg_Setup.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', "$($_prefix)reg_Uninstall.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\winevt', "$($_prefix)reg_Winevt.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\Windows Error Reporting', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp', "$($_prefix)reg_SecurityInfo.txt"),
        ('HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall', "$($_prefix)reg_Uninstall.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\CrashControl', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\Power', "$($_prefix)reg_Power.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders', "$($_prefix)reg_SecurityInfo.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\Session Manager', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Power', "$($_prefix)reg_Power.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\Terminal Server', "$($_prefix)reg_TermServices.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\TimeZoneInformation', "$($_prefix)reg_TimeZone.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\WMI', "$($_prefix)reg_WMI.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Services\kbdhid', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Services\i8042prt', "$($_prefix)reg_Recovery.txt"),
        ('HKLM:SYSTEM\DriverDatabase', "$($_prefix)reg_DriverDatabase_System.txt"),
        ('HKLM:SYSTEM\Setup', "$($_prefix)reg_Setup.txt"),
        ('HKCU:SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$($_prefix)reg_CurrentUser-AppCompatFlags.txt")
    )
    FwExportRegistry "MiscInfo" $RegKeysMiscInfoQuery

    LogInfo ("[MiscInfo] Getting Misc info.")
    $CommandsMiscInfo = @(
		"reg.exe save `"HKLM\SYSTEM\CurrentControlSet\services`" `"$($_prefix)reg_services.hiv`""
		"reg.exe save `"HKLM\SYSTEM\DriverDatabase`" `"$($_prefix)reg_DriverDatabase_System.hiv`""
		"reg.exe save `"HKLM\SOFTWARE\Microsoft\Windows\currentversion\winevt`" `"$($_prefix)reg_Winevt.hiv`""
		"reg.exe query `"HKLM\Software\Microsoft\Windows NT\CurrentVersion`" | Out-File -Append $($_prefix)reg_CurrentVersion_Windows_NT.txt"
		"reg.exe query `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`" | Out-File -Append $($_prefix)reg_CurrentVersion_Windows.txt"
		"verifier.exe /query | Out-File -Append $($_prefix)verifier.txt"
		#"cmd /r Copy `"$Env:windir\system32\config\drivers`" `"$($_prefix)drivers.hiv`""
    )
    RunCommands "MiscInfo" $CommandsMiscInfo -ThrowException:$False -ShowMessage:$True
# #we-test#>
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\system32\netsetupmig.log", "$($_prefix)netsetupmig.log"),
		@("$Env:windir\dpinst.log", "$($_prefix)dpinst.log"),
		@("$Env:windir\certutil.log", "$($_prefix)certutil.log"),
		@("$Env:windir\System32\catroot2\dberr.txt", "$($_prefix)dberr.txt"),
		@("c:\users\public\documents\sigverif.txt", "$($_prefix)sigverif.txt")
		#@("$Env:windir\system32\config\drivers", "$($_prefix)drivers.hiv")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	Try {
		LogInfo "[Get-DNDMiscInfo] waiting max 50 sec to succeed on copy $Env:windir\system32\config\drivers" "Gray"
		$StopWait = $False
		$attempt = 0
		While (($StopWait -eq $False) -and ($attempt -lt 10)) {
			$attempt +=1
			$Result = (cmd /r copy "$Env:windir\system32\config\drivers" "$($_prefix)reg_Drivers.hiv" 2>&1)
			if ($Result -match '1 file') {$StopWait = $True; LogInfo "[Get-DNDMiscInfo] - Result: $Result (@attempt=$attempt)" "Green" } else {$StopWait = $False ; LogErrorFile "[Get-DNDCbsPnpInfo] waiting +5 sec - Result: $Result (@attempt=$attempt)"; Start-Sleep -Milliseconds 5000}
		}
		if ($Result -match '0 file') {LogInfo "[Get-DNDMiscInfo] - Result: $Result (@attempt=$attempt) - copy $Env:windir\system32\config\drivers FAILED after $attempt attempts" "Magenta"}
	} catch { LogException "[Get-DNDMiscInfo] copying $Env:windir\system32\config\drivers failed" $_ }
    # Get All Scheduled Task on the system
    LogInfo ("[MiscInfo] Get all scheduled task on the system.")
	$outFile = "$($_prefix)ScheduledTask.txt"
	"This file contains scheduled task info first in summary and then in verbose format" | Out-File -Append $outFile
	Write-Output $_line | Out-File -Append $outFile
    $Commands = @(
		"SCHTASKS /query					| Out-File -Append $($_prefix)ScheduledTask.txt"
		"SCHTASKS /query /v					| Out-File -Append $($_prefix)ScheduledTask.txt"
		"bcdedit.exe /enum 2>&1				| Out-File -Append $($_prefix)BCDEdit.txt"
		"bcdedit.exe /enum all 2>&1			| Out-File -Append $($_prefix)BCDEdit.txt"
		"bcdedit.exe /enum all /v 2>&1		| Out-File -Append $($_prefix)BCDEdit.txt"
		"Dism /english /online /get-drivers /Format:Table | Out-File -Append $($_prefix)dism_3rdPartyDrivers.txt"
		"Get-CimInstance Win32_PnPEntity	| Out-File -Append $($_prefix)drivers_WMIQuery.txt"
    )
    RunCommands "MiscInfo" $Commands -ThrowException:$False -ShowMessage:$True

    # Get MDM Info
    if (Test-Path $Env:windir\system32\MDMDiagnosticsTool.exe)
    {
        FwCreateFolder $_tempdir\MDMDiag
        LogInfo ("[MiscInfo] Getting MDM info.")
        $MDM = @(
    		"cmd /r $Env:windir\system32\MDMDiagnosticsTool.exe -out $_tempdir\MDMDiag\"
    		"cmd /r $Env:windir\system32\MDMDiagnosticsTool.exe -area 'Autopilot;DeviceEnrollment' -cab $_tempdir\MDMDiag\AutopilotDeviceEnrollmentTpmDiag.cab"
        )
        RunCommands "MiscInfo" $MDM -ThrowException:$False -ShowMessage:$True

        #cmd /r "$Env:windir\system32\MDMDiagnosticsTool.exe" -area 'Autopilot;DeviceEnrollment;Tpm' -cab "$_tempdir\MDMDiag\AutopilotDeviceEnrollmentTpmDiag.cab" >$null 2>>$null
        #Specifying TMP causes error on non-TPM machines. Removing it

        LogInfo ("[MiscInfo] Querying MDM registry keys.")
        $RegKeysMDM = @(
            ('HKLM:SOFTWARE\Microsoft\PolicyManager')
        )
        FwExportRegToOneFile "MiscInfo" $RegKeysMDM "$_tempdir\MDMDiag\REG_PolicyManager.txt"
    }

    # - Power report info - general info
    # more details could be obtained from Get-DNDEnergyInfo
    LogInfo ("[MiscInfo] Getting power report info.")
	$outFile = "$($_prefix)Powercfg_Settings.txt"
    $Power = @(
		"powercfg /L		| Out-File -Append $outFile"
		"powercfg /aliases	| Out-File -Append $outFile"
		"Powercfg /a		| Out-File -Append $outFile"
		"powercfg /qh		| Out-File -Append $outFile"
    )
    RunCommands "MiscInfo" $Power -ThrowException:$False -ShowMessage:$True

    # - Get .Net info
    LogInfo ("[MiscInfo] Getting .Net info.")
    Write-Output $_line | Out-File -Append ($_prefix+"reg_.NET-Setup.txt")
    Write-Output "Get .Net info using PS script" | Out-File -Append ($_prefix+"reg_.NET-Setup.txt")
    Write-Output $_line | Out-File -Append ($_prefix+"reg_.NET-Setup.txt")

    $DotNetVersions = Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Updates | Where-Object {$_.name -like "*.NET Framework*"}
    ForEach($Version in $DotNetVersions)
    {
        $Updates = Get-ChildItem $Version.PSPath
        $Version.PSChildName | Out-File -Append ($_prefix+"reg_.NET-Setup.txt")
        ForEach ($Update in $Updates)
        {
            $Update.PSChildName | Out-File -Append ($_prefix+"reg_.NET-Setup.txt")
        }
    }
    #################### END OF FUNCTION MISCFunc ####################

    #################### SECTION Powershell commands for Win10 Only ####################
    # Skip for now
    if ($_WIN10 -eq 3)
    {
		$outFile = $_prefix+"MiscInfo.txt"
		$Commands = @(
			"Get-computerinfo -verbose | Format-list	| Out-File -Append $outFile"
			"Get-localgroup | Format-list				| Out-File -Append $outFile"
			"Get-localuser								| Out-File -Append $outFile"
			"Get-WUIsPendingReboot						| Out-File -Append $outFile"
			"Get-WUAVersion								| Out-File -Append $outFile"
			"Get-WULastInstallationDate					| Out-File -Append $outFile"
			"Get-WULastScanSuccessDate					| Out-File -Append $outFile"
		)
		RunCommands "MiscInfo" $Commands -ThrowException:$False -ShowMessage:$True
    }
    #################### END SECTION Powershell commands for Win10 Only ####################

    $date = Get-Date
    Write-Output ("Completed at--------------------------------------------- $date") | Out-File -Append ($_prefix+"MiscInfo.txt")
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION MISCINFOFunc ####################

#################### FUNCTION DEFENDERINFOFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDDefenderInfo {
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    # - Get Windows Defender info if running on Windows 10
    if ($_WIN10 -eq 1)
    {
        $LogPrefixWindowsDefender = "WindowsDefender"
        LogInfo ("[$LogPrefixWindowsDefender] Windows Defender info.")
        # FwExportRegistry is using the /s (recursive) switch by default and appends to an existing file
        $RegKeysWindowsDefender = @(
            ('HKLM:SOFTWARE\Microsoft\Windows Defender')
            )
            FwExportRegToOneFile $LogPrefixWindowsDefender $RegKeysWindowsDefender "$($_prefix)reg_Defender.txt"
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION DEFENDERINFOFunc ####################

#################### FUNCTION MINIDUMPSFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDMiniDumps {
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    # Get mini dumps
    if (Test-Path $Env:windir\Minidump) {
        $LogPrefixDMP = "DMP"
        LogInfo ("[$LogPrefixDMP] Collecting mini dumps.")
        FwCreateFolder $_tempdir\Minidump
        $CommandsDMP = @(
    		"xcopy /cherky $Env:windir\Minidump\*.* `"$_tempdir\Minidump\`""
        )
        RunCommands $LogPrefixDMP $CommandsDMP -ThrowException:$False -ShowMessage:$True
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION MINIDUMPSFunc ####################

#################### FUNCTION NETWORKBasicFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDNetworkBasic {
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefixNetwork = "Network"
    LogInfo ("[$LogPrefixNetwork] Getting basic network info.")
    $CommandsNetworkBasic = @(
		"cmd /r Copy `"$Env:windir\System32\drivers\etc\hosts`" `"$($_prefix)NETWORK_hosts.txt`" /y"
		"ipconfig /all | Out-File -Append $($_prefix)NETWORK_TCPIP_info.txt"
		"cmd /r route print  | Out-File -Append $($_prefix)NETWORK_TCPIP_info.txt"
		"cmd /r netstat -nato | Out-File -Append $($_prefix)NETWORK_TCPIP_info.txt"
		"cmd /r netstat -anob | Out-File -Append $($_prefix)NETWORK_TCPIP_info.txt"
		"cmd /r netstat -es | Out-File -Append $($_prefix)NETWORK_TCPIP_info.txt"
		"cmd /r arp -a | Out-File -Append $($_prefix)NETWORK_TCPIP_info.txt"
		"cmd /r netsh winhttp show proxy | Out-File -Append $($_prefix)NETWORK_Proxy.txt"
		"cmd /r ipconfig.exe /displaydns | Out-File -Append $($_prefix)NETWORK_DnsClient_ipconfig-displaydns.txt"
    )
    RunCommands $LogPrefixNetwork $CommandsNetworkBasic -ThrowException:$False -ShowMessage:$True

    LogInfo ("[$LogPrefixNetwork] Querying basic network registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    $RegKeysNetwork = @(
        ('HKLM:SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}', "$($_prefix)NETWORK_NetworkAdapters_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\Network', "$($_prefix)NETWORK_NetworkAdapters_reg_output.txt")
    )
    FwExportRegistry $LogPrefixNetwork $RegKeysNetwork

    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION NETWORKBasicFunc ####################

#################### FUNCTION NETWORKSETUPFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDNetworkSetup {
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefixNetwork = "Network"
    LogInfo ("[$LogPrefixNetwork] Getting detailed network info.")
    $CommandsNetworkSetup = @(
		"netsh int tcp show global | Out-File -Append $($_prefix)NETWORK_TCPIP_OFFLOAD.txt"
		"netsh int ipv4 show offload | Out-File -Append $($_prefix)NETWORK_TCPIP_OFFLOAD.txt"
		"netstat -nato -p tcp | Out-File -Append $($_prefix)NETWORK_TCPIP_OFFLOAD.txt"
		"netsh int show int | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"netsh int ip show int | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"netsh int ip show address | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"netsh int ip show config | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"netsh int ip show dns | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"netsh int ip show joins | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"netsh int ip show offload | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"netsh int ip show wins | Out-File -Append $($_prefix)NETWORK_TCPIP_netsh_info.txt"
		"nbtstat.exe -c | Out-File -Append $($_prefix)NETWORK_WinsClient_nbtstat-output.txt"
		"nbtstat.exe -n | Out-File -Append $($_prefix)NETWORK_WinsClient_nbtstat-output.txt"
		"net.exe config workstation | Out-File -Append $($_prefix)NETWORK_SmbClient_info_net.txt"
		"net.exe statistics workstation | Out-File -Append $($_prefix)NETWORK_SmbClient_info_net.txt"
		"net.exe use | Out-File -Append $($_prefix)NETWORK_SmbClient_info_net.txt"
		"net.exe accounts | Out-File -Append $($_prefix)NETWORK_SmbClient_info_net.txt"
		"net.exe accounts | Out-File -Append $($_prefix)NETWORK_SmbServer_info_net.txt"
		"net.exe config server | Out-File -Append $($_prefix)NETWORK_SmbServer_info_net.txt"
		"net.exe session | Out-File -Append $($_prefix)NETWORK_SmbServer_info_net.txt"
		"net.exe files | Out-File -Append $($_prefix)NETWORK_SmbServer_info_net.txt"
		"net.exe share | Out-File -Append $($_prefix)NETWORK_SmbServer_info_net.txt"
		"netsh.exe rpc show int | Out-File -Append $($_prefix)NETWORK_RPC_netsh_output.txt"
		"netsh.exe rpc show settings | Out-File -Append $($_prefix)NETWORK_RPC_netsh_output.txt"
		"netsh.exe rpc filter show filter | Out-File -Append $($_prefix)NETWORK_RPC_netsh_output.txt"
		"netsh.exe firewall show allowedprogram | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show config | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show currentprofile | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show icmpsetting | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show logging | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show multicastbroadcastresponse | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show notifications | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show opmode | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show portopening | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show service | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe firewall show state | Out-File -Append $($_prefix)NETWORK_Firewall_netsh.txt"
		"netsh.exe ipsec dynamic show all | Out-File -Append $($_prefix)NETWORK_IPsec_netsh_dynamic.txt"
		"netsh.exe ipsec static show all | Out-File -Append $($_prefix)NETWORK_IPsec_netsh_static.txt"
		"netsh.exe ipsec static exportpolicy `"$($_prefix)NETWORK_IPsec_netsh_LocalPolicyExport.ipsec.txt`""
		"netsh.exe wlan show all | Out-File -Append $($_prefix)NETWORK_Wireless_netsh.txt"
    )
    RunCommands $LogPrefixNetwork $CommandsNetworkSetup -ThrowException:$False -ShowMessage:$True

    LogInfo ("[$LogPrefixNetwork] Querying network registry keys.")
    # FwExportRegistry using -RealExport will overwrite any existing file
    $RegKeysNetwork = @(
        ('HKCU:Network', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SOFTWARE\Policies\Microsoft\Windows\IPSec', "$($_prefix)NETWORK_IPsec_reg_.txt"),
        ('HKLM:SOFTWARE\Microsoft\Rpc', "$($_prefix)NETWORK_RPC_reg.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Control\NetworkProvider', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\Dhcp', "$($_prefix)NETWORK_DhcpClient_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\Dnscache', "$($_prefix)NETWORK_DnsClient_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\IKEEXT', "$($_prefix)NETWORK_IPsec_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\iphlpsvc', "$($_prefix)NETWORK_TCPIP_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\LanManWorkstation', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\LanManServer', "$($_prefix)NETWORK_SmbServer_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\lmhosts', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\MrxSmb', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\MrxSmb10', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\MrxSmb20', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\MUP', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\NetBIOS', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\NetBT', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\PolicyAgent', "$($_prefix)NETWORK_IPsec_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\Rdbss', "$($_prefix)NETWORK_SmbClient_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\SharedAccess', "$($_prefix)NETWORK_Firewall_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\SRV2', "$($_prefix)NETWORK_SmbServer_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\SRVNET', "$($_prefix)NETWORK_SmbServer_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\TCPIP', "$($_prefix)NETWORK_TCPIP_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\Tcpip6', "$($_prefix)NETWORK_TCPIP_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\tcpipreg', "$($_prefix)NETWORK_TCPIP_reg_output.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\RpcEptMapper', "$($_prefix)NETWORK_RPC_reg.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\RpcLocator', "$($_prefix)NETWORK_RPC_reg.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\RpcSs', "$($_prefix)NETWORK_RPC_reg.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmbus', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\VMBusHID', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmicguestinterface', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmicheartbeat', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmickvpexchange', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmicrdv', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmicshutdown', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmictimesync', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\services\vmicvss', "$($_prefix)NETWORK_HyperVNetworking_reg_.txt")
    )
    FwExportRegistry $LogPrefixNetwork $RegKeysNetwork
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION NETWORKSETUPFunc ####################

#################### FUNCTION SLOWPROCESSINGFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDSlowProcessing
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # - Move things here that are not as critical, take a long time or are more prone to failure
    $LogPrefixSLOW = "SLOW"
    LogInfo "[$LogPrefixSLOW] enter Slow processing section."
    LogInfo "[$LogPrefixSLOW]  Exporting servicing registry hives...may take several minutes." "Cyan"
    LogInfo "[$LogPrefixSLOW]  Note, if this takes more than 15 minutes please stop the script and zip and upload all the data that have been captured to this point." "Cyan"
    LogInfo "[$LogPrefixSLOW]  Data will be in folder $_tempdir" "Cyan"

    $Commands = @(
		"Dism /english /online /Cleanup-Image /CheckHealth | Out-File -Append $($_prefix)dism_checkHealth.txt"
		"reg.exe save `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide`" `"$($_prefix)reg_SideBySide.hiv`""
		"reg.exe save `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing`" `"$($_prefix)reg_Component_Based_Servicing.hiv`""
		"reg.exe query `"HKLM\SYSTEM\CurrentControlSet\services\TrustedInstaller`" /s | Out-File -Append $($_prefix)reg_TrustedInstaller.txt"
		"reg.exe export `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide`" `"$($_prefix)reg_SideBySide.txt`""
    )
    RunCommands $LogPrefixSLOW $Commands -ThrowException:$False -ShowMessage:$True
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION SLOWPROCESSINGFunc ####################

#################### FUNCTION GENERALPERFMONFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDGeneralPerfmon
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo ("[DND_SETUPReport] Getting 15 Seconds PerfMon_Setup-15sec")
    Logman.exe create counter PerfMon_Setup-15sec -o ($_prefix+'PerfLog-Short.blg') -f bincirc -v mmddhhmm -max 300 -c '\LogicalDisk(*)\*' '\Memory\*' '\Cache\*' '\Network Interface(*)\*' '\Paging File(*)\*' '\PhysicalDisk(*)\*' '\Processor(*)\*' '\Processor Information(*)\*' '\Process(*)\*' '\Redirector\*' '\Server\*' '\System\*' '\Server Work Queues(*)\*' '\Terminal Services\*"' -si 00:00:01 >$null 2>> $_errorfile
    Logman.exe start PerfMon_Setup-15sec >$null 2>>$_errorfile
    Timeout /T 15 /nobreak >$null
    Logman.exe stop PerfMon_Setup-15sec >$null 2>>$_errorfile
    Logman.exe delete PerfMon_Setup-15sec >$null 2>>$_errorfile
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION GENERALPERFMONFunc ####################

#################### FUNCTION RFLCheckPrereqsFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDRFLCheckPrereqs
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefixRFL = "RFL"
    LogInfo ("[$LogPrefixRFL] Getting RFLcheck prereqs.")

	if (!$global:IsLiteMode) {
		try {
			$outfile = "$($_prefix)Pstat.txt"
			$Commands = @(
				"$global:PstatPath | Out-File -Append $outfile"
			)
			RunCommands $LogPrefixRFL $Commands -ThrowException:$False -ShowMessage:$True
		} catch {
			LogException "An Exception happend when running $global:PstatPath" $_
		}
	}else{ LogInfo "Skipping Pstat in Lite mode"}

    # Make RFLcheck happy, create dummy _sym_.txt file, collect hotfix
    Write-Output $_line | Out-File -Append ($_prefix+"sym_.csv")

	if (Test-Path -Path `"$($_prefix)Hotfix-WMIC.txt`"){
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("$($_prefix)Hotfix-WMIC.txt", "$($_prefix)Hotfixes.csv")
		)
		FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
    }else{
        Get-CimInstance -ClassName win32_quickfixengineering | Out-File -Append "$($_prefix)Hotfixes.csv"
    }
    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION GENERALPERFMONFunc ####################

#################### FUNCTION AppLockerFunc ####################
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function Get-DNDAppLocker
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefixAppLocker = "AppLocker"
    LogInfo ("[$LogPrefixAppLocker] Getting Applocker policy.")
    Get-AppLockerPolicy -Effective -Xml | Out-File -Append "$($_prefix)AppLockerPolicy.xml"

    EndFunc $MyInvocation.MyCommand.Name
}
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#################### END OF FUNCTION AppLockerFunc ####################



#For SetupCollector
Function CollectDND_SETUPLog
{
    EnterFunc $MyInvocation.MyCommand.Name
	# do we run elevated?
    if (!(FwIsElevated) -or ($Host.Name -match "ISE Host"))
    {
		if ($Host.Name -match "ISE Host")
        {
			LogInfo "Exiting on ISE Host." "Red"
		}
		LogInfo 'This script needs to run from elevated command/PowerShell prompt.' "Red"
        return
    }

    # =================================================================
    # Create Output Folder and Log File
    # =================================================================

    Write-Output "Creating Output Folder and Log File"

    $_EXPORTDIR = "$LogFolder\DnDLog$LogSuffix"
    FwCreateLogFolder $_EXPORTDIR

    $_COMMANDLOG = $_EXPORTDIR + '\COMMANDLOG.log'

    Write-Output "... done.`n"
    Write-Output "Create Output Folder and Log File`n... done.`n" | Out-File -Append $_COMMANDLOG


    # =================================================================
    # Collect Driver information
    # =================================================================
    Write-Output 'Collecting Driver information'
    Write-Output 'Collecting Driver information' | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\Driver') -ItemType directory

    driverquery /fo csv /v                                                                                        > ($_EXPORTDIR+'\Driver\driverquery.csv')
    pnputil -e                                                                                                    > ($_EXPORTDIR+'\Driver\pnputil_enum.txt')
    dism /online /get-drivers                                                                                     > ($_EXPORTDIR+'\Driver\DISM_Drivers.txt')
    Get-CimInstance Win32_PnPEntity | Out-File -Append ($_EXPORTDIR+'\Driver\wmi_PnPEntity.txt')

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect System information
    # =================================================================

    Write-Output "Collecting System information"
    Write-Output "Collecting System information" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\System') -ItemType directory

	FwGetMsInfo32 "nfo" -Subfolder "Setup_Report$LogSuffix"
	FwGetSysInfo -Subfolder "Setup_Report$LogSuffix"
    Get-CimInstance -ClassName win32_quickfixengineering | Out-File -Append ($_EXPORTDIR + '\System\wmic_qfe_list.txt')
    Get-HotFix | Select-Object * | Out-File -Append ($_EXPORTDIR + '\System\get-hotfix.log')
    gpresult /h ($_EXPORTDIR + '\System\gpresult.html') 2>&1
    bcdedit /enum all > ($_EXPORTDIR + '\System\BCDedit.log') 2>&1
    schtasks /query /v > ($_EXPORTDIR + '\System\schtasks_query_v.txt') 2>&1
    schtasks /query /v /FO CSV > ($_EXPORTDIR + '\System\tasklog.csv') 2>&1
    Get-ScheduledTask | Select-Object * | Out-File -Append ($_EXPORTDIR + '\System\get-scheduledtask.log')
    compact /CompactOS:query > ($_EXPORTDIR + '\System\compactos_query.txt') 2>&1
    BitsAdmin /list /AllUsers /Verbose > ($_EXPORTDIR + '\System\BitsAdmin.log') 2>&1
    tasklist > ($_EXPORTDIR + '\System\tasklist.txt') 2>&1
    tasklist /M > ($_EXPORTDIR + '\System\tasklist-M.txt') 2>&1
    tasklist /SVC > ($_EXPORTDIR + '\System\tasklist-SVC.txt') 2>&1
    Get-Process | Format-Table -Property "Handles","NPM","PM","WS","VM","CPU","Id","ProcessName","StartTime",@{ Label = 'Running Time';Expression={(GetAgeDescription -TimeSpan (new-TimeSpan $_.StartTime))}} -AutoSize | Out-File -Append ($_EXPORTDIR + '\System\get-process.txt')
    Get-CimInstance -ClassName Win32_PnPSignedDriver | Out-File -Append ($_EXPORTDIR + '\System\Win32_PnPSignedDriver.log')
    ipconfig /all > ($_EXPORTDIR + '\System\ipconfig-all.txt') 2>&1
    netsh advfirewall firewall show rule name=all > ($_EXPORTDIR + '\System\firewall.txt') 2>&1
    cscript //nologo ($Env:WinDir + '\System32\slmgr.vbs') /dlv > ($_EXPORTDIR + '\System\slmgr_dlv.txt') 2>&1
    cscript //nologo ($Env:WinDir + '\System32\slmgr.vbs') /dlv all > ($_EXPORTDIR + '\System\slmgr_dlv_all.txt') 2>&1

    #if EXIST %~dp0\libs\Checksym%PROCESSOR_ARCHITECTURE%.exe (
    #  %~dp0\libs\Checksym%PROCESSOR_ARCHITECTURE%.exe -F c:\Windows\System32 -R > %_EXPORTDIR%\System\system32Checksym.log 2>&1
    #  %~dp0\libs\Checksym%PROCESSOR_ARCHITECTURE%.exe -F c:\Windows\System32\drivers -R > %_EXPORTDIR%\System\system32driversChecksym.log 2>&1
    #)

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect DISM information
    # =================================================================

    Write-Output "Collecting DISM information"
    Write-Output "Collecting DISM information" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\Dism') -ItemType directory

    dism /Online /Get-Intl > ($_EXPORTDIR + '\Dism\Get_Intl.log') 2>&1
    dism /Online /Get-Packages /Format:Table > ($_EXPORTDIR + '\Dism\Get-Packages.log') 2>&1
    dism /Online /Get-Features /Format:Table > ($_EXPORTDIR + '\Dism\Get-Features.log') 2>&1

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect Disk information
    # =================================================================

    Write-Output "Collecting Disk information"
    Write-Output "Collecting Disk information" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\Disk') -ItemType directory

    Get-Disk | Select-Object * | Out-File -Append ($_EXPORTDIR + '\Disk\get-disk.txt')
    Get-PhysicalDisk | Select-Object * | Out-File -Append ($_EXPORTDIR + '\Disk\get-physicaldisk.txt')
    Get-VirtualDisk | Select-Object * | Out-File -Append ($_EXPORTDIR + '\Disk\get-virtualdisk.txt')
    Get-Partition | Select-Object * | Out-File -Append ($_EXPORTDIR + '\Disk\get-partition.txt')
    Get-Volume | Select-Object * | Out-File -Append ($_EXPORTDIR + '\Disk\get-volume.txt')

    Get-CimInstance Win32_DiskDrive | Out-File -Append ($_EXPORTDIR + '\DISK\Win32_DiskDrive.log')
    Get-CimInstance Win32_DiskPartition | Out-File -Append ($_EXPORTDIR + '\DISK\Win32_DiskPartition.log')
    Get-CimInstance Win32_LogicalDiskToPartition | Out-File -Append ($_EXPORTDIR + '\DISK\Win32_LogicalDiskToPartition.log')
    Get-CimInstance Win32_LogicalDisk  | Out-File -Append ($_EXPORTDIR + '\DISK\Win32_LogicalDisk.log')
    Get-CimInstance Win32_Volume | Out-File -Append ($_EXPORTDIR + '\DISK\Win32_Volume.log')

    #if EXIST %~dp0\libs\dosdev.exe (
    #   %~dp0\libs\dosdev.exe -a > %_EXPORTDIR%\Disk\dosdev.txt 2>&1
    #)

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect  Power infomation
    # =================================================================
    Write-Output "Collecting Power information"
    Write-Output "Collecting Power information" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\Power') -ItemType directory

    powercfg /qh > ($_EXPORTDIR + '\Power\power-qh.txt') 2>&1
    powercfg /l > ($_EXPORTDIR + '\Power\power-l.txt') 2>&1

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect Service information
    # =================================================================

    Write-Output "Collecting Service information"
    Write-Output "Collecting Service information" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\Service') -ItemType directory

    sc.exe queryex > ($_EXPORTDIR + '\Service\sc_queryex.log') 2>&1
    sc.exe sdshow TrustedInstaller > ($_EXPORTDIR + '\Service\sc_sdshow_TrustedInstaller.log') 2>&1
    sc.exe sdshow wuauserv > ($_EXPORTDIR + '\Service\sc_sdshow_wuauserv.log') 2>&1
    cmd /r Copy ($Env:WinDir + '\System32\LogFiles\SCM\*.EVM*') ($_EXPORTDIR + '\Service') >> $_COMMANDLOG 2>&1

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect Registry information
    # =================================================================

    Write-Output "Collecting registry information"
    Write-Output "Collecting registry information" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\Registry') -ItemType directory

    REG LOAD 'HKLM\COMPONENTS' ($Env:WinDir + '\System32\config\components') >> $_COMMANDLOG 2>&1
    REG SAVE 'HKLM\COMPONENTS' ($_EXPORTDIR + '\registry\COMPONENTS.hiv') >> $_COMMANDLOG 2>&1
    REG EXPORT 'HKLM\COMPONENTS' ($_EXPORTDIR + '\registry\COMPONENTS.reg') >> $_COMMANDLOG 2>&1

    REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion' ($_EXPORTDIR + '\registry\Software.hiv') >> $_COMMANDLOG 2>&1
    REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows NT' ($_EXPORTDIR + '\registry\WindowsNT.hiv') >> $_COMMANDLOG 2>&1
    REG SAVE 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' ($_EXPORTDIR + '\registry\WindowsUpdate.hiv') >> $_COMMANDLOG 2>&1

    REG SAVE 'HKLM\SYSTEM\CurrentControlSet' ($_EXPORTDIR + '\registry\SYSTEM.hiv') >> $_COMMANDLOG 2>&1
    REG SAVE 'HKLM\SYSTEM\DriverDatabase' ($_EXPORTDIR + '\registry\DriverDatabase.hiv') >> $_COMMANDLOG 2>&1
    REG SAVE 'HKLM\SYSTEM\CurrentControlSet\Services' ($_EXPORTDIR + '\registry\Services.hiv') >> $_COMMANDLOG 2>&1
    REG EXPORT 'HKLM\SYSTEM\CurrentControlSet\Services' ($_EXPORTDIR + '\registry\Services.reg') >> $_COMMANDLOG 2>&1

    REG EXPORT 'HKLM\SOFTWARE\Microsoft\NET Framework Setup' ($_EXPORTDIR + '\registry\NETFrameworkSetup.reg') >> $_COMMANDLOG 2>&1

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect Event Log
    # =================================================================

    Write-Output "Collecting eventLogs"
    Write-Output "Collect eventLogs" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR+'\Eventlog') -ItemType directory

    wevtutil export-log System ($_EXPORTDIR + '\EventLog\System.evtx') 2>&1
    wevtutil archive-log ($_EXPORTDIR + '\EventLog\System.evtx') /locale:ja 2>&1
    wevtutil query-events System /f:text > ($_EXPORTDIR + '\eventlog\System.txt') 2>&1

    wevtutil export-log Application ($_EXPORTDIR + '\EventLog\Application.evtx') 2>&1
    wevtutil archive-log ($_EXPORTDIR + '\EventLog\Application.evtx') /locale:ja 2>&1
    wevtutil query-events Application /f:text > ($_EXPORTDIR + '\EventLog\Application.txt') 2>&1

    wevtutil export-log Setup ($_EXPORTDIR + '\EventLog\Setup.evtx') 2>&1
    wevtutil archive-log ($_EXPORTDIR + '\EventLog\Setup.evtx') /locale:ja 2>&1
    wevtutil query-events Setup /f:text > ($_EXPORTDIR + '\EventLog\Setup.txt') 2>&1

    wevtutil export-log Microsoft-Windows-TaskScheduler/Operational ($_EXPORTDIR + '\EventLog\TaskScheduler-Operational.evtx') 2>&1
    wevtutil archive-log ($_EXPORTDIR + '\EventLog\TaskScheduler-Operational.evtx') /locale:ja 2>&1
    wevtutil query-events Microsoft-Windows-TaskScheduler/Operational /f:text > ($_EXPORTDIR + '\EventLog\TaskScheduler-Operational.txt') 2>&1

    $null = New-Item -Path ($_EXPORTDIR+'\Eventlog\Logs') -ItemType directory

    robocopy ($Env:WinDir + '\System32\winevt\Logs') ($_EXPORTDIR + '\EventLog\Logs') /e /COPY:DT >> $_COMMANDLOG 2>&1

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect File information
    # =================================================================

    Write-Output "Collecting file information"
    Write-Output "Collecting File information" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR + '\File') -ItemType directory
    $Commands = @(
		"cmd /r Dir /t:c /a /s /c /n ($Env:WinDir + '\System32\config\') 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\dir_C_WINDOWS_System32_config.log')"
		"icacls ($Env:WinDir + '\System32\config') /t /c 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\icacls_C_WINDOWS_System32_config.log')"
		"cmd /r Dir /t:c /a /s /c /n ($Env:WinDir + '\System32\Drivers\') 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\dir_C_WINDOWS_System32_Drivers.log')"
		"icacls ($Env:WinDir + '\System32\Drivers') /t /c 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\icacls_C_WINDOWS_System32_Drivers.log')"
		"cmd /r Dir /t:c /a /s /c /n ($Env:WinDir + '\SoftwareDistribution\') 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\dir_C_WINDOWS_SoftwareDistribution.log')"
		"icacls ($Env:WinDir + '\SoftwareDistribution') /t /c 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\icacls_C_WINDOWS_SoftwareDistribution.log')"
		"cmd /r Dir /t:c /a /s /c /n ($Env:WinDir + '\inf\') 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\dir_C_WINDOWS_inf.log')"
		"icacls ($Env:WinDir + '\inf') /t /c 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\icacls_C_WINDOWS_inf.log')"
		"cmd /r Dir /t:c /a /s /c /n ($Env:WinDir + '\WinSxS\') 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\dir_C_WINDOWS_WinSxS.log')"
		"icacls ($Env:WinDir + '\WinSxS\catalogs') /t /c  2>&1 | Out-File -Append ($_EXPORTDIR+'\File\icacls_C_WINDOWS_WinSxS_catalogs.log')"
		"cmd /r Dir /t:c /a /s /c /n ($Env:WinDir + '\servicing\Packages') 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\dir_C_WINDOWS_servicing_Packages.log')"
		"icacls ($Env:WinDir + '\servicing\Packages') /t /c  2>&1 | Out-File -Append ($_EXPORTDIR+'\File\icacls_C_servicing_Packages.log')"
		"cmd /r Dir /t:c /a /s /c /n C:\ 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\dir_C.log')"
		"icacls C:\ 2>&1 | Out-File -Append ($_EXPORTDIR+'\File\icacls_C.log')"
	)
    RunCommands "FileInfo" $Commands -ThrowException:$False -ShowMessage:$True

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect Setup Log
    # =================================================================

    Write-Output "Collecting setup logs"
    Write-Output "Collecting setup logs" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR + '\Setup') -ItemType directory
    $null = New-Item -Path ($_EXPORTDIR + '\Setup\C_WINDOWS_Logs') -ItemType directory

    robocopy ($Env:WinDir + '\Logs') ($_EXPORTDIR + '\Setup\C_WINDOWS_Logs') /e /COPY:DT >> $_COMMANDLOG 2>&1

    # for installation
    cmd /r Copy ($Env:WinDir + '\inf\Setupapi.*') ($_EXPORTDIR + '\Setup') >> $_COMMANDLOG 2>&1
    cmd /r Copy ($Env:WinDir + '\WinSxS\pending.xml.*') ($_EXPORTDIR + '\Setup') >> $_COMMANDLOG 2>&1
    cmd /r Copy ($Env:WinDir + '\WinSxS\poqexec.log') ($_EXPORTDIR + '\Setup') >> $_COMMANDLOG 2>&1

    # for windows update
    cmd /r Copy ($Env:WinDir + '\SoftwareDistribution\ReportingEvents.log') ($_EXPORTDIR + '\Setup') >> $_COMMANDLOG 2>&1
    cmd /r Copy ($Env:WinDir + '\WindowsUpdate.log') ($_EXPORTDIR + '\Setup') >> $_COMMANDLOG 2>&1

    $null = New-Item -Path ($_EXPORTDIR + '\Setup\USOShared_Logs') -ItemType directory
    #cmd /r Copy ($Env:programdata + '\USOShared\Logs\*') ($_EXPORTDIR + '\Setup\USOShared_Logs') >> $_COMMANDLOG 2>&1
    xcopy ($Env:programdata + '\USOShared\Logs\*') ($_EXPORTDIR + '\Setup\USOShared_Logs') /E /C /Y >> $_COMMANDLOG 2>&1

    # for windows update - run Get-WindowsUpdateLog cmdlet for Windows10-based OS
    $osver = cmd /r ver | find /i "Version 10.0."
    $osver | Out-File -Append $_COMMANDLOG
    if($osver -match 'Version 10.0.')
    {
        Get-WindowsUpdateLog -LogPath ($_EXPORTDIR + '\Setup\Get-WindowsUpdateLog.log') | Out-File -Append $_COMMANDLOG
    }

    cmd /r Copy ($Env:WinDir + '\IE11_main.log') ($_EXPORTDIR + '\Setup') >> $_COMMANDLOG 2>&1

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect Upgrade Log
    # =================================================================

    Write-Output "Collecting upgrade logs"
    Write-Output "Collecting upgrade logs" | Out-File -Append $_COMMANDLOG

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade') -ItemType directory

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade\C_$Windows.~BT_Sources') -ItemType directory
    robocopy 'C:\$Windows.~BT\Sources' ($_EXPORTDIR + '\Upgrade\C_$Windows.~BT_Sources') /e /COPY:DT /xf '*.esd' '*.wim' '*.dll' '*.sdi' '*.mui' >> $_COMMANDLOG 2>&1

    Start-Sleep -Seconds 3

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade\C_$Windows.~WS_Sources') -ItemType directory
    robocopy 'C:\$Windows.~WS\Sources' ($_EXPORTDIR + '\Upgrade\C_$Windows.~WS_Sources') /e /COPY:DT /xf "*.esd" "*.wim" "*.dll" "*.sdi" "*.mui" >> $_COMMANDLOG 2>&1

    Start-Sleep -Seconds 3

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade\C_Windows_Panther') -ItemType directory
    robocopy ($Env:WinDir + '\Panther') ($_EXPORTDIR + '\Upgrade\C_Windows_Panther') /e /COPY:DT >> $_COMMANDLOG 2>&1

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade\C_Windows_system32_sysprep_Panther') -ItemType directory
    robocopy ($Env:WinDir + '\System32\Sysprep\Panther') ($_EXPORTDIR + '\Sysprep\C_Windows_system32_sysprep_Panther') /e /COPY:DT >> $_COMMANDLOG 2>&1

    Start-Sleep -Seconds 3

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade\C_windows.old_Windows_System32_Winevt_Logs') -ItemType directory
    robocopy 'C:\Windows.old\Windows\System32\Winevt\Logs' ($_EXPORTDIR + '\Upgrade\C_Windows.old_Windows_System32_Winevt_Logs') /e /COPY:DT >> $_COMMANDLOG 2>&1

    Start-Sleep -Seconds 3

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade\C_WINDOWS_servicing_sessions') -ItemType directory
    cmd /r Copy ($Env:WinDir + '\servicing\sessions\*.*') ($_EXPORTDIR + '\Upgrade\C_WINDOWS_servicing_sessions') >> $_COMMANDLOG 2>&1

    Start-Sleep -Seconds 3

    $null = New-Item -Path ($_EXPORTDIR + '\Upgrade\C_$SysReset') -ItemType directory
    robocopy 'C:\$SysReset' ($_EXPORTDIR + '\Upgrade\C_$SysReset') /e /COPY:DT >> $_COMMANDLOG 2>&1

    Start-Sleep -Seconds 3

    #if($osver -match 'Version 10.0.')
    #{
    #  if EXIST %~dp0\libs\SetupDiag.exe (
    #    md %_EXPORTDIR%\Upgrade\SetupDiag >> %_COMMANDLOG% 2>&1
    #    %~dp0\libs\SetupDiag.exe /Output:%_EXPORTDIR%\Upgrade\SetupDiag\Results.log >> %_COMMANDLOG% 2>&1
    #    del %~dp0\libs\SetupDiag.exe.config >> %_COMMANDLOG% 2>&1
    #  )
    #) else (
    #    Write-Output OS version is not Windows 10. Please run offline SetupDiag. >> %_COMMANDLOG%
    #)

    Write-Output "... done.`n"
    Write-Output "... done.`n" | Out-File -Append $_COMMANDLOG

    # =================================================================
    # Collect WSUS Log
    # =================================================================

    # Write-Output Collect WSUS Log

    # if EXIST %~dp0\libs\copylogs.cmd (
    # md %_EXPORTDIR%\WSUS >> %_COMMANDLOG% 2>&1
    # call %~dp0\libs\copylogs.cmd >> %_COMMANDLOG% 2>&1
    # move %~dp0\libs\WULogs-* %_EXPORTDIR%\WSUS >> %_COMMANDLOG% 2>&1
    # )

    # Write-Output ... done.
    # Write-Output.

    Write-Output '-----------------------------------------------------------------'
    Write-Output ('Support log files are saved successfully at' + $_EXPORTDIR)
    Write-Output '-----------------------------------------------------------------'
    Write-Output '-----------------------------------------------------------------'  | Out-File -Append $_COMMANDLOG
    Write-Output ('Support log files are saved successfully at' + $_EXPORTDIR)  | Out-File -Append $_COMMANDLOG
    Write-Output '-----------------------------------------------------------------'  | Out-File -Append $_COMMANDLOG
	FwWaitForProcess $global:msinfo32NFO 300
    EndFunc $MyInvocation.MyCommand.Name
}

# prevent FwCollect_MiniBasicLog from running by using the -noBasicLog switch
# example: .\TSSv2.ps1 -Start -DND_CodeIntegrity -noBasicLog -noUpdate
<#
function CollectDND_CodeIntegrityLog
{
    EnterFunc $MyInvocation.MyCommand.Name
    $global:ParameterArray += "noBasicLog"
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
#>

function DND_CodeIntegrityPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."

    $LogPrefixCodeIntegrity = "CodeIntegrity"
    LogInfo ("[$LogPrefixCodeIntegrity] Starting CIDiag.")
    $CodeIntegrity = @(
		"CIDiag.exe /start"
    )
    RunCommands $LogPrefixCodeIntegrity $CodeIntegrity -ThrowException:$False -ShowMessage:$True

    EndFunc $MyInvocation.MyCommand.Name
}

function  DND_CodeIntegrityPostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."

    #$_tempdir = "$LogFolder\Setup_Report$LogSuffix"
    FwCreateFolder $LogFolder\CIDiag
    $LogPrefixCodeIntegrity = "CodeIntegrity"
    LogInfo ("[$LogPrefixCodeIntegrity] Stopping CIDiag.")
    $CodeIntegrity = @(
		"CIDiag.exe /stop $LogFolder\CIDiag"
    )
    RunCommands $LogPrefixCodeIntegrity $CodeIntegrity -ThrowException:$False -ShowMessage:$True

    EndFunc $MyInvocation.MyCommand.Name
}


Function CollectDND_ServicingLog
{
    EnterFunc $MyInvocation.MyCommand.Name
    # do we run elevated?
    if (!(FwIsElevated) -or ($Host.Name -match "ISE Host"))
    {
		if ($Host.Name -match "ISE Host")
        {
			LogInfo "Exiting on ISE Host." "Red"
		}
		LogInfo 'This script needs to run from elevated command/PowerShell prompt.' "Red"
        return
    }

    $global:ParameterArray += "noBasicLog"

    $_tempdir= "$LogFolder\Servicing$LogSuffix"
    FwCreateLogFolder $_tempdir

    $_prefix="$_tempdir\$Env:COMPUTERNAME" + "_"
    $_robocopy_log="$_tempdir\robocopy.log"
    $_errorfile= $_prefix+'Errorout.txt'
    $_line='--------------------------------------------------------------------------------------------------------'
    # use tss_config.cfg to modify these parameters on the fly as you need them
    # Flush Windows Update logs by stopping services before copying...usually not needed.
    $_flush_logs=0
    # $global:DND_SETUPReport_FlushLogs set in tss_config.cfg?
    if (($DND_SETUPReport_FlushLogs -eq '0') -or ($DND_SETUPReport_FlushLogs -eq '1')) {$_flush_logs = $DND_SETUPReport_FlushLogs}

    # call function CBS and PNP
    Get-DNDCbsPnpInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    Get-DNDSlowProcessing $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectDND_TPMLog
{
    EnterFunc $MyInvocation.MyCommand.Name
	# do we run elevated?
    if (!(FwIsElevated) -or ($Host.Name -match "ISE Host"))
    {
		if ($Host.Name -match "ISE Host")
        {
			LogInfo "Exiting on ISE Host." "Red"
		}
		LogInfo 'This script needs to run from elevated command/PowerShell prompt.' "Red"
        return
    }
    $global:ParameterArray += "noBasicLog"

    $_tempdir= "$LogFolder\TPM$LogSuffix"
    FwCreateLogFolder $_tempdir

    $_prefix="$_tempdir\$Env:COMPUTERNAME" + "_"
    $_robocopy_log="$_tempdir\robocopy.log"
    $_errorfile= $_prefix+'Errorout.txt'
    $_line='--------------------------------------------------------------------------------------------------------'
    $LogPrefix = "TPM"

    if ($_WIN8_OR_LATER)
    {
        if ((Get-Tpm).TpmPresent) { LogWarn LogWarn "[$LogPrefix] TPM not present." }
    }

    # starting MsInfo early
    FwGetMsInfo32 -Subfolder "TPM$LogSuffix" #-Formats TXT
    FwGet-SummaryVbsLog -Subfolder "TPM$LogSuffix"
    FwGetWhoAmI -Subfolder "TPM$LogSuffix"
    FwGetSysInfo -Subfolder "TPM$LogSuffix"

    # call function BitlockerInfo
    Get-DNDReliabilitySummary $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    Get-DNDEventLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
    Get-DNDBitlockerInfo $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs

    EndFunc $MyInvocation.MyCommand.Name
}


### Diag function
function RunDND_SETUPDiag
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    $PathToLogFolder = "$LogFolder\SetupLog$LogSuffix"
    LogInfo "log folder is $PathToLogFolder"

    $filelist = New-Object System.Collections.ArrayList($NULL)

    LogInfo ("Searching log files under " + $PathToLogFolder)
    #--------------------------
    #For SetupCollector
    #--------------------------
    #search for cbs logs and add them
    $cbsPath = Join-Path $PathToLogFolder '\Setup\C_WINDOWS_Logs\CBS\'
    if(Test-Path $cbsPath)
    {
        # expand .cab files and add to filelist.
        Write-Output ("Expanding .cab files under $cbsPath")
        foreach ($file in (Expand-CabFiles -FolderPath $cbsPath))
        {
            Write-Output ("Adding file " + $file)
            $NULL = $filelist.Add($file)
        }
        $cbsFiles = Get-ChildItem -Path ($cbsPath + "\cbs*.log")
        foreach ($file in $cbsFiles)
        {
            $fullPath = $cbsPath + $file.Name
            # skip expanded CBS files which has been included in filelist
            if ($filelist.Contains($fullPath))
            {
                continue
            }
            Write-Output ("Adding file " + $fullPath)
            $NULL = $filelist.Add($fullPath)
        }
    }
    #add  panther logs
    $fullPath = Join-Path $PathToLogFolder "\Upgrade\C_Windows_Panther\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\Upgrade\C_Windows_Panther\NewOs\Panther\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\Upgrade\C_`$Windows.~BT_Sources\Panther\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\Upgrade\C_`$Windows.~BT_Sources\Rollback\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }

    #add  OOBE logs
    $fullPath = Join-Path $PathToLogFolder "\Upgrade\C_Windows_Panther\UnattendGC\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\Upgrade\C_`$Windows.~BT_Sources\Panther\UnattendGC\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }

    #add SYSPREP logs
    $fullPath = Join-Path $PathToLogFolder "\Setup\Syprep_Logs\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }

    foreach ($filename in $filelist)
    {
        Analyze-File($filename)
    }
    if ($filelist)
    {
        Cleanup-TempFolder -FileList $filelist
    }

    LogInfo "Finished analyzing everything. Thank you for using this tool!!!"
    EndFunc $MyInvocation.MyCommand.Name
}

function RunDND_SETUPReportDiagNotWantedAsOfNow
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    $PathToLogFolder = "$LogFolder\Setup_Report$LogSuffix"
    LogInfo "log folder is $PathToLogFolder"

    $filelist = New-Object System.Collections.ArrayList($NULL)

    LogInfo ("Searching log files under " + $PathToLogFolder)
    #--------------------------
    #For SetupReport
    #--------------------------
    #search for cbs logs and add them
    $cbsPath = Join-Path $PathToLogFolder "\Logs\CBS\"
    if(Test-Path $cbsPath)
    {
        # expand .cab files and add to filelist.
        Write-Output ("Expanding .cab files under $cbsPath")
        foreach ($file in (Expand-CabFiles -FolderPath $cbsPath))
        {
            Write-Output ("Adding file " + $file)
            $NULL = $filelist.Add($file)
        }
        $cbsFiles = Get-ChildItem -Path ($cbsPath + "\cbs*.log")
        foreach ($file in $cbsFiles)
        {
            $fullPath = $cbsPath + $file.Name
            # skip expanded CBS files which has been included in filelist
            if ($filelist.Contains($fullPath))
            {
                continue
            }
            Write-Output ("Adding file " + $fullPath)
            $NULL = $filelist.Add($fullPath)
        }
    }
    #add  panther logs
    $fullPath = Join-Path $PathToLogFolder "\UpgradeSetup\win_Panther\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\UpgradeSetup\win_Panther\NewOs\Panther\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\UpgradeSetup\~bt_Panther\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\UpgradeSetup\~bt_Rollback\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    #add  OOBE logs
    $fullPath = Join-Path $PathToLogFolder "\UpgradeSetup\win_Panther\UnattendGC\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    $fullPath = Join-Path $PathToLogFolder "\UpgradeSetup\~bt_Panther\UnattendGC\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }
    #add SYSPREP logs
    $fullPath = Join-Path $PathToLogFolder "\UpgradeSetup\sysprep_Panther\setupact.log"
    if(Test-Path $fullPath)
    {
        Write-Output ("Adding file " + $fullPath)
        $NULL = $filelist.Add($fullPath)
    }

    foreach ($filename in $filelist)
    {
        Analyze-File($filename)
    }
    if ($filelist)
    {
        Cleanup-TempFolder -FileList $filelist
    }

    LogInfo "Finished analyzing everything. Thank you for using this tool!!!"
    EndFunc $MyInvocation.MyCommand.Name
}

<#
class CbsProcessingStartEnd
{
    [bool]   $isStart
    [string] $time
    [string] $info

    CbsProcessingStartEnd([bool]$isStart, [string] $time, [string] $info) {
        $this.isStart = $isStart
        $this.time = $time
        $this.info = $info
    }
}
#>
#------- start of Parse-UpgradeLog -------
Function Parse-UpgradeLog()
{
   	param(
		[parameter(Mandatory=$TRUE)]
		[System.IO.StreamReader]$infile
	)


    $upgrade_begin_time = $NULL
    $upgrade_end_time = $NULL
    $upgrade_failed_time = $NULL
    $upgrade_failed_phase = $NULL
    #$source_os_language = $NULL
    $host_os_edition = $NULL
    $host_os_version = $NULL
    $host_os_build = $NULL
    #$host_os_langid = $NULL
    $host_os_arch = $NULL
    $target_os_edition = $NULL
    $target_os_version = $NULL
    $target_os_lang = $NULL
    $target_os_arch = $NULL
    $has_hardblock = $FALSE
    $has_Conexant_ISST_Audio = $FALSE
    $l_missing_packages = New-Object System.Collections.ArrayList($NULL)
    $l_executing_phases = New-Object System.Collections.ArrayList($NULL)

    Write-Verbose "in Parse-UpgradeLog"

    while( $NULL -ne ($line = $infile.ReadLine()) )
	{

            if($line -Match "SetupHost::Initialize: CmdLine")
            {
                if($line -Match "/Install")
                {
                    $upgrade_begin_time = ($line -Split ",")[0]
                }
                elseif($line -Match "/Success")
                {
                    $upgrade_end_time = ($line -Split ",")[0]
                }
            }

            elseif($line -Match "Failed execution phase")
            {
                $upgrade_failed_time = ($line -split ",")[0]
                $upgrade_failed_phase = ($line -split "Failed execution phase ")[1]
                $upgrade_failed_phase = ($upgrade_failed_phase -split "\.")[0]
            }

            elseif(($line -Match "Setup phase change:") -and ($line -Match "-> \[SetupPhaseError\]"))
            {
                $upgrade_failed_time = ($line -split ",")[0]
                $upgrade_failed_phase = ($line -split "Setup phase change: \[")[1]
                $upgrade_failed_phase = ($upgrade_failed_phase -split "\]")[0]
            }
            elseif( ($line -Match "Target OS: Detected Source Edition") -And ($NULL -eq $host_os_edition) )
            {
                $host_os_edition = ($line -Split "\[")[1]
                $host_os_edition = "[" + ($host_os_edition -Split "`n")[0]
            }
            elseif( ($line -Match "Target OS: Detected Source Version") -And ($NULL -eq $host_os_version) )
            {
                $host_os_version = ($line -Split "\[")[1]
                $host_os_version = "[" + ($host_os_version -Split "`n")[0]
            }
            elseif(($line -match "Host OS Build String") -and ($null -eq $host_os_build))
            {
                $host_os_build = ($line -split "\[")[1]
                $host_os_build = "[" + ($host_os_build -split "`n")[0]
            }
            elseif(($line -match "Target OS: Detected Source Arch") -and ($null -eq $host_os_arch))
            {
                $host_os_arch = ($line -split "\[")[1]
                $host_os_arch = "[" + ($host_os_arch -split "`n")[0]
            }
            elseif(($line -match "Target OS: Edition") -and ($null -eq $target_os_edition))
            {
                $target_os_edition = ($line -split "\[")[1]
                $target_os_edition = "[" + ($target_os_edition -split "`n")[0]
            }
            elseif(($line -match "Target OS: Version") -and ($null -eq $target_os_version))
            {
                $target_os_version = ($line -split "\[")[1]
                $target_os_version = "[" + ($target_os_version -split "`n")[0]
            }
            elseif(($line -match "Target OS: Language") -and ($null -eq $target_os_lang))
            {
                $target_os_lang = ($line -split "\[")[1]
                $target_os_lang = "[" + ($target_os_lang -split "`n")[0]
            }
            elseif(($line -match "Target OS: Architecture") -and ($null -eq $target_os_arch))
            {
                $target_os_arch = ($line -split "\[")[1]
                $target_os_arch = "[" + ($target_os_arch -split "`n")[0]
            }

            elseif($line -match "Executing phase")
            {
                if($line -Match "\[.*\]")
                {
                    foreach ($phase in $Matches[0])
                    {
                        $time = ($line -split ",")[0]
                        $phase = $time + " " + $phase
                        if($l_executing_phases -NotContains $phase)
                        {
                            $null = $l_executing_phases.add($phase)
                        }
                    }
                }
            }
            elseif($line -match "SetupManager: Skipping ActionList supplied path as it doesn\'t exist")
            {
                $packageName = ($line -split "\[")[1]
                $packageName = ($packageName -split "\]")[0]
                $null = $l_missing_packages.add($packageName)
            }

#case #1001
            elseif(($line -match "CSetupHost::OnProgressChanged") -and ($line -match "0x800704C7"))
            {
                $time = ($line -split ",")[0]
                if ($NULL -ne $upgrade_begin_time)
                {
                    Write-Output ("`nProblem:`n" + $time + " Upgrade is cancelled by client. Installation start time: " + $upgrade_begin_time)
                }
                else
                {
                    Write-Output ("`nProblem:`n" + $time + " Upgrade is cancelled by client")
                }
                Write-Output "`nSolution:`nIf you are using SCCM, set the timeout of SCCM to a larger value.`nOr consider upgrading locally using OS image media"
            }

#case #1002
            elseif(($line -match "TargetLanguageIsCompatibleForUpgrade") -and ($line -match "not compatible"))
            {
                $time = ($line -split ",")[0]
                if($line -match "Target language")
                {
                    $targetLanguage = ($line -split "Target language ")[1]
                    $targetLanguage = ($targetLanguage -split " ")[0]
                    Write-Output ("`nProblem:`n" + $time + " Upgrade failed because the target language [", $targetLanguage, "] is not compatible with the host language")
                }
                else
                {
                    Write-Output ("`nProblem:`n" +$time + " Upgrade failed because the target language is not compatible with the host language")
                }
                Write-Output "`nSolution:`nUse an install image that is of the same language as the host system"
            }


#case #1003
            elseif($line -match "SetupUI: Logging EndSession")
            {
                $time = ($line -split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Upgrade is terminated because of logoff or OS shutdown/reboot")
                Write-Output "`nSolution:`nDo not manually logoff or shutdown/reboot the OS during OS upgrade"
            }

#case #1004
            elseif($line -match "checked FeaturesOnDemandDetected, found HardBlock")
            {
                $time = ($line -split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " the following packages are missing (may be due to download failure)")
                foreach( $packageName in $l_missing_packages)
                {
                    Write-Output ("    " + $packageName)
                }
                Write-Output "`nSolution:`nTry install the FeatureOnDemand packages in the list first and then retry the upgrade"
            }

#case #1005
            elseif($line -match "Provider wsc:wica: reports HardBlock")
            {
                $has_hardblock = $True
            }
            elseif(($has_hardblock -eq $True) -and ($line -match "0xC1900208")) #0xC1900208 is MOSETUP_E_COMPAT_INSTALLREQ_BLOCK
            {
                $time = ($line -split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " The system did not pass the compatibility check for the upgrade.(0xc1900208 MOSETUP_E_COMPAT_INSTALLREQ_BLOCK)")
                Write-Output "`nSolution:`nLook at ScanResult.xml to find out what application(s) failed to pass the compatibility check."
                $has_hardblock = $FALSE
            }


#case #1006
            elseif(($line -match "Error 183 while applying object ") -and ($line -match "Shell application requested abort"))
            {
                $time = ($line -split ",")[0]
                $folderName = ($line -split "object ")[1]
                $folderName = ($folderName -split " \[")[0]
                $objName = ($line -split "\[")[1]
                $objName = ($objName -split "\]")[0]
                Write-Output ("`nProblem: `n" + $time + " `"" + $objName + "`" under " + $folderName + " might be corrupted and is causing unexpected error in the Windows shell component")
                Write-Output "`nSolution: `nPlease delete this file and try again"
            }


#case #1007
            elseif($line -match "Conexant ISST Audio")
            {
                $has_Conexant_ISST_Audio = $True
            }
            elseif(($has_Conexant_ISST_Audio -eq $True) -and ($line -match "0x800704C7"))
            {
                $time = ($line -split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Incompatible Conexant ISST audio drivers are detected that failed the upgrade.")
                Write-Output "`nSolution:`nCheck the device manufacturer to see if an updated driver of Conexant ISST Audio is available, or just uninstall the driver."
                $has_Conexant_ISST_Audio = $False
            }


#case #1008
#           elif 'User profile suffix mismatch' in line:
#                print('\nWarning: ')
#                print(line)
#                if supportingFunctions.check_error(line) == '0x000007E7' and 'Error' in line:
#                    time = line.split(',')[0]
#                    print('\nProblem: \n' + time + ' User profile suffix mismatch.')
#                    print('\nSolution: \nPlease check if more than one ProfilePath is linked to a single ProfileList. Reference SR: 120082126002557')

#case #1009
            elseif(($line -match "InsufficientSystemPartitionDiskSpace") -and ($line -match "HardBlock"))
            {
                $time = ($line -split ",")[0]
                $volumeName = ($line -split "partition \[")[1]
                $volumeName = ($volumeName -split "\] ")[0]
                Write-Output ("`nProblem:`n" + $time + " Insufficient disk space on system partition " + $volumeName)
                Write-Output "`nSolution:`nSome 3rd party softwares may have added data to the system partition. `nMount the system partition with `"mountvol {driveletter:} /S`" and then check, under the `"EFI`" folder on the mounted drive, if there are folders other than `"Microsoft`" and `"BOOT`""
                Write-Output "Contact the 3rd party software vendor to check if that folder can be deleted"
            }

#case #1010
            elseif($line -match "User profile suffix mismatch: upgrade asked for")
            {
                $time = ($line -split ",")[0]
                $profileName = ($line -split "upgrade asked for ")[1]
                $profileName = ($profileName -split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Upgrade failed because the profile folder for " + $profileName + " already exists")
                Write-Output "`nSolution:`nThere are many possible causes for this problem. Below are some of the known causes"
                Write-Output "1. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\ProfileList contains multiple SIDs with the same user name"
                Write-Output "   If this is the case, remove the duplicated entries"
                Write-Output "2. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger contains autologger entries for which the FileName is set to be under this profile folder"
                Write-Output "   If this is the case, remove that autologger entry"
                Write-Output "3. Some special shell folder, like CSIDL_COMMON_DESKTOPDIRECTORY, are redirected to somewhere under this profile folder"
                Write-Output "   If this is the case, stop redirecting or redirect it to somewhere else"
            }


#case #1011
            elseif($line -match "BFSVC: BCD Error: Failed to set boot entry order")
            {
                $time = ($line -split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Error when accessing BCD - Boot Configuration Data")
                Write-Output "`nSolution:`nThe device's firmware is restricting access to BCD storage. Please contact device maker for instructions on how to unlock it"
            }

#case 1012
            elseif ($line -match "AppxUpgradeMigrationPlugin.dll:Gather - plugin call timed out")
            {
                $time = ($line -split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Plugin call timed out for AppxUpgradeMigrationPlugin.dll, maybe due to too many user profile.")
                Write-Output "`nSolution:`nChange the timeout value and/or reduce number of user profiles"
                Write-Output "1. Run cmd.exe as administrator and use the following command to change the timeout values"
                Write-Output "SETX MIG_PLUGIN_CALL_TIMEOUT 90 /M"
                Write-Output "SETX MIG_PLUGIN_CALL_TIMEOUT_INTERVALS 60;10 /M"
                Write-Output "2. Delete no longer used user profiles."
            }
#case 1013
            elseif($line -Match "BCD: BcdExportStore: Failed clone BCD")
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + "BCD: BcdExportStore: Failed clone BCD")
                Write-Output "`nSolution:`You may be affected by a filter driver from a third party product, or a drive that is not a system volume may be recognized as a system volume."
                Write-Output "Try the following actions"
                Write-Output "1. execute FU with USB memory removed"
                Write-Output "2. Disable or uninstall any third-party security products or third-party anti-virus software, and then perform FU."
            }
#case 1014 is used outside the loop.
#use case 1015 for next case
    }

#case 1014
#special case. The log ends up with processing the audio driver
    if (($has_Conexant_ISST_Audio) -and ($l_executing_phases.Count -eq 0))
    {
        Write-Output ("`nProblem:`nIncompatible Conexant ISST audio driver causing hang in upgrade.")
        Write-Output "`nSolution:`nCheck the device manufacturer to see if an updated driver of Conexant ISST Audio is available, or just uninstall the driver."
    }

    if($AdditionalLogInformation)
    {
        if(($null -ne $host_os_edition) -and ($null -ne $target_os_edition))
        {
            Write-Output "`nSummary information:"                      #-ForegroundColor Yellow
            Write-Output "         Edition      Arch     Version       Lang"
            Write-Output ("Host:   " + $host_os_edition + " " + $host_os_arch + " "  + $host_os_version)
            Write-Output ("Target: " + $target_os_edition + " " + $target_os_arch + " " + $target_os_version + " " + $target_os_lang + "`n")

            if($null -ne $upgrade_begin_time)
            {
                Write-Output ("Upgrade start time:  " + $upgrade_begin_time)
            }
            if($l_executing_phases.Count -ne 0)
            {
                $i = 1
                $phaseString = "Upgrade phases:`n"
                foreach($phase in $l_executing_phases)
                {
                    if($i -ne $l_executing_phases.Count)
                    {
                        $phaseString += "                     " + $phase + "`n"
                    }
                    else
                    {
                        $phaseString += "                     " + $phase
                    }
                    $i++
                }
                Write-Output $phaseString
            }
            else
            {
                Write-Warning "no executing phase found - upgrade was terminated before [Safe OS] phase"
            }

            if($null -ne $upgrade_end_time)
            {
                Write-Output ("Upgrade end time:    " + $upgrade_end_time)
            }
            elseif($null -ne $upgrade_failed_time)
            {
                if($null -ne $upgrade_failed_phase)
                {
                    Write-Output ("Upgrade failed time: " + $upgrade_failed_time + " `(At " + $upgrade_failed_phase + " phase`)")
                }
                else
                {
                    Write-Output ("  Upgrade failed time: " + $upgrade_failed_time)
                }
            }
            else
            {
                Write-Warning "didn't find upgrade end time"
            }
        }
        else
        {
            Write-Output $host_os_edition
            Write-Output $target_os_edition
        }

    }
}

#-------   end of Parse-UpgradeLog() -------




#------- Start of Parse-SysprepLog -------
Function Parse-SysprepLog()
{
   	param(
		[parameter(Mandatory=$TRUE)]
		[System.IO.StreamReader]$infile
	)
    $has_package_blocking_sysprep = $FALSE
    $l_package_blocking_sysprep = New-Object System.Collections.ArrayList($NULL)

    Write-Verbose "in Parse-SysprepLog"

    while( $NULL -ne ($line = $infile.ReadLine()) )
	{


#case #3001
            if($line -Match "was installed for a user, but not provisioned for all users. This package will not function properly in the sysprep image")
            {
                $has_package_blocking_sysprep = $TRUE
                $packageName = ($line -Split "SYSPRP Package ")[1]
                $packageName = ($packageName -Split " ")[0]
                $addToList = $TRUE
                foreach ($item in $l_package_blocking_sysprep)
                {
                    if($item -eq $packageName)
                    {
                        $addToList = $FALSE
                        break;
                    }
                }
                if($addToList -eq $TRUE)
                {
                    $NULL = $l_package_blocking_sysprep.Add($packageName)
                }
            }
#case #3002
            elseif( ($line -Match "SYSPRP Failed while deleting repository files") -And ($line -Match "0x80070005") )
            {
                $time = ($line -Split "," )[0]
                Write-Output ("`nProblem:`n" + $time + " ERROR_ACCESS_DENIED when deleting repository files.")
                Write-Output "`nSolution:`nMake sure you are using the built-in Administrator account to run SYSPREP.`nPlease also check https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--system-preparation--overview#unsupported-scenarios"
            }


#case #3003
            elseif( ($line -Match "Audit mode can\'t be turned on if there is an active scenario") -And ($line -Match "0x800F0975") )
            {
                $time = ($line -Split "," )[0]
                Write-Output ("`nProblem:`n" + $time + " SYSPREP failed to enter Audit mode, probably because Windows Update is currently using reserved storage.")
                Write-Output "`nSolution:`nTry disconnect the device from network, then carry out the following steps to cancel any in-progress Windows Update session, and rerun SYSPREP:"
                Write-Output "1. Go to Settings -> Update & Security -> Windows Update -> Advanced options -> Pause updates, and Set `"Pause until`" to anytime in the future"
                Write-Output "2. Set `"ActiveScenario`" under `"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager`" to 0 "
            }

#case #3004
            elseif( ($line -Match "Failure occurred while executing") -And ($line -Match "clipc.dll") -And ($line -Match "0xc0020036") )
            {
                $time = ($line -Split "," )[0]
                Write-Output ("`nProblem:`n" + $time + " SYSPREP failed probably because Client License Service (ClipSVC) is disabled.")
                Write-Output "`nSolution:`nPlease enable Client License Service (ClipSVC)"
            }

#case #3005
            elseif($line -Match "Failed to delete Authentication key subtree")
            {
                $time = ($line -Split "," )[0]
                Write-Output ("`nProblem:`n" + $time + ' SYSPREP failed to delete registry subtree under HKCU\Software\Microsoft\Windows\CurrentVersion\Authentication')
                Write-Output "`nSolution:`nCheck if the Administrators group is not given full control access to any of the subkeys under HKCU\Software\Microsoft\Windows\CurrentVersion\Authentication"
                Write-Output "If not, add full control access for the Adminstrators group to that key"
            }

#case #3006
            elseif($line -Match "Failed to remove staged package")
            {
                $time = ($line -Split "," )[0]
                $packageName = ($line -Split "Failed to remove staged package ")[1]
                $packageName = ($packageName  -Split ":")[0]
                Write-Output ("`nProblem:`n" + $time + ' SYSPREP failed to remove staged package ' + $packageName + '.')
                Write-Output ("`nSolution:`nRemove the " + $packageName + " package manually.")
                Write-Output "If the package is not a system app, then you can use `"Remove-AppxPackage -Package {pakcagename}`" powershell command to remove it."
                Write-Output "If the package is a system app, please contact Microsoft support on how to remove it."
            }

    }

    if( $has_package_blocking_sysprep -eq $TRUE )
    {
        Write-Output "`nProblem:`nThe following packages are installed but not provisioned for all users, and some of them are causing errors in SYSPREP."
        foreach($item in $l_package_blocking_sysprep)
        {
            Write-Output ('    ' + $item)
        }
        Write-Output "`nSolution:`nTry uninstalling these packages with powershell command `"Get-AppxPackage -Name {package-name} | Remove-AppxPackage`""
    }
}
#------- End of Parse-SysprepLog -------


#------- Start of Parse-OobeLog() -------
Function Parse-OobeLog()
{
   	param(
		[parameter(Mandatory=$TRUE)]
		[System.IO.StreamReader]$infile
	)

    Write-Verbose "in Parse-OobeLog"

    while( $NULL -ne ($line = $infile.ReadLine()) )
	{

#case #2001
            if($line -Match "Not allowed to run the Setupcomplete.cmd, will not run SetupComplete.cmd")
            {
                $time = ($line -Split "," )[0]
                Write-Output ("`nProblem:`n" + $time + " You are using OEM product key for which SetupComplete.cmd is disabled. This may become a problem if you are using SCCM task sequence to upgrade the OS.")
                Write-Output "`nSolution:`nCheck https://support.microsoft.com/en-in/help/4494015 for solutions if you are using SCCM."
            }

#case #2002
            elseif($line -Match  "Failed to read in time zone information for time zone")
            {
                $time = ($line -Split "," )[0]
                $timezoneName = ($line -Split "for time zone ")[1]
                $timezoneName = ($timezoneName -Split " with")[0]
                Write-Output ("`nProblem:`n" + $time + " The time zone information for `"" + $timezoneName + "`" under `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones`" is not in correct format.")
                Write-Output "`nSolution:`nFill in correct data in the above registry setting for the time zone, or delete it."
            }
    }
}
#-------   End of Parse-OobeLog() -------

#-------   Start of Parse-CbsLog() -------
Function Parse-Cbslog
{
	param(
		[parameter(Mandatory=$TRUE)]
		[System.IO.StreamReader]$infile
	)

    $has_manifest_mismatch = $FALSE
    $loading_user_account = $FALSE
    $loading_user_account_sid = $NULL
    $profile_unloaded_sid = $NULL
    $l_corrupt_manifest = New-Object System.Collections.ArrayList($NULL)
    $l_corrupt_files = New-Object System.Collections.ArrayList($NULL)
    #[CbsProcessingStartEnd]$cbsStart
    #$l_cbsprocessing_startend = New-Object System.Collections.ArrayList($NULL)

    $font_detector_has_component = $FALSE
    $font_detector_has_installer = $FALSE
    $font_detector_already_detected = $FALSE

    $EFI_GUID_detector_already_detected = $FALSE

    $network_driver_detector_has_installer = $FALSE
    $network_driver_detector_already_detected = $FALSE

    Write-Verbose "in Parse-CbsLog"

    while( $NULL -ne ($line = $infile.ReadLine()) )
	{
            <#
            if($line -match "Exec: Processing started")
            {
                $time = ($line -Split "," )[0]
                $info = "Session " + ($line -Split "Session" )[1]
                $cbsStart = [CbsProcessingStartEnd]::new($TRUE, $time, $info)
                $null = $l_cbsprocessing_startend.add($cbsStart)

            }
            elseif($line -match "Exec: Processing complete")
            {
                $time = ($line -Split "," )[0]
                $info = "Session " + ($line -Split "Session" )[1]
                $cbsEnd = [CbsProcessingStartEnd]::new($FALSE, $time, $info)
                $null = $l_cbsprocessing_startend.add($cbsEnd)
            }
            #>

#case #1
#Disable this one for now because it is too noisy.
#            if 'Higher version found for package: Package_for_RollupFix' in line:
#                #only choose the RollupFix ones for this case. It looks like the lower version of FoD packages are retried and it causes noises.
#                time = line.split(',')[0]
#                InstalledVersion = line.split('Version on system:')[1]
#                InstalledVersion = InstalledVersion.split(')')[0]
#                KBVersion = line.split('Higher version found for package:')[1]
#                KBVersion = KBVersion.split(',')[0]
#                print('\nProblem: \n' + time + ' Windows Update package', KBVersion, 'failed to install because a newer version of KB ', InstalledVersion, ' is already installed on this machine')
#                print('\nSolution: \nYou do not need to install this KB')

#case #2
            if(($line -Match "Error") -and ($line -Match "requires Servicing Stack"))
            {
                $time = ($line -Split "," )[0]
                $SSUVersion = ($line -Split "requires Servicing Stack")[1]
                $SSUVersion = ($SSUVersion -Split " ")[1]
                $KBVersion = ($line -Split "`"")[1]
                $KBVersion = ($KBVersion -Split "`"")[0]
                Write-Output ("`nProblem:`n" + $time + " Windows Update package " + $KBVersion + " failed to install because a newer version of Service Stack Update is required")
                Write-Output ("`nSolution:`nInstall SSU version " + $SSUVersion + " and then retry installing the Windows Update package")
            }

#case #3
            elseif($line -Match "applicable state: Installed Invalid")
            {
                $time = ($line -Split "," )[0]
                $KBNumber = ($line -Split"_for_")[1]
                $KBNumber = ($KBNumber -Split "~")[0]
                Write-Output ("`nProblem:`n" + $time + " Some sub-packages of " + $KBNumber + " that is installed on this machine is marked as InstalledButInvalid")
                Write-Output "`nSolution:`nIn regedit.exe, under `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`", find all instances of `"CurrentState`" that is set to 0xffffff90, and change all the values from  0xffffff90 to 0x70, then reboot and retry the installation"
            }
#case #4
            elseif( ($line -Match "SupplementalServicing") -And ($line -Match "This machine is not eligible for supplemental servicing") )
            {
                $time = ($line -Split "," )[0]
                Write-Output ("`nProblem:`n" + $time + " Trying to install KB on Windows that is out of support")
                Write-Output "`nSolution:`nPlease upgrade to newer, supported versions of Windows 10"
            }
#case #5
            elseif($line -Match "A possible hang was detected on the last boot")
            {
                $time = ($line -Split "," )[0]
                Write-Output ("`nProblem:`n" + $time + " Hang was detected in CBS startup processing")
                Write-Output "`nSolution:`nNeed to troubleshoot why the CBS startup processing is not finished in time."
            }


#case #6
            elseif($line -Match "Manifest hash mismatch")
            {
                $has_manifest_mismatch = $True
                if($line -Match "'.*'")
                {
                    foreach ($filename in $Matches[0])
                    {
                        if($l_corrupt_manifest -NotContains $filename)
                        {
                            $null = $l_corrupt_manifest.add($filename)
                        }
                    }
                }
            }

#case #7
            elseif($line -Match "Failed while processing critical primitive operations queue")
            {
                $time = ($line -Split "," )[0]
                $errorCode = ($line -Split "HRESULT = ")[1]
                $errorCode = ($errorCode -Split "`]")[0]
                Write-Output ("`nProblem:`n" + $time + " Error (" + $errorCode + ") occurred when carrying out primitive operations (operations on files or registries)")
                Write-Output "`nSolution:`n3rd party filesystem filter drivers may cause this problem. Please uninstall 3rd party security softwares and try again"
            }
#case #8
            elseif($line -Match "FOD: Mismatched package")
            {
                $time = ($line -Split "," )[0]
                $cabFile = ($line -Split "Mismatched package: ")[1]
                $cabFile = ($cabFile -Split ",")[0]
                $fodVersion = ($line -Split "FOD identity:")[1]
                $fodVersion = ($fodVersion -Split ",")[0]
                $fodVersion = ($fodVersion -Split "~~")[1]
                $cabVersion = ($line -Split "cab identity:")[1]
                $cabVersion = ($cabVersion -Split "`n")[0]
                $cabVersion = ($cabVersion -Split "~~")[1]
                Write-Output ("`nProblem:`n" + $time + " The version of the FOD package `"" + $cabFile + "`" is not correct. Version of the package provided: " + $cabVersion + ". Version needed: " + $fodVersion)
                Write-Output ("`nSolution:`nDownload the FOD package with version " + $fodVersion + " and try again")
            }

#case #9
            elseif( ($line -Match "Failed to add package") -And ($line -Match "ERROR_DISK_FULL") )
            {
                $time = ($line -Split "," )[0]
                $packageFile = ($line -Split "Failed to add package: ")[1]
                $packageFile = ($packageFile -Split " \[")[0]
                Write-Output ("`nProblem:`n" + $time + " ERROR_DISK_FULL error when installing " + $packageFile)
                Write-Output "`nSolution:`nCleanup the system disk with the Disk Cleanup tool to make more free spaces"
            }


#case #10
            elseif($line -Match "Store corruption, manifest missing for package:")
            {
                $time = ($line -Split ",")[0]
                $packageFile = ($line -Split "Store corruption, manifest missing for package: ")[1]
                $packageFile = ($packageFile -Split "`n")[0]
                Write-Output ("`nProblem:`n" + $time + " Manifest missing for package: " + $packageFile)
                Write-Output "`nSolution:`nDownload the standalone KB package, expand it and install the expanded cab file with `"Dism /online /Add-Package /PackagePath:{full-path-to-the-expanded-cab-file}`""
            }


#case #11
            elseif($line -Match "Exec: Some sessions are pended with exclusive flag set")
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\SessionsPending:Exclusive is not 0. Windows Update will not be installed correctly in this state")
                Write-Output "`nSolution:`nChange the above reg setting to 0 in regedit.exe, and retry installing Windows Update packages"
            }


#case #12
            elseif(($line -Match "STATUS_DELETE_PENDING") -And ($line -Match "SysCreateFile") -And ($line -Match "on:\[") )
            {
                $info_list = $line -Split ","
                $time = $info_list[0]
                foreach ($item in $info_list)
                {
                    if(($item -Match "on:") -and ($item -Match "'.*'"))
                    {
                        foreach ($filename in $Matches[0])
                        {
                            Write-Output ("`nProblem:`n" +  $time + " STATUS_DELETE_PENDING error when opening " + $filename)
                            Write-Output "`nSolution: `nTroubleshoot this file/directory open error using Process Monitor or other filesystem utilities"
                        }
                    }
                }
            }

#case #13
            elseif($line -Match "Loading user account SID")
            {
                $loading_user_account = $TRUE
                $loading_user_account_sid = ($line -Split "SID ")[1]
                $loading_user_account_sid = ($loading_user_account_sid -Split "`n")[0]
            }
            elseif( ($line -Match "Loaded") -And ($line -Match "'user account profiles") )
            {
                $loading_user_account = $FALSE
            }
            elseif( ($line -Match "Error") -And ($line -Match "AutoHive::Load") )
            {
                if( ($loading_user_account -Eq $TRUE) -And ($NULL -ne $loading_user_account_sid) )
                {
                    $time = ($line -Split ",")[0]
                    $errorString = ($line -Split ": Error ")[1]
                    $errorString = ($errorString -Split " ")[0]
                    Write-Output ("`nProblem:`n" + $time + " " + $errorString + " error when loading user profile for user " + $loading_user_account_sid)
                    Write-Output "`nSolution:`nTroubleshoot this profile load error with Process Monitor or other filesystem activity monitoring tools"
                }
            }

#case #14
            elseif($line -Match "STATUS_FILE_CORRUPT_ERROR")
            {
                $info_list = $line -Split ","
                $time = $info_list[0]
                foreach ($item in $info_list)
                {
                    if(($item -Match "on:") -and ($item -Match "`".*`""))
                    {
                        foreach ($filename in $Matches[0])
                        {
                            if($l_corrupt_files -NotContains $filename)
                            {
                                $null = $l_corrupt_files.add($filename)
                                Write-Output ("`nProblem:`n" +  $time + " Component store file corruption detected. File name is: " + $filename)
                                Write-Output "`nSolution: `nRepair the corrupted files by using DISM.exe /Online /Cleanup-image /retorehealth"
                            }
                        }
                    }
                }
            }
#case #15
            elseif( ($line -Match "Error") -And ($line -Match "failed to perform Synchronous Cleanup operation") -And ($line -Match "0x80070002") )
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Error 0x80070002 was detected in component cleanup during Cab file compression.")
                Write-Output "`nSolution:`nThis is a known issue in Windows 10 Version 1607 or earlier. You can ignore this error."
                Write-Output "Please check https://docs.microsoft.com/ja-jp/archive/blogs/askcorejp/componentcleanup_win10 for more details"
            }

#case #16
            elseif( ( ($line -Match "Failed to pin deployment while resolving Update") -And ($line -Match "ERROR_SXS_ASSEMBLY_MISSING") -And ($line -Match "Package_") ) -Or ( ($line -Match "Failed to resolve execution package") -And ($line -Match "ERROR_SXS_ASSEMBLY_MISSING") -And ($line -Match "Package_") ) )
            {
                $time = ($line -Split ",")[0]
                $kbName = ($line -Split "_for_")[1]
                $kbName = ($kbName -Split "~")[0]
                Write-Output ("`nProblem:`n" + $time + " Some components are missing for " + $kbName)
                Write-Output ("`nSolution:`nDownload the standalone "+ $kbName + " package, expand it and install the expanded cab file with `"Dism /online /Add-Package /PackagePath:{full-path-to-the-expanded-cab-file}`"")
            }

#            elseif( ($line -Match "Failed to resolve execution package") -And ($line -Match "ERROR_SXS_ASSEMBLY_MISSING") -And ($line -Match "Package_") )
#            {
#                $time = ($line -Split ",")[0]
#                $kbName = ($line -Split "_for_")[1]
#                $kbName = ($kbName -Split "~")[0]
#                Write-Output "`nProblem:"
#                Write-Output time,  "Some components are missing for", $kbName
#                Write-Output "`nSolution:`nDownload the standalone", $kbName, "package, expand it and install the expanded cab file with `"Dism /online /Add-Package /PackagePath:{full-path-to-the-expanded-cab-file}`""
#            }
#case #17
##            elif 'Manifest hash for component' in line and 'does not match expected value' in line:
##                time = line.split(',')[0]
##                componentName = None
##                if '\"' in line:
##                    componentName = line.split('\"')[1]
##                elif '\'' in line:
##                    componentName = line.split('\'')[1]
##                if componentName is None:
##                    print('\nProblem: \n' + time + ' Found incorrect manifest hash value for components in the component store')
##                else:
##                    print('\nProblem: \n' + time + ' Found incorrect manifest hash value for ' + componentName + ' in the component store')
##                print('\nSolution: \nPlease fix component store corruptions with the \"Dism /Online /Cleanup-Image /RestoreHealth\" command')
##                print('Check https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image for more details')

#case #18
            elseif($line -Match "Store corruption detected in function")
            {
                $time = ($line -Split ",")[0]
                $line = $infile.readline() # read the next line because it contains the resource name
                if($null -eq $line)
                {
                    break
                }
                if($line -Match "on resource")
                {
                    $resourceName = $NULL
                    if($line -Match  "`"")
                    {
                        $resourceName = ($line -Split "`"")[1]
                    }
                    elseif($line -Match "`'")
                    {
                        $resourceName = ($line -Split "`'")[1]
                    }

                    if($NULL -eq $resourceName)
                    {
                        Write-Output ("`nProblem:`n" + $time + " Found corruption in the component store")
                        Write-Output "`nSolution:`nPlease fix component store corruptions with the `"Dism /Online /Cleanup-Image /RestoreHealth`" command"
                        Write-Output "Check https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image for more details"
                    }
                    elseif($resourceName -eq '\Registry\Machine\COMPONENTS\\StoreDirty')
                    {
                        Write-Output ("`nProblem:`n" + $time + " StoreDirty flag is set in component store")
                        Write-Output "`nSolution:`nRun the following commands in an elevated command prompt to delete the StoreDirty flag"
                        Write-Output "1. REG LOAD HKLM\COMPONENTS C:\Windows\System32\config\components"
                        Write-Output "2. REG Delete HKLM\COMPONENTS /v StoreDirty /f"
                    }
                    else
                    {
                        Write-Output ("`nProblem:`n" + $time + " Found corruption in the component store. Resource name is " + $resourceName)
                        Write-Output "`nSolution:`nPlease fix component store corruptions with the `"Dism /Online /Cleanup-Image /RestoreHealth`" command"
                        Write-Output "Check https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image for more details"
                    }
                }
            }


#case #19
            elseif( ($line -Match "STATUS_OBJECT_NAME_NOT_FOUND") -And ($line -Match "SysOpenKey") -And ($line -Match "\\REGISTRY\\USER\\") )
            {
                $profile_unloaded_sid = ($line -Split "\\REGISTRY\\USER\\")[1]
                $profile_unloaded_sid = ($profile_unloaded_sid -Split "`'")[0]
            }
            elseif( ($line -Match "STATUS_OBJECT_NAME_NOT_FOUND") -And ($line -Match "OpenProfileRootKey") -And ($NULL -ne $profile_unloaded_sid) )
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Cannot access user profile for " + $profile_unloaded_sid)
                Write-Output "`nSolution:`nPlease check if there are scheduler tasks that uses the `"At startup`" trigger and the user account for that task is set to the above user"
                Write-Output "If there are such tasks, consider changing the settings for those tasks as follows"
                Write-Output "1. Change the user account to System"
                Write-Output "2. Temporarily disable these tasks when installing Windows updates"
                Write-Output "3. Temporarily enable the `"Do not forcefully unload the users registry at user logoff`" policy under `"Computer Configuration\Administrative Templates\System\User Profiles`""
            }

#case #20
            elseif( ($line -Match "AppX Registration Installer") -And ($line -Match "1058") ) #1058 == ERROR_SERVICE_DISABLED
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Failed to run Appx Registration Installer because the `"App Readiness`" service is disabled")
                Write-Output "`nSolution:`nPlease set the startup type of the `"App Readiness`" service to `"Manual`""
            }

#case #21
            elseif($line -Match "Font")
            {
                $font_detector_has_component = $TRUE
            }
            elseif($line -Match "CSI Cleanup Cache Installer")
            {
                $font_detector_has_installer = $TRUE
            }
            elseif( ($line -Match "Error") -And ($line -Match "MarkFileDeletePending") -And ($font_detector_has_component -Eq $TRUE) -And ($font_detector_has_installer -Eq $TRUE) -And ($font_detector_already_detected -Eq $FALSE) )
            {
                $font_detector_already_detected = $TRUE
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Failed to uninstall Font by CSI Cleanup Cache Installer.")
                Write-Output "`nSolution:`nPlease delete font cache C:\\Windows\\System32\\FNTCACHE.DAT in administrator mode and try again."
                Write-Output "If it cannot be deleted, stop (not disable) the `"Windows Font Cache Service`" service and try again."
            }
#case #22
            elseif( ($line -Match "Failed to get system partition! Last Error = 0x3bc3") -And ($EFI_GUID_detector_already_detected -Eq $FALSE) )
            {
                $EFI_GUID_detector_already_detected = $TRUE
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Failed to update BCD related component as the system partition's attribute is basic, not EFI.")
                Write-Output "`nSolution:`nPlease reallocate EFI GUID to the system partition."
            }

#case #23
            elseif( ($line -Match "Network Drivers") -And ($network_driver_detector_has_installer -Eq $FALSE) )
            {
                $network_driver_detector_has_installer = $TRUE
            }
            elseif( ($line -Match "Error") -And ($line -Match "800106d9") -And ($network_driver_detector_has_installer -Eq $TRUE) -And ($network_driver_detector_already_detected -Eq $FALSE) )
            {
                if( ($line -Match "Failed execution of queue item Installer: Network Drivers") -Or ($line -Match "Network Drivers") )
                {
                    $network_driver_detector_already_detected = $TRUE
                    $time = ($line -Split ",")[0]
                    Write-Output ("`nProblem:`n" + $time + " Failed to update Network Driver.")
                    Write-Output "`nSolution:`nPlease isolate Network Setup Service by running this command below and try installing the KB again."
                    Write-Output "<sc config netsetupsvc type= own>"
                    Write-Output "When finished, run the command below to restore the original setting"
                    Write-Output "<sc config netsetupsvc type= share>"
                }
            }

#case #24
            elseif( ($line -Match "Doqe: Recording result") -And ($line -Match "for Inf") )
            {
                $time = ($line -Split ",")[0]
                $errorCode = ($line -Split "result: ")[1]
                $errorCode = ($errorCode -Split ",")[0]
                $infName = ($line -Split "for Inf: ")[1]
                $infName = ($infName -Split "\n")[0]
                Write-Output ("`nProblem:`n" +$time + " Driver update failed for " + $infName + " with error " + $errorCode)
                Write-Output "`nSolution:`nPlease check $Env:windir\inf\setupapi.dev.log for error details, and also check the registry settings for this driver"
            }


#case #25
            elseif($line -Match "c01a001d") #STATUS_LOG_FULL
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " STATUS_LOG_FULL error occurred")
                Write-Output "`nSolution:`nUse the following steps to reset the transaction logs under %windir%\system32\config\txr"
                Write-Output "1. Download the MoveFile tool from https://docs.microsoft.com/en-us/sysinternals/downloads/movefile"
                Write-Output "2. Run cmd.exe as administrator"
                Write-Output "3. Run the 2 commands below to make the transaction files accessible"
                Write-Output "   cd /d %windir%\system32\config\txr"
                Write-Output "   attrib -r -s -h *"
                Write-Output "4. Move to the folder that contains the Movefile tool, and then run the following commands"
                Write-Output "   movefile.exe `"%windir%\System32\config\TxR\{711988c4-afbd-11e6-80c9-782bcb3928e1}.TxR.0.regtrans-ms`" `"`""
                Write-Output "   movefile.exe `"%windir%\System32\config\TxR\{711988c4-afbd-11e6-80c9-782bcb3928e1}.TxR.1.regtrans-ms`" `"`""
                Write-Output "   movefile.exe `"%windir%\System32\config\TxR\{711988c4-afbd-11e6-80c9-782bcb3928e1}.TxR.2.regtrans-ms`" `"`""
                Write-Output "   movefile.exe `"%windir%\System32\config\TxR\{711988c4-afbd-11e6-80c9-782bcb3928e1}.TxR.blf`" `"`""
                Write-Output "   movefile.exe `"%windir%\System32\config\TxR\{711988c4-afbd-11e6-80c9-782bcb3928e1}.TM.blf`" `"`""
                Write-Output "   movefile.exe `"%windir%\System32\config\TxR\{711988c4-afbd-11e6-80c9-782bcb3928e1}.TMContainer00000000000000000001.regtrans-ms`" `"`""
                Write-Output "   movefile.exe `"%windir%\System32\config\TxR\{711988c4-afbd-11e6-80c9-782bcb3928e1}.TMContainer00000000000000000002.regtrans-ms`" `"`""
                Write-Output "5. Restart your machine"
            }

#case #26
            elseif($line -Match "PerfCounterInstaller Error: Counter database is corrupted")
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " Performace Counter database is corrupt")
                Write-Output "`nSolution:`nUse the following steps to repair the Performance Counter databese"
                Write-Output "1.Run cmd.exe as administrator"
                Write-Output "2. C:\Windows\System32\lodctr /R"
                Write-Output "3. C:\Windows\SysWOW64\lodcrt /R"
            }

#case #27

            elseif ( ($line -Match "Failed to pre- stage package") -And ($line -Match "0x800f0988") )
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " PSFX_E_INVALID_DELTA_COMBINATION error occurred due to file corruption")
                Write-Output "`nSolution:`nPlease run StartComponentCleanup and Restorehealth"
                Write-Output "1. Run cmd.exe as administrator"
                Write-Output "2. DISM.exe /Online /cleanup-image /StartComponentCleanup"
                Write-Output "3. DISM.exe /Online /Cleanup-image /Restorehealth"
            }

#case #28
            elseif ($line -Match "ESU: Failed to Get PKey Info c004f014")
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " ESU: Failed to find product key (SL_E_PKEY_NOT_INSTALLED)")
                Write-Output "`nSolution:`nTry rebuilding the Tokens.dat file with the following steps"
                Write-Output "1. Run cmd.exe as administrator"
                Write-Output "2. net stop sppsvc"
                Write-Output "3. For Windows 10, Windows Server 2016 and later versions of Windows:"
                Write-Output "     cd %windir%\system32\spp\store\2.0"
                Write-Output "   For Windows Server 2012 and Windows Server 2012 R2:"
                Write-Output "     cd %windir%\ServiceProfiles\LocalService\AppData\Local\Microsoft\WSLicense"
                Write-Output "   For Windows 7, Windows Server 2008 and Windows Server 2008 R2:"
                Write-Output "     cd %windir%\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareProtectionPlatform"
                Write-Output "4. ren tokens.dat tokens.bar"
                Write-Output "5. net start sppsvc"
                Write-Output "6. cscript.exe %windir%\system32\slmgr.vbs /rilc"
                Write-Output "7. Restart the computer"
                Write-Output "PLease also check https://docs.microsoft.com/en-US/troubleshoot/windows-server/deployment/rebuild-tokens-dotdat-file"
            }
#case #29
            elseif($line -Match "Failed to get user security token")
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + "Failed to get user security token")
                Write-Output "`nSolution:`nUse the following steps to check your DCOM Settings"
                Write-Output "1. Run the below command as Administrator to open the component service"
                Write-Output "dcomcnfg.exe "
                Write-Output "2. Open Component Services -> Computers -> My Computer -> Properties -> Default Properties, please check if Default Authentication Level is set to Connect, if not, please correct it. The Default Authentication Level is set to none on the issue server"
            }
#case #30

#case #31
            elseif (($line -Match " Failed execution of queue item Installer: Extended Security Updates AI installer ") -And ($line -Match "CRYPT_E_NOT_FOUND"))
               {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " CRYPT_E_NOT_FOUND")
                Write-Output "`nSolution:`nYou may be experiencing a TLS certificate problem. Import additional certificates and apply the update again."
                Write-Output "Download and import the certificates (Microsoft RSA TLS CA 01.crt and Microsoft RSA TLS CA 02.crt) from the URL below."
                Write-Output "URL : microsoft.com/pki/mscorp/cps/default.htm"
               }

#case #32
            elseif (($line -Match "ESU: not eligible") -And ($line -Match "HRESULT_FROM_WIN32\(1633\)"))
            {
                $time = ($line -Split ",")[0]
                Write-Output ("`nProblem:`n" + $time + " ESU license has not been activated")
                Write-Output "`nSolution:`nYou need to install and activate ESU license."
                Write-Output "PLease check https://techcommunity.microsoft.com/t5/windows-it-pro-blog/obtaining-extended-security-updates-for-eligible-windows-devices/ba-p/1167091"
            }

#case #33
            elseif($line -Match "Failed execution of queue item") #this is the general handler of this error. There are 2 specific errors above (#23 #31)
            {
                $time = ($line -Split ",")[0]
                $strItem = ($line -Split "queue item ")[1]
                $strItem = ($strItem -Split " with")[0]
                $strError = ($line -Split "HRESULT_FROM_WIN32")[1]
                $strError = ($strError -Split ". ")[0]
                Write-Output ("`nProblem:`n" + $time + " Error " + $strError + " when executing " + $strItem)
                Write-Output "`nSolution:`nNeed to further investigate this error in details"
            }

    }


#Out of the read-fileline loop
#manifest mismatch
    if($has_manifest_mismatch -Eq $TRUE)
    {
        Write-Output "`nProblem: `nThe following manifests' hashes are incorrect"
        foreach( $item in $l_corrupt_manifest)
        {
            Write-Output ("    " + $item )
        }
        Write-Output "`nSolution: Please fix component store corruptions with the `"Dism /Online /Cleanup-Image /RestoreHealth`" command"
        Write-Output "Check https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image for more details"
    }

    if($AdditionalLogInformation)
    {
        <#
        if($l_cbsprocessing_startend.Count -ne 0)
        {
            Write-Output "`nSummary information:"               #-ForegroundColor Yellow

            foreach( $cbsStartEnd in $l_cbsprocessing_startend)
            {
                if($cbsStartEnd.isStart)
                {
                    Write-Output ("`nCBS Session Start: " + $cbsStartEnd.time + "  Info: " + $cbsStartEnd.info)
                }
                else
                {
                    Write-Output ("CBS Session end:   " + $cbsStartEnd.time + "  Info: " + $cbsStartEnd.info)
                }
            }
        }
        #>
    }
<#
    if has_manifest_mismatch:
        print('\nProblem: \nManifest hash mismatch')
        with open('corrupted_manifest.txt', 'w') as f:
            for item in set(flat_list):
                f.write("%s\n" % item)
        if hivename is None:
            print('\nSuggestion1: See Corrupted_manifest.txt for mismatched manifests. ')
            print('\nSuggestion2: Please also specify .hiv of HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion and rerun as Administrator for further investigation. E.g.: -hiv path_to_software.hiv')
        else
        {
            # Retrieve .reg from .hiv. This needs to be done in Administrator mode.
            temp_hiv = "HKLM\\Temp"
            cbs_hiv = "HKLM\\Temp\\Component Based Servicing"
            os.makedirs('./tmp', exist_ok=True)
            reg_path = "./tmp/CBS_hiv.reg"
            print(hivename.replace('\\', '/'))
            subprocess.run(['reg.exe', 'load', temp_hiv, hivename.replace('\\', '/')])
            subprocess.run(["reg.exe", "export", cbs_hiv, reg_path])
            subprocess.run(["reg.exe", "unload", temp_hiv])

            #testloc = r".\demolog\Component Based Servicing2.reg" #cleng thoughts - need to automate this - retrieve reg file from software.hiv
            # Create registry parser.
            regdata = configparser.ConfigParser()
            with open(reg_path, "r", encoding="utf-16") as f:
                f.readline()  # skip version info in first line
                regdata.read_file(f)
            OCCURANCE = 3
            with open('corrupted_component.csv', 'w') as f:
                f.write('Comp Name, Reg Name, Comp Version, Related KB\n')
                for idx, comp_item in enumerate(set(flat_list)):
                    groups = comp_item.split('_')
                    comp_name, comp_ver= '_'.join(groups[:OCCURANCE]),'_'.join(groups[OCCURANCE:OCCURANCE+1])
                    # Find the related KB specified in the registry.
                    for reg_key in regdata.sections():
                        if comp_name in reg_key:
                            for (each_key, each_val) in regdata.items(reg_key):
                                if comp_ver in each_val:
                                    package_groups = each_key.split('_')
                                    related_KB = '_'.join(package_groups[OCCURANCE:OCCURANCE+1])
                                    related_KB = related_KB.split('~')[0]
                                    print ("processing %d out of %d manifest corruptions." % (idx+1, len(set(flat_list))),end="")
                                    supportingFunctions.backline()
                                    f.write('%s,%s,%s,%s\n' % (comp_item, reg_key, comp_ver,related_KB))
            if os.path.isfile(reg_path):
                os.remove(reg_path)
            print('\n\nSolution: \nCorrupted components with their KB numbers are saved in corrupted_component.csv. Please restore these KBs using "Dism /Online /Cleanup-Image /RestoreHealth /Source:C:\\KBtmp\\cab\\ex /LimitAccess"')
        }
#>
}
#-------   end of Parse-Cbslog() -------



#-------   start of Analyze-File() -------
Function Analyze-File
{
	param(
		[parameter(Mandatory=$TRUE)]
		[String[]]$FileName
	)
    Write-Output ("`n*** Analyzing " + $FileName + " ***")

	$stream_reader = New-Object System.IO.StreamReader -ArgumentList $FileName
	$current_line = $stream_reader.ReadLine()
	if($NULL -ne $current_line)
	{
		if( ($current_line -Match "CBS") -Or ($current_line -Match "CSI") )
		{
			Parse-Cbslog($stream_reader)
		}
		elseif($current_line -Match "MOUPG")
		{
            Parse-UpgradeLog($stream_reader)
		}
		elseif( ($current_line -Match "windeploy.exe") -Or ($current_line -Match "oobe") )
		{
            Parse-OobeLog($stream_reader)
		}
		elseif($current_line -Match "SYSPRP")
		{
            Parse-SysprepLog($stream_reader)
		}
		else
		{
			Write-Output "File type unknown. Going to run all parsers"
            Parse-Cbslog($stream_reader)
            Parse-Upgradelog($stream_reader)
            Parse-OobeLog($stream_reader)
            Parse-SysprepLog($stream_reader)
		}
	}
	$stream_reader.Close()
	Write-Output "`n*** done ***"
}
#-------   end of Analyze-File() -------

#------- start of Expand-CabFiles() -------
Function Expand-CabFiles
{
    param(
        [parameter(Mandatory=$TRUE)]
        [String]$FolderPath
    )

    $cabFiles = Get-ChildItem -Path $FolderPath -Name "*.cab"
    $cabFilePaths = @()
    foreach ($cabFile in $cabFiles)
    {
        # expand cab to LogFolder
        $outFile = Join-Path $FolderPath $cabFile.Replace(".cab", ".log")
        if (Test-Path $outFile)
        {
            Write-Verbose "skip expand cab"
        }
        else
        {
            $NULL = expand (Join-Path $FolderPath $cabFile) $outFile
        }
        if (Test-Path $outFile)
        {
            $cabFilePaths += $outFile
        }
        # expand cab to Local TEMP Folder
        else
        {
            $outFile = Join-Path $env:TEMP $cabFile.Replace(".cab", ".log")
            $NULL = expand (Join-Path $FolderPath $cabFile) $outFile
            if (Test-Path $outFile)
            {
                $cabFilePaths += $outFile
            }
        }
    }

    return $cabFilePaths
}
#------- end of Expand-CabFiles() -------

#------- start of Cleanup-TempFolder() -------
function Cleanup-TempFolder
{
    param(
        [parameter(Mandatory=$TRUE)]
        [String[]]$FileList
    )
#    Write-Output ("Cleanup TEMP Folder.")
    foreach ($file in $FileList)
    {
        if ($file.Contains($env:TEMP))
        {
            Write-Output ("Deleting temporary file " + $file)
            Remove-Item $file -Force
        }
    }
}
#------- end of Cleanup-TempFolder() -------


#------- start of Unzip-Files() -------
function Unzip-Files
{
    param(
        [Parameter(Mandatory=$true)]$rootPath
    )
	EnterFunc $MyInvocation.MyCommand.Name
    Write-Verbose "Entering Unzip-Folder function."

    $zipFiles = Get-ChildItem -Path $rootPath -Filter *.zip

    foreach ($zipFile in $zipFiles)
    {
        $ExpandDestinationPath = $zipFile.FullName.Replace(".zip", "")

        if ((Test-Path $ExpandDestinationPath) -eq $false)
        {
            Write-Verbose ("Unzip file : " + $zipFile.FullName)
            try
            {
                Expand-Archive -Path $zipFile.FullName -DestinationPath $ExpandDestinationPath -ErrorAction Stop
            }
            catch
            {
                Write-Error ("ERROR: Sorry, failed to unzip the file : " + $zipFile.FullName)
                if (Test-Path $ExpandDestinationPath)
                {
                    Remove-Item $ExpandDestinationPath -Confirm:$false -Force
                }
                continue
            }
        }
        else
        {
            Write-Verbose ("Skip unzip : " + $zipFile.FullName)
        }

        if (Test-Path $ExpandDestinationPath)
        {
            if ((Get-ChildItem $ExpandDestinationPath).Count -eq 0)
            {
                continue
            }

            # if the folder name is duplicated.
            if (($tempDir = Get-ChildItem $ExpandDestinationPath -Directory).Count -eq 1)
            {
                Move-Item -Path ($tempDir[0].FullName + "\*") -Destination $ExpandDestinationPath -Force
                Remove-Item $tempDir[0].FullName -Confirm:$false -Force
            }
        }
    }

    Write-Verbose "Leaving Unzip-Folder function."

    return (Get-ChildItem -Path $rootPath -Directory).FullName
	EndFunc $MyInvocation.MyCommand.Name
}
#------- end of Unzip-Files() -------

### Pre-Start / Post-Stop function for trace
<#
function DND_TEST1PreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

function DND_TEST1PostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
#>

Function DND_WUPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    $WUServices = @('uosvc','wuauserv')
    $WUTraceKey = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Trace'
    ForEach($WUService in $WUServices){
        $Service = Get-Service -Name $WUService -ErrorAction SilentlyContinue
        If($Null -eq $Service){
            LogDebug ('[WindowsUpdate] ' + $WUService + ' does not exist in this system.')
            Continue
        }
        If($Service.Status -eq 'Running'){
            LogInfo ('[WindowsUpdate] Stopping ' + $Service.Name + ' service to enable verbose mode.')
            Stop-Service -Name $Service.Name
            $Service.WaitForStatus('Stopped', '00:01:00')
        }
        $Service = Get-Service -Name $Service.Name
        If($Service.Status -ne 'Stopped'){
            $ErrorMessage = ('[WindowsUpdate] Failed to stop ' + $Service.Name + ' service. Skipping Windows Update trace.')
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw ($ErrorMessage)
        }
        LogDebug ('[WindowsUpdate] ' + $WUService + ' was stopped.')
    }

    If(!(Test-Path -Path $WUTraceKey)){
        Try{
            New-Item -Path $WUTraceKey -ErrorAction Stop | Out-Null
        }Catch{
            $ErrorMessage = 'An exception happened in New-ItemProperty'
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw ($ErrorMessage)
        }
    }

    Try{
        New-ItemProperty -Path $WUTraceKey -Name 'WPPLogDisabled' -PropertyType DWord -Value 1 -force -ErrorAction Stop | Out-Null
    }Catch{
        $ErrorMessage = 'An exception happened in New-ItemProperty'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    LogDebug ('[WindowsUpdate] ' + $WUTraceKey + '\WPPLogDisabled was set to 1.')
    EndFunc $MyInvocation.MyCommand.Name
}

Function DND_WUPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    $WUTraceKey = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Trace'
    Try{
        Remove-Item -Path $WUTraceKey -Recurse -force -ErrorAction Stop | Out-Null
    }Catch{
        $ErrorMessage = ("[WUStopTrace] Unable to delete $WUTraceKey")
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    LogDebug ('[WindowsUpdate] ' + $WUTraceKey + ' was deleted.')

    $WUServices = @('uosvc','wuauserv')
    ForEach($WUService in $WUServices){
        $Service = Get-Service -Name $WUService -ErrorAction SilentlyContinue
        If($Null -eq $Service){
            LogDebug ('[WindowsUpdate] ' + $WUService + ' does not exist in this system.')
            Continue
        }
        If($Service.Status -eq 'Running'){
            LogInfo ('[WindowsUpdate] Stopping ' + $Service.Name + ' service to enable verbose mode.')
            Stop-Service -Name $Service.Name
            $Service.WaitForStatus('Stopped', '00:01:00')
        }
        $Service = Get-Service -Name $Service.Name
        If($Service.Status -ne 'Stopped'){
            $ErrorMessage = ('[WindowsUpdate] Failed to stop ' + $Service.Name + ' service. Skipping Windows Update trace.')
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw ($ErrorMessage)
        }
            LogDebug ('[WindowsUpdate] ' + $Service.Name + ' service was stopped.')
    }
    EndFunc $MyInvocation.MyCommand.Name
}


<# ### Pre-Start / Post-Stop function for scenario trace
function DND_MyScenarioTestScenarioPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

function DND_MyScenarioTestScenarioPostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
#>
#endregion Functions

#region Registry Key modules for FwAddRegItem
	<# Example:
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
	#>
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAwG6I9iTvCXS71
# gNAAy8fFMazVi4dYh+RuKl4Il/mTe6CCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZgjCCGX4CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg/IK+jd0k
# ZUO5egegwGsA5lSZgPHOeuKpdhgn4AXhmPowQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCRFXJok428bDeAQV70PdLrJcAH71hlbnlbVaHpc61d
# BLSB3Ttqqjn0RtgO4O9RCL0x9++sAw0jGbwvN6ckJTOX4gE+2+XBddJ/OikLprHx
# hn0uxCn0ZobnWmtyYTZmjowXPgu4YgyzKBQjHmsi44xg5wqmy1pNM5tO3DCsdqY0
# dVcPt3JEGa+ApFaZlD/6++V4PT6putDeA5CoSa4daWlMp1hL8NkVim7N2KqPKj+7
# guaoNXwMKa38F850ek6jks/ahI9skg5z2LbqD60tsrtf1ZPbDt1bErlGZZZbEvSX
# ZPJRDvN6O7XIxJf79oU62YTWORHLLwNUy6NvxkzE+gdSoYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIEjVwEV+r2pDK8tk421JHUfw5ohtpiGPXe3Hd2tw
# jx3tAgZi9DfhEEMYEzIwMjIwODE2MDkxODExLjAwMlowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo3ODgwLUUzOTAtODAxNDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABqFXwYanMMBhcAAEA
# AAGoMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTEyM1oXDTIzMDUxMTE4NTEyM1owgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3ODgw
# LUUzOTAtODAxNDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKPabcrALiXX8pjyXpcM
# N89KTvcmlAiDw4pU+HejZhibUeo/HUy+P9VxWhCX7ogeeKPJ677+LeVdPdG5hTvG
# DgSuo3w+AcmzcXZ2QCGUgUReLUKbmrr06bB0xhvtZwoelhxtPkjJFsbTGtSt+V7E
# 4VCjPdYqQZ/iN0ArXXmgbEfVyCwS+h2uooBhM5UcbPogtr5VpgdzbUM4/rWupmFV
# jPB1asn3+wv7aBCK8j9QUJroY4y1pmZSf0SuGMWY7cm2cvrbdm7XldljqRdHW+CQ
# AB4EqiOqgumfR+aSpo5T75KG0+nsBkjlGSsU1Bi15p4rP88pZnSop73Gem9GWO2G
# RLwP15YEnKsczxhGY+Z8NEa0QwMMiVlksdPU7J5qK9gxAQjOJzqISJzhIwQWtELq
# gJoHwkqTxem3grY7B7DOzQTnQpKWoL0HWR9KqIvaC7i9XlPv+ue89j9e7fmB4nh1
# hulzEJzX6RMU9THJMlbO6OrP3NNEKJW8jipCny8H1fuvSuFfuB7t++KK9g2c2NKu
# 5EzSs1nKNqtl4KO3UzyXLWvTRDO4D5PVQOda0tqjS/AWoUrxKC5ZPlkLE+YPsS5G
# +E/VCgCaghPyBZsHNK7wHlSf/26uhLnKp6XRAIroiEYl/5yW0mShjvnARPr0GIlS
# m0KrqSwCjR5ckWT1sKaEb8w3AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUNsfb4+L4
# UutlNh/MxjGkj0kLItUwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAcTuCS2Rqqmf2mPr6OUydhmUx+m6vpEPszWio
# JXbnsRbny62nF9YXTKuSNWH1QFfyc/2N3YTEp4hE8YthYKgDM/HUhUREX3WTwGse
# YuuDeSxWRJWCorAHF1kwQzIKgrUc3G+uVwAmG/EI1ELRExA4ftx0Ehrf59aJm7On
# gn0lTSSiKUeuGA+My6oCi/V8ETxz+eblvQANaltJgGfppuWXYT4jisQKETvoJjBv
# 5x+BA0oEFu7gGaeMDkZjnO5vdf6HeKneILs9ZvwIWkgYQi2ZeozbxglG5YwExoix
# ekxrRTDZwMokIYxXmccscQ0xXmh+I3vo7hV9ZMKTa9Paz5ne4cc8Odw1T+624mB0
# WaW9HAE1hojB6CbfundtV/jwxmdKh15plJXnN1yM7OL924HqAiJisHanpOEJ4Um9
# b3hFUXE2uEJL9aYuIgksVYIq1P29rR4X7lz3uEJH6COkoE6+UcauN6JYFghN9I8J
# RBWAhHX4GQHlngsdftWLLiDZMynlgRCZzkYI24N9cx+D367YwclqNY6CZuAgzwy1
# 2uRYFQasYHYK1hpzyTtuI/A2B8cG+HM6X1jf2d9uARwH6+hLkPtt3/5NBlLXpOl5
# iZyRlBi7iDXkWNa3juGfLAJ3ISDyNh7yu+H4yQYyRs/MVrCkWUJs9EivLKsNJ2B/
# IjNrStYwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
# DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
# MAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAx
# MDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/
# XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1
# hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7
# M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3K
# Ni1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy
# 1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF80
# 3RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQc
# NIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahha
# YQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkL
# iWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV
# 2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIG
# CSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUp
# zxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBT
# MFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcN
# AQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1
# OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYA
# A7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbz
# aN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6L
# GYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3m
# Sj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0
# SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxko
# JLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFm
# PWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC482
# 2rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7
# vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCC
# AjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3ODgwLUUzOTAtODAxNDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# bLr8xJ9BB4rL4Yg58X1LZ5iQdyyggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOalTccwIhgPMjAyMjA4MTYwMjU3
# MTFaGA8yMDIyMDgxNzAyNTcxMVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5qVN
# xwIBADAKAgEAAgIEGAIB/zAHAgEAAgISYTAKAgUA5qafRwIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBADwZHPVNnCHDTTJ8gRrDzxaZmZkkMHnTgfznOiA5htNe
# 9dWWD6p+izzoAR7ONQgsrLfNtlTOjWqj+KDOseTwQD0g4MA/uJqCkwjMrrFxZiCH
# bzUAEOezf27zu5xrD28WiaT3R1c/7G0dLIYi/NtcbEb9NA7lw0Z2jKlTPf1Ng2yk
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGoVfBhqcwwGFwAAQAAAagwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgk7NorUZXVjrd9hVJzgna
# d8hdkgxB7cU1+LtnbrdzD5wwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCB0
# /ssdAMsHwnNwhfFBXPlFnRvWhHqSX9YLUxBDl1xlpjCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABqFXwYanMMBhcAAEAAAGoMCIEIHYu
# rYSmu+R/kApBk/G2Eysn0kE49VxQoRt4Gb66VjQdMA0GCSqGSIb3DQEBCwUABIIC
# AIlt69cPyue7a5dkFfBWpV1wIGh4ru8GSWN21RH7y0hLM6dLbNhntP6Sk5YXZ2ls
# J/vJFurQQ1c6Zmn8gU8V5W6KqshuX2VsK7kaMPui7A0uYUpizn/tgf2sm8wEpGH6
# KR8/54yh8FNvpUMIKij/9BuaeeZaIDzjaDAU4MkR9b1VN3RmGFCGOgaHRTnkpwQf
# Ej3s7bfnndR+KtTiYaBJOd1OpCVkNJCgu+38DWJIC2FP0caAOcczaoIWPVfOg7BD
# youxMBPPjvQWLDh1QXIDs3eKGNXECUxhy1OXKFq6nuFu06YzmsfnaJBTrOQp6Usy
# DP2wos77u/IGeDibe1nLX6/1OWh6WbWBJOwByyKU4BsHRAZFjvArrNfrsfDfHhbl
# C4n5itA7Ej9UcBIdJq5UBLGFKZShB33aIjJnxu/pekBvr943GFlox3oZGPog/c8n
# FHPBQDxTh9qPZAGPSsA3ekSX/THkrTbQvj5JhUb96IHv8v/zYW7ErUtW0ImYISJK
# 1qwLeXg4D+PwcDO6YVgIoNc8R4Eg7Hue3zqXbhOwxOrXwVIJMtEnjgDcFD+tJAQC
# D9ktz5IASf08BbW8fjRzp/M32xX0dbMUqJNWd+BDf5bWzJbwW7pYlLE5wxjs/+6i
# 5w+9f4UwYI5rpG/8poIVE1y/PvxxaPnct0x+4aogbqSZ
# SIG # End signature block
