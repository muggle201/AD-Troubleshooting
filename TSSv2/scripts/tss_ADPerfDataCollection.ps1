# tss_ADPerfDataCollection.ps1
<# 432728 ADPERF: TOOLS: Domain Controller AD Perf Data Collection Script https://internal.evergreen.microsoft.com/en-us/topic/adperf-tools-domain-controller-ad-perf-data-collection-script-d4959f71-e2bd-061e-4acd-a0b48c52d766
# latest changes:

:: 2022.07.27.1 [we] add Warning for ProcDump on Lsass.exe; adjusted for TSS
:: 2022.07.27.0 [wa]Adjustment for Member servers
#>

<#
	.SYNOPSIS
	Microsoft CSS ADPerf data collection script.
	.DESCRIPTION
	The Microsoft CSS ADPerf data collection scripts are used to diagnose Active Directory related issues on Domain Controllers and member servers.

	The output of this data collection will be in C:\ADPerfData

	.PARAMETER Scenario
	Select one of the following scenarios. (0 - 8)
	0: Interactive
	1: High CPU
	2: High CPU Trigger Start
	3: High Memory
	4: High Memory Trigger Start
	5: Out of ATQ threads on Domain Controller (always trigger start)
	6: Baseline performance (5 minutes)
	7: Long Term Baseline performance
	8: Stop tracing providers (run this if you previously cancelled before script completion)
	.PARAMETER DelayStop
	The number of minutes after the triggered condition has been met that the data collection should stop. (0 - 30)

	If parameter not specified the delay will be 5 minutes in trigger scenarios.
	.PARAMETER Threshold
	The % resource utilization by lsass that will trigger the stop condition. (50 - 100)

	- Used in scenario 2 for CPU threshold.
	- Used in scenario 4 for memory threshold.

	This parameter must be specified in scenario 2 or 4.

	.PARAMETER DumpPreference
	Preferrence for procdump collection. (Full, MiniPlus)
	- Full	  : procdump -ma
	- MiniPlus  : procdump -mp

	Use MiniPlus when retrieving Full dumps takes too long. WARNING: You may experience incompleted call stacks with this option.
	.EXAMPLE
	.\ADPerfDataCollection.ps1											  # Interactive
	.EXAMPLE
	.\ADPerfDataCollection.ps1 -Scenario 1								  # High CPU data collection
	.EXAMPLE
	.\ADPerfDataCollection.ps1 -Scenario 4 -DelayStop 5 -Threshold 80	# High Memory Trigger stop at 80% utilization with 5 minute delay
#>
[CmdletBinding()]
Param(
	$DataPath = $global:LogFolder,	# from TSS script
	[ValidateRange(1, 8)]
	[int]$Scenario = 0,				# reset any previous Scenario
	[ValidateRange(0, 30)]
	[int]$DelayStop = 0,
	[ValidateRange(20, 99)]
	[int]$Threshold = 0,
	[ValidateSet("Full", "MiniPlus")]
	[string]$DumpPreference = "Full",
	[int]$BaseLineTimeMinutes = 5,
	[switch]$AcceptEula
)
$ADperfVer = "2022.07.27.1"			# dated version number
if ([String]::IsNullOrEmpty($DataPath)) {$DataPath="c:"}
if ([String]::IsNullOrEmpty($global:ScriptFolder)) {$global:ScriptFolder="C:\TSSv2\"}
$Script:FieldEngineering = "0"
$Script:NetLogonDBFlags = "0"
$Script:ADPerfFolder = $DataPath + "\ADPerfData"	# final output folder
$Script:DataPath = "$Script:ADPerfFolder"
$Script:Custom1644 = $false
$Script:CustomADDSUsed = $false
$Script:TriggerScenario = $false
[int]$Script:TriggeredTimerLength = 5
$Script:TriggerThreshold = 50
$Script:Interactive = $false
$Script:IsDC = $false

[int]$Script:BaseLineTimeMinutes = $BaseLineTimeMinutes
$PerfLogsRoot = "C:\PerfLogs"								# this is also mentioned in ADDS.xml
$ToolsExeDir = Join-Path $global:ScriptFolder "BIN" 		# from TSS script
$Script:ProcDumpCommand = Join-Path $ToolsExeDir "ProcDump.exe"	# from TSS script
if (!(Test-Path -path $PerfLogsRoot)) {FwCreateFolder $PerfLogsRoot}															 

function ADPerf-Menu {
	Write-Host "============AD Perf Data Collection Tool=============="
	Write-Host "1: High CPU"
	Write-Host "2: High CPU Trigger Start"
	Write-Host "3: High Memory"
	Write-Host "4: High Memory Trigger Start"
	Write-Host "5: Out of ATQ threads on Domain Controller (always trigger start)"
	Write-Host "6: Baseline performance ($Script:BaseLineTimeMinutes minutes)"
	Write-Host "7: Long Term Baseline performance (Wait on User)"
	Write-Host "8: Stop tracing providers (run this if you previously cancelled before script completion)"
	Write-Host "q: Press Q  or Enter to quit"
	Write-Host "======================================================"
}

function CommonTasksCollection {
	if (!$Script:Custom1644 -and $Script:IsDC) {
		Write-Host "Enabling 1644 Events...."
		Enable1644RegKeys
		Write-Host "1644 Events Enabled"
	}
	Write-Host "Turning on Netlogon Debug flags"
	$NetlogonParamKey = get-itemproperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
	$Script:NetLogonDBFlags = $NetlogonParamKey.DBFlag
	New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DBFlag" -Value 0x2080ffff -PropertyType DWORD -Force | Out-Null
	Write-Host "Enabling the AD Data Collector Set...."
	StartADDiagnostics
	StartLSATracing
	StartSamSrvTracing
	Write-Host "SamSrv Tracing Started"
}

function HighCpuDataCollection {
	Write-Host -ForegroundColor Cyan "->1: Gathering Data for High CPU"
	CommonTasksCollection
	Write-Host "Collecting LSASS Process Dumps...."
	GetProcDumps -Count 2 -Seconds 5
	StartWPR "-Start GeneralProfile -Start CPU"
	StartNetTrace
	if ($Script:TriggerScenario) {
		Write-Host "Collecting Data for $Script:TriggeredTimerLength minutes"
		$sleepTime = 60000 * [int]$Script:TriggeredTimerLength
		Start-Sleep -m $sleepTime
	}
	else {
		Write-Host -ForegroundColor Green "HighCpu Data Collection is running..."
		Read-Host "Ensure you have had enough time for the issue to reproduce and then press the [Enter] Key to Stop tracing..."
	}
	StopWPR
	StopNetTrace
	StopADDiagnostics
}

function HighCpuDataCollectionTriggerstart {
	Write-Host -ForegroundColor Cyan "->2: Gathering Data for High CPU Usage Trigger"
	if ($Script:Interactive) {
		while ($true) {
			$CPUThreshold = Read-Host "CPU Percent Threshold(20-99)"
			if ([int]$CPUThreshold -gt 20 -and [int]$CPUThreshold -lt 100) {
				$Script:TriggerThreshold = $CPUThreshold
				break
			}
			else {
				Write-Host "Invalid Input"
			}
		}
		$dataCollectionTime = Read-Host "How long in minutes to collect data after trigger is met?"
		if ([int]$dataCollectionTime -gt 0 -and [int]$dataCollectionTime -lt 31) {
			$Script:TriggeredTimerLength = $dataCollectionTime
		}
		$Script:TriggerScenario = $true
	}
	Write-Host "Waiting for high cpu condition of greater than $Script:TriggerThreshold`0%..."
	While ($true) {
		$CPUValue = get-counter -Counter "\Processor Information(_Total)\% Processor Time" -SampleInterval 5 -MaxSamples 1
		if ($CPUValue.CounterSamples.CookedValue -gt $Script:TriggerThreshold) {
			Write-Host "CPU Usage is Greater than $Script:TriggerThreshold`0% - Starting Data Collection...."
			break
		}
	}
	HighCpuDataCollection
}

function HighMemoryDataCollection {
	Write-Host -ForegroundColor Cyan "->3: Gathering Data for High Memory on a Domain Controller"
	CommonTasksCollection
	StartWPR "-Start GeneralProfile -Start Heap -Start VirtualAllocation"
	Write-Host "Getting Arena Info and Thread State Information..."
	if ($Script:IsDC) { GetRootDSEArenaInfoAndThreadStates }
	Write-Host "Collecting LSASS Process Dump...."
	$lsassProcess = Get-Process "lsass"
	GetProcDumps
	if ($Script:TriggerScenario) {
		Write-Host "Collecting Data for $Script:TriggeredTimerLength minutes"
		$sleepTime = 60000 * [int]$Script:TriggeredTimerLength
		Start-Sleep -m $sleepTime
	}
	else {
		Write-Host -ForegroundColor Green "HighMemory Data Collection is running..."
		Read-Host "Ensure you have had enough time for the issue to reproduce and then press the [Enter] Key to Stop tracing..."
	}
	StopWPR
	StopADDiagnostics
	if ($Script:IsDC) {
		Write-Host "Getting Arena Info and Thread State Information again..."
		GetRootDSEArenaInfoAndThreadStates
	}
}

function HighMemoryDataCollectionTriggerStart {
	Write-Host -ForegroundColor Cyan "->4: Gathering Data for High Memory Usage Trigger"
	if ($Script:Interactive) {
		while ($true) {
			$MemoryThreshold = Read-Host "Memory Percent Threshold(50-99)"
			if ([int]$MemoryThreshold -gt 20 -and [int]$MemoryThreshold -lt 100) {
				$Script:TriggerThreshold = $MemoryThreshold
				break
			}
			else {
				Write-Host "Invalid Input"
			}
		}
		$dataCollectionTime = Read-Host "How long in minutes to collect data after trigger is met?"
		if ([int]$dataCollectionTime -gt 0 -and [int]$dataCollectionTime -lt 31) {
			$Script:TriggeredTimerLength = $dataCollectionTime
		}
		$Script:TriggerScenario = $true
	}
	Write-Host "Attempting to enable RADAR Leak Diag"
	StartRadar
	Write-Host "Waiting for high memory condition of greater than $Script:TriggerThreshold`0%..."
	While ($true) {
		$CommittedBytesInUse = get-counter -Counter "\Memory\% Committed Bytes In Use" -SampleInterval 5 -MaxSamples 1
		if ($CommittedBytesInUse.CounterSamples.CookedValue -gt $Script:TriggerThreshold) {
			Write-Host "Committed Bytes in Use Percentage is Greater than $Script:TriggerThreshold`0% - Starting Data Collection...."
			break
		}
	}
	StopRadar
	HighMemoryDataCollection
}

function ATQThreadDataCollection {
	Write-Host -ForegroundColor Cyan "->5: Gathering Data for ATQ Thread depletion scenario"
	Write-Host ""
	Write-Host "Waiting for ATQ Threads being exhausted..."
	While ($true) {
		$LdapAtqThreads = get-counter -counter "\DirectoryServices(NTDS)\ATQ Threads LDAP" -SampleInterval 5 -MaxSamples 1
		$OtherAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Other" -SampleInterval 5 -MaxSamples 1
		$TotalAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Total" -SampleInterval 5 -MaxSamples 1
		if ($LdapAtqThreads.CounterSamples.CookedValue + $OtherAtqThreads.CounterSamples.CookedValue -eq $TotalAtqThreads.CounterSamples.CookedValue) {
			Write-Host ATQ Threads are depleted - Starting Data Collection....
			break
		}
	}
	Write-Host "Collecting LSASS Process Dumps...."
	GetProcDumps -Count 3 -Seconds 5
	CommonTasksCollection
	Write-Host "Please wait around $Script:BaseLineTimeMinutes minutes while we collect traces.  The collection will automatically stop after the time has elapsed"
	$sleepTime = 60000 * $Script:BaseLineTimeMinutes
	Start-Sleep -m $sleepTime
	StopADDiagnostics
}

function BaseLineDataCollection {
	Write-Host -ForegroundColor Cyan "->6: Gathering Baseline Performance Data"
	if ($Script:IsDC) {
		Write-Host "Enabling 1644 Events with Paremeters to collect all requests...."
		Enable1644RegKeys $true 1 0 0
		Write-Host "1644 Events Enabled"
	}
	CommonTasksCollection
	StartWPR "-Start GeneralProfile -Start CPU -Start Heap -Start VirtualAllocation"
	Write-Host "Collecting LSASS Process Dumps...."
	GetProcDumps -Count 3 -Seconds 5
	Write-Host "Please wait around 5 minutes while we collect performance baseline traces.  The collection will automatically stop after the time has elapsed"
	$sleepTime = 60000 * $Script:BaseLineTimeMinutes
	Start-Sleep -m $sleepTime
	StopWPR
	StopADDiagnostics
}

function LongBaseLineCollection {
	Write-Host -ForegroundColor Cyan "->7: Gathering Baseline Performance Data of a Domain Controller"
	GetProcDumps
	if ($Script:IsDC) {
		Write-Host "Enabling 1644 Events with Paremeters to collect all requests...."
		Enable1644RegKeys $true
		Write-Host "1644 Events Enabled"
	}
	StartADDiagnostics
	Write-Host "Starting Short and Long Perflogs"
	StartPerfLog $true
	StartPerfLog $false
	$NetlogonParamKey = get-itemproperty  -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
	$Script:NetLogonDBFlags = $NetlogonParamKey.DBFlag
	Write-Host -ForegroundColor Green "LongBaseLine Data Collection is running..."
	Read-Host "Ensure you have had enough time for a good baseline and then press the [Enter] Key to Stop tracing..."
	StopADDiagnostics
	StopPerfLogs $true
	StopPerfLogs $false
}

function GetRootDSEArenaInfoAndThreadStates {
	Import-Module ActiveDirectory
	$LdapConnection = new-object System.DirectoryServices.Protocols.LdapConnection(new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($env:computername, 389))
	$msDSArenaInfoReq = New-Object System.DirectoryServices.Protocols.SearchRequest
	$msDSArenaInfoReq.Filter = "(objectclass=*)"
	$msDSArenaInfoReq.Scope = "Base"
	$msDSArenaInfoReq.Attributes.Add("msDS-ArenaInfo") | Out-Null
	$msDSArenaInfoResp = $LdapConnection.SendRequest($msDSArenaInfoReq)
	(($msDSArenaInfoResp.Entries[0].Attributes["msds-ArenaInfo"].GetValues([string]))[0]) | Out-File $Script:DataPath\msDs-ArenaInfo.txt -Append
	Add-Content -Path $Script:DataPath\msDs-ArenaInfo.txt -Value "=========================================================="
	$msDSArenaInfoReq.Attributes.Clear()
	$msDSArenaInfoReq.Attributes.Add("msds-ThreadStates") | Out-Null
	$msDSThreadStatesResp = $LdapConnection.SendRequest($msDSArenaInfoReq)
	(($msDSThreadStatesResp.Entries[0].Attributes["msds-ThreadStates"].GetValues([string]))[0]) | Out-File $Script:DataPath\msDs-ThreadStates.txt -Append
	Add-Content -Path $Script:DataPath\msDs-ThreadStates.txt -Value "=========================================================="
}

function GetProcDumps {
	#Note: Procdump on lsass will fail with Access Denied, see https://mikesblogs.net/access-denied-when-running-procdump/ + https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs
		param(
		[int]$Count = 1,
		[int]$Seconds
	)
	$PDArgs = "lsass.exe "
	if ($PDArgs -like "*lsass*") {
		LogWarn "Procdump on lsass may fail with Access Denied, see https://mikesblogs.net/access-denied-when-running-procdump/ + https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs" "Magenta"
	}
	if ($Script:DumpType -eq "MiniPlus") {
		$PDArgs += "-mp "
	}
	else {
		$PDArgs += " -ma "
	}
	if ($Count -eq 1) { $PDArgs += " -a -r 3 -AcceptEula $Script:DataPath" }
	else { $PDArgs += "-n $Count -s $Seconds -a -r 3 -AcceptEula $Script:DataPath" }
	$procdump = Test-Path "$Script:ProcDumpCommand"
	if ($procdump) {
		try {
			$ps = new-object System.Diagnostics.Process
			$ps.StartInfo.Filename = "$Script:ProcDumpCommand"
			$ps.StartInfo.Arguments = $PDArgs
			$ps.StartInfo.RedirectStandardOutput = $false
			$ps.StartInfo.UseShellExecute = $false
			$ps.start()
			$ps.WaitForExit()
		}
		catch [System.Management.Automation.MethodInvocationException] {
			LogError "Failed to run $Script:ProcDumpCommand $arg"
			Write-Error $_
			Write-Host -ForegroundColor Yellow "Please check the following"
			Write-Host -ForegroundColor Yellow "1. Is LSASS running as PPL?"
			Write-Host -ForegroundColor Yellow "2. Has Windows Defender have Real-Time protection enabled?"
			Write-Host -ForegroundColor Yellow "3. Do you have 3rd party AV blocking process dumps+"
		}
	}
	else {
		Write-Host -ForegroundColor Magenta "Procdump.exe not found at $Script:ProcDumpCommand - Skipping dump collection"
	}
}

function StartRADAR {
	Write-Host -ForegroundColor Gray "-->Enter StartRADAR"
	$lsassProcess = Get-Process "lsass"
	$lsassPid = $lsassProcess.Id.ToString()
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "rdrleakdiag.exe"
	$ps.StartInfo.Arguments = " -p $lsassPid -enable"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<-- Leave StartRADAR"
}

function StopRadar {
	Write-Host -ForegroundColor Gray "-->Enter StopRadar"
	$lsassProcess = Get-Process "lsass"
	$lsassPid = $lsassProcess.Id.ToString()
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "rdrleakdiag.exe"
	$ps.StartInfo.Arguments = " -p $lsassPid -snap -nowatson -nocleanup "
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<-- Leave StopRadar"
}

function StartWPR([string]$arg) {
	Write-Host -ForegroundColor Yellow "Starting Windows Performance Recording..."
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "wpr.exe"
	$ps.StartInfo.Arguments = "$arg"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<-- Leave StartWPR"
}
function StopWPR {
	Write-Host -ForegroundColor Yellow "Stopping Windows Performance Recording (WPR) Tracing"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "wpr.exe"
	$ps.StartInfo.Arguments = " -Stop $Script:DataPath\WPR.ETL"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Yellow "Windows Performance Recording Stopped"
}

function StartADDiagnostics {
	Write-Host -ForegroundColor Yellow "Starting AD Data Collector"
	##Import custom data collector set xml if it exists
	$customADDSxml = Test-path "$PSScriptRoot\ADDS.xml"
	$StartArgs = ' start "system\Active Directory Diagnostics" -ets'
	if ($customADDSxml) {
		Write-Host "Custom Data Collector Set Found - Importing..."
		$ps = new-object System.Diagnostics.Process
		$ps.StartInfo.Filename = "logman.exe"
		$ps.StartInfo.Arguments = ' -import -name "Enhanced Active Directory Diagnostics" ' + " -xml `"$PSScriptRoot\ADDS.xml`" "
		$ps.StartInfo.RedirectStandardOutput = $false
		$ps.StartInfo.UseShellExecute = $false
		$ps.start()
		$ps.WaitForExit()
		$Script:CustomADDSUsed = $true
		Write-Host "Customer Data Collector Set Imported"
		$StartArgs = ' start "Enhanced Active Directory Diagnostics"'
	}
	$ps1 = new-object System.Diagnostics.Process
	$ps1.StartInfo.Filename = "logman.exe"
	$ps1.StartInfo.Arguments = $StartArgs
	$ps1.StartInfo.RedirectStandardOutput = $false
	$ps1.StartInfo.UseShellExecute = $false
	$ps1.start()
	$ps1.WaitForExit()
	Write-Host -ForegroundColor Yellow "AD Data Collector Set Started"
}

function StopADDiagnostics {
	Write-Host -ForegroundColor Yellow "Stopping AD Data Collector Set"
	if ($Script:CustomADDSUsed) {
		$StartArgs = ' stop "Enhanced Active Directory Diagnostics" '
	}
	else {
		$StartArgs = ' stop "system\Active Directory Diagnostics" -ets'
	}
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = $StartArgs
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function StartPerfLog {
	param(
		[bool]$Long
	)
	if ($Long) {
		Write-Host -ForegroundColor Gray "-->Enter StartPerfLog (Long)"
		[string]$StartArg = ' create counter PerfLogLong -o ' + "$Script:DataPath\PerfLogLong.blg" + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* " + "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* " + "\Redirector\* " + "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:05:00"
		$StartArg1 = 'start "PerfLogLong"'
	}
	else {
		Write-Host -ForegroundColor Gray "-->Enter StartPerfLog (Short)"
		[string]$StartArg = ' create counter PerfLogShort -o ' + "$Script:DataPath\PerfLogShort.blg" + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* " + "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* " + "\Redirector\* " + "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:00:05"
		$StartArg1 = ' start "PerfLogShort"'
	}
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = $StartArg
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()

	$ps1 = new-object System.Diagnostics.Process
	$ps1.StartInfo.Filename = "logman.exe"
	$ps1.StartInfo.Arguments = $StartArg1
	$ps1.StartInfo.RedirectStandardOutput = $false
	$ps1.StartInfo.UseShellExecute = $false
	$ps1.Start()
	$ps1.WaitForExit()
	Write-Host -ForegroundColor Yellow "Short / Long Perflogs started"
}

function StopPerfLogs([bool]$Long = $false) {
	if ($Long) {
		Write-Host -ForegroundColor Yellow "Stopping Perflogs (Long)"
		$StartArgs = ' stop "PerfLogLong"'
		$StartArgs1 = ' delete "PerfLogLong"'
	}
	else {
		Write-Host -ForegroundColor Yellow "Stopping Perflogs (Short)"
		$StartArgs = ' stop "PerfLogShort"'
		$StartArgs1 = ' delete "PerfLogShort"'
	}
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = $StartArgs
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()

	$ps1 = new-object System.Diagnostics.Process
	$ps1.StartInfo.Filename = "logman.exe"
	$ps1.StartInfo.Arguments = $StartArgs1
	$ps1.StartInfo.RedirectStandardOutput = $false
	$ps1.StartInfo.UseShellExecute = $false
	$ps1.start()
	$ps1.WaitForExit()
}

function StartLSATracing {
	Write-Host -ForegroundColor Yellow "Starting LSA/LSP Tracing...."
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = " start LsaTrace -p {D0B639E0-E650-4D1D-8F39-1580ADE72784} 0x40141F -o $Script:DataPath\LsaTrace.etl -ets"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	$LSA = get-itemproperty  -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA
	if ($null -eq $LSA.LspDbgTraceOptions) {
		#Create the value and then set it to TRACE_OPTION_LOG_TO_FILE = 0x1,
		New-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions' -PropertyType DWord -Value '0x1'
	}
	elseif ($LSA.LspDbgTraceOptions -ne '0x1') {
		#Set the existing value to 1
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions' '0x00320001'
	}
	if ($null -eq $LSA.LspDbgInfoLevel) {
		New-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgInfoLevel' -PropertyType DWord -Value '0xF000800'
	}
	elseif ($LSA.LspDbgInfoLevel -ne '0xF000800') {
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgInfoLevel' -Value '0xF000800'
	}
	Write-Host -ForegroundColor Yellow "LSA/LSP Tracing Started"
}
function StopLSATracing {
	Write-Host -ForegroundColor Gray "-->Enter StopLSATracing"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = ' stop LsaTrace -ets'
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions'  -Value '0x0'
	Write-Host -ForegroundColor Gray "<--Leave StopLSATracing"
}

function StartSamSrvTracing {
	Write-Host -ForegroundColor Yellow "Starting SamSrv Tracing...."
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = " create trace SamSrv -p {F2969C49-B484-4485-B3B0-B908DA73CEBB} 0xffffffffffffffff 0xff -ow -o $Script:DataPath\SamSrv.etl -ets"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function StopSamSrvTracing {
	Write-Host -ForegroundColor Gray "-->Enter StopSamSrvTracing"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = ' stop SamSrv -ets'
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<--Leave StopSamSrvTracing"
}

function StartNetTrace {
	Write-Host -ForegroundColor Yellow "Starting Network Capture"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "netsh.exe"
	$ps.StartInfo.Arguments = " trace start scenario=netconnection capture=yes tracefile=$Script:DataPath\\nettrace.etl"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function StopNetTrace {
	Write-Host -ForegroundColor Yellow "Stopping Network Capture"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "netsh.exe"
	$ps.StartInfo.Arguments = " trace stop"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function Enable1644RegKeys([bool]$useCustomValues = $false, $searchTimeValue = "50", $expSearchResultsValue = "10000", $inEfficientSearchResultsValue = "1000") {
	##make sure the Event Log is at least 50MB
	$DirSvcLog = Get-WmiObject -Class Win32_NTEventLogFile -Filter "LogFileName = 'Directory Service'"
	$MinLogSize = 50 * 1024 * 1024
	if ($DirSvcLog.MaxFileSize -lt $MinLogSize) {
		Write-Host "Increasing the Directory Service Event Log Size to 50MB"
		Limit-EventLog -LogName "Directory Service" -MaximumSize 50MB
	}
	$registryPathFieldEngineering = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
	$fieldEngineering = "15 Field Engineering"
	$fieldEngineeringValue = "5"
	$DiagnosticsKey = get-itemproperty -Path $registryPathFieldEngineering
	$Script:FieldEngineering = $DiagnosticsKey."15 Field Engineering"
	##$Script:FieldEngineering = get-itemproperty -Path $registryPathFieldEngineering -Name $fieldEngineering
	New-ItemProperty -Path $registryPathFieldEngineering -Name $fieldEngineering -Value $fieldEngineeringValue -PropertyType DWORD -Force | Out-Null
	if ($useCustomValues) {
		$registryPathParameters = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
		$thresholdsKey = get-itemproperty -Path $registryPathParameters
		##Only set custom thresholds if there are none previously defined by customer
		if (($null -eq $thresholdsKey."Search Time Threshold (msecs)") -and ($null -eq $thresholdsKey."Expensive Search Results Threshold") -and ($null -eq $thresholdsKey."Inefficient Search Results Threshold")) {
			$searchTime = "Search Time Threshold (msecs)"
			New-ItemProperty -Path $registryPathParameters -Name $searchTime -Value $searchTimeValue -PropertyType DWORD -Force | Out-Null
			$expSearchResults = "Expensive Search Results Threshold"
			New-ItemProperty -Path $registryPathParameters -Name $expSearchResults -Value $expSearchResultsValue -PropertyType DWORD -Force | Out-Null
			$inEfficientSearchResults = "Inefficient Search Results Threshold"
			New-ItemProperty -Path $registryPathParameters -Name $inEfficientSearchResults -Value $inEfficientSearchResultsValue -PropertyType DWORD -Force | Out-Null
			$Script:Custom1644 = $true
		}
	}
}

function Disable1644RegKeys {
	$registryPathFieldEngineering = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
	$fieldEngineering = "15 Field Engineering"
	New-ItemProperty -Path $registryPathFieldEngineering -Name $fieldEngineering -Value $Script:FieldEngineering -PropertyType DWORD -Force | Out-Null
	if ($Script:Custom1644) {
		##Safest to just remove these entries so it reverts back to default
		$registryPathParameters = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
		$searchTime = "Search Time Threshold (msecs)"
		Remove-ItemProperty -Path $registryPathParameters -Name $searchTime
		$expSearchResults = "Expensive Search Results Threshold"
		Remove-ItemProperty -Path $registryPathParameters -Name $expSearchResults
		$inEfficientSearchResults = "Inefficient Search Results Threshold"
		Remove-ItemProperty -Path $registryPathParameters -Name $inEfficientSearchResults
	}
}

function CorrelateDataAndCleanup {
	##Copy Directory Services Event Log
	if ($Script:IsDC) {
		Copy-Item -Path "$env:SystemRoot\System32\Winevt\Logs\Directory Service.evtx" -dest "$Script:DataPath" -force
	}
	Copy-Item -Path "$env:SystemRoot\Debug\Netlogon.log" -dest $Script:DataPath -Force
	$NetlogonBakExists = Test-Path "$env:SystemRoot\Debug\Netlogon.bak"
	if ($NetlogonBakExists) {
		Copy-Item -Path "$env:SystemRoot\Debug\Netlogon.bak" -dest $Script:DataPath -Force
	}
	Disable1644RegKeys
	New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DBFlag" -Value $Script:NetLogonDBFlags -PropertyType DWORD -Force | Out-Null
	StopLSATracing
	Copy-Item -Path "$env:SystemRoot\Debug\lsp.log" -dest $Script:DataPath -Force
	StopSamSrvTracing
	##Do all the AD Data Collector stuff
	$perflogPath =$PerfLogsRoot + "\ADDS"
	if ($Script:CustomADDSUsed) {
		$perflogPath =$PerfLogsRoot + "\Enhanced-ADDS"	
	}
	Write-Host -ForegroundColor Yellow "Waiting for report.html creation to be complete, this process can take a while to complete..."
	$ADDataCollectorPath = Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 -ErrorAction SilentlyContinue
	## just a fail safe in case for whatever reason the custom ADDS data collector import failed
	if (!$ADDataCollectorPath) {
		Write-Host -ForegroundColor Red "AD Data Collector path was not found... skipping"
		return
	}
	$Attempts = 0;
	while ($true) {
		$reportcomplete = Test-Path "$perflogPath\$ADDataCollectorPath\Report.html"
		if ($reportcomplete -or [int]$Attempts -eq 120) {
			break
		}
		Start-Sleep -Seconds 30
		$Attempts = [int]$Attempts + 1
	}
	if ([int]$Attempts -eq 120) {
		Write-Host "Waited an hour and the report is still not generated, copying just the raw data that is available"
	}
	else {
		Write-Host "Report.html compile completed"
	}
	Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Copy-Item -Destination $Script:DataPath -Recurse -Force
	if ($Script:CustomADDSUsed) {
		## have to clean up the source folder otherwise the subsequent runs will fail as it will try to re-use existing folder name
		Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Remove-Item -Recurse -Force
		$ps1 = new-object System.Diagnostics.Process
		$ps1.StartInfo.Filename = "logman.exe"
		$ps1.StartInfo.Arguments = ' delete "Enhanced Active Directory Diagnostics" '
		$ps1.StartInfo.RedirectStandardOutput = $false
		$ps1.StartInfo.UseShellExecute = $false
		$ps1.start()
		$ps1.WaitForExit()
	}
}
function StopFailedTracing {
	Write-Host -ForegroundColor Cyan "->8:  A previous collection failed or was cancelled prematurely this option will just attempt to stop everything that might still be running"
	StopWPR
	$customADDSxml = Test-path "$PSScriptRoot\ADDS.xml"
	if ($customADDSxml) {
		$Script:CustomADDSUsed = $true
	}
	StopADDiagnostics
	StopLSATracing
	StopSamSrvTracing
	StopPerfLogs $true
	StopPerfLogs $false
	if ($Script:CustomADDSUsed) {
		## have to clean up the source folder otherwise the subsequent runs will fail as it will try to re-use existing folder name
		$perflogPath =$PerfLogsRoot + "\Enhanced-ADDS"
		Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Remove-Item -Recurse -Force
		$ps1 = new-object System.Diagnostics.Process
		$ps1.StartInfo.Filename = "logman.exe"
		$ps1.StartInfo.Arguments = ' delete "Enhanced Active Directory Diagnostics" '
		$ps1.StartInfo.RedirectStandardOutput = $false
		$ps1.StartInfo.UseShellExecute = $false
		$ps1.start()
		$ps1.WaitForExit()
	}
}

[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode) {
	$EULA = New-Object -TypeName System.Windows.Forms.Form
	$richTextBox1 = New-Object System.Windows.Forms.RichTextBox
	$btnAcknowledge = New-Object System.Windows.Forms.Button
	$btnCancel = New-Object System.Windows.Forms.Button
	$EULA.SuspendLayout()
	$EULA.Name = "EULA"
	$EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"
	$richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
	$richTextBox1.Location = New-Object System.Drawing.Point(12, 12)
	$richTextBox1.Name = "richTextBox1"
	$richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
	$richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
	$richTextBox1.TabIndex = 0
	$richTextBox1.ReadOnly = $True
	$richTextBox1.Add_LinkClicked({ Start-Process -FilePath $_.LinkText })
	$richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
	$richTextBox1.BackColor = [System.Drawing.Color]::White
	$btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
	$btnAcknowledge.Name = "btnAcknowledge";
	$btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
	$btnAcknowledge.TabIndex = 1
	$btnAcknowledge.Text = "Accept"
	$btnAcknowledge.UseVisualStyleBackColor = $True
	$btnAcknowledge.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::Yes })

	$btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnCancel.Location = New-Object System.Drawing.Point(669, 415)
	$btnCancel.Name = "btnCancel"
	$btnCancel.Size = New-Object System.Drawing.Size(119, 23)
	$btnCancel.TabIndex = 2
	if ($mode -ne 0) {
		$btnCancel.Text = "Close"
	}
	else {
		$btnCancel.Text = "Decline"
	}
	$btnCancel.UseVisualStyleBackColor = $True
	$btnCancel.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::No })

	$EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
	$EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
	$EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
	$EULA.Controls.Add($btnCancel)
	$EULA.Controls.Add($richTextBox1)
	if ($mode -ne 0) {
		$EULA.AcceptButton = $btnCancel
	}
	else {
		$EULA.Controls.Add($btnAcknowledge)
		$EULA.AcceptButton = $btnAcknowledge
		$EULA.CancelButton = $btnCancel
	}
	$EULA.ResumeLayout($false)
	$EULA.Size = New-Object System.Drawing.Size(800, 650)

	Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode) {
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if (Test-Path $eulaRegPath) {
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else {
		$eulaRegKey = New-Item $eulaRegPath
	}
	if ($mode -eq 2) {
		# silent accept
		$eulaAccepted = "Yes"
		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else {
		if ($eulaAccepted -eq "No") {
			$eulaAccepted = ShowEULAPopup($mode)
			if ($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes) {
				$eulaAccepted = "Yes"
				$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

#region MAIN   =====================================

## EULA
# Show EULA if needed.
If ($AcceptEULA.IsPresent) {
	$eulaAccepted = ShowEULAIfNeeded "AD Perf Data Collection Tool" 2  # Silent accept mode.
}
Else {
	$eulaAccepted = ShowEULAIfNeeded "AD Perf Data Collection Tool" 0  # Show EULA popup at first run.
}
if ($eulaAccepted -eq "No") {
	Write-Error "EULA not accepted, exiting!"
	exit -1
}
$exists = Test-Path $Script:ADPerfFolder
if ($exists) {
	Write-Host "$Script:ADPerfFolder already exists - using existing folder"
}
else {
	New-Item $ADPerfFolder -type directory | Out-Null
	Write-Host "Created AD Perf Data Folder: $ADPerfFolder"
}

Write-Host ""
Write-Host ""

if ($Scenario -eq 0) {
	ADPerf-Menu
	$Script:Interactive = $true
	$Selection = Read-Host "=> Choose the scenario you are troubleshooting"
}
else {
	$Selection = $Scenario
	# Checking for thresholds
	if (($Selection -eq 2 -or $Selection -eq 4) -and $Threshold -eq 0) {
		throw "FATAL: -Threshold must be supplied in scenarios 2 & 4"
	}
	if ($Threshold -ne 0) {
		$Script:TriggerThreshold = $Threshold
		$Script:TriggerScenario = $true
	}
	if ($DelayStop -ne 0) {
		$Script:TriggerScenario = $true
		$Script:TriggeredTimerLength = $DelayStop
	}
}

$DateTime = Get-Date -Format yyyyMMddMMTHHmmss
$Script:DataPath = "$Script:ADPerfFolder\" + $env:computername + "_" + $DateTime + "_Scenario_" + $Selection
if ($Selection -gt 0 -and $Selection -lt 9) {
	New-Item $Script:DataPath -type directory | Out-Null
}
$ComputerInfo = Get-ComputerInfo
if ($ComputerInfo.CsDomainRole -eq "BackupDomainController" -or $ComputerInfo.CsDomainRole -eq "PrimaryDomainController") {
	$Script:IsDC = $true
	Write-Host "Detected running on Domain Controller"
}
else {
	Write-Host "Detected running on Member Server"
}
$Script:DumpType = $DumpPreference
switch ($Selection) {
	1 { HighCpuDataCollection }
	2 { HighCpuDataCollectionTriggerStart }
	3 { HighMemoryDataCollection }
	4 { HighMemoryDataCollectionTriggerStart }
	5 {
		if (!$Script:IsDC) { throw "This scenario is only supported on Domain Controllers" }
		ATQThreadDataCollection
	}
	6 { BaseLineDataCollection }
	7 { LongBaseLineCollection }
	8 { StopFailedTracing }
	'q' {}
}

if ($Selection -gt 0 -and $Selection -lt 8) {
	Write-Host "Copying Data to $ADPerfFolder and performing cleanup"
	if ($Script:IsDC) {
		dcdiag /v | Out-File $Script:DataPath\DCDiag.txt
	}
	tasklist /svc | Out-File $Script:DataPath\tasklist.txt
	tasklist /v /fo csv | Out-File $Script:DataPath\Tasklist.csv
	netstat -anoq | Out-File $Script:DataPath\Netstat.txt
	CorrelateDataAndCleanup
	if ($Script:IsDC) {
		Copy-Item "$env:SystemRoot\system32\ntdsai.dll" -Destination $Script:DataPath
		Copy-Item "$env:SystemRoot\system32\ntdsatq.dll" -Destination $Script:DataPath
	}
	Copy-Item "$env:SystemRoot\system32\samsrv.dll" -Destination $Script:DataPath
	Copy-Item "$env:SystemRoot\system32\lsasrv.dll" -Destination $Script:DataPath
	Copy-Item "$env:Temp\RDR*" -Destination $Script:DataPath -Recurse -Force -ErrorAction SilentlyContinue
	Write-Host -ForegroundColor Green "Data copy is finsihed, please zip the $Script:DataPath folder and upload to DTM"
}

#endregion MAIN   =====================================


# SIG # Begin signature block
# MIIntwYJKoZIhvcNAQcCoIInqDCCJ6QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBxRMKRWpq+pn8i
# B10LNvUn9PPN1DQveWXDr5yAP/TOPqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZjDCCGYgCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgD5C4ujT3
# iLGIqASv8otBXGHjCj2LLMYdLNVftNtBEQgwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBE/bwvwJHr9yHk18igbyh8uCo94gYgjLCNo4fXiA7y
# M+rS4qrw9PtRznyQ85SiHtosv0yKLrygA8GCY9cAaBVHhyKfYJ4mOzF3YA4iXLXa
# /YbtjymTGGY5TBUsH1I4ZBnbFzmmyL0VCbHpIr+EI0/TcoQhod97EPWHuJFUwJmV
# Y+oSOemLhRh+5fpiYys74/bvoEP9IpoeWzo/kKc7zZJljM3AZECYVdJNCdzeDp8J
# GJ2YwJXo+i7H/Cmks3b5FCNNf1++jy8X531+tAsLlHsX/gyNF1PlPhofpsknANdT
# 1p7D+TsxI3PlCfnbf+ecnIevb7Dv0noVjvORazrP6ctuoYIXFjCCFxIGCisGAQQB
# gjcDAwExghcCMIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIGS4rJGZzandIjXyGYANtW2ZNtGN44GGqjkxXVUz
# tp66AgZi3n9zZRoYEzIwMjIwODE2MDkyMDEzLjMzMlowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY5Z20YAqBCU
# zAABAAABjjANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMTEwMjgxOTI3NDVaFw0yMzAxMjYxOTI3NDVaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqiMCq6OM
# zLa5wrtcf7Bf9f1WXW9kpqbOBzgPJvaGLrZG7twgwqTRWf1FkjpJKBOG5QPIRy7a
# 6IFVAy0W+tBaFX4In4DbBf2tGubyY9+hRU+hRewPJH5CYOvpPh77FfGM63+OlwRX
# p5YER6tC0WRKn3mryWpt4CwADuGv0LD2QjnhhgtRVidsiDnn9+aLjMuNapUhstGq
# Cr7JcQZt0ZrPUHW/TqTJymeU1eqgNorEbTed6UQyLaTVAmhXNQXDChfa526nW7RQ
# 7L4tXX9Lc0oguiCSkPlu5drNA6NM8z+UXQOAHxVfIQXmi+Y3SV2hr2dcxby9nlTz
# Yvf4ZDr5Wpcwt7tTdRIJibXHsXWMKrmOziliGDToLx34a/ctZE4NOLnlrKQWN9ZG
# +Ox5zRarK1EhShahM0uQNhb6BJjp3+c0eNzMFJ2qLZqDp2/3Yl5Q+4k+MDHLTipP
# 6VBdxcdVfd4mgrVTx3afO5KNfgMngGGfhSawGraRW28EhrLOspmIxii92E7vjncJ
# 2tcjhLCjBArVpPh3cZG5g3ZVy5iiAaoDaswpNgnMFAK5Un1reK+MFhPi9iMnvUPw
# tTDDJt5YED5DAT3mBUxp5QH3t7RhZwAJNLWLtpTeGF7ub81sSKYv2ardazAe9XLS
# 10tV2oOPrcniGJzlXW7VPvxqQNxe8lCDA20CAwEAAaOCATYwggEyMB0GA1UdDgQW
# BBTsQfkz9gT44N/5G8vNHayep+aV5DAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQA1UK9xzIeTlKhSbLn0bekR5gYh
# 6bB1XQpluCqCA15skZ37UilaFJw8+GklDLzlNhSP2mOiOzVyCq8kkpqnfUc01ZaB
# ezQxg77qevj2iMyg39YJfeiCIhxYOFugwepYrPO8MlB/oue/VhIiDb1eNYTlPSmv
# 3palsgtkrb0oo0F0uWmX4EQVGKRo0UENtZetVIxa0J9DpUdjQWPeEh9cEM+RgE26
# 5w5WAVb+WNx0iWiF4iTbCmrWaVEOX92dNqBm9bT1U7nGwN5CygpNAgEaYnrTMx1N
# 4AjxObACDN5DdvGlu/O0DfMWVc6qk6iKDFC6WpXQSkMlrlXII/Nhp+0+noU6tfEp
# HKLt7fYm9of5i/QomcCwo/ekiOCjYktp393ovoC1O2uLtbLnMVlE5raBLBNSbINZ
# 6QLxiA41lXnVVLIzDihUL8MU9CMvG4sdbhk2FX8zvrsP5PeBIw1faenMZuz0V3UX
# CtU5Okx5fmioWiiLZSCi1ljaxX+BEwQiinCi+vE59bTYI5FbuR8tDuGLiVu/JSpV
# FXrzWMP2Kn11sCLAGEjqJYUmO1tRY29Kd7HcIj2niSB0PQOCjYlnCnywnDinqS1C
# XvRsisjVlS1Rp4Tmuks+pGxiMGzF58zcb+hoFKyONuL3b+tgxTAz3sF3BVX9uk9M
# 5F+OEoeyLyGfLekNAjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUw
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
# ZvKhggLUMIICPQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0
# LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoB
# ATAHBgUrDgMCGgMVAD1iK+pPThHqgpa5xsPmiYruWVuMoIGDMIGApH4wfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmpVUxMCIY
# DzIwMjIwODE2MDcyODQ5WhgPMjAyMjA4MTcwNzI4NDlaMHQwOgYKKwYBBAGEWQoE
# ATEsMCowCgIFAOalVTECAQAwBwIBAAICDqkwBwIBAAICEUcwCgIFAOamprECAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBxq1pnnK7N7J8CIw0SdVDDTa6hHt6i
# 5npYAS5wcWkdeltApLgRQvbriR3+00GWJ2tz40N+hQvXVVwzGtCBgTLZ2+Cw/ytb
# kOQAsMPrSQxv2WJBMcXYKuB/xfajFUbydI0KiIzkW7ckt456SwJqQhgkKNLz9aZS
# fy3Yd+4R9bSXdTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABjlnbRgCoEJTMAAEAAAGOMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEICnkrALp
# K48M84baYDEQPHxwGVRBBmdv6hEKLt5yFEq5MIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgvQWPITvigaUuV5+f/lWs3BXZwJ/l1mf+yelu5nXmxCUwgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY5Z20YAqBCUzAAB
# AAABjjAiBCD19UQHsNkkOXnCWjE3k05LSjnH7yxDcf6FcDFGksclZzANBgkqhkiG
# 9w0BAQsFAASCAgA+W2o/HeH1VGql4YL7L/aUz7qSMMI1FZXRrSdy1a9b5M3REpRi
# CIKZRi6hEi2zLG8wD03fligqle1zs693C6A1Ee7U0KnhjEaNBlmqDJz8yrpbUpeZ
# Q9UXRZrvEIps1dFmedrygp5qtzKvYcvDU4bQ2vnMbZEGBEmILFkvUJXuRnQ1ZeCp
# R0F0Oqbs4FTSGoRYJeBQ9DFBuB8wAHoq1yJTQ1CowyHd54kPaxBy/b91aZ4qFAhU
# JlEl/Dvltlr7vFeipdeSqQkckjwFyZDQKWKdbKMz1q8KSgSfhfBVCPr5+Yzed+Li
# 18CFQx2yo2ttYBYlJhFR8l5QzEpDyMx3OZoM/Ji7uSbzW0JiF/g27eWQJFXrNyIl
# lesc9Xp9A8VuDCuO5jH7FXb/8tZ0UGZBc8J0A3YOkdZoHSCqvPDPHu+1Mgq8Ttp2
# 61XXaRIBEm3gfcFVrjg2yhbDzKQ24yt99JvcIOGlBbKtfWwUyEjS3/i3rBDwJnLY
# cxzaoLnaX5toJ/chzDy0yxV7hy6emf6YhGxyBzKPqHyzWaFCnRmx4nKoOZZZ9+b+
# Ud7KPdoK3tN/Pyj9cHU/T1WbFXY9BZtBcDTwQsn3vgLjgI2y3KhIfj8169ydv/ui
# 9FSBgAuNTcewhIFK0KYktenOT1vratEbisA98BBjNG7j4ApNXOfZ9Q/MoA==
# SIG # End signature block
