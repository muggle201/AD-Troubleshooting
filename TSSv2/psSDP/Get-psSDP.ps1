<# Script name: Get-psSDP.ps1
 Purpose: Powershell Script to collect SDP (Support Diagnostic Platform) report
 Help:  get-help .\Get-psSDP.ps1 -detailed
 Last edit: 2022-01-19
#> 

<#
.SYNOPSIS
The script generates Support Diagnostic Platform files to run in PowerShell window on your system.
One package to collect SDPs for different speciality reports (SDPtech), also able to collect Mini (*_msinfo.*, hotfixes.*, _sym.*, *_pstat.txt) or Nano (network) report.

.DESCRIPTION
The script generates Support Diagnostic files when running in an elevated PowerShell window on your system.
It will collect the same file set as done in classic CSS SDP troubleshooters.
To start data collection, open an elevated PowerShell CMD
Usage:
 .\Get-psSDP.ps1 [Apps|Cluster|S2D|SCCM|CTS|DA|Dom|DPM|HyperV|Net|Perf|Print|RDS|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|SUVP|VSS|Mini|Nano|RFL|Repro|All]

If you get an error that running scripts is disabled, run 
	Set-ExecutionPolicy Bypass -force -Scope Process
and verify with 'Get-ExecutionPolicy -List' that no ExecutionPolicy with higher precedence is blocking execution of this script.
Then run ".\Get-psSDP.ps1 <speciality-of-SDP>" again.

Alternate method#1: to sign .ps1 scripts: run in elevated CMD 
  tss_PS1sign.cmd Get-psSDP
Alternate method#2: run in elevated Powershell: 
 Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass

.PARAMETER savePath
 This switch determines the path for output files
 
.PARAMETER UseExitCode
 This switch will cause the script to close after the error is logged if an error occurs.
 It is used to pass the error number back to the task scheduler or CMD script.

.PARAMETER noNetAdapters
 This switch will skip NetAdapters data collection in network section of SDPs

.PARAMETER runFull
 This switch will run full data collection in SETUP edition of SDPs

.PARAMETER localNodeOnly
 This switch will collect Cluster SDP on local node only
.PARAMETER skipBPA
 This switch will skip all Best Practice Analyzer (BPA) TroubleShooter
.PARAMETER skipHang
 This switch will skip steps in datacollection, that potentially could cause a hang situation during datacollection
 .PARAMETER skipHVreplica
 This switch will skip HyperV Replica script
 .PARAMETER skipCsvSMB
 This switch will skip Cluster tests "Testing accessing shares via SMB..."
.PARAMETER skipNetview
 This switch will skip Get-Netview output
.PARAMETER skipSddcDiag
 This switch will skip PrivateCloud.DiagnosticInfo output
.PARAMETER skipTS
 This switch will skip all TroubleShooter (TS and RC) scripts in TS_AutoAddCommands*.ps1 scripts
.PARAMETER skipTScluster
 This switch will skip Cluster TroubleShooter (TS and RC) scripts in TS_AutoAddCommands*.ps1 scripts
.PARAMETER skipXray
 This switch will skip xray troubleshooter, as it is perhaps already performed in TSS
 
.PARAMETER Transcript
 use -Transcript:$true to start PS Transcription, sometimes you may see error 'Transcription cannot be started.'
 
.PARAMETER sVersion
 use -sVersion to show script version
 
.PARAMETER RoleType
 use -RoleType Client or -RoleType Server to distinguis between roles when using DA SDP
 
.PARAMETER EvtDaysBack
 convert Eventlogs only $EvtDaysBack
.EXAMPLE
 .\Get-psSDP.ps1 Net -savePath C:\temp
 for collecting SDP NETworking Diagnostic data, saving data to folder C:\temp
 
.EXAMPLE
 .\Get-psSDP.ps1 Mini
 for SDP Basic minimal data collection, saving data to current folder
 
.EXAMPLE
  .\Get-psSDP.ps1 Net -NoCab
  .\Get-psSDP.ps1 Net -NoZip
  for SDP Net without zipping results
 
.LINK
email: waltere@microsoft.com
https://github.com/CSS-Windows/WindowsDiag/tree/master/ALL/psSDP
#>

[CmdletBinding()]
PARAM (
	[ValidateSet("Apps","Net","DA","Dom","DPM","CTS","Print","HyperV","Setup","Perf","Cluster","S2D","SCCM","RDS","Remote","SQLbase","SQLconn","SQLmsdtc","SQLsetup","SUVP","VSS","mini","nano","Repro","RFL","All")]
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose one technology from: Apps|Cluster|S2D|SCCM|CTS|DA|Dom|DPM|HyperV|Net|Perf|Print|RDS|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|SUVP|VSS|Mini|Nano|Remote|Repro|RFL|All')]
	[string]$SDPtech = "Net",
	[string]$savePath = "C:\MS_DATA\SDP", # will be $global:LogFolder, if called by TSSv2
	[switch]$NoCab,					# skip zipping results
	[switch]$NoZip,					# skip zipping results
	[switch]$ZipIt,					#
	[int]$EvtDaysBack,				# convert Eventlogs only $EvtDaysBack
	[switch]$noNetAdapters,			# skip NetAdapters data collection in network section of SDPs
	[switch]$skipBPA,				# skip all Best Practice Analyzer (BPA) TroubleShooter
	[switch]$skipNetview,			# skip Get-Netview output
	[switch]$skipSddcDiag,			# skip PrivateCloud.DiagnosticInfo output _SddcDiag*
	[switch]$skipTS,				# skip all TroubleShooter TS and RC scripts in TS_AutoAddCommands*.ps1
	[switch]$skipTScluster,			# skip all TroubleShooter TS and RC scripts in TS_AutoAddCommands*.ps1	
	[switch]$localNodeOnly = $true,	# use -localNodeOnly:$false to try collecting SDP info on all cluster nodes 
	[switch]$skipHang,				# skip steps that potentially could cause a hang situation
	[switch]$skipHVreplica,	# skip HyperV Replica
	[switch]$skipCsvSMB,			# skip Cluster tests "Testing accessing shares via SMB..."
	[switch]$skipXray,				# skip xray troubleshooter
	[switch]$Transcript,			# use -Transcript:$true to start PS Transcription 
	[switch]$runFull,				# use -runFull:$true to run full Data collectors for Setup-Report
	[switch]$UseExitCode = $true,	# This will cause the script to close after the error is logged if an error occurs.
	[switch]$sVersion,				# This will show current psSDP script version
	[switch]$SkipEULA,				# This will silently accept eula
	[switch]$skipQEdit,				#
	[switch]$skipVerifySignature,	# do not verify *.vbs signatures
	[ValidateSet("Client","Server")]
	[Parameter(Mandatory=$False,HelpMessage='Choose for role from: Client|Server')]
	[string]$RoleType = "Client",
	[ValidateSet("on","off")]
	[Parameter(Mandatory=$False,HelpMessage='Debug facility: on|off')]
	[string]$Debug_script = "off"
	)

BEGIN {
	$ScriptBeginTimeStamp = Get-Date

	# This saves the starting ErrorActionPreference and then sets it to 'Stop'.
	$startErrorActionPreference = $errorActionPreference
	$StartExecPolicy = Get-ExecutionPolicy -Scope Process
	if ($startErrorActionPreference -NotMatch 'Continue'){
		$errorActionPreference = 'Continue' #'Stop'
	}
	# This gets the current path and name of the script.
	$invocation = (Get-Variable MyInvocation).Value
	#$invocationLine= $($MyInvocation.Line)
	$ScriptParentPath 	= Split-Path $MyInvocation.MyCommand.Path -Parent
	$ScriptGrandParentPath 	= $MyInvocation.MyCommand.Path | Split-Path -Parent | Split-Path -Parent
	$scriptName = $invocation.MyCommand.Name
	$computername 	= $env:computername
	$Script:PSver = $PSVersionTable.PSVersion.Major
	$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent()) 
	
	If($Host.Name -match "ISE"){
		Write-Host ""
		Write-Host -ForegroundColor Magenta "*** TSSv2 is running on PowerShell ISE.  Please launch a regular PowerShell Admin window and run same SDP command again. ***"
		Exit # exit here as next step with ReadKey is not supported in ISE
	}
	
	$isElev = ($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
	if (-not $isElev) { Write-Host -ForegroundColor Yellow "For complete SDP results it is recommended to start this script with elevated priv - Run as Administrator `n
			 === Please respond with 'y' to proceed, or 'n' key to exit. ===`n" 
		do {
			$UserDone = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			if ($UserDone.Character -ieq 'n') {exit}
		} until ($UserDone.Character -ieq 'y')
	}
	$ProcArch=$ENV:PROCESSOR_ARCHITECTURE
	switch($ProcArch)
		{
		"AMD64"			{ Set-Variable -scope Global -name BinProcArch -Value BINx64 }
		"x86"			{ Set-Variable -scope Global -name BinProcArch -Value BINx86 }
		} 

	function Get-TimeStampUTC { # SYNOPSIS: Returns a UUTC timestamp string
		return (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss")
	}
	
	# variables
	$Global:SDPtech 		= $SDPtech
	$Global:RoleType 		= $RoleType
	$global:savePath		= $savePath
	$global:savePathTmp 	= "$savePath`\Results_$SDPtech`_$(Get-TimeStampUTC)"
	$TranscriptLog			= "$global:savePathTmp`\_psSDP_$SDPtech`_Transcript_$ComputerName`_$(Get-TimeStampUTC)`.Log"
	$script:DiagLogName			= $global:savePathTmp + "\_psSDP-DiagLog_" + $(Get-TimeStampUTC) + ".txt"
	$script:ErrorVarFile 	= $global:savePathTmp + "\_psSDP-ErrorVariable.txt"
		
	# Remember original ExecutionPolicy in Registry and temp changing policy based ExecutionPolicy
	$PSregExists = Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell
	if ($PSregExists) {
		$StartPSExePolicyReg = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -ErrorAction SilentlyContinue).ExecutionPolicy
		# next step might be no more be needed with signed scripts?
		if ($StartPSExePolicyReg) {Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass -ErrorAction SilentlyContinue}
	}


	#region ### customization section of script, logging configuration -----------------------#
	$global:ToolsPath 	= "$ScriptGrandParentPath\psSDP\Diag\global"
	$global:VerDate = ( Get-content -Path "$ScriptGrandParentPath\psSDP\version_psSDP.dat")[0] #"2021.05.17.0"
	$global:Publish_Date = ( Get-content -Path "$ScriptGrandParentPath\psSDP\version_psSDP.dat")[1] #"17-May-2021"
	# [string]$xrayActiveComponents = "DHCPsrv,802Dot1x,WLAN,Firewall"
	$ProcessWaitMin=10	# wait max minutes to complete MSinfo32
	#endregion ### customization section -----------------------------------------------------#
	
	if ($noNetAdapters) {Set-Variable -scope Global -name noNetAdapters -Value $true} else {if ($Global:noNetAdapters) {Clear-Variable -scope Global -name noNetAdapters}}
	if ($runFull) {Set-Variable -scope Global -name runFull -Value $true} else {if ($Global:runFull) {Clear-Variable -scope Global -name runFull}}
	if ($skipTS) {Set-Variable -scope Global -name skipTS -Value $true} else {if ($Global:skipTS) {Clear-Variable -scope Global -name skipTS}}
	if ($skipTScluster) {Set-Variable -scope Global -name skipTScluster -Value $true} else {if ($Global:skipTScluster) {Clear-Variable -scope Global -name skipTScluster}}
	if ($localNodeOnly) {Set-Variable -scope Global -name localNodeOnly -Value $true} else {if ($Global:localNodeOnly) {Clear-Variable -scope Global -name localNodeOnly}}
	if ($skipBPA) {Set-Variable -scope Global -name skipBPA -Value $true} else {if ($Global:skipBPA) {Clear-Variable -scope Global -name skipBPA}}
	if ($skipHang) {Set-Variable -scope Global -name skipHang -Value $true} else {if ($Global:skipHang) {Clear-Variable -scope Global -name skipHang}}
	if ($skipHVreplica) {Set-Variable -scope Global -name skipHVreplica -Value $true} else {if ($Global:skipHVreplica) {Clear-Variable -scope Global -name skipHVreplica}}
	if ($skipCsvSMB) {Set-Variable -scope Global -name skipCsvSMB -Value $true} else {if ($Global:skipCsvSMB) {Clear-Variable -scope Global -name skipCsvSMB}}
	if ($skipNetview) {Set-Variable -scope Global -name skipNetview -Value $true} else {if ($Global:skipNetview) {Clear-Variable -scope Global -name skipNetview}}
	if ($skipSddcDiag) {Set-Variable -scope Global -name skipSddcDiag -Value $true} else {if ($Global:skipSddcDiag) {Clear-Variable -scope Global -name skipSddcDiag}}
	if ($skipXray) {Set-Variable -scope Global -name skipXray -Value $true} else {if ($Global:skipXray) {Clear-Variable -scope Global -name skipXray}}
	if ($skipEula) { $EulaMode=2 } else { $EulaMode=0 }
	If(($EvtDaysBack.IsPresent) -or ($EvtDaysBack -ne 0)) { $Global:EvtDaysBck=$EvtDaysBack}

	#if ($RoleType) {Set-Variable -scope Global -name RoleType -Value $true} else {if ($Global:RoleType) {Clear-Variable -scope Global -name RoleType}}

	If ($PSBoundParameters['Debug']) { $DebugPreference='Continue'}

	# Unblock all *.ps* and *.exe files in ToolsPath and $BinProcArch
	Get-ChildItem -Recurse $global:ToolsPath\*.ps*,$global:ToolsPath\*.exe | Unblock-File -Confirm:$false
	#_#Get-ChildItem $ScriptGrandParentPath\$BinProcArch\*.* | Unblock-File -Confirm:$false
	Get-ChildItem $ScriptGrandParentPath\xray\*.ps* | Unblock-File -Confirm:$false
	
	#region ::::: Helper Functions ::::
	function Get-TimeStamp { # SYNOPSIS: Returns a timestamp string
		return "$(Get-Date -format "yyyyMMdd_HHmmss")"
	}
	
	function Create-ZipFromDirectory { # SYNOPSIS: Creates a ZIP file from a given directory
		<#
		.DESCRIPTION
		Creates a ZIP file from a given directory.

		.PARAMETER SourceDirectory
		The folder with the files you intend to zip.
		
		.PARAMETER ZipFileName
		The zip file that you intend to create
		
		.PARAMETER IncludeParentDirectory
		Setting this option will include the parent directory.
		
		.PARAMETER Overwrite
		Setting this option will overwrite the zip file if already exits.
		
		.EXAMPLE
		Create-ZipFromDirectory -Source $SourceDirectory -ZipFileName $ZipFileName -IncludeParentDirectory -Overwrite

		.EXAMPLE
		Create-ZipFromDirectory -S $SourceDirectory -O $ZipFileName -Rooted -Force
		#>

		PARAM
		(
			[Alias('S')]
			[Parameter(Position = 1, Mandatory = $true)]
			[ValidateScript({Test-Path -Path $_})]
			[string]$SourceDirectory,
		 
			[Alias('O')]
			[parameter(Position = 2, Mandatory = $false)]
			[string]$ZipFileName,

			[Alias('Rooted')]
			[Parameter(Mandatory = $false)]
			[switch]$IncludeParentDirectory,

			[Alias('Force')]
			[Parameter(Mandatory = $false)]
			[switch]$Overwrite
		)
		PROCESS
		{
			$ZipFileName = (("{0}.zip" -f $ZipFileName), $ZipFileName)[$ZipFileName.EndsWith('.zip', [System.StringComparison]::OrdinalIgnoreCase)]

			if(![System.IO.Path]::IsPathRooted($ZipFileName))
			{
				$ZipFileName = ("{0}\{1}" -f (Get-Location), $ZipFileName)
			}
						
			if($Overwrite)
			{
			 if(Test-Path($ZipFileName)){ Remove-Item $ZipFileName -Force -ErrorAction SilentlyContinue }
			}
			
			$source = Get-Item $SourceDirectory

			if ($source.PSIsContainer)
			{
				if($null -eq $newZipperAvailable)
				{
					try
					{
						$ErrorActionPreference = 'Stop'
						Add-Type -AssemblyName System.IO.Compression.FileSystem
						$newZipperAvailable = $true
					}
					catch
					{
						$newZipperAvailable = $false
					}
				}

				if($newZipperAvailable -eq $true) # More efficent and works silently.
				{
					[System.IO.Compression.ZipFile]::CreateFromDirectory($source.FullName, $ZipFileName, [System.IO.Compression.CompressionLevel]::Optimal, $IncludeParentDirectory)
				}
				else # Will show progress dialog.
				{

					# Preparing zip if not available.
					if(-not(Test-Path($ZipFileName)))
					{
						Set-Content $ZipFileName (“PK” + [char]5 + [char]6 + (“$([char]0)” * 18))
						(Get-ChildItem $ZipFileName).IsReadOnly = $false
					}

					if(-not $IncludeParentDirectory)
					{
						$source = Get-ChildItem $SourceDirectory
					}
				
					$zipPackage = (New-Object -ComObject Shell.Application).NameSpace($ZipFileName)
			
					[System.Int32]$NoProgressDialog = 16 #Tried but not effective.
					foreach($file in $source)
					{ 
						$zipPackage.CopyHere($file.FullName, $NoProgressDialog)
						do
						{
							Start-Sleep -Milliseconds 256
						}
						while ($zipPackage.Items().count -eq 0) # Waiting for an operation to complete.
					}
				}
				return $true
			}
			else
			{
				Write-Error 'The directory name is invalid.'
				return $false
			}
		}
	}
	
	function Write-Log { # SYNOPSIS: Writes script information to a log file and to the screen when -Verbose is set
		PARAM (
			[Parameter(Mandatory=$true,Position=0)]
			[String]$logEntry,
			[switch]$tee = $false,
			[string]$foreColor = $null)

		$foreColors = "Black","Blue","Cyan","DarkBlue","DarkCyan","DarkGray","DarkGreen","DarkMagenta","DarkRed","DarkYellow","Gray","Green","Magenta","Red","White","Yellow"
		# check the log file, create if missing
		$isPath = Test-Path "$script:DiagLogName"
		if (!$isPath) {
			"$(Get-TimeStamp): Local log file path: $("$script:DiagLogName")"	| Out-File $script:DiagLogName -Force
			"Start time (UTC):    $((Get-Date).ToUniversalTime())" 				| Out-File $script:DiagLogName -Append
			"Start time (Local):  $((Get-Date).ToLocalTime()) $(if ((Get-Date).IsDaylightSavingTime()) {([System.TimeZone]::CurrentTimeZone).DaylightName} else {([System.TimeZone]::CurrentTimeZone).StandardName})`n" | Out-File $script:DiagLogName -Append
			"OS Culture:          $((Get-Culture).name) [ UI Culture: $((Get-UICulture).name) ]" | Out-File $script:DiagLogName -Append
			"Eventlog DaysBack:   $Global:EvtDaysBck" 							| Out-File $script:DiagLogName -Append
			Write-Verbose " Local log file path: $("$script:DiagLogName")"
		}

		$callStack = Get-PSCallStack
		if ($callStack.Count -gt 1) {
			$caller = $callStack[1].FunctionName + " " + (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
		}
		$timestamp = (Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff").ToString()
		# write into log
		"$timestamp [$caller]: $logEntry" | Out-File "$script:DiagLogName" -Append
		# write logEntry verbosely to screen
		Write-Verbose $logEntry
		if ($tee)
		{
			# make sure the foreground color is valid
			if ($foreColors -contains $foreColor -and $foreColor) { Write-Host -ForegroundColor $foreColor $logEntry
			} else { Write-Host $logEntry }        
		}
	} # end function Write-Log
	
	function Add-Path { # SYNOPSIS: Adds a Directory to the Current Path
	 <#
		.SYNOPSIS
		 Adds a Directory to the Current Path | Join-Path ?
		.DESCRIPTION
		 Add a directory to the current path. This is useful for temporary changes to the path or, when run from your 
		 profile, for adjusting the path within your powershell prompt.
		.EXAMPLE
		 Add-Path -Directory "C:\Program Files\Notepad++"
		.PARAMETER Directory
		 The name of the directory to add to the current path.
	 #>
	 PARAM (
		[Parameter(
		 Mandatory=$True,
		 ValueFromPipeline=$True,
		 ValueFromPipelineByPropertyName=$True,
		 HelpMessage='What directory would you like to add?')]
		[Alias('dir')]
		[string[]]$Directory
	 )
	 PROCESS {
		$Path = $env:PATH.Split(';')
		foreach ($dir in $Directory) {
		 if ($Path -contains $dir) {
			Write-Log "$dir is already present in PATH"
		 } else {
			if (-not (Test-Path $dir)) {
			 Write-Log "$dir does not exist in the filesystem"
			} else {
			 $Path += $dir
			}
		 }
		}
		$env:PATH = [String]::Join(';', $Path)
	 }
	} #end function Add-Path
	
	function inform_onError { # SYNOPSIS: Inform user on error
		Write-Log -foreColor Gray -tee "`n [psSDP-Info] in case you see any red error messages regarding signing, [method#1] open an Admin Powershell CMD and run this command first:"
		Write-Log -foreColor White -tee "	 Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
		Write-Log -foreColor Gray -tee   "     [Alternate method#2]: To self sign .ps1 scripts: run in elevated CMD"
		Write-Log -foreColor White -tee "         tss_PS1sign.cmd Get-psSDP"
		Write-Log -foreColor Gray -tee   "     [Alternate method#3a]: If scripts are blocked by MachinePolicy, run in elevated Powershell: "
		Write-Log -foreColor White -tee "	 Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass"
		Write-Log -foreColor White -tee "	 Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name EnableScripts  -Value 1 -Type DWord"
		Write-Log -foreColor Gray -tee   "     [Alternate method#3b]: If scripts are blocked by UserPolicy, run in elevated Powershell: "
		Write-Log -foreColor White -tee "	 Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ExecutionPolicy -Value ByPass"
		Write-Log -foreColor White -tee "	 Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name EnableScripts  -Value 1 -Type DWord `n"
	} #end inform_onError
	
	function Move-LogFiles { # SYNOPSIS: move Log files like stdout.log into working folder
		if (Test-Path $ScriptGrandParentPath\stdout*.log) 	{Move-Item $ScriptGrandParentPath\stdout*.log $global:savePathTmp -Force}
		if (Test-Path $savePath\*SDPExecution.log) 		{Move-Item $ScriptGrandParentPath\*SDPExecution.log $global:savePathTmp -Force}
		if (Test-Path $savePath\*_LogFile_sdp.txt) 		{Move-Item $ScriptGrandParentPath\*_LogFile_sdp.txt 	$global:savePathTmp -Force}
		if (Test-Path $savePath\stdout*.log) 			{Move-Item $savePath\stdout*.log 		$global:savePathTmp -Force}
		if (Test-Path $savePath\xray_*.*) 				{Move-Item $savePath\xray_*.* 			$global:savePathTmp -Force}
		if (Test-Path $savePath\*ErrorVariable.txt) 	{Move-Item $savePath\*ErrorVariable.txt $global:savePathTmp -Force}
	}
	
	function Log-PSExecPolicy { # SYNOPSIS: log current Powershell ExecutionPolicy  and Reg.Settings
	" Current ExecutionPolicy: $(Get-ExecutionPolicy)" | Out-File "$script:DiagLogName" -Append
	Get-ExecutionPolicy -List | Out-File "$script:DiagLogName" -Append
	"Registry: HKLM\Software\Policies\Microsoft\Windows\PowerShell" | Out-File "$script:DiagLogName" -Append
	Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -EA SilentlyContinue | Out-File "$script:DiagLogName" -Append
	"Registry: HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" | Out-File "$script:DiagLogName" -Append
	Get-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -EA SilentlyContinue | Out-File "$script:DiagLogName" -Append
	}
	
	function Run-xray { # SYNOPSIS: run xray troubleshooter for components
	PARAM (
			[String]$Component,
			[String]$Area,
			[String]$DataPath
		)
	"... running  xray troubleshooter for Area: $Area  - DataPath: $DataPath "| Out-File "$script:DiagLogName" -Append
	Push-Location $ScriptGrandParentPath\xray
		& "$ScriptGrandParentPath\xray\xray.ps1" -DataPath $savePath -Area $Area -WaitBeforeClose -AcceptEULA
	Pop-Location
	}

# EULA	
[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode)
{
    $EULA = New-Object -TypeName System.Windows.Forms.Form
    $richTextBox1 = New-Object System.Windows.Forms.RichTextBox
    $btnAcknowledge = New-Object System.Windows.Forms.Button
    $btnCancel = New-Object System.Windows.Forms.Button

    $EULA.SuspendLayout()
    $EULA.Name = "EULA"
    $EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

    $richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $richTextBox1.Location = New-Object System.Drawing.Point(12,12)
    $richTextBox1.Name = "richTextBox1"
    $richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
    $richTextBox1.TabIndex = 0
    $richTextBox1.ReadOnly=$True
    $richTextBox1.Add_LinkClicked({Start-Process -FilePath $_.LinkText})
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
    $btnAcknowledge.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::Yes})

    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Location = New-Object System.Drawing.Point(669, 415)
    $btnCancel.Name = "btnCancel"
    $btnCancel.Size = New-Object System.Drawing.Size(119, 23)
    $btnCancel.TabIndex = 2
    if($mode -ne 0)
    {
	    $btnCancel.Text = "Close"
    }
    else
    {
	    $btnCancel.Text = "Decline"
    }
    $btnCancel.UseVisualStyleBackColor = $True
    $btnCancel.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::No})

    $EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
    $EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
    $EULA.Controls.Add($btnCancel)
    $EULA.Controls.Add($richTextBox1)
    if($mode -ne 0)
    {
	    $EULA.AcceptButton=$btnCancel
    }
    else
    {
        $EULA.Controls.Add($btnAcknowledge)
	    $EULA.AcceptButton=$btnAcknowledge
        $EULA.CancelButton=$btnCancel
    }
    $EULA.ResumeLayout($false)
    $EULA.Size = New-Object System.Drawing.Size(800, 650)

    Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode)
{
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if(Test-Path $eulaRegPath)
	{
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else
	{
		$eulaRegKey = New-Item $eulaRegPath
	}
	if($mode -eq 2) # silent accept
	{
		$eulaAccepted = "Yes"
       		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else
	{
		if($eulaAccepted -eq "No")
		{
			$eulaAccepted = ShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
	        		$eulaAccepted = "Yes"
	        		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

	# Call ShowEULAIfNeeded from your main entry point, with your tool name (used to maintain 'already accepted' registry value)
	# $mode: 
	#    0=popup eula if not yet accepted for this tool
	#    1=popup eula for display
	#    2=silently accept eula
	# if the function does not return "Yes" then you should exit
	# e.g.
	# 
	# 
	#
	 $eulaAccepted = ShowEULAIfNeeded "psSDP" $EulaMode
	 if($eulaAccepted -ne "Yes")
	 {
		 "EULA Declined"
		 exit
	 }
	 "EULA Accepted"
	# ... continue

	if (-not $skipQEdit) {
		# --- QuickEditCode ---
		# This function disable quick edit mode. If the mode is enabled, 
		# console output will hang when key input or strings are selected. 
		# So disable the quick edit mode druing running script and 
		# re-enable it after script is finished.
#region QE mode
$QuickEditCode=@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

public static class DisableConsoleQuickEdit
{
    const uint ENABLE_QUICK_EDIT = 0x0040;
    // STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
    const int STD_INPUT_HANDLE = -10;
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll")]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll")]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    public static bool SetQuickEdit(bool SetEnabled)
    {
        IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);
        // get current console mode
        uint consoleMode;
        if (!GetConsoleMode(consoleHandle, out consoleMode))
        {
            // ERROR: Unable to get console mode.
            return false;
        }
        // Clear the quick edit bit in the mode flags
        if (SetEnabled)
        {
            consoleMode &= ~ENABLE_QUICK_EDIT;
        }
        else
        {
            consoleMode |= ENABLE_QUICK_EDIT;
        }
        // set the new mode
        if (!SetConsoleMode(consoleHandle, consoleMode))
        {
            // ERROR: Unable to set console mode
            return false;
        }
        return true;
    }
}
"@
#endregion QE mode
		Try{
			$QuickEditMode = add-type -TypeDefinition $QuickEditCode -Language CSharp -ErrorAction Stop
			# Keep disabled when DebugMode for better debugging.
			If(!$DebugMode.IsPresent){
				$fQuickEditCodeExist = $True
			}
		}Catch{
			$fQuickEditCodeExist = $False
		}
	} else { $fQuickEditCodeExist = $True }

Function CleanUpandExit{
		# Restore Quick Edit mode
		If($fQuickEditCodeExist){
			[DisableConsoleQuickEdit]::SetQuickEdit($False) | Out-Null
		}																  
		# Stop console logging.
		Try{
			Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
		}Catch{
		}
		$Error.Clear()	#_#
		Exit
	}
	#endregion ::::: Helper Functions ::::
	
} #end BEGIN

PROCESS {
	try {
		# Show only sVersion, then exit
		if ($sVersion) {Write-Host -ForegroundColor Cyan "psSDP Script Version: $global:VerDate"; exit 0}
		
		#$ScriptBeginTimeStamp = Get-Date
		#region: MAIN :::::
		if (-NOT (Test-Path $global:savePathTmp)) {[void](new-item -path $global:savePathTmp -type directory)}
		Write-Log "Bound Param: " 
		$PSBoundParameters |Format-Table 											| Out-File $script:DiagLogName -Append
		Write-Log "ScriptGrandParentPath: $ScriptGrandParentPath"
		Write-Log "ToolsPath:             $global:ToolsPath"
		Write-Log "savePath:              $savePath"
		Write-Log "savePathTmp:           $global:savePathTmp"
		Write-Log "LogName:               $script:DiagLogName"
		Log-PSExecPolicy
		##Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -Whatif | Out-File "$script:DiagLogName" -Append
		# Before starting logging, close existing session.
		Try{
			#_# Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
		}Catch{
			# Do nothing
		}
		if (($Script:PSver -gt 2) -and ($Transcript -eq $true)) { Start-Transcript -Path $TranscriptLog }
		 else {Write-Log "... will not start Transcript log. -Transcript:$False or old PS version $Script:PSver"}
		
		# First thing we need to check is 'Constrained Language Mode' as this prevents most .net types from being accessed and it is very critical for this script.
		# https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/
		$ConstrainedLanguageMode = $ExecutionContext.SessionState.LanguageMode
		$LockdownPolicy = $Env:__PSLockdownPolicy
		If($ConstrainedLanguageMode -ne 'FullLanguage'){
			If($Null -eq $LockdownPolicy){
				$fIsLockdownByEnvironmentVariable = $False
			}Else{
				$fIsLockdownByEnvironmentVariable = $True
			}
			Write-Host("Current constrained language mode is `'" + $ConstrainedLanguageMode + "`' but this script must be run with `'FullLanguage`' mode.") -ForegroundColor Red
			Write-Host('Please ask administrator why $ExecutionContext.SessionState.LanguageMode is set to ' + $ConstrainedLanguageMode + '.') -ForegroundColor Red
			Write-Host("")
			If($fIsLockdownByEnvironmentVariable){
				Write-Host("To fix this issue, remove `'__PSLockdownPolicy`' environment valuable.")
				Write-Host("")
			}
			CleanUpandExit
		}

		# Disabling quick edit mode as somethimes this causes the script stop working until enter key is pressed.
		If($fQuickEditCodeExist){
			[DisableConsoleQuickEdit]::SetQuickEdit($True) | Out-Null
		}

		Write-Host "$(Get-Date -Format 'HH:mm:ss') starting psSDP v$VerDate Data Collection Report for Windows Technology: '$SDPtech'" -ForegroundColor White -BackgroundColor DarkGreen
		Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "** -runFull: $Global:runFull -SkipTS: $Global:skipTS -SkipBPA: $Global:skipBPA  -skipNetView: $Global:skipNetview -skipSddcDiag: $Global:skipSddcDiag -noNetAdapters: $Global:noNetAdapters -skipHVreplica: $Global:skipHVreplica -skipCsvSMB: $Global:skipCsvSMB -skipHang: $Global:skipHang -skipXray: $Global:skipXray"
		Write-Host "`n"
		if ($SDPtech -match "All|DA|Dom|DPM|Repro|SQLbase") {
			Write-Log -foreColor Yellow -tee "Note: You may be asked for additional input for '$SDPtech' report... "
			[System.Media.SystemSounds]::Hand.Play() } # Play sound to get some attention 

		### Debug output is stored in $env:TEMP\longGUID.txt i.e. d61ae9b514e84e5984cd8992acd1dd4b.txt
		switch($Debug_script)
			{
			"off"			{$Global:Debug=$false}
			"on"			{$Global:Debug=$true}
			} 

		# create supporting folders
		if (-NOT (Test-Path $global:savePathTmp\output)) {[void](new-item -path $global:savePathTmp\output -type directory)}	# for Filter UpdateDiagReport
		if (-NOT (Test-Path $global:savePathTmp\result)) {[void](new-item -path $global:savePathTmp\result -type directory)}	# in utils_CTS.ps1

		if ((-not $skipVerifySignature.IsPresent) -and $FALSE) { #disable temporary
			# verify signature of *.VBS files
			$VBSlist = (Get-ChildItem $global:ToolsPath\*.vbs).Name
			$fTampered=$False	# init
			foreach ($VBSname in $VBSlist) {
				$SigStatus = ((Get-AuthenticodeSignature $global:ToolsPath\$VBSname ).status)	#_# ToDo: check if signature is valid after 2/11/2022
				if ($SigStatus -ne [System.Management.Automation.SignatureStatus]::Valid) {	# "Valid" may differ on localized OS, so using enum
					$fTampered=$True
					write-host -ForegroundColor Red "VBS script signature status: $SigStatus - Tampered: $fTampered - File: $VBSname"
					"VBS script signature status: $SigStatus - Tampered: $fTampered - File: $VBSname" | Out-File $script:DiagLogName -Append
					Get-AuthenticodeSignature C:\TSSv2\psSDP\Diag\global\$VBSname | Format-List * | Out-File $script:DiagLogName -Append 
					Break
				}
			}
			if ($fTampered) {
				# compress all *.vbs , which seem to be tampered 22-03-08
				try { Compress-Archive -Path $global:ToolsPath\*.vbs -CompressionLevel Fastest -DestinationPath $global:savePathTmp`\_VBSfiles } catch { Write-Log "___unable to compress *.vbs files" }
				#write-host -ForegroundColor Red "VBS script signature Status: $SigStatus - File: $VBSname"
				CHOICE /T 20 /C yn /D n /M " Press Y for Yes = proceed anyways, N for No = Exit"
				If($LASTEXITCODE -eq 2){
					Write-Host ".. exiting because of possibly tampered VBS script(s)" -ForegroundColor Yellow
					CleanUpandExit
				}
			}
		}

		if (Test-Path $global:savePathTmp) {
			Add-Path -Directory "$global:ToolsPath", "$ScriptGrandParentPath\$BinProcArch", "$ScriptGrandParentPath\BIN"
			Write-Log "___Path: $env:PATH"
			Push-Location -path $global:savePathTmp
			
			###  _Copy utils...
			if (-NOT ($SDPtech -match "mini|nano|RFL")) {
				Write-Log -foreColor White -tee "$(Get-Date -UFormat "%R:%S") _Copy utils..."
				Write-Log "_Copy-Item *.exe *.ico *.js *.mui *.vbs *.sql *.cs *.ps* *.xml *.xsl* Files to $($global:savePathTmp)\* -Force"
				[string[]]$Files = @("exe", "ico", "js", "mui", "vbs", "sql", "cs", "ps*", "xml", "xsl*")
				foreach ($File in $Files){ 
					if ( Get-ChildItem -path "$global:ToolsPath`\*.$File" -ErrorAction SilentlyContinue ) {[void](Copy-Item "$global:ToolsPath`\*.$File" $global:savePathTmp -Force) }
				}
			}
			if ($SDPtech -match "mini|nano|RFL") {
				#	\Run_Discovery.ps1 and \ConfigXPLSchema.xml are needed in Discovery
				Write-Log "Copy-Item $global:ToolsPath`\Run_Discovery.ps1 $global:savePathTmp`\Run_Discovery.ps1 -Force"
				Copy-Item $global:ToolsPath`\Run_Discovery.ps1 $global:savePathTmp`\Run_Discovery.ps1 -Force
				Copy-Item $global:ToolsPath`\ConfigXPLSchema.xml $global:savePathTmp`\ConfigXPLSchema.xml -Force
				Copy-Item $global:ToolsPath`\GetEvents.VBS $global:savePathTmp`\GetEvents.VBS -Force
				if (Test-Path $global:ToolsPath`\results_$SDPtech`.xml) {Copy-Item $global:ToolsPath`\results_$SDPtech`.xml $global:savePathTmp`\results.xml -Force}
			}

			# Create and copy Images
			if (-NOT (Test-Path $global:savePathTmp\Images)) {new-item -path $global:savePathTmp\Images -type directory |out-null}
			$imageFiles =$global:ToolsPath + "\images\*.png"
			Copy-Item $imageFiles ($global:savePathTmp + "\Images\") -Force
			Write-Log -foreColor White -tee "$(Get-Date -UFormat "%R:%S") _Copy utils... done"
			
			### Load Common Library
			Write-Log "_Load Common Library: $global:ToolsPath\utils_Cts.ps1"
			. "$global:ToolsPath\utils_Cts.ps1"
			. "$global:ToolsPath\Utils_Discovery.ps1"
			. "$global:ToolsPath\utils_Remote.ps1"	# Filter Update-Diagreport, Function Write-DiagProgress
			if ($SDPtech -match "CTS|All") {. "$global:ToolsPath\utils_DSD.ps1"
										. "$global:ToolsPath\utils_Exchange_all_exchange_versions_using_powershell_should_not_be_called_while_loading_powershell.ps1"
										. "$global:ToolsPath\utils_Exchange_all_exchange_versions_withoutpowershellaccess.ps1"
										. "$global:ToolsPath\utils_load20072010powershell.ps1"
										. "$global:ToolsPath\utils_loadex2013powershell.ps1" }

			Write-Log -foreColor White -tee "`n... starting script: TS_Main_$SDPtech`.ps1 (... please be patient until all modules finished ...)"
			
			if ($SDPtech -match "mini|nano|RFL") { # collect Mini (*_msinfo.*, hotfixes.*, _sym.*, *_pstat.txt) or Nano (network) report:
				$PSscript_Names = Get-Content "$global:ToolsPath\_Script_names_$($SDPtech).txt"
				foreach ($line in $PSscript_Names){
					if (-not $line.StartsWith('#')) {
						Write-Log -foreColor White -tee "$(Get-Date -UFormat "%R:%S") _running_ $line"
						& "$($global:ToolsPath)\$($line)"
						}
				}
			}
			else { ### collect various speciality reports (SDPtech):
				if (Test-Path $global:ToolsPath`\TS_AutoAddCommands_$SDPtech`.ps1)	{Copy-Item $global:ToolsPath`\TS_AutoAddCommands_$SDPtech`.ps1 $global:savePathTmp`\TS_AutoAddCommands.ps1 -Force}
				if (Test-Path $global:ToolsPath`\DiagPackage_$SDPtech`.diagpkg) 	{Copy-Item $global:ToolsPath`\DiagPackage_$SDPtech`.diagpkg $global:savePathTmp`\DiagPackage.diagpkg -Force}
				if (Test-Path $global:ToolsPath`\DiagPackage_$SDPtech`.dll) 		{Copy-Item $global:ToolsPath`\DiagPackage_$SDPtech`.dll $global:savePathTmp`\DiagPackage.dll -Force}
				if (Test-Path $global:ToolsPath`\results_$SDPtech`.xml) 			{Copy-Item $global:ToolsPath`\results_$SDPtech`.xml $global:savePathTmp`\results.xml -Force}
				# now run main SDP report
				& ".\TS_Main_$SDPtech.ps1"
				#_# now run xray Troubleshooters for known trending issues; $TechAreas = @("ADS", "DND", "NET", "PRF", "SHA", "UEX") / * = All
				if ($Global:skipXray -ne $true) {
					Write-Log "Run-xray -Area * -DataPath $global:savePathTmp"
					Run-xray -Area * -DataPath $global:savePathTmp
				} else {Write-Log "Skipping xray, PS version: $Script:PSver , skipXray: $Global:skipXray"}
			}
			
			# if started and still running: wait for msinfo32/checkSym*/Autorun*.exe to complete - moved to end before compressing
			if (Get-Process msinfo32 -EA Ignore) {$nid = (Get-Process msinfo32).id }
			if (Get-Process CheckSym* -EA Ignore) {$nidChkSym = (Get-Process CheckSym*).id }
			if (Get-Process AutorunS* -EA Ignore) {$nidAutorun= (Get-Process Autorun*).id }
			if (($nid) -or ($nidChkSym) -or ($nidAutorun)) {
				Write-Log -foreColor Cyan -tee "$(Get-Date -UFormat "%R:%S") ... waiting max $ProcessWaitMin minutes on MsInfo32 PID $nid and/or CheckSym* PID $nidChkSym processes to complete, before compressing SDP"
				$processWaitList = @("msinfo32","CheckSym*","Autorun*")
				foreach ($process in $processWaitList) {
					Wait-Process -Name $process -Timeout ($ProcessWaitMin * 60) -EA Ignore
				}
			}
			
			## remove Util files
			Write-Log "$(Get-Date -UFormat "%R:%S") _Remove utils..."  
			[string[]]$Files = @("*.exe", "*.dll", "*.ico", "*.js", "*.mui", "*.vbs", "*.sql", "*.cs", "*.ps*", "*.diagpkg", "*.xsl*", "*.xml")
			foreach ($File in $Files) { 
				if ( Get-ChildItem -path "$global:savePathTmp\$File" -ErrorAction SilentlyContinue ) {[void](Remove-Item "$global:savePathTmp\$File" -Exclude $Env:computername`*.xml,results.xml,MachineInfo.xml -Force) }
			}
			# Remove temp/empty Folders
			if (Test-Path .\EventLogs) 		{Remove-Item .\EventLogs -Recurse -Force}
			if (Test-Path .\Perfmon) 		{Remove-Item .\Perfmon -Recurse -Force}
			if (Test-Path .\RasTracingDir) 	{Remove-Item .\RasTracingDir -Recurse -Force}
			# Rename *.XML items
			if (Test-Path $global:savePathTmp`\$ENV:Computername`_EventLogAlerts.XML) 		{Rename-Item $global:savePathTmp`\$ENV:Computername`_EventLogAlerts.XML $global:savePathTmp`\$ENV:Computername`_EventLogAlerts.htm -Force}
			# Copy BPAinfo html and .xml files
				###Get-ChildItem -Path "$ENV:USERPROFILE" -Filter "*$ENV:Computername`*BPAInfo.*" | Rename-Item -NewName {$global:savePathTmp + $_.Name}
			if (Test-Path $ENV:USERPROFILE`\$ENV:Computername`*BPAInfo.*) 	{Copy-Item $ENV:USERPROFILE`\$ENV:Computername*BPAInfo.HTM $global:savePathTmp\ -Force}
			if (Test-Path $ScriptGrandParentPath`\$ENV:Computername`*BPAInfo.*) {Move-Item $ScriptGrandParentPath`\$ENV:Computername*BPAInfo.* $global:savePathTmp\ -Force}
			if (Test-Path $global:savePath`\BPAresults.*) 						{Move-Item $global:savePath`\BPAresults.* $global:savePathTmp\ -Force}
			if (Test-Path C:\GenericMessageUpdateDiagReport.xml) 				{Move-Item C:\GenericMessageUpdateDiagReport.xml $global:savePathTmp\ -Force}

			### begin compress -inner-
			if ($ZipIt.IsPresent) {
				$OutputFileZip = "psSDP_i_$SDPtech`_$ComputerName`_$(Get-TimeStampUTC)`.zip"
				Write-Log -foreColor White -tee "$(Get-Date -UFormat "%R:%S") ... zipping $OutputFileZip"
				$zipComp = CompressCollectFiles -Recursive -NumberofDays 1 -filesToCollect $global:savePathTmp -DestinationFileName $OutputFileZip -renameOutput $false -fileDescription "psSDP Logs" -sectionDescription "psSDP data collection" 
				if ($zipComp) {	Write-Log "_zipped $OutputFileZip" }
			}

			Move-LogFiles
			
			# Stop Transcript
			if (($Script:PSver -gt 2) -and ($Transcript -eq $true)) {
				try { Stop-Transcript -ErrorAction Ignore | Out-Null} catch {} 
			}
			else {Write-Log -foreColor White "... Transcript log was not started. -Transcript:$False or old PS version $Script:PSver"}
			
			# Record all errors in $Error variable.
			If($Error.Count -ne 0){
				$Error | Out-File -FilePath $script:ErrorVarFile
			}
			### begin compress files (zip cab)
			if ($NoCab.IsPresent -ne $true -and !$NoZip) {
				#$TimeStampUTC = Get-Date -Format "yyMMdd-HHmmss"
				$OutputFileZip = "$savePath`\tss_$(Get-TimeStampUTC)`_$ENV:ComputerName`_psSDP_$SDPtech`.zip"
				try {
					### Zip file if PowerShell v3 or higher is installed
					if ($Script:PSver -gt 2) { Write-Log -foreColor White -tee "$(Get-Date -UFormat "%R:%S") ... now zipping '$SDPtech' data folder $global:savePathTmp" 
												Write-Log "Resulting cabinet/zip: $OutputFileZip"
												$zipped = Create-ZipFromDirectory -SourceDirectory $global:savePathTmp -ZipFileName $OutputFileZip -overwrite }
					else {Write-Log -foreColor Yellow -tee "`n*** Please zip all results files in $global:savePathTmp and upload to workspace"}
					}
				catch {$zipped=$null;Write-Log -foreColor Red -tee "`n*** Failure during compression. Exception Message:`n $($_.Exception.Message)"}
			} #end compress
			else {Write-Log -foreColor Yellow -tee "`n*** Please zip all results files in $global:savePathTmp and upload to workspace"}

			#set-location -path $CurrentPath
			Pop-Location
			if ($zipped) {
				Write-Log "_Remove-Item $global:savePathTmp -Force -Recurse"
				Start-Sleep -Seconds 2
				Remove-Item $global:savePathTmp -Force -Recurse -EA SilentlyContinue
				Write-Host -ForegroundColor Green " [psSDP-Info] done. Resulting cabinet/zip: $OutputFileZip"
			}
		Write-Host "$(Get-Date -Format 'HH:mm:ss') *** end of psSDP Report datacollection for Windows Technology: '$SDPtech'" -ForegroundColor White -BackgroundColor DarkGreen
		}
		#endregion: MAIN :::::
	} # end try PROCESS
	catch {
		$errorMessage = "$scriptName v$VerDate caught an exception on $($ENV:COMPUTERNAME):`n`n"
		$errorMessage += "Exception Type:    $($_.Exception.GetType().FullName)`n`n"
		$errorMessage += "Exception Message: $($_.Exception.Message)"

		Write-Error $errorMessage -ErrorAction Continue
		#echo $_.Exception|format-list -force
		$errMsg = $_.Exception|format-list -force; $line = $_.InvocationInfo.ScriptLineNumber; Write-Log "$errorMessage"; $line; Write-Log -foreColor Red -tee "[ERROR] v$VerDate Please report above error message in $scriptName line: $line - Elevated: $isElev"
		Move-LogFiles
		Start-Sleep -Seconds 2
		Write-Debug $errorMessage
		$ErrorThrown = $true
		if ( $UseExitCode ) {
			$error.clear()	# clear script errors
			exit 1
		}
  } #end Catch PROCESS
	Finally {
		if (Test-Path $global:savePathTmp) {
			$TmpCnt = (get-childitem $global:savePathTmp).count 
			if ($TmpCnt -eq 0) {Remove-Item $global:savePathTmp -ErrorAction SilentlyContinue}
		}
		if($ErrorThrown) { inform_onError }
		# Reset original ExecutionPolicy
		$currentStartExecPolicy = Get-ExecutionPolicy -Scope Process
		if ($currentStartExecPolicy -NotMatch $StartExecPolicy){
			Set-ExecutionPolicy -Scope Process -ExecutionPolicy $StartExecPolicy -Force -ErrorAction SilentlyContinue
		}
		# Reset original ExecutionPolicy in Policies Registry
		if ($StartPSExePolicyReg) {
			Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value $StartPSExePolicyReg
		}
		if ($Script:PSver -gt 2) {
			Unblock-File -Path $ScriptParentPath\Get-psSDP.ps1 -ErrorAction Ignore
			Try{
				Stop-Transcript -ErrorAction Ignore | Out-Null
			}Catch{
				$Error.RemoveAt(0)
			}
		}
		if ($Global:MissingCU) { 
			Write-Host -ForegroundColor Red "*** [WARNING] latest OS cumulative KB $Global:MissingCU is missing. Please update this machine with recommended Microsoft KB$Global:MissingCU and verify if your issue is resolved."
			Clear-Variable -scope Global -name MissingCU
		}
		CleanUpandExit
	} #end Finally PROCESS
} #end PROCESS


END {
	$ScriptEndTimeStamp = Get-Date
	$Duration = $(New-TimeSpan -Start $ScriptBeginTimeStamp -End $ScriptEndTimeStamp)
	#$LogLevel = 0
	if($ErrorThrown) {Throw $error[0].Exception.Message}

	Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "$(Get-Date -UFormat "%R:%S") Done on this PC $env:COMPUTERNAME; script $scriptName '$SDPtech' v$VerDate took $Duration"
	[System.Media.SystemSounds]::Hand.Play() # Play sound to signal end of SDP data collection
	
  # This resets the ErrorActionPreference to the value at script start time.
  if ($ErrorActionPreference -NotMatch $startErrorActionPreference){
	  $ErrorActionPreference = $startErrorActionPreference
  }
} #end END

#region: comments
<# Info:
Files collected within SDP report:
- "Net","DA","Dom","DPM","CTS","Print","HyperV","Perf","Setup","Cluster","Mini","Nano","RFL","All"

 2027424	[SDP 3][d92078bc-87a3-492b-978e-1f91d4eaaed9] Windows Printing
 http://support.microsoft.com/kb/2027424/EN-US
 2224427	[SDP 2][9B947211-ED5B-4BAE-85A5-823B8718DB59] Setup - Windows XP, Server 2003, Windows Vista, and Windows Server 2008 MSDT manifest
 http://support.microsoft.com/kb/2224427/EN-US
 2415016	[SDP 3][62ec9a58-1f9e-4550-b65c-87827221dd05] FailoverCluster Multinode troubleshooter for Windows Server
 http://support.microsoft.com/kb/2415016/EN-US


VERSION and AUTHORs:
    Ver 1.00 - 12.03.2017
	Walter Eder	- waltere@microsoft.com

HISTORY
**psSDP Revision History** - see online https://github.com/CSS-Windows/WindowsDiag/blob/master/ALL/psSDP/revision-history.txt
Version number=Change Date | Notes
2022.06.10.0 copy *BPAinfo results
2021.12.17.0 moved "verify signature of VBS files" into PROCESS block
2021.11.17.0 added signature check for *.vbs (Get-AuthenticodeSignature)
2021.07.26.0 changed folder structure; disable QuickEditMode during script execution
2021.07.08.1 fixing some SUVP issues
2021.07.08.0 add SUVP  
2021.06.21.0 add CES Diagnostic Scripts and Utilities License  
2021.04.19.0 mod AlwaysOnDiagScript.sql
2021.04.12.0 add SCCM
2021.03.30.0 add RDS
2021.03.17.0 add Get-WindowsUpdateLog to skipHang
2021.02.02.0 upd GetNetview; Hyper-V Shielded VM EventLogs
2021.01.26.0 skipHang for DC_W32Time.ps1
2021.01.13.0 skipHang for TS_DumpCollector
2020.12.16.0 upd xray 201217
2020.12.16.0 fixed AutorunsC, replaced .exe with older version
2020.12.09.0 added DPM
2020.11.03.0 upd DNSsrv
2020.11.02.0 upd xray
2020.10.26.0 added CscDbDump for NET
2020.10.16.0 include reg.Hives
2020.08.20.0 fixed CORE running without 'Get-ClusterNode'
2020.08.15.0 upd Get_SmbShare, UTC time
2020.06.14.0 upd xray, added ReFs event log collection to Setup, Hyper-V, Cluster and S2D SDP logs
2020.06.01.0 remove XP/W2k3
2020.05.31.0 upd xray
2020.05.07.0 run xray, if PSver > 4.0 run xray, if PSver > 1
2020.04.24.0 upd xray, SQL
2020.04.22.1 upd xray; added Schannel to DS_regEntries
2020.04.19.1 activated xray; SDDC
2020.04.13.2 upd of many troubleshooter to run on Win10; add SkipXray
	
ToDo: handle utils_Remote.ps1:Function Get-DiagInput :: in DC_CollectSecurityEventLog.ps1 (done), DC_DfsrInfo.ps1, DC_HyperVReplica.ps1, DC_ServerCoreR2Setup.ps1, TS_RemoteSetup.ps1, TS_SelectClusterNodes.ps1 
	- only run once CTS report, else errors: New-Variable : Cannot overwrite variable SQL:PSSDIAGXML because it is read-only or constant.
	- findstr /i /c:"get-diaginput" *.*
	- consider adding for DOM: ADdiag - see https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/son-of-spa-ad-data-collector-sets-in-win2008-and-beyond/ba-p/397893
#>
#endregion: comments


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAj35LV1JJdIOsE
# qHNWrGtWfCn+Y1eMxw3YwPQfkjz816CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHs6rsp0JAG7dWvasVx8gZ+F
# AzrGQ8KT2xw3boxpmAl/MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCukz0rRsVkR0BkIAWNHUdikgHkMp71D2e5rZidjtSRFmI4jP+SLvm3
# qYpQ34uuZqzhZHamlAC/xVIGt5777n17fAOBDRqPbUF0SM3VTsuoqMDqGAmyKZ+m
# 5UVC5nAvB//rVG7DEuxtck5g0tj9YU2tOchMyDIpqA64GUeOdjoxPiU6cARNkOxc
# uRhprL7pWp4bnzVBVn468GDRO6RW2O2E5/W+5m1fcQXt8J6elfRlvPMEASSpZ4cU
# 6LHSnMVGp/i4ORdc3xFgSGPpKQdXyCDRXuluDosSOWMCTdVuOqZ6GtTxCT7htuc1
# DIp0PIG/Ll6YcKoSMo3ZyeKDW+M441BQoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHCqR+640Pmxt9EeRGhD2U/ZSb6El/0LJMRKnRMn8K7KAgZi3n87
# U+sYEzIwMjIwODExMDgzNTA5LjAyNFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY5Z20YAqBCUzAABAAABjjAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDVaFw0yMzAxMjYxOTI3NDVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEt
# NEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqiMCq6OMzLa5wrtcf7Bf
# 9f1WXW9kpqbOBzgPJvaGLrZG7twgwqTRWf1FkjpJKBOG5QPIRy7a6IFVAy0W+tBa
# FX4In4DbBf2tGubyY9+hRU+hRewPJH5CYOvpPh77FfGM63+OlwRXp5YER6tC0WRK
# n3mryWpt4CwADuGv0LD2QjnhhgtRVidsiDnn9+aLjMuNapUhstGqCr7JcQZt0ZrP
# UHW/TqTJymeU1eqgNorEbTed6UQyLaTVAmhXNQXDChfa526nW7RQ7L4tXX9Lc0og
# uiCSkPlu5drNA6NM8z+UXQOAHxVfIQXmi+Y3SV2hr2dcxby9nlTzYvf4ZDr5Wpcw
# t7tTdRIJibXHsXWMKrmOziliGDToLx34a/ctZE4NOLnlrKQWN9ZG+Ox5zRarK1Eh
# ShahM0uQNhb6BJjp3+c0eNzMFJ2qLZqDp2/3Yl5Q+4k+MDHLTipP6VBdxcdVfd4m
# grVTx3afO5KNfgMngGGfhSawGraRW28EhrLOspmIxii92E7vjncJ2tcjhLCjBArV
# pPh3cZG5g3ZVy5iiAaoDaswpNgnMFAK5Un1reK+MFhPi9iMnvUPwtTDDJt5YED5D
# AT3mBUxp5QH3t7RhZwAJNLWLtpTeGF7ub81sSKYv2ardazAe9XLS10tV2oOPrcni
# GJzlXW7VPvxqQNxe8lCDA20CAwEAAaOCATYwggEyMB0GA1UdDgQWBBTsQfkz9gT4
# 4N/5G8vNHayep+aV5DAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQA1UK9xzIeTlKhSbLn0bekR5gYh6bB1XQpluCqC
# A15skZ37UilaFJw8+GklDLzlNhSP2mOiOzVyCq8kkpqnfUc01ZaBezQxg77qevj2
# iMyg39YJfeiCIhxYOFugwepYrPO8MlB/oue/VhIiDb1eNYTlPSmv3palsgtkrb0o
# o0F0uWmX4EQVGKRo0UENtZetVIxa0J9DpUdjQWPeEh9cEM+RgE265w5WAVb+WNx0
# iWiF4iTbCmrWaVEOX92dNqBm9bT1U7nGwN5CygpNAgEaYnrTMx1N4AjxObACDN5D
# dvGlu/O0DfMWVc6qk6iKDFC6WpXQSkMlrlXII/Nhp+0+noU6tfEpHKLt7fYm9of5
# i/QomcCwo/ekiOCjYktp393ovoC1O2uLtbLnMVlE5raBLBNSbINZ6QLxiA41lXnV
# VLIzDihUL8MU9CMvG4sdbhk2FX8zvrsP5PeBIw1faenMZuz0V3UXCtU5Okx5fmio
# WiiLZSCi1ljaxX+BEwQiinCi+vE59bTYI5FbuR8tDuGLiVu/JSpVFXrzWMP2Kn11
# sCLAGEjqJYUmO1tRY29Kd7HcIj2niSB0PQOCjYlnCnywnDinqS1CXvRsisjVlS1R
# p4Tmuks+pGxiMGzF58zcb+hoFKyONuL3b+tgxTAz3sF3BVX9uk9M5F+OEoeyLyGf
# LekNAjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQyMjAxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD1iK+pPThHqgpa5xsPmiYruWVuMoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmnr2yMCIYDzIwMjIwODEx
# MDcyODUwWhgPMjAyMjA4MTIwNzI4NTBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaevbICAQAwBwIBAAICFqswBwIBAAICETwwCgIFAOagDzICAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCiFpzGNotgRc/YgUvREL7pAntKPvOckDEKUAoepxXm
# QXraOIyrzTLerxq0uqHuznUkPofd7prONQyJHZuqB55IXixMPDifv/HJjFQHCItk
# AXgMUn1sbRx+b39RHIWNn2+Axn8RHTb1QCfEm+4RQgNJHKBlay5be8JEywweEp4A
# RzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjlnbRgCoEJTMAAEAAAGOMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIEDplvsozAZiJ+WFVagx
# cOEKyJ0B3xY+D+guXemmh+pbMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# vQWPITvigaUuV5+f/lWs3BXZwJ/l1mf+yelu5nXmxCUwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY5Z20YAqBCUzAABAAABjjAiBCBA
# TqI4iI4me4Ljg+9D5JZK71W0ZeAr6JiMCfhM9fsmvzANBgkqhkiG9w0BAQsFAASC
# AgCJRqqcqhnjlprEzHPkc0J0Xd+K7yLS/tVnZIJY6BL4K69YpSL8arJXWoE0rHpL
# zbrYDkE9r/S1SyRflcuUuBxSbtT7LnpmodLfCA6eUxm2C27eEWeha+VefvsYVLr8
# M2Y8e3pfDP9IiClUrIEIjyDm8rICCpDeTHdB+HR+Um4ykUI61u/IowNBTsMJVPmf
# yCi2kIivAeI2CgVbmRC1wg6qUrn4SfbD539Hcs0eaW4K6cZAbXI+Pe4N4wKnF8Az
# k5q4g/lMWHHgIyDvloPrLnyMKoPmktlGNZaJJuYXGmr0nOjXjx6PfrwZi+3r8GWg
# XZbeDx8Cb36uyA83T+E9yx5qT8KRDytjIHPUKtgLN3toiCQWkG3WmDfEAFmlxqkZ
# Y0gjSgDHYrHVdLx9nX3M2E5w4KssG75bRkYQT0KngFhH26RNooijMEr4m3wrifZ+
# E0tWAmrthw5r09IRLYtJBv5EnJiba2oAChT1GX1KPdA9Ykx43AH0Nc3uUuviw2kM
# JQiTwkYWuDQ1JOG8Ch4XbbTnBoy5FGp18D8xeSnAuHry7t8EFGYTUq8bNEERz7yE
# +Hja+UjTpAGcPgmKTDr38ZKM2rMTmrZazbRY7eGcTYWLgDfY5ryhv5H6jK0gK/ze
# 3u25TOn/JI7+NjTBng5fKAtRvtYnumYlnfkdHhyvMvOyOw==
# SIG # End signature block
