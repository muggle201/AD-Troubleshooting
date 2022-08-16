#************************************************
# DC_ChkSym.ps1
# Version 1.0.1
# Date: 7/15/2019
# Author: +waltere 2019.07.15
# Description:  This file will use Checksym.exe to list all file versions on the local machine
#************************************************

PARAM($range="All", $prefix="_sym", $FolderName=$null, $FileMask=$null, $Suffix=$null, $FileDescription = $null, [switch] $Recursive, [switch] $SkipCheckSymExe)

#$ProcArc = $Env:PROCESSOR_ARCHITECTURE
$ChkSymExe = "Checksym.exe"
$IsSkipChecksymExe = ($SkipCheckSymExe.IsPresent)

if (($OSArchitecture -eq 'ARM') -and (-not($IsSkipChecksymExe))){
	'Skipping running chksym executable since it is not supported in ' + $OSArchitecture + ' architecture.' | WriteTo-StdOut
	$IsSkipChecksymExe=$true
}
if($IsSkipChecksymExe){
	"External chksym executable not be used since $ChkSymExe does not exist" | WriteTo-StdOut -ShortFormat
}

$Error.Clear() | Out-Null 

Import-LocalizedData -BindingVariable LocalsCheckSym -FileName DC_ChkSym

trap [Exception] 
{
	$errorMessage = $Error[0].Exception.Message
	$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
	$line = $Error[0].InvocationInfo.PositionMessage
	"[DC_ChkSym] Error " + $errorCode + " on line " + $line + ": $errorMessage running dc_chksym.ps1" | WriteTo-StdOut -ShortFormat
	$Error.Clear() | Out-Null 
}

function GetExchangeInstallFolder{
	If ((Test-Path "HKLM:SOFTWARE\Microsoft\ExchangeServer\v14") -eq $true){
		[System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath)
	} ElseIf ((Test-Path "HKLM:SOFTWARE\Microsoft\Exchange\v8.0") -eq $true) {
		[System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\Exchange\Setup).MsiInstallPath)
	} Else { 
		$null
	}
}

function GetDPMInstallFolder{
	if ((Test-Path "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup") -eq $true)
	{
		return [System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup).InstallPath)
	}
	else
	{
		return $null
	}
}

Function FileExistOnFolder($PathToScan, $FileMask, [switch] $Recursive){
	trap [Exception] {
	
		$ErrorStd = "[FileExistOnFolder] The following error ocurred when checking if a file exists on a folder:`n" 
		$errorMessage = $Error[0].Exception.Message
		$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
		$line = $Error[0].InvocationInfo.PositionMessage
		"$ErrorStd Error " + $errorCode + " on line " + $line + ": $errorMessage`n   Path: $PathToScan`n   FileMask: $FileMask" | WriteTo-StdOut -ShortFormat
		 $error.Clear
		 continue
	}
	
	$AFileExist = $false
	
	if (Test-Path $PathToScan)
	{
		foreach ($mask in $FileMask) {
			if ($AFileExist -eq $false) {
				if ([System.IO.Directory]::Exists($PathToScan)) {
					if ($Recursive.IsPresent)
					{
						$Files = [System.IO.Directory]::GetFiles($PathToScan, $mask,[System.IO.SearchOption]::AllDirectories)
					} else {
						$Files = [System.IO.Directory]::GetFiles($PathToScan, $mask,[System.IO.SearchOption]::TopDirectoryOnly)
					}
					$AFileExist = ($Files.Count -ne 0)
				}
			}
		}
	}
	return $AFileExist
}

Function GetAllRunningDriverFilePath([string] $DriverName){
	$driversPath = "HKLM:System\currentcontrolset\services\"+$DriverName
	if(Test-Path $driversPath){
		$ImagePath = (Get-ItemProperty ("HKLM:System\currentcontrolset\services\"+$DriverName)).ImagePath
	}
	if($null -eq $ImagePath){
		$driversPath = "system32\drivers\"+$DriverName+".sys"
		$ImagePath = join-path $env:windir $driversPath
		if(-not(Test-Path $ImagePath))
		{
			$Driver.Name + "not exist in the system32\drivers\"| WriteTo-StdOut -ShortFormat
		}
	}
	else{
		if($ImagePath.StartsWith("\SystemRoot\")){
			$ImagePath = $ImagePath.Remove(0,12)
		}
		elseif($ImagePath.StartsWith("\??\")){
			$ImagePath = $ImagePath.Remove(0,14)
		}
		$ImagePath = join-path $env:windir $ImagePath	
	}
	return $ImagePath
}

Function PrintTXTCheckSymInfo([PSObject]$OutPut, $StringBuilder, [switch]$S, [switch]$R){	
	if($null -ne $OutPut.Processes)
	{
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		[void]$StringBuilder.Append("[PROCESSES] - Printing Process Information for "+$OutPut.Processes.Count +" Processes.`r`n")
		[void]$StringBuilder.Append("[PROCESSES] - Context: System Process(es)`r`n")
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		
		Foreach($Process in $OutPut.Processes)
		{
			$Index = 1
			[void]$StringBuilder.Append("-----------------------------------------------------------`r`n")
			[void]$StringBuilder.Append("Process Name ["+$Process.ProcessName.ToUpper()+".EXE] - PID="+$Process.Id +" - "+ $Process.Modules.Count +" modules recorded`r`n")
			[void]$StringBuilder.Append("-----------------------------------------------------------`r`n")
			foreach($mod in $Process.Modules)
			{
				if($null -ne $mod.FileName)
				{
					[void]$StringBuilder.Append("Module[  "+$Index+"] [" + $mod.FileName+"]`r`n")
					if($R.IsPresent)
					{
						$FileItem = Get-ItemProperty $mod.FileName
						[void]$StringBuilder.Append("  Company Name:      " + $FileItem.VersionInfo.CompanyName	+"`r`n")
						[void]$StringBuilder.Append("  File Description:  " + $FileItem.VersionInfo.FileDescription +"`r`n")
						[void]$StringBuilder.Append("  Product Version:   " + $FileItem.VersionInfo.ProductVersion+"`r`n")
						[void]$StringBuilder.Append("  File Version:      " + $FileItem.VersionInfo.FileVersion+"`r`n")
						[void]$StringBuilder.Append("  File Size (bytes): " + $FileItem.Length+"`r`n")
						[void]$StringBuilder.Append("  File Date:         " + $FileItem.LastWriteTime+"`r`n")
					
					}	
				
					if($S.IsPresent)
					{
						
					}
					[void]$StringBuilder.Append("`r`n")
					$Index+=1
				}
			}	
		}
	}
	
	if($null -ne $OutPut.Drivers)
	{		
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		[void]$StringBuilder.Append( "[KERNEL-MODE DRIVERS] - Printing Module Information for "+$OutPut.Drivers.Count +" Modules.`r`n")
		[void]$StringBuilder.Append( "[KERNEL-MODE DRIVERS] - Context: Kernel-Mode Driver(s)`r`n")
		[void]$StringBuilder.Append( "*******************************************************************************`r`n")
		$Index = 1
		Foreach($Driver in $OutPut.Drivers)
		{		
			$DriverFilePath = GetAllRunningDriverFilePath $Driver.Name	
			[void]$StringBuilder.Append("Module[  "+$Index+"] [" + $DriverFilePath+"]`r`n")
						
			if($R.IsPresent)
			{
				$FileItem = Get-ItemProperty $DriverFilePath
				if(($null -ne $FileItem.VersionInfo.CompanyName) -and ($FileItem.VersionInfo.CompanyName -ne ""))
				{
					[void]$StringBuilder.Append("  Company Name:      " + $FileItem.VersionInfo.CompanyName	+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileDescription) -and ($FileItem.VersionInfo.FileDescription.trim() -ne ""))
				{
					[void]$StringBuilder.Append("  File Description:  " + $FileItem.VersionInfo.FileDescription +"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.ProductVersion) -and ($FileItem.VersionInfo.ProductVersion -ne ""))
				{
					[void]$StringBuilder.Append("  Product Version:   " + $FileItem.VersionInfo.ProductVersion+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileVersion) -and ($FileItem.VersionInfo.FileVersion -ne ""))
				{
					[void]$StringBuilder.Append("  File Version:      " + $FileItem.VersionInfo.FileVersion+"`r`n"	)
				}
				[void]$StringBuilder.Append("  File Size (bytes): " + $FileItem.Length+"`r`n")
				[void]$StringBuilder.Append("  File Date:         " + $FileItem.LastWriteTime+"`r`n")
			}
			
			if($S.IsPresent)
			{

			}
			
			[void]$StringBuilder.Append("`r`n")
			$Index+=1
		}
	}
	
	if($null -ne $OutPut.Files)
	{
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		[void]$StringBuilder.Append("[FILESYSTEM MODULES] - Printing Module Information for "+$OutPut.Files.Count +" Modules.`r`n")
		[void]$StringBuilder.Append("[FILESYSTEM MODULES] - Context: Filesystem Modules`r`n")
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		$Index = 1
		Foreach($File in $OutPut.Files)
		{
			[void]$StringBuilder.Append("Module[  "+$Index+"] [" + $File+"]`r`n")
			if($R.IsPresent)
			{	
				$FileItem = Get-ItemProperty $File
				if(($null -ne $FileItem.VersionInfo.CompanyName) -and ($FileItem.VersionInfo.CompanyName -ne ""))
				{
					[void]$StringBuilder.Append("  Company Name:      " + $FileItem.VersionInfo.CompanyName	+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileDescription) -and ($FileItem.VersionInfo.FileDescription.trim() -ne ""))
				{
					[void]$StringBuilder.Append("  File Description:  " + $FileItem.VersionInfo.FileDescription +"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.ProductVersion) -and ($FileItem.VersionInfo.ProductVersion -ne ""))
				{
					[void]$StringBuilder.Append("  Product Version:   " + $FileItem.VersionInfo.ProductVersion+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileVersion) -and ($FileItem.VersionInfo.FileVersion -ne ""))
				{
					[void]$StringBuilder.Append("  File Version:      " + $FileItem.VersionInfo.FileVersion+"`r`n"	)
				}
				[void]$StringBuilder.Append("  File Size (bytes): " + $FileItem.Length+"`r`n")
				[void]$StringBuilder.Append("  File Date:         " + $FileItem.LastWriteTime+"`r`n")	
			}	
				
			if($S.IsPresent)
			{
						
			}
			[void]$StringBuilder.Append("`r`n")
			$Index+=1
		}			
	}
}

Function PrintCSVCheckSymInfo([PSObject]$OutPut, $StringBuilder, [switch]$S, [switch]$R){
	[void]$StringBuilder.Append("Create:,"+[DateTime]::Now+"`r`n")
	[void]$StringBuilder.Append("Computer:,"+ $ComputerName+"`r`n`r`n")

	if($null -ne $OutPut.Processes)
	{	
		[void]$StringBuilder.Append("[PROCESSES]`r`n")
		[void]$StringBuilder.Append(",Process Name,Process ID,Module Path,Symbol Status,Checksum,Time/Date Stamp,Time/Date String,Size Of Image,DBG Pointer,PDB Pointer,PDB Signature,PDB Age,Product Version,File Version,Company Name,File Description,File Size,File Time/Date Stamp (High),File Time/Date Stamp (Low),File Time/Date String,Local DBG Status,Local DBG,Local PDB Status,Local PDB`r`n")
		Foreach($Process in $OutPut.Processes)
		{
			if($null -ne $Process.Modules)
			{
				foreach($mod in $Process.Modules)
				{						
					if($null -ne $mod.FileName)
					{
						[void]$StringBuilder.Append("," +$Process.Name+".EXE,"+$Process.Id+",")
						[void]$StringBuilder.Append( $mod.FileName+",")
						if($S.IsPresent)
						{
							[void]$StringBuilder.Append("SYMBOLS_PDB,,,,,,,,,")
						}
						else
						{
							[void]$StringBuilder.Append("SYMBOLS_No,,,,,,,,,")
						}
						
						if($R.IsPresent)
						{
							$FileItem = Get-ItemProperty $mod.FileName
							[void]$StringBuilder.Append( "("+$FileItem.VersionInfo.ProductVersion.Replace(",",".")+"	),("+$FileItem.VersionInfo.FileVersion.Replace(",",".")+"	),"+$FileItem.VersionInfo.CompanyName.Replace(",",".")+","+$FileItem.VersionInfo.FileDescription.Replace(",",".")+","+$FileItem.Length+",,,"+$FileItem.LastWriteTime+",,,,,`r`n")
						}
						else
						{
							[void]$StringBuilder.Append( ",,,,,,,,,,,,`r`n")
						}
					}
				}
			}	
		}
	}
	
	if($null -ne $OutPut.Drivers)
	{
		[void]$StringBuilder.Append("[KERNEL-MODE DRIVERS]`r`n")
		[void]$StringBuilder.Append(",,,Module Path,Symbol Status,Checksum,Time/Date Stamp,Time/Date String,Size Of Image,DBG Pointer,PDB Pointer,PDB Signature,PDB Age,Product Version,File Version,Company Name,File Description,File Size,File Time/Date Stamp (High),File Time/Date Stamp (Low),File Time/Date String,Local DBG Status,Local DBG,Local PDB Status,Local PDB`r`n")
		Foreach($Driver in $OutPut.Drivers)
		{		
			$DriverFilePath = GetAllRunningDriverFilePath $Driver.Name	
			[void]$StringBuilder.Append(",,," +$DriverFilePath+",")
			if($S.IsPresent)
			{
				[void]$StringBuilder.Append("SYMBOLS_PDB,,,,,,,,,")
			}
			else
			{
				[void]$StringBuilder.Append("SYMBOLS_NO,,,,,,,,,")
			}
						
			if($R.IsPresent)
			{
				$DriverItem = Get-ItemProperty $DriverFilePath
				if($null -ne $DriverItem.VersionInfo.ProductVersion)
				{
					[void]$StringBuilder.Append("("+$DriverItem.VersionInfo.ProductVersion.Replace(",",".")+"),("+$DriverItem.VersionInfo.FileVersion.Replace(",",".")+"),"+$DriverItem.VersionInfo.CompanyName.Replace(",",".")+","+$DriverItem.VersionInfo.FileDescription.Replace(",",".")+","+$DriverItem.Length+",,,"+$DriverItem.LastWriteTime+",,,,,`r`n")
				}
				else
				{
					[void]$StringBuilder.Append(",,,,"+$DriverItem.Length+",,,"+$DriverItem.LastWriteTime+",,,,,`r`n")
				}
			}
			else
			{
				[void]$StringBuilder.Append(",,,,,,,,,,,,`r`n")
			}	
		}
	}
	
	if($null -ne $OutPut.Files)
	{	
		[void]$StringBuilder.Append("[FILESYSTEM MODULES]`r`n")
		[void]$StringBuilder.Append(",,,Module Path,Symbol Status,Checksum,Time/Date Stamp,Time/Date String,Size Of Image,DBG Pointer,PDB Pointer,PDB Signature,PDB Age,Product Version,File Version,Company Name,File Description,File Size,File Time/Date Stamp (High),File Time/Date Stamp (Low),File Time/Date String,Local DBG Status,Local DBG,Local PDB Status,Local PDB`r`n")
		Foreach($File in $OutPut.Files)
		{						
			[void]$StringBuilder.Append(",,," +$File+",")
			if($S.IsPresent)
			{
				[void]$StringBuilder.Append("SYMBOLS_PDB,,,,,,,,,")
			}
			else
			{
				[void]$StringBuilder.Append("SYMBOLS_NO,,,,,,,,,")
			}
						
			if($R.IsPresent)
			{
				$FileItem = Get-ItemProperty $File
				if($null -ne $FileItem.VersionInfo.ProductVersion)
				{
					[void]$StringBuilder.Append("("+$FileItem.VersionInfo.ProductVersion.Replace(",",".")+"	),("+$FileItem.VersionInfo.FileVersion.Replace(",",".")+"	),"+$FileItem.VersionInfo.CompanyName.Replace(",",".")+","+$FileItem.VersionInfo.FileDescription.Replace(",",".")+","+$FileItem.Length+",,,"+$FileItem.LastWriteTime+",,,,,`r`n")
				}
				else
				{
					[void]$StringBuilder.Append(",,,,"+$FileItem.Length+",,,"+$FileItem.LastWriteTime+",,,,,`r`n")
				}
			}
			else
			{
				[void]$StringBuilder.Append(",,,,,,,,,,,,`r`n")
			}	
		}
	}
}

Function PSChkSym ([string]$PathToScan="", [array]$FileMask = "*.*", [string]$O2="", [String]$P ="", [switch]$D, [switch]$F, [switch]$F2, [switch]$S, [switch]$R){
	#check the system information
	# P ---- get the process information, can give a * get all process info or give a process name get the specific process
	# D ---- get the all local running drivers infor
	# F ---- search the top level folder to get the files
	# F2 ---- search the all level from folder, Recursive
	# S ---- get Symbol Information
	# R ---- get the Version and File-System Information
	# O2 ---- Out the result to the file
	trap [Exception] {
	
		$ErrorStd = "[PSChkSym] The following error ocurred when getting the file from a folder:`n" 
		$errorMessage = $Error[0].Exception.Message
		$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
		$line = $Error[0].InvocationInfo.PositionMessage
		"$ErrorStd Error " + $errorCode + " on line " + $line + ": $errorMessage`n   Path: $PathToScan`n   FileMask: $FileMask" | WriteTo-StdOut -ShortFormat
		 $error.Clear
		 continue
	}	

	$OutPutObject = New-Object PSObject
	$SbCSVFormat = New-Object -TypeName System.Text.StringBuilder
	$SbTXTFormat = New-Object -TypeName System.Text.StringBuilder
	[void]$SbTXTFormat.Append("***** COLLECTION OPTIONS *****`r`n")
	
	if($P -ne "")
	{
		[void]$SbTXTFormat.Append("Collect Information From Running Processes`r`n")
		if($P -eq "*")
		{
			[void]$SbTXTFormat.Append("    -P *     (Query all local processes) `r`n")
			
			$Processes = [System.Diagnostics.Process]::GetProcesses()
		}
		else
		{
			[void]$SbTXTFormat.Append("    -P $P     (Query for specific process by name) `r`n" )
			
			$Processes = [System.Diagnostics.Process]::GetProcessesByName($P)
		}
	}
	
	if($D.IsPresent)
	{
		[void]$SbTXTFormat.Append("    -D     (Query all local device drivers) `r`n")
		Add-Type -assemblyname System.ServiceProcess
		$DeviceDrivers = [System.ServiceProcess.ServiceController]::GetDevices() | where-object {$_.Status -eq "Running"}
		#$DeviceDrivers = GetAllRunningDriverFileName
	}
	
	if($F.IsPresent -or $F2.IsPresent)
	{
		[void]$SbTXTFormat.Append("Collect Information From File(s) Specified by the User`r`n")
		[void]$SbTXTFormat.Append("   -F $PathToScan\$FileMask`r`n")
		if($F.IsPresent) 
		{
			Foreach($Mask in $FileMask)
			{
				$Files += [System.IO.Directory]::GetFiles($PathToScan, $Mask,[System.IO.SearchOption]::TopDirectoryOnly)
			}
		}
		else
		{
			Foreach($Mask in $FileMask)
			{
				$Files += [System.IO.Directory]::GetFiles($PathToScan, $Mask,[System.IO.SearchOption]::AllDirectories)
			}
		}
	}
	
	[void]$SbTXTFormat.Append("***** INFORMATION CHECKING OPTIONS *****`r`n")
	if($S.IsPresent -or $R.IsPresent)
	{
		if($S.IsPresent)
		{
			
			[void]$SbTXTFormat.Append("Output Symbol Information From Modules`r`n")
			[void]$SbTXTFormat.Append("   -S `r`n")
		}
		
		if($R.IsPresent)
		{
			[void]$SbTXTFormat.Append("Collect Version and File-System Information From Modules`r`n")
			[void]$SbTXTFormat.Append("   -R `r`n")
		}
	}
	else
	{
		[void]$SbTXTFormat.Append("Output Symbol Information From Modules`r`n")
		[void]$SbTXTFormat.Append("   -S `r`n")
		[void]$SbTXTFormat.Append("Collect Version and File-System Information From Modules`r`n")
		[void]$SbTXTFormat.Append("   -R `r`n")
	}
	
	[void]$SbTXTFormat.Append("***** OUTPUT OPTIONS *****`r`n")
	[void]$SbTXTFormat.Append("Output Results to STDOUT`r`n")
	[void]$SbTXTFormat.Append("Output Collected Module Information To a CSV File`r`n")
	
	if($O2 -ne "")
	{
		$OutFiles = $O2.Split('>')
		[void]$SbTXTFormat.Append("   -O "+$OutFiles[0]+" `r`n")
	}
	
	add-member -inputobject $OutPutObject -membertype noteproperty -name "Processes" -value $Processes
	add-member -inputobject $OutPutObject -membertype noteproperty -name "Drivers" -value $DeviceDrivers
	add-member -inputobject $OutPutObject -membertype noteproperty -name "Files" -value $Files
	
	if(($S.IsPresent -and $R.IsPresent) -or (-not$S.IsPresent -and -not$R.IsPresent))
	{
		PrintTXTCheckSymInfo -OutPut $OutPutObject $SbTXTFormat -S -R
		PrintCSVCheckSymInfo -OutPut $OutPutObject $SbCSVFormat -S -R
	}
	elseif($S.IsPresent -and -not$R.IsPresent)
	{
		PrintTXTCheckSymInfo -OutPut $OutPutObject $SbTXTFormat -S
		PrintCSVCheckSymInfo -OutPut $OutPutObject $SbCSVFormat -S
	}
	else
	{
		PrintTXTCheckSymInfo -OutPut $OutPutObject $SbTXTFormat -R
		PrintCSVCheckSymInfo -OutPut $OutPutObject $SbCSVFormat -R
	}	
	
	foreach($out in $OutFiles)
	{
		if($out.EndsWith("CSV",[StringComparison]::InvariantCultureIgnoreCase))
		{
			$SbCSVFormat.ToString() | Out-File $out -Encoding "utf8"
		}
		else
		{
			if(Test-Path $out)
			{
				$SbTXTFormat.ToString() | Out-File $out -Encoding "UTF8" -Append
			}
			else
			{
				$SbTXTFormat.ToString() | Out-File $out -Encoding "UTF8"
			}
		}
	}
}

Function RunChkSym ([string]$PathToScan="", [array]$FileMask = "*.*", [string]$Output="", [boolean]$Recursive=$false, [string]$Arguments="", [string]$Description="", [boolean]$SkipChksymExe=$false){
	if (($Arguments -ne "") -or (Test-Path ($PathToScan))) 
	{
		if ($PathToScan -ne "")
		{
			$eOutput = $Output
			ForEach ($scFileMask in $FileMask){ #
				$eFileMask = ($scFileMask.replace("*.*","")).toupper()
				$eFileMask = ($eFileMask.replace("*.",""))
				$eFileMask = ($eFileMask.replace(".*",""))
				if (($eFileMask -ne "") -and (Test-Path ("$eOutput.*") )) {$eOutput += ("_" + $eFileMask)}
				$symScanPath += ((Join-Path -Path $PathToScan -ChildPath $scFileMask) + ";")
			}
		}
		
		if ($Description -ne "") 
		{
			$FileDescription = $Description
		} else {
			$fdFileMask = [string]::join(";",$FileMask)
			if ($fdFileMask -contains ";") { 
				$FileDescription = $PathToScan + " [" + $fdFileMask + "]"
			} else {
				$FileDescription = (Join-Path $PathToScan $fdFileMask)
			}
		}
	

		if ($Arguments -ne "") 
		{
			$eOutput = $Output
			Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status $Description
			if(-not($SkipChksymExe))
			{
				$CommandToExecute = "cmd.exe /c $ChkSymExe $Arguments"
			}
			else
			{
				#calling the method to implement the functionalities
				$Arguments = $Arguments.Substring(0,$Arguments.IndexOf("-O2")+4) +"$Output.CSV>$Output.TXT"
				invoke-expression "PSChkSym  $Arguments"
			}
		}
		else {
			Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status ($FileDescription)# + " Recursive: " + $Recursive)
			if ($Recursive -eq $true) {
				$F = "-F2"
				$AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask -Recursive) 
			} else {
				$F = "-F"
				$AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask)
				
			}
			if ($AFileExistOnFolder) 
			{
				if(-not($SkipChksymExe))
				{
					$CommandToExecute = "cmd.exe /c $ChkSymExe $F `"$symScanPath`" -R -S -O2 `"$eOutput.CSV`" > `"$eOutput.TXT`""
				}
				else
				{
					#calling the method to implement the functionalities
					if($F -eq "-F2")
					{
						PSChkSym -PathToScan $PathToScan -FileMask $FileMask -F2 -S -R -O2 "$eOutput.CSV>$eOutput.TXT"
					}
					else
					{
						PSChkSym -PathToScan $PathToScan -FileMask $FileMask -F -S -R -O2 "$eOutput.CSV>$eOutput.TXT"
					}
				}
			} 
			else 
			{
				"Chksym did not run against path '$PathToScan' since there are no files with mask ($scFileMask) on system" | WriteTo-StdOut -ShortFormat
				$CommandToExecute = ""
			}
		}
		if ($CommandToExecute -ne "") {
			RunCmD -commandToRun $CommandToExecute -sectionDescription "File Version Information (ChkSym)" -filesToCollect ("$eOutput.*") -fileDescription $FileDescription -BackgroundExecution
		}
	}
	else {
		"Chksym did not run against path '$PathToScan' since path does not exist" | WriteTo-StdOut -ShortFormat
	}
}

### Main ###
#Check if using $FolderName or $RangeString
if (($null -ne $FolderName) -and ($null -ne $FileMask) -and ($null -ne $Suffix)) {
	$OutputBase = $ComputerName + $Prefix + $Suffix
	$IsRecursive = ($Recursive.IsPresent)
	RunChkSym -PathToScan $FolderName -FileMask $FileMask -Output $OutputBase  -Description $FileDescription -Recursive $IsRecursive -CallChksymExe $IsSkipChecksymExe
} else {
	[array] $RunChkSym = $null
	Foreach ($RangeString in $range) 
	{
		if ($RangeString -eq "All")	
		{
			$RunChkSym += "ProgramFilesSys", "Drivers", "System32DLL", "System32Exe", "System32SYS", "Spool", "iSCSI", "Process", "RunningDrivers", "Cluster"
		} else {
			$RunChkSym += $RangeString
		}
	}

	switch ($RunChkSym)	{
		"ProgramFilesSys" {
			$OutputBase="$ComputerName$Prefix" + "_ProgramFiles_SYS"
			RunChkSym -PathToScan "$Env:ProgramFiles" -FileMask "*.sys" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_ProgramFilesx86_SYS"
				RunChkSym -PathToScan (${Env:ProgramFiles(x86)}) -FileMask "*.sys" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"Drivers" {
			$OutputBase="$ComputerName$Prefix" + "_Drivers"
			RunChkSym -PathToScan "$Env:SystemRoot\System32\drivers" -FileMask "*.*" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			}
		"System32DLL" {
			$OutputBase="$ComputerName$Prefix" + "_System32_DLL"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.DLL" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_DLL"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.dll" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"System32Exe" {
			$OutputBase="$ComputerName$Prefix" + "_System32_EXE"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.EXE" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_EXE"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.exe" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"System32SYS" {
			$OutputBase="$ComputerName$Prefix" + "_System32_SYS"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.SYS" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_SYS"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.sys" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"Spool" {
			$OutputBase="$ComputerName$Prefix" + "_PrintSpool"
			RunChkSym -PathToScan "$Env:SystemRoot\System32\Spool" -FileMask "*.*" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"Cluster" {
			$OutputBase="$ComputerName$Prefix" + "_Cluster"
			RunChkSym -PathToScan "$Env:SystemRoot\Cluster" -FileMask "*.*" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			}
		"iSCSI" {
			if(Test-Path "$Env:ProgramFiles\Microsoft iSNS Server" ) {
				$OutputBase="$ComputerName$Prefix" + "_MS_iSNS"
				RunChkSym -PathToScan "$Env:ProgramFiles\Microsoft iSNS Server" -FileMask "*.*" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			$OutputBase="$ComputerName$Prefix" + "_MS_iSCSI"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "iscsi*.*" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			}
		"Process" {
			$OutputBase="$ComputerName$Prefix" + "_Process"
			Get-Process | Format-Table -Property "Handles","NPM","PM","WS","VM","CPU","Id","ProcessName","StartTime",@{ Label = "Running Time";Expression={(GetAgeDescription -TimeSpan (new-TimeSpan $_.StartTime))}} -AutoSize | Out-File "$OutputBase.txt" -Encoding "UTF8" -Width 200
			"--------------------------------" | Out-File "$OutputBase.txt" -Encoding "UTF8" -append
			tasklist -svc | Out-File "$OutputBase.txt" -Encoding "UTF8" -append -EA SilentlyContinue
			"--------------------------------" | Out-File "$OutputBase.txt" -Encoding "UTF8" -append
			RunChkSym -Output $OutputBase -Arguments "-P * -R -O2 `"$OutputBase.CSV`" >> `"$OutputBase.TXT`"" -Description "Running Processes" -SkipChksymExe $IsSkipChecksymExe
			}
		"RunningDrivers" {
			$OutputBase="$ComputerName$Prefix" + "_RunningDrivers"
			RunChkSym -Output $OutputBase -Arguments "-D -R -S -O2 `"$OutputBase.CSV`" > `"$OutputBase.TXT`"" -Description "Running Drivers" -SkipChksymExe $IsSkipChecksymExe
			}
		"InetSrv" {
			$inetSrvPath = (join-path $env:systemroot "system32\inetsrv")
			$OutputBase = "$ComputerName$Prefix" + "_InetSrv"
			RunChkSym -PathToScan $inetSrvPath -FileMask ("*.exe","*.dll") -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"Exchange" {
			$ExchangeFolder = GetExchangeInstallFolder
			if ($null -ne $ExchangeFolder){
				$OutputBase = "$ComputerName$Prefix" + "_Exchange"
				RunChkSym -PathToScan $ExchangeFolder -FileMask ("*.exe","*.dll") -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			} else {
				"Chksym did not run against Exchange since it could not find Exchange server installation folder" | WriteTo-StdOut -ShortFormat
			}
		}
		"DPM" {
			$DPMFolder = GetDPMInstallFolder
			If ($null -ne $DPMFolder)
			{
				$DPMFolder = Join-Path $DPMFolder "bin"
				$OutputBase= "$ComputerName$Prefix" + "_DPM"
				RunChkSym -PathToScan $DPMFolder -FileMask("*.exe","*.dll") -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			} else {
				"Chksym did not run against DPM since it could not find the DPM installation folder" | WriteTo-StdOut -ShortFormat
			}
		}
		"WinSxsDLL" {
			$OutputBase="$ComputerName$Prefix" + "_WinSxS_DLL"
			RunChkSym -PathToScan "$Env:SystemRoot\WinSxS" -FileMask "*.DLL" -Output $OutputBase -Recursive $True -SkipChksymExe $IsSkipChecksymExe
			}
		"WinSxsEXE" {
			$OutputBase="$ComputerName$Prefix" + "_WinSxS_EXE"
			RunChkSym -PathToScan "$Env:SystemRoot\WinSxS" -FileMask "*.EXE" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"WinSxsSYS" {
			$OutputBase="$ComputerName$Prefix" + "_WinSxS_SYS"
			RunChkSym -PathToScan "$Env:SystemRoot\WinSxS" -FileMask "*.SYS" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"RefAssmDLL" {
			$OutputBase="$ComputerName$Prefix" + "_RefAssm_DLL"
			RunChkSym -PathToScan "$Env:programfiles\Reference Assemblies" -FileMask "*.DLL" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"DotNETDLL" {
			$OutputBase="$ComputerName$Prefix" + "_DotNET_DLL"
			RunChkSym -PathToScan "$Env:SystemRoot\Microsoft.NET" -FileMask "*.DLL" -Output $OutputBase -Recursive $True -SkipChksymExe $IsSkipChecksymExe
			}
	}
}


# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCBz9Vl1N2x2iV0
# s8x77ctdArz3zMsz0ZEzxmLd4Vj6CqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICpCLWnRhSbluNcfXEYfRlFk
# 6bsGfbJhrQE8UCaiHUswMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA4FkY9vxIEMU+Q2Mdz5faW/M1zreLFF2Rqask7G00ChltemyiZmcBS
# 80openfg6flV5moeOFrjFjWX0uSfyfMkz2YqzRTecci9NEaR7qabfxwgunDN7UXm
# v4etueWuJQk/3b6e925bsgnMvkyWN0h7w/o62jwHWAoYWoM7otcBDI4oyXImPipz
# LIE3kohw4qW7+tlT/CglzLmA+yIvaUmOjQNvFXCzq7X7ZKeS8Zj8B9vWshCi90kF
# /H5ALp12Sp5Ydg462RlX2KO44aM0nTR8v2CLXp2Hkl1w2XdVaLqSzmbtcLZIQ5W0
# StpHd2AqbzTs83TT61Nyed/U23ly106+oYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEINYBqPHaH4mlXKICc7YRWlH89qQ+rwZgeKV0gNGEcfWyAgZi2yMn
# O4IYEzIwMjIwODA4MDkxNTEzLjkxNlowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoz
# MkJELUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABrfzfTVjjXTLpAAEAAAGtMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEzNloXDTIzMDUxMTE4NTEzNlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozMkJELUUzRDUtM0Ix
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAOieUyqlTSrVLhvY7TO8vgC+T5N/y/MX
# eR3oNwE0rLI1Eg/gM5g9NhP+KqqJc/7uPL4TsoALb+RVf6roYNllyQrYmquUjwsq
# 262MD5L9l9rU1plz2tMPehP8addVlNIjYIBh0NC4CyME6txVppQr7eFd/bW0X9tn
# Zy1aDW+zoaJB2FY8haokq5cRONEW4uoVsTTXsICkbYOAYffIIGakMFXVvB30Ncsu
# iDn6uDk83XXTs0tnSr8FxzPoD8SgPPIcWaWPEjCQLr5I0BxfdUliwNPHIPEglqos
# rClRjXG7rcZWbWeODgATi0i6DUsv1Wn0LOW4svK4/Wuc/v9dlmuIramv9whbgCyk
# UuYZy8MxTzsQqU2Rxcm8h89CXA5jf1k7k3ZiaLUJ003MjtTtNXzlgb+k1A5eL17G
# 3C4Ejw5AoViM+UBGQvxuTxpFeaGoQFqeOGGtEK0qk0wdUX9p/4Au9Xsle5D5fvyp
# BdscXBslUBcT6+CYq0kQ9smsTyhV4DK9wb9Zn7ObEOfT0AQyppI6jwzBjHhAGFyr
# KYjIbglMaEixjRv7XdNic2VuYKyS71A0hs6dbbDx/V7hDbdv2srtZ2VTO0y2E+4Q
# qMRKtABv4AggjYKz5TYGuQ4VbbPY8fBO9Xqva3Gnx1ZDOQ3nGVFKHwarGDcNdB3q
# esvtJbIGJgJjAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUfVB0HQS8qiFabmqEqOV9
# LrLGwVkwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAi9AdRbsx/gOSdBXndwRejQuutQqce3k3bgs1slPjZSx6FDXp
# 1IZzjOyT1Jo/3eUWDBFJdi+Heu1NoyDdGn9vL6rxly1L68K4MnfLBm+ybyjN+xa1
# eNa4+4cOoOuxE2Kt8jtmZbIhx2jvY7F9qY/lanR5PSbUKyClhNQhxsnNUp/JSQ+o
# 7nAuQJ+wsCwPCrXYE7C+TvKDja6e6WU0K4RiBXFGU1z6Mt3K9wlMD/QGU4+/IGZD
# mE+/Z/k0JfJjZyxCAlcmhe3rgdhDzAsGxJYq4PblGZTBdr8wkQwpP2jggyMMawMM
# 5DggwvXaDbrqCQ8gksNhCZzTqfS2dbgLF0m7HfwlUMrcnzi/bdTSRWzIXg5QsH1t
# 5XaaIH+TZ1uZBtwXJ8EOXr6S+2A6q8RQVY10KnBH6YpGE9OhXPfuIu882muFEdh4
# EXbPdARUR1IMSIxg88khSBC/YBwQhCpjTksq5J3Z+jyHWZ4MnXX5R42mAR584iRY
# c7agYvuotDEqcD0U9lIjgW31PqfqZQ1tuYZTiGcKE9QcYGvZFKnVdkqK8V0M9e+k
# F5CqDOrMMYRV2+I/FhyQsJHxK/G53D0O5bvdIh2gDnEHRAFihdZj29Z7W0paGPot
# GX0oB5r9wqNjM3rbvuEe6FJ323MPY1x9/N1g126T/SokqADJBTKqyBYN4zMwggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjozMkJELUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAQJLRrUVR4ZbB
# DgWPjuNqVctUzpCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaauMMwIhgPMjAyMjA4MDgwMjE4NDNaGA8yMDIy
# MDgwOTAyMTg0M1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pq4wwIBADAKAgEA
# AgIb2wIB/zAHAgEAAgIRTzAKAgUA5pwKQwIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBABocWkhZo8F1K3s+ryX+BBEval+sP3cKS4jYOsZUShbG55fGxfjAHyTC
# m1EMzhnYSdjqSr5WjRVFYbMpPw/bJp0XMlj5h/Feg7lSa9TYu8Y7TShQsohmJvP1
# 2SKYVdVQI84hDsPgRwobCmyVrWMH7LJ01ugtJVNMTMVBqENlYTNkMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGt/N9NWONd
# MukAAQAAAa0wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgd7PzU6UXehtL2pXQYmwcfF0euCvZ4COs
# jlqiWnjROQgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCf6nw9CR5e1+Ot
# tcn1w992Kmn8YMTY/DWPIHeMbMtQgjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABrfzfTVjjXTLpAAEAAAGtMCIEIFg192AqBWWd6MHx
# xYCTDE8+rZcj63Sjvd/VZtHfvUxqMA0GCSqGSIb3DQEBCwUABIICANJVUdkPU6ue
# gCZ5vedxQxEpMlBUUI+jHGTZpkeeassnhJklZThNWviDGb/GKSb0K5hcAoqms51h
# E2MxL1DB8A+2fqYjtex+QYGoegmF6zNCOoTaAZqDSL54q5WazgEDgrvn5zV3DgTX
# zkq6+EYMKcw/1UF5w0J2CaBVhWpyNoEIyicgQsPAZQ+yvzUMOm45j320GgyyT5Xv
# usSIu0rM41PHJtYxAhSyNSKlJPhXEfaYJfU1T/bW91CA0k9nPJr32Zar32za/ErG
# NLxP8W+fVMCa+UfbRTEhDC27Pk8tTxeQogFUo1uaksYYUSYriz6Hpi/xy2J8zUk2
# feELcxZA2pNSx3dUMPjeHNTADtt52LhiJRTDPZbNZqlPx3qRHuT/aLKt/X095Orq
# SmHvp2Ys2Cbomv/wCb8wuPhzEjhQbTWQiqI13pro7nF1nfSjRBl7mfw+nqyR6M4E
# nxQZor/zmDi0KPqzqrj5G+bvJzoXfOYvfTKlhLNbncehMcyYJEmNmrT5G80G1ylT
# UTIs2VfiKD82vNkkreDGpNva2ySMu+kTWJHrOoqLgOgpm1KgclW1SBGmhPFk5eku
# tN/zRcVxAZMvQFLVw8Lg1GAaJQrSSw2wgPwS0uw0nY1HhfrFlHrBfhGEbChWIgMT
# DbIU96J4Ul17VSkV+MZ4ua1khMyXg7mr
# SIG # End signature block
