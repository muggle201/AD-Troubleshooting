#************************************************
# DC_HotfixRollups.ps1
# Version 1.0.04.02.14: Created script to easily view what rollups are installed for W7/WS2008R2, W8/WS2012, and W8.1/WS2012R2
# Version 1.1.05.16.14: Added W8.1 Update1 (April2014 rollup);  Added OS Version below each heading.
# Version 1.6.10.16.14: Added Oct2014 updates for W8/W8.1
# Date: 2019,2020
# Author: Boyd Benson (bbenson@microsoft.com) +WalterE
# Description: Creates output to easily identify what rollups are installed on W7/WS2008R2 and later.
# Called from: Networking Diagnostics, and all psSDP
#  ToDo: read latest KB# from \xray\xray_WU.psm1 -or- KBonlyRollup_* from RFL
#*******************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptVariable

$OutputFile = $Env:ComputerName + "_HotfixRollups.TXT"
$sectionDescription = "Hotfix Rollups"


function CheckForHotfix ($hotfixID, $title, $Warn="")
{
	$hotfixesWMIQuery = "SELECT * FROM Win32_QuickFixEngineering WHERE HotFixID='KB$hotfixID'"
	$hotfixesWMI = Get-CimInstance -query $hotfixesWMIQuery #_# or PS > Get-HotFix
	$link = "http://support.microsoft.com/kb/" + $hotfixID
	if ($null -eq $hotfixesWMI)
	{
		"No          $hotfixID - $title   ($link)" | Out-File -FilePath $OutputFile -append
		If ($Warn -match "Yes") {
			Write-Host "This system is not up-to-date. Many known issues are resolved by applying latest cumulative update!"
			Write-Host -ForegroundColor Red "*** [WARNING] latest OS cumulative KB $hotfixID is missing.`n Please update this machine with recommended Microsoft KB $hotfixID and verify if your issue is resolved."
			$Global:MissingCU = $hotfixID
		}
	}
	else
	{
		"Yes         $hotfixID - $title   ($link)" | Out-File -FilePath $OutputFile -append
	}
}

#----------detect OS version and SKU
	$wmiOSVersion = Get-WmiObject -Namespace "root\cimv2" -Class Win32_OperatingSystem
	[int]$bn = [int]$wmiOSVersion.BuildNumber
	#$sku = $((Get-WmiObject win32_operatingsystem).OperatingSystemSKU)

if ($bn -match 2200) # Win 11 = 22000
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 11 " | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016629 -title "August 9, 2022-KB5016629 (OS Build 22000.856)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015814 -title "July 12, 2022-KB5015814 (OS Build 22000.795)"
	CheckForHotfix -hotfixID 5014697 -title "June 14, 2022-KB5014697 (OS Build 22000.739)"
	CheckForHotfix -hotfixID 5013943 -title "May 10, 2022-KB5013943 (OS Build 22000.675)" 
	CheckForHotfix -hotfixID 5012592 -title "April 12, 2022-KB5012592 (OS Build 22000.613)"
	CheckForHotfix -hotfixID 5011493 -title "March 8, 2022-KB5011493 (OS Build 22000.556)"
	CheckForHotfix -hotfixID 5010386 -title "February 8, 2022-KB5010386 (OS Build 22000.493)"
	CheckForHotfix -hotfixID 5009566 -title "January 11, 2022-KB5009566 (OS Build 22000.434)"
	CheckForHotfix -hotfixID 5008215 -title "December 14, 2021-KB5008215 (OS Build 22000.376)"
	CheckForHotfix -hotfixID 5007215 -title "November 9, 2021-KB5007215 (OS Build 22000.318)"
	CheckForHotfix -hotfixID 5006674 -title "October 12, 2021-KB5006674 (OS Build 22000.258)"
}

elseif ($bn -match 20348) # Server 2022 = 20348
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Server 2022 " | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016627 -title "August 9, 2022-KB5016627 (OS Build 20348.887)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015827 -title "July 12, 2022-KB5015827 (OS Build 20348.825)"
	CheckForHotfix -hotfixID 5014678 -title "June 14, 2022-KB5014678 (OS Build 20348.768)"
	CheckForHotfix -hotfixID 5013944 -title "May 10, 2022-KB5013944 (OS Build 20348.707)"
	CheckForHotfix -hotfixID 5012604 -title "April 12, 2022-KB5012604 (OS Build 20348.643)"
	CheckForHotfix -hotfixID 5011497 -title "March 8, 2022-KB5011497 (OS Build 20348.587)"
	CheckForHotfix -hotfixID 5010354 -title "February 8, 2022-KB5010354 (OS Build 20348.524)"
	CheckForHotfix -hotfixID 5009555 -title "January 11, 2022-KB5009555 (OS Build 20348.469)"
	CheckForHotfix -hotfixID 5008223 -title "December 14, 2021-KB5008223 (OS Build 20348.405)"
	CheckForHotfix -hotfixID 5007205 -title "November 9, 2021-KB5007205 (OS Build 20348.350)"
	CheckForHotfix -hotfixID 5006699 -title "October 12, 2021-KB5006699 (OS Build 20348.288)"
}
elseif ($bn -match 1904) # 2004 = 19041, 20H2 = 19042, 21H1 = 19043, 21H2 = 19044
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 20H1 v2004/20H2/21H1/21H2 and Windows Server 2019 20H1/20H2/21H1/21H2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016616 -title "August 9, 2022-KB5016616 (OS Builds 19042.1889, 19043.1889, and 19044.1889)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015807 -title "July 12, 2022-KB5015807 (OS Builds 19042.1826, 19043.1826, and 19044.1826)"
	CheckForHotfix -hotfixID 5014699 -title "June 14, 2022-KB5014699 (OS Builds 19042.1766, 19043.1766, and 19044.1766)"
	CheckForHotfix -hotfixID 5013942 -title "May 10, 2022-KB5013942 (OS Builds 19042.1706, 19043.1706, and 19044.1706)"
	CheckForHotfix -hotfixID 5012599 -title "April 12, 2022-KB5012599 (OS Builds 19042.1645, 19043.1645, and 19044.1645)" 
	CheckForHotfix -hotfixID 5011487 -title "March 8, 2022-KB5011487 (OS Builds 19042.1586, 19043.1586, and 19044.1586)"
	CheckForHotfix -hotfixID 5010342 -title "February 8, 2022-KB5010342 (OS Builds 19042.1526, 19043.1526, and 19044.1526)"
	CheckForHotfix -hotfixID 5009543 -title "January 11, 2022-KB5009543 (OS Builds 19042.1466, 19043.1466, and 19044.1466)"
	CheckForHotfix -hotfixID 5008212 -title "December 14, 2021-KB5008212 (OS Builds 19041.1415, 19042.1415, 19043.1415, and 19044.1415)"
	CheckForHotfix -hotfixID 5007186 -title "November 9, 2021-KB5007186 (OS Builds 19041.1348, 19042.1348, and 19043.1348)"
	CheckForHotfix -hotfixID 5006670 -title "October 12, 2021-KB5006670 (OS Builds 19041.1288, 19042.1288, and 19043.1288)"
	CheckForHotfix -hotfixID 5005611 -title "September 30, 2021-KB5005611 (OS Builds 19041.1266, 19042.1266, and 19043.1266) Preview"
	CheckForHotfix -hotfixID 5005565 -title "September 14, 2021-KB5005565 (OS Builds 19041.1237, 19042.1237, and 19043.1237)"
	CheckForHotfix -hotfixID 5005033 -title "August 10, 2021-KB5005033 (OS Builds 19041.1165, 19042.1165, and 19043.1165))"
	CheckForHotfix -hotfixID 5004237 -title "July 13, 2021-KB5004237 (OS Builds 19041.1110, 19042.1110, and 19043.1110)"
	CheckForHotfix -hotfixID 5003637 -title "June 8, 2021-KB5003637 (OS Builds 19041.1052, 19042.1052, and 19043.1052)"
	CheckForHotfix -hotfixID 5003173 -title "May 11, 2021-KB5003173 (OS Builds 19041.985 and 19042.985)"
	CheckForHotfix -hotfixID 5001330 -title "April 13, 2021-KB5001330 (OS Builds 19041.928 and 19042.928)"
	CheckForHotfix -hotfixID 5001649 -title "March 18, 2021-KB5001649 (OS Builds 19041.870 and 19042.870) Out-of-band"
	CheckForHotfix -hotfixID 4601319 -title "February 9, 2021-KB4601319 (OS Builds 19041.804 and 19042.804)"
	CheckForHotfix -hotfixID 4598481 -title "Servicing stack update for Windows 10, version 2004 and 20H2: January 12, 2021"
}
elseif ($bn -match  1836) # 1903 = 18362, 1909 = 18363
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 19H2 v1909 and Windows Server 2019 19H2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5013945 -title "May 10, 2022-KB5013945 (OS Build 18363.2274)" -Warn "Yes"
	CheckForHotfix -hotfixID 5012591 -title "April 12, 2022-KB5012591 (OS Build 18363.2212)"
	CheckForHotfix -hotfixID 5011485 -title "March 8, 2022-KB5011485 (OS Build 18363.2158)"
	CheckForHotfix -hotfixID 5010345 -title "February 8, 2022-KB5010345 (OS Build 18363.2094)"
	CheckForHotfix -hotfixID 5009545 -title "January 11, 2022-KB5009545 (OS Build 18363.2037)"
	CheckForHotfix -hotfixID 5008206 -title "December 14, 2021-KB5008206 (OS Build 18363.1977)"
	CheckForHotfix -hotfixID 5007189 -title "November 9, 2021-KB5007189 (OS Build 18362.1916)"
	CheckForHotfix -hotfixID 5006667 -title "October 12, 2021-KB5006667 (OS Build 18363.1854)"
	CheckForHotfix -hotfixID 5005566 -title "September 14, 2021-KB5005566 (OS Build 18363.1801)"
	CheckForHotfix -hotfixID 5005031 -title "August 10, 2021-KB5005031 (OS Build 18363.1734)"
	CheckForHotfix -hotfixID 5004245 -title "July 13, 2021-KB5004245 (OS Build 18363.1679)"
	CheckForHotfix -hotfixID 5003635 -title "June 8, 2021-KB5003635 (OS Build 18363.1621)"
	CheckForHotfix -hotfixID 4601395 -title "KB4601395: Servicing stack update for Windows 10, version 1903: February 9, 2021"
}
elseif ($bn -eq 17763)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 RS5 v1809 and Windows Server 2019 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016623 -title "August 9, 2022-KB5016623 (OS Build 17763.3287)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015811 -title "July 12, 2022-KB5015811 (OS Build 17763.3165)"
	CheckForHotfix -hotfixID 5014692 -title "June 14, 2022-KB5014692 (OS Build 17763.3046)"
	CheckForHotfix -hotfixID 5013941 -title "May 10, 2022-KB5013941 (OS Build 17763.2928)"
	CheckForHotfix -hotfixID 5012647 -title "April 12, 2022-KB5012647 (OS Build 17763.2803)"
	CheckForHotfix -hotfixID 5011503 -title "March 8, 2022-KB5011503 (OS Build 17763.2686)"
	CheckForHotfix -hotfixID 5010351 -title "February 8, 2022-KB5010351 (OS Build 17763.2565)"
	CheckForHotfix -hotfixID 5009557 -title "January 11, 2022-KB5009557 (OS Build 17763.2452)"
	CheckForHotfix -hotfixID 5008218 -title "December 14, 2021-KB5008218 (OS Build 17763.2366)"
	CheckForHotfix -hotfixID 5007206 -title "November 9, 2021-KB5007206 (OS Build 17763.2300)"
	CheckForHotfix -hotfixID 5006672 -title "October 12, 2021-KB5006672 (OS Build 17763.2237)"
	CheckForHotfix -hotfixID 5005568 -title "September 14, 2021-KB5005568 (OS Build 17763.2183)"
	CheckForHotfix -hotfixID 5005030 -title "August 10, 2021-KB5005030 (OS Build 17763.2114"
	CheckForHotfix -hotfixID 5004244 -title "July 13, 2021-KB5004244 (OS Build 17763.2061)"
	CheckForHotfix -hotfixID 5003646 -title "June 8, 2021-KB5003646 (OS Build 17763.1999)"
	CheckForHotfix -hotfixID 5003171 -title "May 11, 2021-KB5003171 (OS Build 17763.1935)"
	CheckForHotfix -hotfixID 5001342 -title "April 13, 2021-KB5001342 (OS Build 17763.1879)"
	CheckForHotfix -hotfixID 5001638 -title "March 18, 2021-KB5001638 (OS Build 17763.1823) Out-of-band"
	CheckForHotfix -hotfixID 4601345 -title "February 9, 2021-KB4601345 (OS Build 17763.1757)"
	CheckForHotfix -hotfixID 4601393 -title "KB4601393: Servicing stack update for Windows 10, version 1809: February 9, 2021"
}
elseif ($bn -eq 14393)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 RS1 v1607 and Windows Server 2016 RS1 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016622 -title "August 9, 2022-KB5016622 (OS Build 14393.5291)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015808 -title "July 12, 2022-KB5015808 (OS Build 14393.5246)"
	CheckForHotfix -hotfixID 5014702 -title "June 14, 2022-KB5014702 (OS Build 14393.5192)"
	CheckForHotfix -hotfixID 5013952 -title "May 10, 2022-KB5013952 (OS Build 14393.5125)"
	CheckForHotfix -hotfixID 5012596 -title "April 12, 2022-KB5012596 (OS Build 14393.5066)"
	CheckForHotfix -hotfixID 5011495 -title "March 8, 2022-KB5011495 (OS Build 14393.5006)"
	CheckForHotfix -hotfixID 5010359 -title "February 8, 2022-KB5010359 (OS Build 14393.4946)"
	CheckForHotfix -hotfixID 5009546 -title "January 11, 2022-KB5009546 (OS Build 14393.4886)"
	CheckForHotfix -hotfixID 5008207 -title "December 14, 2021-KB5008207 (OS Build 14393.4825)"
	CheckForHotfix -hotfixID 5007192 -title "November 9, 2021-KB5007192 (OS Build 14393.4770)"
	CheckForHotfix -hotfixID 5006669 -title "October 12, 2021-KB5006669 (OS Build 14393.4704)"
	CheckForHotfix -hotfixID 5005573 -title "September 14, 2021-KB5005573 (OS Build 14393.4651)"
	CheckForHotfix -hotfixID 5005043 -title "August 10, 2021-KB5005043 (OS Build 14393.4583)"
	CheckForHotfix -hotfixID 5004238 -title "July 13, 2021-KB5004238 (OS Build 14393.4530)"
	CheckForHotfix -hotfixID 5003638 -title "June 8, 2021-KB5003638 (OS Build 14393.4467)"
	CheckForHotfix -hotfixID 5003197 -title "May 11, 2021-KB5003197 (OS Build 14393.4402)"
	CheckForHotfix -hotfixID 5001347 -title "April 13, 2021-KB5001347 (OS Build 14393.4350)"
	CheckForHotfix -hotfixID 5001633 -title "March 18 2021-KB5001633 (OS Build 14393.4288) Out-of-band"
	CheckForHotfix -hotfixID 4601318 -title "February 9, 2021-KB4601318 (OS Build 14393.4225)" 
	CheckForHotfix -hotfixID 4601392 -title "Servicing stack update for Windows 10, version 1607: Februar 9, 2021"
}	
elseif ($bn -eq 10240)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 and Windows Server 2016 RTM Rollups"	 | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016639 -title "August 9, 2022-KB5016639 (OS Build 10240.19387)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015832 -title "July 12, 2022-KB5015832 (OS Build 10240.19360)"
	CheckForHotfix -hotfixID 5014710 -title "June 14, 2022-KB5014710 (OS Build 10240.19325)"
	CheckForHotfix -hotfixID 5013963 -title "May 10, 2022-KB5013963 (OS Build 10240.19297)"
	CheckForHotfix -hotfixID 5012653 -title "April 12, 2022-KB5012653 (OS Build 10240.19265)"
	CheckForHotfix -hotfixID 5011491 -title "March 8, 2022-KB5011491 (OS Build 10240.19235)"
	CheckForHotfix -hotfixID 5010358 -title "February 8, 2022-KB5010358 (OS Build 10240.19204)"
	CheckForHotfix -hotfixID 5009585 -title "January 11, 2022-KB5009585 (OS Build 10240.19177)"
	CheckForHotfix -hotfixID 5008230 -title "December 14, 2021-KB5008230 (OS Build 10240.19145)"
	CheckForHotfix -hotfixID 5007207 -title "November 9, 2021-KB5007207 (OS Build 10240.19119)"
	CheckForHotfix -hotfixID 5006675 -title "October 12, 2021-KB5006675 (OS Build 10240.19086)"
	CheckForHotfix -hotfixID 5005569 -title "September 14, 2021-KB5005569 (OS Build 10240.19060)"
	CheckForHotfix -hotfixID 5005040 -title "August 10, 2021-KB5005040 (OS Build 10240.19022)"
	CheckForHotfix -hotfixID 5004249 -title "July 13, 2021-KB5004249 (OS Build 10240.19003)"
	CheckForHotfix -hotfixID 5003687 -title "June 8, 2021-KB5003687 (OS Build 10240.18967)"
	CheckForHotfix -hotfixID 5003172 -title "May 11, 2021-KB5003172 (OS Build 10240.18932)"
	CheckForHotfix -hotfixID 5001340 -title "April 13, 2021-KB5001340 (OS Build 10240.18906)"
	CheckForHotfix -hotfixID 5001631 -title "March 18, 2021-KB5001631 (OS Build 10240.18875) Out-of-band"
	CheckForHotfix -hotfixID 4601331 -title "February 9, 2021-KB4601331 (OS Build 10240.18842)"
	CheckForHotfix -hotfixID 4601390 -title "KB4601390: Servicing stack update for Windows 10: February 9, 2021"
}
elseif ($bn -eq 9600)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 8.1 and Windows Server 2012 R2 Rollups"	 | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016681 -title "August 9, 2022-KB5016681 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015874 -title "July 12, 2022-KB5015874 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014738 -title "June 14, 2022-KB5014738 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014011 -title "May 10, 2022-KB5014011 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012670 -title "April 12, 2022-KB5012670 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011564 -title "March 8, 2022-KB5011564 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5010419 -title "February 8, 2022-KB5010419 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009624 -title "January 11, 2022-KB5009624 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008263 -title "December 14, 2021-KB5008263 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007247 -title "November 9, 2021-KB5007247 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006714 -title "October 12, 2021-KB5006714 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005613 -title "September 14, 2021-KB5005613 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005076 -title "August 10, 2021-KB5005076 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5004298 -title "July 13, 2021-KB5004298 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003671 -title "June 8, 2021-KB5003671 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003209 -title "May 11, 2021-KB5003209 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001382 -title "April 13, 2021-KB5001382 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000848 -title "March 9, 2021-KB5000848 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601384 -title "February 9, 2021-KB4601384 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4566425 -title "Servicing stack update for Windows 8.1, RT 8.1, and Server 2012 R2: July 14, 2020"
	CheckForHotfix -hotfixID 4541509 -title "March 10, 2020-KB4541509 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4537821 -title "February 11, 2020-KB4537821 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4534297 -title "January 14, 2020-KB4534297 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4530702 -title "December 10, 2019-KB4530702 (Monthly Rollup)"
	CheckForHotfix -hotfixID 3123245 -title "Update improves port exhaustion identification in Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3179574 -title "August 2016 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3172614 -title "July 2016 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3013769 -title "December 2014 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3000850 -title "November 2014 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 2919355 -title "[Windows 8.1 Update 1] Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2 Update: April 2014"
	CheckForHotfix -hotfixID 2883200 -title "Windows 8.1 and Windows Server 2012 R2 General Availability Update Rollup"
}
elseif ($bn -eq 9200)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Server 2012 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	
	CheckForHotfix -hotfixID 5016672 -title "August 9, 2022-KB5016672 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015863 -title "July 12, 2022-KB5015863 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014747 -title "June 14, 2022-KB5014747 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014017 -title "May 10, 2022-KB5014017 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012650 -title "April 12, 2022-KB5012650 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011535 -title "March 8, 2022-KB5011535 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009586 -title "January 11, 2022-KB5009586 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008277 -title "December 14, 2021-KB5008277 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007260 -title "November 9, 2021-KB5007260 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006739 -title "October 12, 2021-KB5006739 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005623 -title "September 14, 2021-KB5005623 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005099 -title "August 10, 2021-KB5005099 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5004294 -title "July 13, 2021-KB5004294 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003697 -title "June 8, 2021-KB5003697 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003208 -title "May 11, 2021-KB5003208 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001387 -title "April 13, 2021-KB5001387 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000847 -title "March 9, 2021-KB5000847 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601348 -title "February 9, 2021-KB4601348 (Monthly Rollup)"
	CheckForHotfix -hotfixID 3179575 -title "August 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3172615 -title "July 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3161609 -title "June 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3156416 -title "May 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3013767 -title "December 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 3000853 -title "November 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 2995388 -title "October 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012 "
	CheckForHotfix -hotfixID 2984005 -title "September 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 2975331 -title "August 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 2967916 -title "July 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012" 
	CheckForHotfix -hotfixID 2962407 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: June 2014" 
	CheckForHotfix -hotfixID 2955163 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: May 2014"
	CheckForHotfix -hotfixID 2934016 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: April 2014" 	
	CheckForHotfix -hotfixID 2928678 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: March 2014" 	
	CheckForHotfix -hotfixID 2919393 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: February 2014"
	CheckForHotfix -hotfixID 2911101 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: January 2014"
	CheckForHotfix -hotfixID 2903938 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: December 2013"
	CheckForHotfix -hotfixID 2889784 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: November 2013"
	CheckForHotfix -hotfixID 2883201 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: October 2013"
	CheckForHotfix -hotfixID 2876415 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: September 2013"
	CheckForHotfix -hotfixID 2862768 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: August 2013"	
	CheckForHotfix -hotfixID 2855336 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: July 2013"	
	CheckForHotfix -hotfixID 2845533 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: June 2013"	
	CheckForHotfix -hotfixID 2836988 -title "Windows 8 and Windows Server 2012 Update Rollup: May 2013" 				
	CheckForHotfix -hotfixID 2822241 -title "Windows 8 and Windows Server 2012 Update Rollup: April 2013"				
	CheckForHotfix -hotfixID 2811660 -title "Windows 8 and Windows Server 2012 Update Rollup: March 2013"				
	CheckForHotfix -hotfixID 2795944 -title "Windows 8 and Windows Server 2012 Update Rollup: February 2013"			
	CheckForHotfix -hotfixID 2785094 -title "Windows 8 and Windows Server 2012 Update Rollup: January 2013"				
	CheckForHotfix -hotfixID 2779768 -title "Windows 8 and Windows Server 2012 Update Rollup: December 2012"			
	CheckForHotfix -hotfixID 2770917 -title "Windows 8 and Windows Server 2012 Update Rollup: November 2012"			
	CheckForHotfix -hotfixID 2756872 -title "Windows 8 Client and Windows Server 2012 General Availability Update Rollup"
}
elseif ($bn -eq 7601)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 7 and Windows Server 2008 R2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn + "   (RTM=7600, SP1=7601)" | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016676 -title "August 9, 2022-KB5016676 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015861 -title "July 12, 2022-KB5015861 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014748 -title "June 14, 2022-KB5014748 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014012 -title "May 10, 2022-KB5014012 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012626 -title "April 12, 2022-KB5012626 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011552 -title "March 8, 2022-KB5011552 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5010404 -title "February 8, 2022-KB5010404 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009610 -title "January 11, 2022-KB5009610 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008244 -title "December 14, 2021-KB5008244 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007236 -title "November 9, 2021-KB5007236 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006743 -title "October 12, 2021-KB5006743 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005633 -title "September 14, 2021-KB5005633 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005088 -title "August 10, 2021-KB5005088 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5004289 -title "July 13, 2021-KB5004289 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003667 -title "June 8, 2021-KB5003667 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003233 -title "May 11, 2021-KB5003233 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001335 -title "April 13, 2021-KB5001335 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000841 -title "March 9, 2021-KB5000841 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601347 -title "February 9, 2021-KB4601347 (Monthly Rollup)"
	CheckForHotfix -hotfixID 3125574 -title "Convenience roll-up update for Windows 7 SP1 and Windows Server 2008 R2 SP1" -Warn "Yes"
	CheckForHotfix -hotfixID 4490628 -title "Servicing stack update for Windows 7 SP1 and Windows Server 2008 R2 SP1: March 12, 2019"
	CheckForHotfix -hotfixID 4580970 -title "Servicing stack update for Windows 7 SP1 and Server 2008 R2 SP1: October 13, 2020"
	CheckForHotfix -hotfixID 4538483 -title "Extended Security Updates (ESU) Licensing Preparation Package for Windows 7 SP1 and Windows Server 2008 R2 SP1"
	CheckForHotfix -hotfixID 2775511 -title "An enterprise hotfix rollup is available for Windows 7 SP1 and Windows Server 2008 R2 SP1"
}
elseif (($bn -eq 6002) -or ($bn -eq 6003))
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Vista and Windows Server 2008 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn + "   (RTM=6000, SP2=6002 or 6003)" | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5016669 -title "August 9, 2022-KB5016669 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5015866 -title "July 12, 2022-KB5015866 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014752 -title "June 14, 2022-KB5014752 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014010 -title "May 10, 2022-KB5014010 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012658 -title "April 12, 2022-KB5012658 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011534 -title "March 8, 2022-KB5011534 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5010384 -title "February 8, 2022-KB5010384 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009627 -title "January 11, 2022-KB5009627 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008274 -title "December 14, 2021-KB5008274 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007263 -title "November 9, 2021-KB5007263 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006736 -title "October 12, 2021-KB5006736 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005606 -title "September 14, 2021-KB5005606 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005090 -title "August 10, 2021-KB5005090 (Monthly Rollup)" 
	CheckForHotfix -hotfixID 5004305 -title "July 13, 2021-KB5004305 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003661 -title "June 8, 2021-KB5003661 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003210 -title "May 11, 2021-KB5003210 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001389 -title "April 13, 2021-KB5001389 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000844 -title "March 9, 2021-KB5000844 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601360 -title "February 9, 2021-KB4601360 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4598288 -title "January 12, 2021-KB4598288 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4592498 -title "December 8, 2020-KB4592498 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4517134 -title "Servicing stack update for Windows Server 2008 SP2: September 10, 2019"
	CheckForHotfix -hotfixID 4572374 -title "Servicing stack update for Windows Server 2008 SP2: August 11, 2020"
}

	CollectFiles -filesToCollect $OutputFile -fileDescription "Hotfix Rollups" -SectionDescription $sectionDescription



# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCk/ya88I0wWayp
# m+YEUei+jX0aSRcZXnJgFVNkGtcABqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKr66W01M+Jb4qdy/gu9ATF4
# ew2eNve/cbpeivu+vSXAMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAiELOfT+EI/XNBob/TvQfkGUAPfvz+P6rMuX79LxhHU8WvXWWFaA9c
# apXSpB/b4EF9dXdCM4pWf13dcY9AI1x0SzsaPDj2nj6a2kFqQbkfCpIXqrq+g7qu
# DXp8mUQvxbP1rdCjvfFA/yLFFNoYABTxCkaH5nxqe7jXKai5N15u7OphZe2MMifK
# zNtSK4ajzn/pw0UvgwoSnJMtcyH4gXJbBAjpMM3sn1IO1W17vOvz5wgqOsjcF5hZ
# i5zzb7C4IN6ugI0knFWDt/mvuqaSQBqvuW6gZWs9P+R/57RbqJBsf3y/wUCw9nYi
# TcOScydpgcSGpJZ09drz0OZGMuZt+f7loYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEICGFZCiiu4m7KG1tEdkiYWln1xImLFfKTXYjnQJXo9Q1AgZi3n87
# U2wYEzIwMjIwODExMDgzNTA3LjQxN1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
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
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIIOQq5sn3bJLMDdps/iL
# HL2d9Akb4HmOxSpkRsx4TILuMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# vQWPITvigaUuV5+f/lWs3BXZwJ/l1mf+yelu5nXmxCUwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY5Z20YAqBCUzAABAAABjjAiBCBA
# TqI4iI4me4Ljg+9D5JZK71W0ZeAr6JiMCfhM9fsmvzANBgkqhkiG9w0BAQsFAASC
# AgB/T8/0JUvFa/P448B+qfhQeW/qjBwgOPM2t2HfxgfZx8eY4XlJ9XAFgtniVLFY
# 7ip1Y7gOtUOEwgSS2g/YEITfyAtrym04SKqRgguvtlvfMHJT1+XGi9w74OwvxD4h
# jfljlrk8nBY3ai/bna3wEajWHZF0GB912T6l9mLPybwb82MrXbmq46tVvmLzWzOw
# DXI6M3XwdwHumPNIqfgXbmEd07g5Xhinryq8nCF/WHQ2koZY5+u0TaIJbzU3sr8y
# 1kHlt9gjV81/mSiOuBG1mMh31UtdfIuhs2AryKZ+R0/Fh7aHBKr1vwZhWt5sfbOu
# fSWBDO7Yk357auTeg5zmVrTndtFcw+sM0n2guZqU300g2wn6PXL/ox+xmWSSZ4B4
# C54PleHWkwik6b5gJtL5YKsTj/VndG4pPjHbevcERFXLN0i48I53jaBstsrOKlzd
# YYpZu33pQYQE7xcHf6mIMfi7FDovNjTF2zcnC9zF1jF1dNplP5BJ8kcyIkPkfTNt
# E7ksXLM6uIYVFnYwQXwRPhGGV/Tc4gne8fMnzJ96SiAaZfcaxhyrThDe9xwkj1Y9
# SWAfGfkGA+EIwbzDNlq1hvQ6S0bgi72Gls1OoyPCQdv5swHAaLIl2OhhNpq8PAh/
# SiOUapWv4IxC9+gSnvevA0l3LqSgJPmabhaYs8Cxlwjcig==
# SIG # End signature block
