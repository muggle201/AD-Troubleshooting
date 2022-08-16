#************************************************
# DC_TCPIP-Component.ps1
# Version 1.0: Collects information from the registry, netsh, arp, ipconfig, etc. 
# Version 1.1: Updated IPv6 Transition Technologies section for SKU checks to clean up exceptions.
# Version 1.2: Altered the runPS function correctly a column width issue.
# Version 1.3: Corrected the code for Get-NetCompartment (only runs in WS2012+)
# Version 1.4.09.10.14: Add additional netsh commands for Teredo and ISATAP. TFS264243
# Date: 2009-2014 /WalterE 2019 - GetNetTcpConnEstablished
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about TCPIP.
# Called from: Networking Diags
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status $ScriptVariable.ID_CTSTCPIPDescription

"[info]:TCPIP-Component:BEGIN" | WriteTo-StdOut


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status "netsh $NetSHCommandToExecute"
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	"netsh $NetSHCommandToExecute"			| Out-File -FilePath $outputFile -append
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $outputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function RunNetCmd ([string]$NetCmd="", [string]$NetCmdArg="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status "$NetCmd $NetCmdArg"
	$NetCmdLen = $NetCmd.length
	$NetCmdArgLen = $NetCmdArg.Length
	$NetCmdFullLen = $NetCmdLen + $NetCmdArgLen + 1
	"-" * ($NetCmdFullLen)	| Out-File -FilePath $outputFile -append
	"$NetCmd $NetCmdArg"	| Out-File -FilePath $outputFile -append
	"-" * ($NetCmdFullLen)	| Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c $NetCmd $NetCmdArg >> $outputFile"
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function Heading ([string]$header)
{
	"=" * ($borderLen)	| Out-File -FilePath $outputFile -append
	"$header"			| Out-File -FilePath $outputFile -append
	"=" * ($borderLen)	| Out-File -FilePath $outputFile -append
	"`n`n`n" | Out-File -FilePath $outputFile -append
}

function GetNetTcpConnEstablished ()
{
	#get all TCP established connections and match them with its process. Similar output is thrown by using: netstat -ano
	$AllConnections = @()
	$Connections = Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
	ForEach($Connection In $Connections) {
		$ProcessInfo = Get-Process -PID $Connection.OwningProcess -IncludeUserName | Select-Object Path,UserName,StartTime,Name,Id
		$Obj = New-Object -TypeName PSObject
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalAddress -Value $Connection.LocalAddress
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalPort -Value $Connection.LocalPort
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemoteAddress -Value $Connection.RemoteAddress
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemotePort -Value $Connection.RemotePort
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name OwningProcessID -Value $Connection.OwningProcess
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name ProcessName -Value $ProcessInfo.Name
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name UserName -Value $ProcessInfo.UserName
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name CommandLine -Value $ProcessInfo.Path
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name StartTime -Value $ProcessInfo.StartTime
		$AllConnections += $Obj
	}
	$AllConnections #|format-table -autosize
}


$sectionDescription = "TCPIP"
$borderLen = 52

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber



####################################################
# General Information
####################################################
#-----MAIN TCPIP INFO  (W2003+)

#----------TCPIP Information from Various Tools
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info.TXT")
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"TCPIP Networking Information"						| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"Overview"											| Out-File -FilePath $OutputFile -append
"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
"TCPIP Networking Information"						| Out-File -FilePath $OutputFile -append
"   1. hostname"									| Out-File -FilePath $OutputFile -append
"   2. ipconfig /allcompartments /all"				| Out-File -FilePath $OutputFile -append
"   3. route print"									| Out-File -FilePath $OutputFile -append
"   4. arp -a"										| Out-File -FilePath $OutputFile -append
"   5. netstat -nato" 								| Out-File -FilePath $OutputFile -append
"   6. netstat -anob"								| Out-File -FilePath $OutputFile -append
"   7. netstat -es" 								| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

Heading "TCPIP Networking Information"
RunNetCmd "hostname"
# 4/17/14: If WV/WS2008, run "ipconfig /allcompartments /all". If WXP/WS2003 "ipconfig /all".
if ($bn -gt 6000)
{ RunNetCmd "ipconfig" "/allcompartments /all" }
else
{ RunNetCmd "ipconfig" "/all" }
RunNetCmd "route print"
RunNetCmd "arp" "-a"
RunNetCmd "netstat" "-nato"
RunNetCmd "netstat" "-anob"
RunNetCmd "netstat" "-es"
CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Info" -SectionDescription $sectionDescription

#----------Registry (General)
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_reg_output.TXT")
$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\services\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6",
						"HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg",
						"HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "TCPIP registry output" -SectionDescription $sectionDescription

#----------TCP OFFLOAD (netsh)
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_OFFLOAD.TXT")

"=" * ($borderLen)								| Out-File -FilePath $outputFile -append
"TCPIP Offload Information"						| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)								| Out-File -FilePath $outputFile -append
"Overview"										| Out-File -FilePath $OutputFile -append
"-" * ($borderLen)								| Out-File -FilePath $outputFile -append
"TCPIP Offload Information"						| Out-File -FilePath $OutputFile -append
"  1. netsh int tcp show global"				| Out-File -FilePath $outputFile -Append
"  2. netsh int ipv4 show offload"				| Out-File -FilePath $outputFile -Append
"  3. netstat -nato -p tcp"						| Out-File -FilePath $outputFile -Append
"=" * ($borderLen)								| Out-File -FilePath $outputFile -Append
"`n`n`n`n`n" | Out-File -FilePath $outputFile -append
RunNetCmd "netsh" "int tcp show global"
RunNetCmd "netsh" "int ipv4 show offload"
RunNetCmd "netstat" "-nato -p tcp"

CollectFiles -filesToCollect $outputFile -fileDescription "TCP OFFLOAD" -SectionDescription $sectionDescription

#----------Copy the Services File
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_ServicesFile.TXT")

$servicesfile = "$ENV:windir\system32\drivers\etc\services"
if (test-path $servicesfile)
{
  Copy-Item -Path $servicesfile -Destination $outputFile
  CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Services File" -SectionDescription $sectionDescription
}
else
{
	"$servicesfile Does not exist" | writeto-stdout
}

# W8/WS2012
if ($bn -gt 9000)
{
	"[info]: TCPIP-Component W8/WS2012+" | WriteTo-StdOut

	####################################################
	# TCPIP Transition Technologies
	####################################################
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_net.TXT")

	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCPIP Powershell Cmdlets"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"   1. Get-NetCompartment (WS2012+)"				| Out-File -FilePath $OutputFile -append
	"   2. Get-NetIPAddress"							| Out-File -FilePath $OutputFile -append	
	"   3. Get-NetIPInterface"							| Out-File -FilePath $OutputFile -append
	"   4. Get-NetIPConfiguration"						| Out-File -FilePath $OutputFile -append
	"   5. Get-NetIPv4Protocol"							| Out-File -FilePath $OutputFile -append
	"   6. Get-NetIPv6Protocol"							| Out-File -FilePath $OutputFile -append
	"   7. Get-NetOffloadGlobalSetting"					| Out-File -FilePath $OutputFile -append
	"   8. Get-NetPrefixPolicy"							| Out-File -FilePath $OutputFile -append
	"   9. Get-NetRoute -IncludeAllCompartments"		| Out-File -FilePath $OutputFile -append
	"  10. Get-NetTCPConnection"						| Out-File -FilePath $OutputFile -append
	"  10a. GetNetTCPConnEstablished"					| Out-File -FilePath $OutputFile -append
	"  11. Get-NetTransportFilter"						| Out-File -FilePath $OutputFile -append
	"  12. Get-NetTCPSetting"							| Out-File -FilePath $OutputFile -append
	"  13. Get-NetUDPEndpoint"							| Out-File -FilePath $OutputFile -append
	"  14. Get-NetUDPSetting"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

	if ($bn -ge 9600)
	{
		RunPS "Get-NetCompartment"							# W8/WS2012, W8.1/WS2012R2	# fl
	}
	else
	{
		$RunPScmd = "Get-NetCompartment"
		$RunPScmdLength = $RunPScmd.Length
		"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
		"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
		"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
		"The Get-NetCompartment pscmdlet is only available in WS2012R2+."	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetIPAddress"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPInterface"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetIPConfiguration"						# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPv4Protocol"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPv6Protocol"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetOffloadGlobalSetting"					# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetPrefixPolicy"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetRoute -IncludeAllCompartments"	-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetTCPConnection"					-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "GetNetTCPConnEstablished"				-ft	# 
	RunPS "Get-NetTransportFilter"						# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetTCPSetting"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetUDPEndpoint"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetUDPSetting"							# W8/WS2012, W8.1/WS2012R2	# fl

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Net Powershell Cmdlets" -SectionDescription $sectionDescription
}

# W8/WS2012
if ($bn -gt 9000)
{
	####################################################
	# TCPIP IPv6 Transition Technologies
	####################################################
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_IPv6Transition.TXT")
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Transition Technologies Powershell Cmdlets"	| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"   1. Get-Net6to4Configuration"					| Out-File -FilePath $OutputFile -append
	"   2. Get-NetDnsTransitionConfiguration"			| Out-File -FilePath $OutputFile -append
	"   3. Get-NetDnsTransitionMonitoring"				| Out-File -FilePath $OutputFile -append
	"   4. Get-NetIPHttpsConfiguration"					| Out-File -FilePath $OutputFile -append
	"   5. Get-NetIsatapConfiguration"					| Out-File -FilePath $OutputFile -append
	"   6. Get-NetNatTransitionConfiguration"			| Out-File -FilePath $OutputFile -append
	"   7. Get-NetNatTransitionMonitoring"				| Out-File -FilePath $OutputFile -append
	"   8. Get-NetTeredoConfiguration"					| Out-File -FilePath $OutputFile -append
	"   9. Get-NetTeredoState"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

	#Get role, OSVer, hotfix data.
	$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem -ComputerName $ComputerName
	$DomainRole = $cs.domainrole
	
	if ($DomainRole -ge 2)	
	{
		RunPS "Get-Net6to4Configuration"				# W8/WS2012, W8.1/WS2012R2	#fl
		RunPS "Get-NetDnsTransitionConfiguration"		# W8/WS2012, W8.1/WS2012R2	#fl		# server only
		RunPS "Get-NetDnsTransitionMonitoring"			# W8/WS2012, W8.1/WS2012R2	#fl 	# server only
	}
	else
	{
		"------------------------" 									| Out-File -FilePath $outputFile -append
		"Get-Net6to4Configuration"	| Out-File -FilePath $OutputFile -append
		"------------------------" 									| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs." | Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"---------------------------------" | Out-File -FilePath $outputFile -append
		"Get-NetDnsTransitionConfiguration" | Out-File -FilePath $OutputFile -append
		"---------------------------------" | Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"------------------------------" | Out-File -FilePath $outputFile -append
		"Get-NetDnsTransitionMonitoring" | Out-File -FilePath $OutputFile -append
		"------------------------------" | Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetIPHttpsConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetIPHttpsState"							# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetIsatapConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	
	if ($cs.DomainRole -ge 2)	
	{
		RunPS "Get-NetNatTransitionConfiguration"		# W8/WS2012, W8.1/WS2012R2	#fl 	#server only
		RunPS "Get-NetNatTransitionMonitoring"		-ft	# W8/WS2012, W8.1/WS2012R2	#ft		#server only
	}
	else
	{
		"---------------------------------" 		| Out-File -FilePath $outputFile -append
		"Get-NetNatTransitionConfiguration"	| Out-File -FilePath $OutputFile -append
		"---------------------------------" 		| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs." | Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"------------------------------" 		| Out-File -FilePath $outputFile -append
		"Get-NetNatTransitionMonitoring"			| Out-File -FilePath $OutputFile -append
		"------------------------------" 		| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetTeredoConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetTeredoState"							# W8/WS2012, W8.1/WS2012R2	#fl

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP IPv6 Transition Technology Info" -SectionDescription $sectionDescription	
}

#V/WS2008+
if ($bn -gt 6000)
{
	"[info]: TCPIP-Component WV/WS2008+" | WriteTo-StdOut
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_netsh_info.TXT")

	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCPIP Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCP Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int tcp show global"					| Out-File -FilePath $OutputFile -append
	"   2. netsh int tcp show heuristics"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int tcp show chimneyapplications"		| Out-File -FilePath $OutputFile -append
	"   4. netsh int tcp show chimneyports"				| Out-File -FilePath $OutputFile -append
	"   5. netsh int tcp show chimneystats"				| Out-File -FilePath $OutputFile -append
	"   6. netsh int tcp show netdmastats"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int tcp show rscstats"					| Out-File -FilePath $OutputFile -append
	"   8. netsh int tcp show security"					| Out-File -FilePath $OutputFile -append
	"   9. netsh int tcp show supplemental"				| Out-File -FilePath $OutputFile -append
	"  10. netsh int tcp show supplementalports"		| Out-File -FilePath $OutputFile -append
	"  11. netsh int tcp show supplementalsubnets"		| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv4 Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int show int"							| Out-File -FilePath $OutputFile -append
	"   2. netsh int ipv4 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int ipv4 show addresses"				| Out-File -FilePath $OutputFile -append
	"   4. netsh int ipv4 show ipaddresses"				| Out-File -FilePath $OutputFile -append
	"   5. netsh int ipv4 show compartments"			| Out-File -FilePath $OutputFile -append
	"   6. netsh int ipv4 show dnsservers"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int ipv4 show winsservers"				| Out-File -FilePath $OutputFile -append
	"   8. netsh int ipv4 show dynamicportrange tcp"	| Out-File -FilePath $OutputFile -append
	"   9. netsh int ipv4 show dynamicportrange udp"	| Out-File -FilePath $OutputFile -append
	"  10. netsh int ipv4 show global"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv4 show icmpstats"				| Out-File -FilePath $OutputFile -append
	"  12. netsh int ipv4 show ipstats"					| Out-File -FilePath $OutputFile -append
	"  13. netsh int ipv4 show joins"					| Out-File -FilePath $OutputFile -append
	"  14. netsh int ipv4 show offload"					| Out-File -FilePath $OutputFile -append
	"  15. netsh int ipv4 show route"					| Out-File -FilePath $OutputFile -append
	"  16. netsh int ipv4 show subint"					| Out-File -FilePath $OutputFile -append
	"  17. netsh int ipv4 show tcpconnections"			| Out-File -FilePath $OutputFile -append
	"  18. netsh int ipv4 show tcpstats"				| Out-File -FilePath $OutputFile -append
	"  19. netsh int ipv4 show udpconnections"			| Out-File -FilePath $OutputFile -append
	"  20. netsh int ipv4 show udpstats"				| Out-File -FilePath $OutputFile -append
	"  21. netsh int ipv4 show destinationcache"		| Out-File -FilePath $OutputFile -append
	"  22. netsh int ipv4 show ipnettomedia"			| Out-File -FilePath $OutputFile -append
	"  23. netsh int ipv4 show neighbors"				| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int show int"							| Out-File -FilePath $OutputFile -append	
	"   2. netsh int ipv6 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int ipv6 show addresses"				| Out-File -FilePath $OutputFile -append
	"   4. netsh int ipv6 show compartments"			| Out-File -FilePath $OutputFile -append
	"   5. netsh int ipv6 show destinationcache"		| Out-File -FilePath $OutputFile -append
	"   6. netsh int ipv6 show dnsservers"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int ipv6 show dynamicportrange tcp"	| Out-File -FilePath $OutputFile -append
	"   8. netsh int ipv6 show dynamicportrange udp"	| Out-File -FilePath $OutputFile -append
	"   9. netsh int ipv6 show global"					| Out-File -FilePath $OutputFile -append
	"  10. netsh int ipv6 show ipstats"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv6 show joins"					| Out-File -FilePath $OutputFile -append
	"  12. netsh int ipv6 show neighbors"				| Out-File -FilePath $OutputFile -append
	"  13. netsh int ipv6 show offload"					| Out-File -FilePath $OutputFile -append
	"  14. netsh int ipv6 show potentialrouters"		| Out-File -FilePath $OutputFile -append
	"  15. netsh int ipv6 show prefixpolicies"			| Out-File -FilePath $OutputFile -append
	"  16. netsh int ipv6 show privacy"					| Out-File -FilePath $OutputFile -append
	"  17. netsh int ipv6 show route"					| Out-File -FilePath $OutputFile -append
	"  18. netsh int ipv6 show siteprefixes"			| Out-File -FilePath $OutputFile -append
	"  19. netsh int ipv6 show subint"					| Out-File -FilePath $OutputFile -append
	"  20. netsh int ipv6 show tcpstats"				| Out-File -FilePath $OutputFile -append
	"  21. netsh int ipv6 show teredo"					| Out-File -FilePath $OutputFile -append
	"  22. netsh int ipv6 show udpstats"				| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Transition Technologies"						| Out-File -FilePath $OutputFile -append
	"   1. netsh int ipv6 show int"						| Out-File -FilePath $OutputFile -append
	"   2. netsh int 6to4 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int 6to4 show relay"					| Out-File -FilePath $OutputFile -append
	"   4. netsh int 6to4 show routing"					| Out-File -FilePath $OutputFile -append
	"   5. netsh int 6to4 show state"					| Out-File -FilePath $OutputFile -append
	"   6. netsh int httpstunnel show interfaces"		| Out-File -FilePath $OutputFile -append
	"   7. netsh int httpstunnel show statistics"		| Out-File -FilePath $OutputFile -append
	"   8. netsh int isatap show router"				| Out-File -FilePath $OutputFile -append
	"   9. netsh int isatap show state"					| Out-File -FilePath $OutputFile -append
	"  10. netsh int teredo show state"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv6 show int level=verbose"		| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"NetIO Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netio show bindingfilters"					| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"PortProxy"	| Out-File -FilePath $OutputFile -append
	"   1. netsh int portproxy show all"	| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	
	Heading "TCP Netsh Commands"
	RunNetCmd "netsh" "int tcp show global"
	RunNetCmd "netsh" "int tcp show heuristics"
	RunNetCmd "netsh" "int tcp show chimneyapplications"
	RunNetCmd "netsh" "int tcp show chimneyports"
	RunNetCmd "netsh" "int tcp show chimneystats"
	RunNetCmd "netsh" "int tcp show netdmastats"
	RunNetCmd "netsh" "int tcp show rscstats"
	RunNetCmd "netsh" "int tcp show security"
	RunNetCmd "netsh" "int tcp show supplemental"
	RunNetCmd "netsh" "int tcp show supplementalports"
	RunNetCmd "netsh" "int tcp show supplementalsubnets"

	Heading "IPv4 Netsh Commands"
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ipv4 show int"
	RunNetCmd "netsh" "int ipv4 show addresses"
	RunNetCmd "netsh" "int ipv4 show ipaddresses"
	RunNetCmd "netsh" "int ipv4 show compartments"
	RunNetCmd "netsh" "int ipv4 show dnsservers"
	RunNetCmd "netsh" "int ipv4 show winsservers"
	RunNetCmd "netsh" "int ipv4 show dynamicportrange tcp"
	RunNetCmd "netsh" "int ipv4 show dynamicportrange udp"
	RunNetCmd "netsh" "int ipv4 show global"
	RunNetCmd "netsh" "int ipv4 show icmpstats"
	RunNetCmd "netsh" "int ipv4 show ipstats"
	RunNetCmd "netsh" "int ipv4 show joins"
	RunNetCmd "netsh" "int ipv4 show offload"
	RunNetCmd "netsh" "int ipv4 show route"
	RunNetCmd "netsh" "int ipv4 show subint"
	RunNetCmd "netsh" "int ipv4 show tcpconnections"
	RunNetCmd "netsh" "int ipv4 show tcpstats"
	RunNetCmd "netsh" "int ipv4 show udpconnections"
	RunNetCmd "netsh" "int ipv4 show udpstats"
	RunNetCmd "netsh" "int ipv4 show destinationcache"
	RunNetCmd "netsh" "int ipv4 show ipnettomedia"
	RunNetCmd "netsh" "int ipv4 show neighbors"

	Heading "IPv6 Netsh Commands"
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ipv6 show int"
	RunNetCmd "netsh" "int ipv6 show addresses"
	RunNetCmd "netsh" "int ipv6 show compartments"
	RunNetCmd "netsh" "int ipv6 show destinationcache"
	RunNetCmd "netsh" "int ipv6 show dnsservers"
	RunNetCmd "netsh" "int ipv6 show dynamicportrange tcp"
	RunNetCmd "netsh" "int ipv6 show dynamicportrange udp"
	RunNetCmd "netsh" "int ipv6 show global"
	RunNetCmd "netsh" "int ipv6 show ipstats"
	RunNetCmd "netsh" "int ipv6 show joins"
	RunNetCmd "netsh" "int ipv6 show neighbors"
	RunNetCmd "netsh" "int ipv6 show offload"
	RunNetCmd "netsh" "int ipv6 show potentialrouters"
	RunNetCmd "netsh" "int ipv6 show prefixpolicies"
	RunNetCmd "netsh" "int ipv6 show privacy"
	RunNetCmd "netsh" "int ipv6 show route"
	RunNetCmd "netsh" "int ipv6 show siteprefixes"
	RunNetCmd "netsh" "int ipv6 show siteprefixes"
	RunNetCmd "netsh" "int ipv6 show subint"
	RunNetCmd "netsh" "int ipv6 show tcpstats"
	RunNetCmd "netsh" "int ipv6 show teredo"
	RunNetCmd "netsh" "int ipv6 show udpstats"
	
	Heading "IPv6 Transition Technologies"
	RunNetCmd "netsh" "int ipv6 show int"
	RunNetCmd "netsh" "int 6to4 show int"
	RunNetCmd "netsh" "int 6to4 show relay"
	RunNetCmd "netsh" "int 6to4 show routing"
	RunNetCmd "netsh" "int 6to4 show state"
	RunNetCmd "netsh" "int httpstunnel show interfaces"
	RunNetCmd "netsh" "int httpstunnel show statistics"
	RunNetCmd "netsh int isatap show router"
	RunNetCmd "netsh int isatap show state"	
	RunNetCmd "netsh int teredo show state"	
	RunNetCmd "netsh" "int ipv6 show int level=verbose"

	Heading "NetIO Netsh Commands"
	RunNetCmd "netsh" "netio show bindingfilters"

	Heading "PortProxy"
	RunNetCmd "netsh" "int portproxy show all"
	
	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP netsh output" -SectionDescription $sectionDescription

	#----------Iphlpsvc EventLog
	#----------WLAN Autoconfig EventLog
	#Iphlpsvc
	$EventLogNames = @()
	$EventLogNames += "Microsoft-Windows-Iphlpsvc/Operational"
	$EventLogNames += "Microsoft-Windows-WLAN-AutoConfig/Operational"

	$Prefix = ""
	$Suffix = "_evt_"
	.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

}
else # XP/WS2003
{
	"[info]: TCPIP-Component XP/WS2003+" | WriteTo-StdOut
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_netsh_info.TXT")
	
	#----------Netsh for IP (XP/W2003)
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH INT IP]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	"`n" + "-" * (50) + "`r`n[netsh int ipv4 show output]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ip show int"
	RunNetCmd "netsh" "int ip show address"
	RunNetCmd "netsh" "int ip show config"
	RunNetCmd "netsh" "int ip show dns"
	RunNetCmd "netsh" "int ip show joins"
	RunNetCmd "netsh" "int ip show offload"
	RunNetCmd "netsh" "int ip show wins"

	# If RRAS is running, run the following commands
	if ((Get-Service "remoteaccess").Status -eq 'Running')
	{
		RunNetCmd "netsh" "int ip show icmp"
		RunNetCmd "netsh" "int ip show interface"
		RunNetCmd "netsh" "int ip show ipaddress"
		RunNetCmd "netsh" "int ip show ipnet"
		RunNetCmd "netsh" "int ip show ipstats"
		RunNetCmd "netsh" "int ip show tcpconn"
		RunNetCmd "netsh" "int ip show tcpstats"
		RunNetCmd "netsh" "int ip show udpconn"
		RunNetCmd "netsh" "int ip show udpstats"
	}
	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP netsh output" -SectionDescription $sectionDescription
}

"[info]:TCPIP-Component:END" | WriteTo-StdOut


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDrBgfxnODeYJo0
# /yqCYXOqV7XQMeccXU9jgkxlS+5HG6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOapzetfKpxd2Nvog9Bwz3KS
# DNYz9MEWAMNH+fecW3slMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAy6J5oAk0Sr2eogLal/CR4uprxz6MYkuUAG0kxxAIKHV2PBlPiFstD
# 7kWioZ87IL6W69w/k/gS1sF8uwL9ZNn44kf9kCSS1uG3Ap7HwZ5x13+suM2D/WtW
# YdvbtkLNswivzt0b/owyl3M7Pnuwc8oamit5NelEGRa3TE1wUI1ooTSxESaakDMm
# Jc2sANjOMaWahB9rHrPsfMQ6Em33n6aoFWTa3Yt87u2eYtszx0b7VokyM7odCngF
# Qh0qCV23xU6U5kJq25ivv0NQe+AKvNDtFdxFOQrRCn2urue4VZoVGrj7xmlpqZz5
# bbqdlp0tFY/X1OiYTlBlKMsVpZ5b5lskoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIKlmhPalLW7g7Z8Qq38I1PFuqFLmZ1WEHI6/xDHL6aqHAgZi1tDS
# 5bsYEzIwMjIwODAxMDc1MTI0Ljk0N1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkU1QTYt
# RTI3Qy01OTJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGVt/wN1uM3MSUAAQAAAZUwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTEyWhcNMjMwMjI4MTkwNTEyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTVBNi1FMjdDLTU5MkUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCfbUEMZ7ZLOz9aoRCeJL4hhT9Q8JZB2xaVlMNCt3bw
# hcTI5GLPrt2e93DAsmlqOzw1cFiPPg6S5sLCXz7LbbUQpLha8S4v2qccMtTokEaD
# QS+QJErnAsl6VSmRvAy0nlj+C/PaZuLb3OzY0ARw7UeCZLpyWPPH+k5MdYj6NUDT
# NoXqbzQHCuPs+fgIoro5y3DHoO077g6Ir2THIx1yfVFEt5zDcFPOYMg4yBi4A6Xc
# 3hm9tZ6w849nBvVKwm5YALfH3y/f3n4LnN61b1wzAx3ZCZjf13UKbpE7p6DYJrHR
# B/+pwFjG99TwHH6uXzDeZT6/r6qH7AABwn8fpYc1TmleFY8YRuVzzjp9VkPHV8Vz
# vzLL7QK2kteeXLL/Y4lvjL6hzyOmE+1LVD3lEbYho1zCt+F7bU+FpjyBfTC4i/wH
# sptb218YlbkQt1i1B6llmJwVFwCLX7gxQ48QIGUacMy8kp1+zczY+SxlpaEgNmQk
# fc1raPh9y5sMa6X48+x0K7B8OqDoXcTiECIjJetxwtuBlQseJ05HRfisfgFm09kG
# 7vdHEo3NbUuMMBFikc4boN9Ufm0iUhq/JtqV0Kwrv9Cv3ayDgdNwEWiL2a65InEW
# SpRTYfsCQ03eqEh5A3rwV/KfUFcit+DrP+9VcDpjWRsCokZv4tgn5qAXNMtHa8Ni
# qQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFKuX02ICFFdXgrcCBmDJfH5v/KkXMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAOCzNt4fJ+jOvQuq0Itn37IZrYNBGswAi+IAFM3YGK/wGQlEncgjmNBuac95
# W2fAL6xtFVfMfkeqSLMLqoidVsU9Bm4DEBjaWNOT9uX/tcYiJSfFQM0rDbrl8V4n
# M88RZF56G/qJW9g5dIqOSoimzKUt/Q7WH6VByW0sar5wGvgovK3qFadwKShzRYcE
# qTkHH2zip5e73jezPHx2+taYqJG5xJzdDErZ1nMixRjaHs3KpcsmZYuxsIRfBYOJ
# vAFGymTGRv5PuwsNps9Ech1Aasq84H/Y/8xN3GQj4P3MiDn8izUBDCuXIfHYk39b
# qnaAmFbUiCby+WWpuzdk4oDKz/sWwrnsoQ72uEGVEN7+kyw9+HSo5i8l8Zg1Ymj9
# tUgDpVUGjAduoLyHQ7XqknKmS9kJSBKk4okEDg0Id6LeKLQwH1e4aVeTyUYwcBX3
# wg7pLJQWvR7na2SGrtl/23YGQTudmWOryhx9lnU7KBGV/aNvz0tTpcsucsK+cZFK
# DEkWB/oUFVrtyun6ND5pYZNj0CgRup5grVACq/Agb+EOGLCD+zEtGNop4tfKvsYb
# 64257NJ9XrMHgpCib76WT34RPmCBByxLUkHxHq5zCyYNu0IFXAt1AVicw14M+czL
# YIVM7NOyVpFdcB1B9MiJik7peSii0XTRdl5/V/KscTaCBFz3MIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpFNUE2LUUyN0MtNTkyRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA0Y+CyLezGgVHWFNmKI1LuE/hY6ug
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRyb0wIhgPMjAyMjA4MDExMTQwNDVaGA8yMDIyMDgwMjExNDA0NVow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pHJvQIBADAKAgEAAgIkxQIB/zAHAgEA
# AgIRpDAKAgUA5pMbPQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAKnc4eja
# NHGQtFMYlnQrCSihDgi1yJVZFt/wcGCQwz+DF+61Te6N2mXCImPjnqxgiTFepbcl
# 3+vz8Ih+LX7oWetgl7QfhEgrr/oy7p1qZrMHe9n4TfsLDaALwstfsmSS0S4oshuH
# XWBEpiFeuVUOCNhOf8JxJQx3ns823StpSZGUMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGVt/wN1uM3MSUAAQAAAZUwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQg6DRkVIvVDW2WuYVbKJguJuQcCbGSv3Atpzu08xbDe6YwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBc5kvhjZALe2mhIz/Qd7keVOmA/cC1
# dzKZT4ybLEkCxzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABlbf8DdbjNzElAAEAAAGVMCIEIIxp4HDnVtLykNRLgteiviwshiJRAVGl
# B2+QHsqdeu7HMA0GCSqGSIb3DQEBCwUABIICAI7InLuDAROAXo1RtB/NjjLMooYQ
# 5pjd0Vvig59V5Ob2G86xgkHcP05dwKBf+QZsUhFtdA7aqUven6t59I75X47MXwwQ
# gtYqt2B4cPnBEhWsiZ/mjoc3xZiqH6CKowFzyKASPXssE7voUo9mdIqCt0l95Okw
# VBxfGzRm8JylpOhCgO/RIkptSonfx3DOc4DO49uKMxO0Q6Tem9ZJXdz9TUjut2hW
# dpFP2uhQ4s+okcWZXAs38ucQWwu8NOIoosZVevqeR9MMOa90vEISuRKHrz+iw3vr
# fY32TNP/9imXSYv2aIkBN4CmfFJ5hMhjv3Tqe2WYkzrZBHPfSPlRw6xHI/EWMxqA
# nWSrLdW4gd68AVr4C+B25+p9DGi/gyEeZudLKkUtjogjIVFY+wVZlmExIGRX95T0
# //aTSPtWRZdHEXo/nSj1klTy1t96k2yWpCRcSPa2vlxCdXv2axaRLJNNF4Bzc7+K
# WgeFg/yQG9IO4kSBX93ReTOlwO+kcXEW2VZVPmH8hBEsgz7OlMe6Kx3brqGwgjVk
# KP0auP+1D1hx8R8ndjaA9qtyLAtYlSJwy3X4JCID+hM2E1zIkZHWJi6FDdSAdoVl
# d3hPEM4MCVA64ma1pDLknOdu4JearhfevxytLCON4SLbBgjdAH4tQ67Pg2d4tr0A
# YRGqN6NdivDgTcUB
# SIG # End signature block
