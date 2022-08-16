# diag_api.psm1
# by tdimli
# March 2020
# API/helper functions

# errors reported by these diagnostics won't be shown on screen to user
# only saved to xray_ISSUES-FOUND_*.txt report file
$Global:BETA_DIAGS = "
net_802dot1x_KB4556307,
net_firewall_KB4561854,
net_wlan_KB4557342,
net_dnscli_KB4562541,
net_dasrv_KB4504598,
net_netio_KB4563820,
net_srv_KB4562940,
net_hyphost_KB4562593,
net_vpn_KB4553295,
net_vpn_KB4550202,
net_proxy_KB4569506,
net_branchcache_KB4565457,
net_dnssrv_KB4561750,
net_dnssrv_KB4569509,
net_dnscli_KB4617560,
net_ncsi_KB4648334,
net_srv_KB4612362
"

# constants
# return codes
$Global:RETURNCODE_SUCCESS = 0
$Global:RETURNCODE_SKIPPED = 1
$Global:RETURNCODE_FAILED = 2
$Global:RETURNCODE_EXCEPTION = 3

# issue types
$Global:ISSUETYPE_INFO = 0
$Global:ISSUETYPE_WARNING = 1
$Global:ISSUETYPE_ERROR = 2

# value could not be retrieved
$Global:VALUE_NA = "<error!>"

# time format
$Global:TIME_FORMAT = "yyMMdd-HHmmss"

# xray registry path
$xrayRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\xray"

# wmi data
$Global:wmi_Win32_ComputerSystem
$Global:wmi_Win32_OperatingSystem

# poolmon data
$Global:poolmonData

# globals
$version

$startTime
$timestamp

$dataPath
$logFile
$infoFile
$issuesFile
$xmlRptFile

$currDiagFn

$xmlReport
$xmlNsMgr
$nodeXray
$xmlTechAreas
$xmlParameters
$xmlSystemInfo
$xmlDiagnostics

# counters
$Global:numDiagsRun = 0
$Global:numDiagsSuccess = 0
$Global:numDiagsSkipped = 0
$Global:numDiagsFailed = 0
$Global:numIssues = 0

$Global:issueShown = $false

# To report an issue if one was identified by a diagnostic function
# Diagnostic functions use this function to report the issue they have identified 
# $issueType: 0 (Info), 1 (Warning) or 2 (Error)
function ReportIssue 
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $issueMsg,

            [Parameter(Mandatory=$true,
            Position=1)]
            [Int]
            $issueType
        )

    $Global:numIssues++
    $onScreenMsg = $true

    # get caller/diagnostic details
    $loc = $VALUE_NA
    $diagFn = $VALUE_NA
    $callStack = Get-PSCallStack
    if ($callStack.Count -gt 1) {
        $loc = (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
        $diagFn = $callStack[1].FunctionName
        if (($loc -eq "") -or ($loc -eq $null)) {
            $loc = $VALUE_NA
        }
        if (($diagFn -eq "") -or ($diagFn -eq $null)) {
            if ($Global:currDiagFn -ne $null) {
                $diagFn = $Global:currDiagFn
            }
            else {
                $diagFn = $loc
            }
            LogWrite "Diagnostic name uncertainty: No on screen message"
            $onScreenMsg = $false
        }
    }

    XmlDiagnosticUpdateIssue $diagFn $IssueType
    LogWrite "Issue (type:$issueType) reported by diagnostic $diagFn [$loc]"

    $outFile = $issuesFile

    # reported issue not an error
    if ($issueType -lt $ISSUETYPE_ERROR) {
        LogWrite "Issue type is not error: No on screen message, saving to info file instead"
        $outFile = $infoFile
        $onScreenMsg = $false
    }

    # diagnostic in beta, no on-screen message
    if ($BETA_DIAGS.Contains($diagFn)) {
        LogWrite "Diagnostic in beta: No on screen message"
        $onScreenMsg = $false
    }

    if(!(Test-Path -Path $outFile)){
        "xray by tdimli, v$version">$outFile
        "Diagnostic check run on $timestamp UTC`r`n">>$outFile
    }
    else {
        # add separator
        "`r`n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *`r`n">>$outFile
    }
        
    "**">>$outFile
    "** Issue $numIssues`tFound a potential issue (reported by $diagFn):">>$outFile
    "**">>$outFile
    $issueMsg>>$outFile
    
    # show message on screen
    if ($onScreenMsg) {
        $Global:issueShown = $true
        Write-Host ("
**
** Issue $numIssues`tFound a potential issue (reported by $diagFn):
**") -ForegroundColor red
        IndentMsg $issueMsg
    }
}

# Wraps a filename with "xray_" prefix and timestamp & computername suffix for consistency
# Ensures all files created have the same name format, same run of xray script uses the same timestamp-suffix
# Also prepends $dataPath to ensure all files are created in the designated folder
function MakeFilename
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $name,

            [Parameter(Mandatory=$true,
            Position=1)]
            [string]
            $extension
        )

    $computer = hostname
    $filename = "xray_" + $name + "_" + $timestamp + "_" + $computer + "." + $extension
    return Join-Path -Path $dataPath -ChildPath $filename
}

# Logs to activity log with timestamp
function LogWrite
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $msg
        )

    $callStack = Get-PSCallStack
    $caller = $VALUE_NA
    if ($callStack.Count -gt 1) {
        $caller = $callStack[1].FunctionName + " " + (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
    }
    $time = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss.fffffff")
    "$time [$caller] $msg" >> $logFile
}

# returns summary data from poolmon
# if multiple poolmon data sets are available one set for each will be returned
# each returned set will contain two list items with a string[7] in following format
# Example:
# For sample summary:
#  Memory:33356024K Avail:19399488K  PageFlts:400263915   InRam Krnl:12672K P:935188K
#  Commit:15680004K Limit:40433912K Peak:15917968K            Pool N:629240K P:1004712K
# it will return string array(s) containing:
#  Summary1,22/05/2020 22:35:55.53,33356024,19399488,400263915,12672,935188
#  Summary2,22/05/2020 22:35:55.53,15680004,40433912,15917968,629240,1004712
function GetPoolUsageSummary
{
    [System.Collections.Generic.List[string[]]] $poolmonInfo = New-Object "System.Collections.Generic.List[string[]]"

    foreach ($entry in $poolmonData) {
        if ($entry.Contains("Summary")) {
            $poolmonInfo.Add($entry -split ',')
        }
    }

    return $poolmonInfo
}

# returns pool usage info from poolmon for specified pool tag and type
# pooltag has to be 4 characters (case-sensitive), pooltype can be "Nonp" or "Paged" (case-sensitive)
# if multiple poolmon data sets are available all matching entries will be returned
# returns $null if no entry for specified item
# return data type is list of Int64 arrays
# Example:
# For sample entry:
#  Ntfx Nonp    1127072   1037111     89961 26955808        299        
# it will return an Int64 array containing:
#  1127072, 1037111, 89961, 26955808, 299
function GetPoolUsageByTag
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [ValidatePattern(“.{4}”)]
            [string]
            $poolTag,

            [Parameter(Mandatory=$true,
            Position=1)]
            [ValidatePattern(“(Nonp|Paged)")]
            [string]
            $poolType
        )

    [System.Collections.Generic.List[Int64[]]] $poolmonInfo = New-Object "System.Collections.Generic.List[Int64[]]"

    foreach ($entry in $poolmonData) {
        if ($entry.Contains("$poolTag,$poolType")) {
            $pmEntry = $entry -split ','
            [Int[]] $intArr = New-Object Int[] 5
            for ($i =0; $i -lt 5; $i++) {
                $intArr[$i] = [Convert]::ToInt64($pmEntry[$i + 2])
            }

            $poolmonInfo.Add($intArr)
        }
    }

    return ,$poolmonInfo # unary operator comma is to force the output type to array
}

<#
 Checks if one of the required updates ($reqUpdates) or a later update is present
 Returns 
  true if a required update or later is installed (or if none of the required updates do 
  not apply to current OS version)
   or
  false if a required update is not present (and one of the required updates applies to 
  current OS version)
 $required has a list of updates that specifies the minimum required update for any OS versions 
 to be checked
#>
function HasRequiredUpdate
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string[]]
        $reqUpdates
    )

    $unknownUpdates = $true
    $knownUpdateSeen = $false

    foreach ($minReqUpd in $reqUpdates) {
        foreach($name in $updateLists) {
            $updateList = (Get-Variable -Name $name -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
            $minReqIdx = $updateList.IndexOf($minReqUpd)
            if ($minReqIdx -ge 0) {
                $unknownUpdates = $false
                foreach($installedUpdate in $installedUpdates) {
                    # look for $minReqUpd or later update
                    $instIdx = $updateList.IndexOf($installedUpdate.HotFixID)
                    if ($instIdx -ge 0) {
                        $knownUpdateSeen = $true
                        if ($instIdx -le $minReqIdx) { # updates in $updateList are in reverse chronological order, with most recent at idx=0
                            return $true
                        }
                    }
                }
            }
        }
    }

    if ($unknownUpdates) {
        LogWrite "Required update(s) not known"
        throw
    }

    if ($knownUpdateSeen) {
        return $false
    }

    return $true
}

# Shows message on screen indented for readability
function IndentMsg
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $msg
        )

    $newMsg = $msg -split "`n"
    foreach ($line in $newMsg) {
        Write-Host "   $line"
    }
}

function InitGlobals
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $ver,

            [Parameter(Mandatory=$true,
            Position=1)]
            [string]
            $path
        )

    $Global:version = $ver
    $Global:dataPath = $path
    $Global:startTime = (Get-Date).ToUniversalTime()
    $Global:timestamp = $startTime.ToString($TIME_FORMAT)
    $Global:logFile = MakeFilename "log" "txt"
    $Global:infoFile = MakeFilename "INFO" "txt"
    $Global:issuesFile = MakeFilename "ISSUES-FOUND" "txt"
    $Global:xmlRptFile = MakeFilename "report" "xml"
    $Global:issueShown = $false

    # add and populate root node: nodeXray
    $Global:xmlReport = New-Object System.XML.XMLDocument
    $Global:nodeXray = $xmlReport.CreateElement("xray")
    [void] $xmlReport.appendChild($nodeXray)
    $nodeXray.SetAttribute("Version", $version)
    $nodeXray.SetAttribute("Complete", $false)
    $nodeXray.SetAttribute("StartTime", $timestamp)
    $nodeXray.SetAttribute("Complete", $false)
        
    # add nodes
    $Global:xmlTechAreas = $nodeXray.AppendChild($xmlReport.CreateElement("TechAreas"))
    $Global:xmlParameters = $nodeXray.AppendChild($xmlReport.CreateElement("Parameters"))
    $Global:xmlSystemInfo = $nodeXray.AppendChild($xmlReport.CreateElement("SystemInfo"))
    $Global:xmlDiagnostics = $nodeXray.AppendChild($xmlReport.CreateElement("Diagnostics"))

    # namespace manager
    $Global:xmlNsMgr = New-Object System.Xml.XmlNamespaceManager($xmlReport.NameTable)
    $xmlNsMgr.AddNamespace("xrayNS", $xmlReport.DocumentElement.NamespaceURI)
}

function AddSysInfo
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [bool]
            $offline
        )

    if ($offline) {
        # if offline retrieve from data
        LogWrite "Offline system info collection not yet implemented"
        return
    }

    # PSVersionTable
    $PSVer = ($PSVersionTable)
    if ($PSVer -ne $null) {
        XmlAddSysInfo "PSVersionTable" "PSVersion" $PSVer.PSVersion
        XmlAddSysInfo "PSVersionTable" "WSManStackVersion" $PSVer.WSManStackVersion
        XmlAddSysInfo "PSVersionTable" "SerializationVersion" $PSVer.SerializationVersion
        XmlAddSysInfo "PSVersionTable" "CLRVersion" $PSVer.CLRVersion
        XmlAddSysInfo "PSVersionTable" "BuildVersion" $PSVer.BuildVersion
    }

    # installedUpdates
    $Global:installedUpdates = Get-HotFix | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue

    # Win32_ComputerSystem
    $Global:wmi_Win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($wmi_Win32_ComputerSystem -ne $null) {
        XmlAddSysInfo "Win32_ComputerSystem" "BootupState" $wmi_Win32_ComputerSystem.BootupState
        XmlAddSysInfo "Win32_ComputerSystem" "PowerState" $wmi_Win32_ComputerSystem.PowerState
        XmlAddSysInfo "Win32_ComputerSystem" "DomainRole" $wmi_Win32_ComputerSystem.DomainRole
        XmlAddSysInfo "Win32_ComputerSystem" "Manufacturer" $wmi_Win32_ComputerSystem.Manufacturer
        XmlAddSysInfo "Win32_ComputerSystem" "Model" $wmi_Win32_ComputerSystem.Model
        XmlAddSysInfo "Win32_ComputerSystem" "NumberOfLogicalProcessors" $wmi_Win32_ComputerSystem.NumberOfLogicalProcessors
        XmlAddSysInfo "Win32_ComputerSystem" "NumberOfProcessors" $wmi_Win32_ComputerSystem.NumberOfProcessors
        XmlAddSysInfo "Win32_ComputerSystem" "OEMStringArray" $wmi_Win32_ComputerSystem.OEMStringArray
        XmlAddSysInfo "Win32_ComputerSystem" "PartOfDomain" $wmi_Win32_ComputerSystem.PartOfDomain
        XmlAddSysInfo "Win32_ComputerSystem" "PCSystemType" $wmi_Win32_ComputerSystem.PCSystemType
        XmlAddSysInfo "Win32_ComputerSystem" "SystemType" $wmi_Win32_ComputerSystem.SystemType
        XmlAddSysInfo "Win32_ComputerSystem" "TotalPhysicalMemory" $wmi_Win32_ComputerSystem.TotalPhysicalMemory
        XmlAddSysInfo "Win32_ComputerSystem" "HypervisorPresent" $wmi_Win32_ComputerSystem.HypervisorPresent
    }

    # Win32_OperatingSystem
    $Global:wmi_Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($wmi_Win32_OperatingSystem -ne $null) {
        XmlAddSysInfo "Win32_OperatingSystem" "Caption" $wmi_Win32_OperatingSystem.Caption
        XmlAddSysInfo "Win32_OperatingSystem" "Version" $wmi_Win32_OperatingSystem.Version
        XmlAddSysInfo "Win32_OperatingSystem" "BuildType" $wmi_Win32_OperatingSystem.BuildType
        XmlAddSysInfo "Win32_OperatingSystem" "BuildNumber" $wmi_Win32_OperatingSystem.BuildNumber
        XmlAddSysInfo "Win32_OperatingSystem" "ProductType" $wmi_Win32_OperatingSystem.ProductType
        XmlAddSysInfo "Win32_OperatingSystem" "OperatingSystemSKU" $wmi_Win32_OperatingSystem.OperatingSystemSKU
        XmlAddSysInfo "Win32_OperatingSystem" "OSArchitecture" $wmi_Win32_OperatingSystem.OSArchitecture
        XmlAddSysInfo "Win32_OperatingSystem" "OSType" $wmi_Win32_OperatingSystem.OSType
        XmlAddSysInfo "Win32_OperatingSystem" "InstallDate" $wmi_Win32_OperatingSystem.InstallDate
        XmlAddSysInfo "Win32_OperatingSystem" "LocalDateTime" $wmi_Win32_OperatingSystem.LocalDateTime
        XmlAddSysInfo "Win32_OperatingSystem" "LastBootUpTime" $wmi_Win32_OperatingSystem.LastBootUpTime
    }
    
    XmlSave
} 

function XmlAddTechArea
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [string]
        $ver
    )

    [System.XML.XMLElement]$xmlTechArea = $xmlTechAreas.AppendChild($xmlReport.CreateElement("TechArea"))
    $xmlTechArea.SetAttribute("Name", $name)
    $xmlTechArea.SetAttribute("Version", $ver)
}

function XmlAddParameters
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $areas,

        [Parameter(Mandatory=$true,
        Position=1)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $components,

        [Parameter(Mandatory=$true,
        Position=2)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $diagnostics,

        [Parameter(Mandatory=$true,
        Position=3)]
        [bool]
        $offline,

        [Parameter(Mandatory=$true,
        Position=4)]
        [bool]
        $waitBeforeClose,

        [Parameter(Mandatory=$true,
        Position=5)]
        [bool]
        $DevMode
    )

    foreach ($area in $areas) {
        [System.XML.XMLElement] $xmlArea = $xmlParameters.AppendChild($xmlReport.CreateElement("Area"))
        $xmlArea.SetAttribute("Name", $area)
    }
    foreach ($component in $components) {
        [System.XML.XMLElement] $xmlComponent = $xmlParameters.AppendChild($xmlReport.CreateElement("Component"))
        $xmlComponent.SetAttribute("Name", $component)
    }
    foreach ($diagnostic in $diagnostics) {
        [System.XML.XMLElement] $xmlComponent = $xmlParameters.AppendChild($xmlReport.CreateElement("Diagnostic"))
        $xmlComponent.SetAttribute("Name", $diagnostic)
    }
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("Offline"))
    $xmlOffline.SetAttribute("Value", $offline)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("WaitBeforeClose"))
    $xmlOffline.SetAttribute("Value", $waitBeforeClose)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("DevMode"))
    $xmlOffline.SetAttribute("Value", $DevMode)

    # save
    XmlSave
}

# to add a single attribute from a WMI class
function XmlAddSysInfo
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $valueName,

        [Parameter(Mandatory=$true,
        Position=1)]
        [string]
        $attribName,

        [Parameter(Mandatory=$true,
        Position=2)]
        [AllowNull()]
        [System.Object]
        $propertyValue
    )

    if ($propertyValue -ne $null) {

        [System.XML.XMLElement] $wmidata = $nodeXray.SelectSingleNode("/xray/SystemInfo/$valueName")
        if ((!$xmlSystemInfo.HasChildNodes) -or ($wmidata -eq $null)) {
            # doesn't exist, need to add
            $wmidata = $xmlSystemInfo.AppendChild($xmlReport.CreateElement($valueName))
        }
        $wmidata.SetAttribute($attribName, $propertyValue)
    }
}

# to add multiple/all attributes of a WMI class
function XmlAddSysInfoMulti
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $valueName,

        [Parameter(Mandatory=$true,
        Position=1)]
        [System.Object[]]
        $attributes
    )

    [System.XML.XMLElement] $wmidata = $nodeXray.SelectSingleNode("/xray/SystemInfo/$valueName")
    if ((!$xmlSystemInfo.HasChildNodes) -or ($wmidata -eq $null)) {
        # doesn't exist, need to add
        $wmidata = $xmlSystemInfo.AppendChild($xmlReport.CreateElement($valueName))
    }
    foreach($attribute in $attributes) {
        $wmidata.SetAttribute($attribute.Name, $attribute.Value)
    }
    XmlSave
}

function XmlAddDiagnostic
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name)

    [System.XML.XMLElement] $xmlDiagnostic = $xmlDiagnostics.AppendChild($xmlReport.CreateElement("Diagnostic"))
    $xmlDiagnostic.SetAttribute("Name", $name)
    $xmlDiagnostic.SetAttribute("Result", -1)
    $xmlDiagnostic.SetAttribute("Duration", -1)
    XmlSave 
}

function XmlDiagnosticComplete
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [Int]
        $result,

        [Parameter(Mandatory=$true,
        Position=2)]
        [UInt64]
        $duration
    )

    $xmlDiagnostic = $xmlReport.SelectSingleNode("//xrayNS:Diagnostics/Diagnostic[@Name='$name']", $xmlNsMgr)

    if ($xmlDiagnostic -ne $null) {
        $xmlDiagnostic.SetAttribute("Result", $result)
        $xmlDiagnostic.SetAttribute("Duration", $duration)
        XmlSave 
    }
}

function XmlDiagnosticUpdateIssue
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [Int]
        $issueType
    )

    $xmlDiagnostic = $xmlReport.SelectSingleNode("//xrayNS:Diagnostic[@Name='$name']", $xmlNsMgr)

    if ($xmlDiagnostic -ne $null) {
        $xmlDiagnostic.SetAttribute("Reported", $issueType)
        XmlSave 
    }
}

function XmlMarkComplete
{
    $nodeXray.SetAttribute("Complete", $true)
    XmlSave 
}

function XmlSave
{
    $finishTime = (Get-Date).ToUniversalTime()
    $nodeXray.SetAttribute("EndTime", $finishTime.ToString($TIME_FORMAT))
    [UInt64] $timeTaken = ($finishTime - $startTime).TotalMilliseconds
    $nodeXray.SetAttribute("Duration", $timeTaken)
    $xmlReport.Save($xmlRptFile)
}

function InitPoolmonData
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [bool]
            $offline
        )

    $file = Get-ChildItem -Path "$dataPath\*_poolmon.txt" -Name
    if ($file.Count -gt 1) {
        $file = $file[0]
    }

    if ($file -ne $null) {

        $Global:poolmonData = New-Object "System.Collections.Generic.List[string]"
        $pmTimestamp = $VALUE_NA

        $summary1 = "^\s+Memory:\s*(?<memory>[-0-9]+)K Avail:\s*(?<avail>[-0-9]+)K  PageFlts:\s*(?<pageflts>[-0-9]+)   InRam Krnl:\s*(?<inRamKrnl>[-0-9]+)K P:\s*(?<inRamP>[-0-9]+)K"
        $summary2 = "^\s+Commit:\s*(?<commit>[-0-9]+)K Limit:\s*(?<limit>[-0-9]+)K Peak:\s*(?<peak>[-0-9]+)K            Pool N:\s*(?<poolN>[-0-9]+)K P:\s*(?<poolP>[-0-9]+)K"
        $tagentry = "^\s+(?<tag>.{4})\s+(?<type>\w+)\s+(?<allocs>[-0-9]+)\s+(?<frees>[-0-9]+)\s+(?<diff>[-0-9]+)\s+(?<bytes>[-0-9]+)\s+(?<perAlloc>[-0-9]+)\s+$"
        $markerDT = "^\s*===== (?<datetime>(.){22}) ====="
        
        Get-Content "$dataPath\$file" |
        Select-String -Pattern $summary1, $summary2, $tagentry, $markerDT |
        Foreach-Object {

            if ($_.Matches[0].Groups['datetime'].Value -ne "") {
                $pmTimestamp =  $_.Matches[0].Groups['datetime'].Value
            }

            if ($_.Matches[0].Groups['memory'].Value -ne "") {
                #$memory, $avail, $pageflts, $inRamKrnl, $inRamP = $_.Matches[0].Groups['memory', 'avail', 'pageflts', 'inRamKrnl', 'inRamP'].Value
                $memory = $_.Matches[0].Groups['memory'].Value
                $avail = $_.Matches[0].Groups['avail'].Value
                $pageflts = $_.Matches[0].Groups['pageflts'].Value
                $inRamKrnl = $_.Matches[0].Groups['inRamKrnl'].Value
                $inRamP = $_.Matches[0].Groups['inRamP'].Value

                $poolmonData.Add("Summary1,$pmTimestamp,$memory,$avail,$pageflts,$inRamKrnl,$inRamP")
            }

            if ($_.Matches[0].Groups['commit'].Value -ne "") {
                #$commit, $limit, $peak, $poolN, $poolP = $_.Matches[0].Groups['commit', 'limit', 'peak', 'poolN', 'poolP'].Value
                $commit = $_.Matches[0].Groups['commit'].Value
                $limit = $_.Matches[0].Groups['limit'].Value
                $peak = $_.Matches[0].Groups['peak'].Value
                $poolN = $_.Matches[0].Groups['poolN'].Value
                $poolP = $_.Matches[0].Groups['poolP'].Value

                $poolmonData.Add("Summary2,$pmTimestamp,$commit,$limit,$peak,$poolN,$poolP")
                $pmTimestamp = $VALUE_NA
            }

            if ($_.Matches[0].Groups['tag'].Value -ne "") {
                #$tag, $type, $allocs, $frees, $diff, $bytes, $perAlloc = $_.Matches[0].Groups['tag', 'type', 'allocs', 'frees', 'diff', 'bytes', 'perAlloc'].Value
                $tag = $_.Matches[0].Groups['tag'].Value
                $type = $_.Matches[0].Groups['type'].Value
                $allocs = $_.Matches[0].Groups['allocs'].Value
                $frees = $_.Matches[0].Groups['frees'].Value
                $diff = $_.Matches[0].Groups['diff'].Value
                $bytes = $_.Matches[0].Groups['bytes'].Value
                $perAlloc = $_.Matches[0].Groups['perAlloc'].Value 

                $poolmonData.Add("$tag,$type,$allocs,$frees,$diff,$bytes,$perAlloc")
            }
        }
    }
    else {
        LogWrite "Poolmon data not found: $dataPath\*_poolmon.txt"
    }
}

Export-ModuleMember -Function * -Variable *
# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCYaUWmb1HVG4my
# lqoWWQQbFl1UJ13DDCCbnS7KNrxqlqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgxXSU+PrN
# lnG9fpnLCStL3v0hdByR0JwM4m7rEzZIDPswQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAknoOD/NZ+u7AYtNotcljSlTM/fVaC5xpNwF5zZtvx
# HAe0qqyzTTX2eIWNjgvwy2xPxWFIuA8Lg89ZwsXoH3l/LL9ZaWil/uRUIFZ3b269
# JT4M6tL/QFMZ9+SPXPcTCnG7cNmK6wSwZdWR+EfquQVN+38NsLrp1qoammRFKSqB
# W1gIZud5sVe7r3LKaog4kGprkXhikYS99p1gC6GuUbkqKE+kl4dPHLrxdrGHBELf
# g5Oov3hCCk5ko1Hv8MCYcZCr6LKMGrFI8pFAl8jXPae0Blzve2mTAO10YVnCRPVQ
# VCu35JKBcMeZN+fVuqDsorb0sHlDbHv0UN7YQSU65rvFoYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEICk9cv/B1NXm8JtmSoKxQMyHk5/XLxMgZihc2GkI
# 4hzbAgZi2yOF3qMYEzIwMjIwODE2MDkxODEyLjA2OVowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozMkJELUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABrfzfTVjjXTLpAAEA
# AAGtMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTEzNloXDTIzMDUxMTE4NTEzNlowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozMkJE
# LUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOieUyqlTSrVLhvY7TO8
# vgC+T5N/y/MXeR3oNwE0rLI1Eg/gM5g9NhP+KqqJc/7uPL4TsoALb+RVf6roYNll
# yQrYmquUjwsq262MD5L9l9rU1plz2tMPehP8addVlNIjYIBh0NC4CyME6txVppQr
# 7eFd/bW0X9tnZy1aDW+zoaJB2FY8haokq5cRONEW4uoVsTTXsICkbYOAYffIIGak
# MFXVvB30NcsuiDn6uDk83XXTs0tnSr8FxzPoD8SgPPIcWaWPEjCQLr5I0BxfdUli
# wNPHIPEglqosrClRjXG7rcZWbWeODgATi0i6DUsv1Wn0LOW4svK4/Wuc/v9dlmuI
# ramv9whbgCykUuYZy8MxTzsQqU2Rxcm8h89CXA5jf1k7k3ZiaLUJ003MjtTtNXzl
# gb+k1A5eL17G3C4Ejw5AoViM+UBGQvxuTxpFeaGoQFqeOGGtEK0qk0wdUX9p/4Au
# 9Xsle5D5fvypBdscXBslUBcT6+CYq0kQ9smsTyhV4DK9wb9Zn7ObEOfT0AQyppI6
# jwzBjHhAGFyrKYjIbglMaEixjRv7XdNic2VuYKyS71A0hs6dbbDx/V7hDbdv2srt
# Z2VTO0y2E+4QqMRKtABv4AggjYKz5TYGuQ4VbbPY8fBO9Xqva3Gnx1ZDOQ3nGVFK
# HwarGDcNdB3qesvtJbIGJgJjAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUfVB0HQS8
# qiFabmqEqOV9LrLGwVkwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAi9AdRbsx/gOSdBXndwRejQuutQqce3k3bgs1
# slPjZSx6FDXp1IZzjOyT1Jo/3eUWDBFJdi+Heu1NoyDdGn9vL6rxly1L68K4MnfL
# Bm+ybyjN+xa1eNa4+4cOoOuxE2Kt8jtmZbIhx2jvY7F9qY/lanR5PSbUKyClhNQh
# xsnNUp/JSQ+o7nAuQJ+wsCwPCrXYE7C+TvKDja6e6WU0K4RiBXFGU1z6Mt3K9wlM
# D/QGU4+/IGZDmE+/Z/k0JfJjZyxCAlcmhe3rgdhDzAsGxJYq4PblGZTBdr8wkQwp
# P2jggyMMawMM5DggwvXaDbrqCQ8gksNhCZzTqfS2dbgLF0m7HfwlUMrcnzi/bdTS
# RWzIXg5QsH1t5XaaIH+TZ1uZBtwXJ8EOXr6S+2A6q8RQVY10KnBH6YpGE9OhXPfu
# Iu882muFEdh4EXbPdARUR1IMSIxg88khSBC/YBwQhCpjTksq5J3Z+jyHWZ4MnXX5
# R42mAR584iRYc7agYvuotDEqcD0U9lIjgW31PqfqZQ1tuYZTiGcKE9QcYGvZFKnV
# dkqK8V0M9e+kF5CqDOrMMYRV2+I/FhyQsJHxK/G53D0O5bvdIh2gDnEHRAFihdZj
# 29Z7W0paGPotGX0oB5r9wqNjM3rbvuEe6FJ323MPY1x9/N1g126T/SokqADJBTKq
# yBYN4zMwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
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
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozMkJELUUzRDUtM0IxRDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# QJLRrUVR4ZbBDgWPjuNqVctUzpCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOalRMMwIhgPMjAyMjA4MTYwMjE4
# NDNaGA8yMDIyMDgxNzAyMTg0M1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5qVE
# wwIBADAKAgEAAgIevQIB/zAHAgEAAgISCTAKAgUA5qaWQwIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBACMxx0gdoUjpVVoRGYtu+a9IpNJVqiXGPT/1tTz91Yob
# 6D6pjCjeOD+4UnI/E/fyYgoAr+fC8EFZyR+Le/Wl22a/q3S3Si1t2cL7Xds+UKK0
# 5OxOhFqL7fbA639nBurKdXdbyLZ1fe479mzy9NxUFXe+1eX8aNJAC0bRPa5NVHQ1
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGt/N9NWONdMukAAQAAAa0wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg+yUd7wHT9SFKXGUPQXdI
# 8cNGt8/Fh1PgLOb4PhHndZcwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCf
# 6nw9CR5e1+Ottcn1w992Kmn8YMTY/DWPIHeMbMtQgjCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABrfzfTVjjXTLpAAEAAAGtMCIEIAy4
# Z3jEdWX1/OMXPHlcPiN9gRaJdbJJSkeIZayW1XADMA0GCSqGSIb3DQEBCwUABIIC
# ABklLuBnVob+aL/CycCmsOBh5YTcoiygLIeCtcZoa0vZj4k26Hd8tfII15vFU599
# mQ0G48VtU7zSx7kGLRBZGT7NytznxDSCJ+eAgU4H0G2Rxdfdwv+YW0F6JOE+Q5e1
# kVmTkQ0k7HeyY2tVNCplo5FjoxtnkGeYcSJctXS2McpXXmezFK7dI/lKTl6DmyFm
# hAT0S6SOIwX3+2ZiKC7gdMt9sZgV+sIYaobY8yc18leL1zvUmOldP3IhOzOu7V64
# 7Aj0L0LN/eMoOxnUuzD1U5r3SQx+h6u0aFdfsHD7YwNFwr/jJjBSsjD/z8zWQYtR
# lBObxkRa+JXFEu7jtz2Ng0a9V9muKSx/u7a65QXa1C1uPRocig29BbYdlSfH37j5
# l9oYLtXKK0K+E87TNxstlvNAhBydl0GEWn8RLkhCZ+iS8WPYiBCbtL6l34U0YV1z
# 78LWlFh4U84BuLqYC/LpXaXw19Dl5bz1EhTJ6PQzVdmTLWj7FQBTiMWA4rSTrDF2
# 8vQ/3AzIYbGjYBn3uQLCbux1cMUEOctXdKvaQIQvmv7UomSdUi6HeU9gSDvZW7YD
# AakX5Lcb7UL0OVHKynbJfNLAlLVZMcmn5vvGyV2qtG5vysNJ0yEReiDxUqwOk1zp
# Sy4kX1Nv108TC1EW3iRtS5nfEJNdxkTonB7r/CAhJMbR
# SIG # End signature block
