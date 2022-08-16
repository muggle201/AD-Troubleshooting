<#
.SYNOPSIS
Detects known issues and helps resolve them.

.DESCRIPTION
xray aims to automate detection of known issues and help resolve them with minimal time and effort.
It consists of multiple diagnostic functions each looking for a known issue.

.PARAMETER Area
Which technology area xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When area(s) specified, all components within the specified area(s) are checked
"-Area all" or "-Area *" checks all areas

.PARAMETER Conponent
Which conponent xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When component(s) specified, all diagnostics within the specified component(s) are run
No wildcards allowed, to run diagnostics for all components, use -Area parameter instead.

.PARAMETER Diagnostic
Which conponent xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When diagnostic(s) specified, only the specified diagnostics are run
No wildcards allowed, to run all diagnostics, consider using -Area or -Component parameter instead.

.PARAMETER DataPath
Path for input/output files

.PARAMETER Offline
Indicates xray is not running on the actual machine being examined (some -not all- diagnostics can use data files to search for issues)

.PARAMETER WaitBeforeClose
If any known issues are detected, pauses just before script terminates/window closes
Used to ensure detected issues shown on screen are not missed (they are always saved to report file)

.PARAMETER DevMode
For diagnostic developers, to be used only whilst developing a diagnostic function. 
When specified, error messages for diagnostics are not suppressed.

.PARAMETER AcceptEULA
Do not display EULA at start

.EXAMPLE
PS> xray.ps1 -Component dhcpsrv,dnssrv -DataPath c:\xray -WaitBeforeClose

This command runs all diagnostics for both dhcpsrv and dnssrv components, saves results to specified path c:\xray and waits for user before terminating if any issues found.

.EXAMPLE
PS> .\xray.ps1 -Area * -DataPath c:\MS_DATA

This command runs all diagnostics for all components in all technology areas and saves results to data path specified.
#>

Param(
    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [ValidateSet("All", "*", "ADS", "DND", "NET", "PRF", "SHA", "UEX")]
    [String[]]
    $Area,

    [Parameter(Mandatory=$true,
    ParameterSetName="Components")]
    [String[]]
    $Component,

    [Parameter(Mandatory=$true,
    ParameterSetName="Diagnostics")]
    [String[]]
    $Diagnostic,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [String]
    $DataPath,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $Offline,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $WaitBeforeClose,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $DevMode,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $AcceptEULA
)

Import-Module -Name .\xray_WU.psm1 -Force
Import-Module -Name .\diag_api.psm1 -Force

Import-Module -Name .\diag_ads.psm1 -Force
Import-Module -Name .\diag_dnd.psm1 -Force
Import-Module -Name .\diag_net.psm1 -Force
Import-Module -Name .\diag_prf.psm1 -Force
Import-Module -Name .\diag_sha.psm1 -Force
Import-Module -Name .\diag_uex.psm1 -Force

# used for diagnostic development only
if ($DevMode) {
    Import-Module -Name .\diag_test.psm1 -Force
}

# version
$version = "1.0.220713.0"

# Area and Area/Component arrays
$TechAreas = @("ADS", "DND", "NET", "PRF", "SHA", "UEX")
#endregion globals

#region helpers

# Processes provided area(s) with all its components & checks
function RunDiagForArea($areas)
{
    foreach ($area in $areas) {
        LogWrite "Processing area:$area"

        try {
            $components = (Get-Variable -Name $area -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
        }
        catch {
            LogWrite $Error[0].Exception
        }

        if($ErrorMsg) {
            LogWrite $ErrorMsg
        }
        else {
            RunDiagForComponent $components
        }
    }
}

# Processes provided components and runs corresponding diags
function RunDiagForComponent($components)
{
    if($components.Count -eq 0){
        LogWrite "No components!"
        return
    }

    foreach ($component in $components) {
        LogWrite "Processing component: $component"

        try {
            $diags = (Get-Variable -Name $component -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
        }
        catch {
            LogWrite $Error[0].Exception
        }

        if($ErrorMsg) {
            LogWrite $ErrorMsg
        }
        else {
            RunDiag $diags
        }
    }
}

# Runs specified diagnostics
function RunDiag($diagnostics)
{
    if($diagnostics.Count -eq 0){
        LogWrite "No diagnostics!"
        return
    }

    foreach ($diag in $diagnostics) {
        if($executedDiags.Contains($diag)) {
            LogWrite "Skipping duplicate instance: $diag"
            continue
        }
        $Global:currDiagFn = $diag
        $executedDiags.Add($diag)
        LogWrite "Running diagnostic: $diag"
        XmlAddDiagnostic $diag
        Write-Host "." -NoNewline
        $time1 = (Get-Date).ToUniversalTime()

        $Global:numDiagsRun++
        if ($DevMode) {
            # no error/exception protection
            $result = & $diag $Offline
        }
        else {
            # to prevent failure messages from diag functions
            $ErrorActionPreference = "Stop"
            try {
                $result = & $diag $Offline
            }
            catch {
                $result = $RETURNCODE_EXCEPTION
                LogWrite $Error[0].Exception.Message
            }
            # revert to normal error handling 
            $ErrorActionPreference = "Continue"
        }

        LogWrite "$diag returned: $result"
        $time2 = (Get-Date).ToUniversalTime()
        [UInt64] $timeTaken = ($time2 - $time1).TotalMilliseconds
        XmlDiagnosticComplete $diag $result $timeTaken

        if($result -eq $RETURNCODE_SUCCESS){
            $Global:numDiagsSuccess++
        }
        elseif($result -eq $RETURNCODE_SKIPPED){
            $Global:numDiagsSkipped++
        }
        else {
            $Global:numDiagsFailed++
        }
        $Global:currDiagFn = $null
    }
}

# 'Translates' TSS scenarios to xray components 
function ValidateTssComponents
{
    param(
        [Parameter(Mandatory=$true)]
        [String[]]
        $TssComponents
    )

    $tssComps  = @("802Dot1x", "WLAN",     "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")
    $xrayComps = @("802Dot1x", "802Dot1x", "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")

    for ($i = 0; $i -lt $tssComps.Count; $i++) {
        $tssComps[$i] = $tssComps[$i].ToLower()
        $xrayComps[$i] = $xrayComps[$i].ToLower()
    }
    for ($i = 0; $i -lt $TssComponents.Count; $i++) {
        $TssComponents[$i] = $TssComponents[$i].ToLower()
    }
    [System.Collections.Generic.List[String]] $newComps = $TssComponents

    for ($i = 0; $i -lt $TssComponents.Count; $i++) {
        $index = -1
        for ($j = 0; $j -lt $tssComps.Count; $j++) {
            if ($tssComps[$j] -eq $TssComponents[$i]) {
                $index = $j
                break
            }
        }
        if($index -lt 0) {
            continue
        }
        if($TssComponents[$i] -ne $xrayComps[$index]) {
            # remove
            $newComps.RemoveAt($i)
            if(!$newComps.Contains($xrayComps[$index])) {
                # replace
                $newComps.Insert($i, $xrayComps[$index])
            }
        }
    }
    return [String[]] $newComps
}

# Displays help/usage info
function ShowHelp
{
    "
No parameters specified, nothing do. 

For usage info, run:
    Get-Help .\xray.ps1

List of available diagnostic areas/components to scan for issues:

Area (version):  `tComponents:
=================`t==========="

    foreach ($techarea in $TechAreas) {
        $version_name = $techarea + "_version"
        $techarea_version = (Get-Variable -Name $version_name).Value
        $components = (Get-Variable -Name $techarea).Value
        "$techarea ($techarea_version)`t$components"
    }
    ""
}
#endregion helpers

#region EULA
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
#endregion EULA

#region main
# main script

Write-Host "xray by tdimli, v$version"

# validate cmdline
if (($Area -eq $null) -and ($Component -eq $null) -and ($Diagnostic -eq $null)) {
    ShowHelp
    return
}

# EULA
if ($AcceptEULA -eq $false) {
    $eulaAccepted = ShowEULAIfNeeded "xray" 0
    if($eulaAccepted -ne "Yes") {
        "EULA Declined"
        exit
    }
}

# validate DataPath, do it here before any file operations
$origDataPath = $DataPath
if(($DataPath.Length -eq 0) -or -not(Test-Path -Path $DataPath)) {
    $DataPath = (Get-Location).Path
}
else {
    $DataPath = Convert-Path $DataPath
}

InitGlobals $version $DataPath

LogWrite "xray by tdimli, v$version"

Write-Host "`r`nStarting diagnostics, checking for known issues..."
foreach ($techarea in $TechAreas) {
    $version_name = $techarea + "_version"
    $techarea_version = (Get-Variable -Name $version_name).Value
    LogWrite " $techarea $techarea_version"
    XmlAddTechArea $techarea $techarea_version
}

# these splits are needed for TSS interoperability
if ($Area -ne $null) {
    $Area = $Area -split ","
    if (($Area -eq "all") -or ($Area -eq "*")) {
        $Area = $TechAreas
    }
}
if ($Component -ne $null) {
    $Component = $Component -split ","
    for ($i = 0; $i -lt $Component.Count; $i++) {
        $Component[$i] = $Component[$i].Replace(' ', '')
    }
}
if ($Diagnostic -ne $null) {
    $Diagnostic = $Diagnostic -split ","
}

# log parameters
LogWrite "Parameters:"
LogWrite " Area(s): $Area"
LogWrite " Component(s): $Component"
if(($Component -ne $null) -and ($Component.Count -gt 0)) {
    $ConvertedComponent = ValidateTssComponents $Component
    LogWrite "  after conversion: $ConvertedComponent"
    $Component = $ConvertedComponent
}
# handle "-component general"
for ($i = 0; $i -lt $Component.Count; $i++) {
    $Component[$i] = $Component[$i].Replace(' ', '')
    if ($Component[$i].ToLower() -eq "general") {
        $Area = $TechAreas
        $Components = $null
        LogWrite "  general specified, running with -Area All instead"
    }
}
LogWrite " Diagnostic(s): $Diagnostic"
LogWrite " Datapath: $DataPath"
if (!$DataPath.Equals($origDataPath)) {
    LogWrite "  Original Datapath: $origDataPath"
}
LogWrite " Offline: $Offline"
LogWrite " WaitBeforeClose: $WaitBeforeClose"
LogWrite " DevMode: $DevMode"
XmlAddParameters $Area $Component $Diagnostic $Offline $WaitBeforeClose $DevMode

LogWrite "Log file: $logFile"
LogWrite "XML report: $xmlRptFile"

# collect basic system info
LogWrite "Collecting system info..."
AddSysInfo $Offline

# collect poolmon info
LogWrite "Collecting poolmon info..."
InitPoolmonData $Offline

# run diagnostics
LogWrite "Starting diagnostics, checking for known issues..."
[System.Collections.Generic.List[String]] $executedDiags = New-Object "System.Collections.Generic.List[string]"
if ($Area) {
    RunDiagForArea $Area
} elseif ($Component) {
    RunDiagForComponent $Component
} elseif ($Diagnostic) {
    RunDiag $Diagnostic
}
XmlMarkComplete

# log/show summary
$stats1 = "$numDiagsRun diagnostic check(s) run (R:$numDiagsSuccess S:$numDiagsSkipped F:$numDiagsFailed)"
$stats2 = "$numIssues issue(s) found"
if(Test-Path -Path $issuesFile){
    $stats2 += ", details saved to $issuesFile"
}
elseif(Test-Path -Path $infoFile) {
    $stats2 += ", details saved to $infoFile"
}

LogWrite $stats1
LogWrite $stats2
LogWrite "Diagnostics completed."

Write-Host
Write-Host $stats1
Write-Host $stats2
Write-Host "Diagnostics completed.`r`n"

if($WaitBeforeClose -and $issueShown) {
    # wait for user
    pause
}
#endregion main

# SIG # Begin signature block
# MIInqQYJKoZIhvcNAQcCoIInmjCCJ5YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAZokvWh3xA2MtG
# 34QhBAlTIckx+4Bp6dyIiXH70rWXv6CCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZfjCCGXoCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg84ce91bJ
# U0XWwwLfGa1ddK3lce2KvJ2i8TANhg0SueQwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBvLwZFnQPe0ShxpPK+dpfvrxI/lNWmBiqDPiwQt5p8
# Ifv/kYdm8rTwhJyKVgAsHvGh4NAvUhI/O0T8ssaOo84h7zd30J26oG+OJMTf3euQ
# MMtf603t/OUfEuNKxHdTCNhJrdQs67OvqIDAqobkm/1I4gXGbkV8OwijyoDN/qtf
# L9ZnOEXpXydPH1vnOA2oaN/5QNViEOK8ggNoHc0lk+djBedPenETqGmVM/6uqJHs
# 9XPT7g8hYM9axhjLrxewUeiJVLf20arHaRGceWJTdNg04nKqa2chxuiyspY3NQ0L
# agPx3oVp1BxZ3GMJdJrsfS/rg2Xjj4qtasuV6JdD/lA9oYIXCDCCFwQGCisGAQQB
# gjcDAwExghb0MIIW8AYJKoZIhvcNAQcCoIIW4TCCFt0CAQMxDzANBglghkgBZQME
# AgEFADCCAVQGCyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIHWQ4C2zquIe8bzgOn/6RewciT6bBnJJblXYwMON
# B6UqAgZi2wb1k8EYEjIwMjIwODE2MDkxODEwLjMxWjAEgAIB9KCB1KSB0TCBzjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWlj
# cm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBU
# U1MgRVNOOjREMkYtRTNERC1CRUVGMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1T
# dGFtcCBTZXJ2aWNloIIRXDCCBxAwggT4oAMCAQICEzMAAAGwoeODMuiNO8AAAQAA
# AbAwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# HhcNMjIwMzAyMTg1MTQyWhcNMjMwNTExMTg1MTQyWjCBzjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJh
# dGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjREMkYt
# RTNERC1CRUVGMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnMZtOwzX0oKdBzlELtWi
# CXJJcwou63/JZY9BYPpUCUmAF7FUrHafXOBfej/EDZmBn80UZyA0NEInuYmI55bv
# F4eeg1c+WDsSNha6V+Teg4CPprs7Xka9ySliy8tzH6jxJ7wKt8hvjQQnxbRDHhMh
# d/TIPAAnj+o73h0n+EZpt4liDganQbS5CaHAWi8BZMeUPVyL6ynfoDFP3AiEerD/
# vS3My+ucMXuOZCNpVQ+eM6A87IVZmJWvt7quRKXhqdPW0u/bdJaFeoyzXjCiW/hl
# 5BxY/zitXYWuvUpvCQhrS+UeOW/jEb1rqeVNF+jQJhRAN+tk4xcIjkpwA3YFnp9V
# vT2q0J2xZ003EHTLiXAyOe42bHzkU1/M9wxmObAAX1pFRQwse/rbojru3X51mhU+
# kqp9I2Ya1W30MRNaSYOKmcaDj4F1OmW+AZWr0Xcpk8MUdpvFsulJZ9db3Qxlc64U
# fzIIzMMk1TN7ICrK0UXItmKvePhPUbHuVF4I5Q/DWm5XNtYqylXsyh1mO038hRZ1
# Uh2Tcc+nhA3XDB1W91c6xh2EbySCMbIBkgPmivsL/vmHIpBvkXRn4R7Ti5j0r6wN
# neXfPxNBlYB9i6ttkIxZaeYlWy7lXg9Hk875ToPu0C0y8xQs1iJtP36zFVkr9ZB6
# vYkn2rdnuWMWziWCmZ9zoBUCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQ63wEkNwEm
# bh3LoBJketcgR9Y2PzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDdc+KHmw21R8DIueVeroxlKkKHRMX64b6eEgnj
# j/9wxxAYRWJnY3brc3C+tCMIU6eL/6jF/vqNyZSFwpYteT2GF3u98UGFlnNwXlo2
# zTtSWKCzbim95qwW6GYnjLzY5ibUbU5FiwWd1l28X/82tgbFpepQ2VEdCWyRX+mZ
# xyo7c6LrAsdw8HX9ZFMsm1hsiKLAT+5MUQUQvjnBYP/WZMI8SQVfeGWJcTKnFfN1
# nWTpeoZPKwYC0tdQHsgLoIfbpjKApC5cbxCNwkEBQb/0XfI1k51sW+fsWKdnI1wh
# UvGV3uHRsQt9DOEiN6WP7mwEqEtxoVTS9uNuZ/RYQ2AWafIk2Iysvv/YVg4uyCJA
# NsnHoOnLUR++5Eax0vl/6NVV2zmgxoquHGBXugShusDpnnqedZg3juzDCi65wd/T
# KbUNBYfLYMc4VFE3vK/77N6zQZII6NFFg8ruuvVBz47eex3rTg6CbmdH1CqE45zY
# 5BOu+1KBcFK27m8XpbwM9yyezndxDiB1xHVj02DkhgTDEJnPNiyr2hqXGUf5kf8D
# ontkx5I0o2Stc/HqmkVdTEe4LeTibNXJk0ZY/9mBxQ6LapXTeboibK2+LWR8Z7ph
# 0KHfY86BZ40f2V8q353Uz6rgiEkuZfQTZlkgJgRv1DSuiZ4xfwZn5xuG42wWKYmB
# r9+OOzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLPMIIC
# OAIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28x
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjREMkYtRTNERC1CRUVGMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAC
# ni+Q3d8PkU0FVhmSVl5L8kU8GKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5qXRezAiGA8yMDIyMDgxNjEyMTkw
# N1oYDzIwMjIwODE3MTIxOTA3WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDmpdF7
# AgEAMAcCAQACAiGpMAcCAQACAhDGMAoCBQDmpyL7AgEAMDYGCisGAQQBhFkKBAIx
# KDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZI
# hvcNAQEFBQADgYEAX1BNrFQUXtuK51yM9pkXs1360J3JHAKgIn70zQ/5yzh8j8yO
# o3IAWeMbhxmBvpJwSw0WKhHe/KZmpmH3BPt6cx3ntUbNACLQ4wKbhyhzva5HtaKn
# iXCsjBbVvPcuH3DGn36M1/PtC4fbTFdGdk+j/U2T8Ye0lQJ8fpbc4Ltw6xIxggQN
# MIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbCh
# 44My6I07wAABAAABsDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0G
# CyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAJQpYVcljHTcpo4fVTQzhd8CFS
# hHtLhy6HjPXdvNQaYjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIM0GC0N3
# y5/0pOMZ/Ubrsh8qZw0UmZ5ZN3qKUDLnFYSgMIGYMIGApH4wfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAGwoeODMuiNO8AAAQAAAbAwIgQgQB3igvCy
# Fn1YafpmwsBE1Gr29f3+yPB/1P7M7Z3IxDowDQYJKoZIhvcNAQELBQAEggIAgXIe
# IqE0XIBYr6C30sP2pjSw4P86gKHN5OcmVuR5Jo1cQBMO2c8KPpfwj1TF37AQmqhO
# PdSaDygp+a83Heqhs2+evgszlwu0RV0/UkSdIv/YDJ1sGBpFOi07bvR3UOHV5jq5
# 0GbQJJ8a1twF+QayPahZsdBydIp9v2CtMci1+wFaSdLvtYV3v+y8E6l6H3KBwm6c
# wur5utXOW915POLerO0jGQ00AQCTGF0rtDmXN8HW6v7xpTcW73LU0uZzX05S9q9I
# pNozRBEQmjsNacAedU0Z/ICSf/e6c5VyGJ4Zp0MeNusiu+ENAX3s6YNNZEXgMXe0
# mw2skvP/merV8LNLguI8DcS7tOhYaR/aAXGH2b7tQLJPxZMpqwvOOf+6qmOZ4iG+
# 2k4Xm0qDIAFKM1Q4h+3LfKgxeKX4ZPoeBkpquJPVSUtA92HS+5IuKW/fNqGdQld8
# t12n8s01DbvAlZCphcGoJBBmpxPh+iWb5VKHykT55XPdsthf853n9cEZiM2ATT7v
# 6lSWMFN3u8m5FDcYEFVVim0VfvDyM5QnRR0uYb2HVctDqnBh4dSRZW/5NPGZ2C91
# 01wh8d0GwNFIjwHv9aRg++K2jfDDZBDOTxvUde9IVyQUBKEJPfpv+3/AmOmfn5sX
# rD2Cv3yGm4wcEcRbY0usU1pw5hw0X/26iNt1zDM=
# SIG # End signature block
