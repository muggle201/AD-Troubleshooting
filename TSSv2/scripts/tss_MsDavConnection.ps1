# Source: https://github.com/edbarnes-msft/DrDAV/blob/master/Test_MsDavConnection.ps1
<# Script name: tss_MSDavConnection.ps1
Purpose: - check WebDAV/WebClient related settings and connectivity
#>

param(
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose a writable output folder location, i.e. C:\Temp\ ')]
	[string]$DataPath = (Split-Path $MyInvocation.MyCommand.Path -Parent)
)

$ScriptVer="2020.07.06"

$deftesturl =  'https://www.myserver.com'

[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
[uri] $testurl = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the http target web folder", "Web Address", $deftesturl)

$logpath = $DataPath
#_#$logpath = $env:TEMP+"\_DavTest"
#_#New-Item -ItemType Directory -Force -Path $logpath > $null
#_#$logfile = $logpath +"\"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+".log"
#$logfile = [Microsoft.VisualBasic.Interaction]::InputBox("Specify the logging file", "Log File", $logfile)
$logfile = $logpath +"\_DavTest_"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+"_v"+$ScriptVer+".txt"

$outputverbose = $false

$WebClientTestSrc = @'
    [DllImport("ieframe.dll", CharSet = CharSet.Auto)]
    static extern int IEIsProtectedModeURL(string pszUrl);   
    public static int GetProtectedMode(string url)
    {
        return IEIsProtectedModeURL(url);
    }
    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool InternetSetCookie(string lpszUrl, string lpszCookieName, string lpszCookieData);
    public static bool SetCookieString(string url, string name, string value)
    {
        if (!InternetSetCookie(url, name, value)) { Console.Write( "Failed to set cookie. Error code: {0}. ", Marshal.GetLastWin32Error()); return false; }
        return true;
    }

    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool InternetGetCookieEx(string pchURL, string pchCookieName, System.Text.StringBuilder pchCookieData, ref System.UInt32 pcchCookieData, int dwFlags, IntPtr lpReserved);
    const int ERROR_NO_MORE_ITEMS = 259;
    const int flags = 0x00003000; // INTERNET_COOKIE_NON_SCRIPT  0x00001000, INTERNET_COOKIE_HTTPONLY 0x00002000
    public static string GetCookieString(string url)
    {
        // Determine the size of the cookie      
        UInt32 datasize = 256*1024; int iResult = 0; 
        System.Text.StringBuilder cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
        if (!InternetGetCookieEx(url, null, cookieData, ref datasize, flags, IntPtr.Zero)) {
            iResult = Marshal.GetLastWin32Error(); // Console.Write( "The request returned error {0}. ", iResult);
            if ((ERROR_NO_MORE_ITEMS == iResult) | (datasize < 0)) return null; // Console.Write( "Datasize {0}. ", datasize);
            // Allocate stringbuilder large enough to hold the cookie    
            cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
            if (!InternetGetCookieEx(url, null, cookieData, ref datasize, flags, IntPtr.Zero)) { Console.Write( "GetCookie request returned error {0}. ", iResult);return null;}
        }
        return cookieData.ToString();
    }

// referencing values from https://github.com/libgit2/libgit2/blob/master/deps/winhttp/winhttp.h
    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpOpen( [MarshalAs(UnmanagedType.LPWStr)] string pwszAgent, int   dwAccessType,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszProxy, [MarshalAs(UnmanagedType.LPWStr)] string pwszProxyBypass, int dwFlags );

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpOpenRequest( IntPtr hConnect, [MarshalAs(UnmanagedType.LPWStr)] string pwszVerb, [MarshalAs(UnmanagedType.LPWStr)] string pwszObjectName,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszVersion, [MarshalAs(UnmanagedType.LPWStr)] string pwszReferrer, ref byte[] ppwszAcceptTypes, int dwFlags);

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpConnect(IntPtr hSession, [MarshalAs(UnmanagedType.LPWStr)] string pswzServerName, short nServerPort, int dwReserved);

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool WinHttpSetOption( IntPtr hInternet, int dwOption, byte[] lpBuffer, int dwBufferLength );

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool WinHttpSendRequest( IntPtr hRequest, string pwszHeaders, int dwHeadersLength, string lpOptional, uint dwOptionalLength, uint dwTotalLength, int dwContext );

    [DllImport("winhttp.dll", SetLastError=true)]
    static extern bool WinHttpReceiveResponse(IntPtr hRequest, int lpReserved);

    [DllImport("winhttp.dll", SetLastError=true)]
    static extern bool WinHttpCloseHandle(IntPtr hInternet);

    static int WINHTTP_FLAG_SECURE = 0x00800000;
    static int WINHTTP_OPTION_SECURE_PROTOCOLS = 84;
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_SSL3 = 0x00000020;    // decimal 32
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 = 0x00000080;    // decimal 128
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 = 0x00000200;  // decimal 512
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 = 0x00000800;  // decimal 2048

    static int WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
    //static int WINHTTP_ACCESS_TYPE_NO_PROXY = 1;
    //static int WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;

    static int WINHTTP_OPTION_SECURITY_FLAGS = 31;
    static int SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100;
    static int SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000;
    static int SECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000;
    static int SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE = 0x00000200;
    static int SECURITY_FLAG_IGNORE_ALL = SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    static byte[] WINHTTP_DEFAULT_ACCEPT_TYPES = null;
    static string WINHTTP_NO_ADDITIONAL_HEADERS = null;
    static string WINHTTP_NO_REQUEST_DATA = null;
    static string WINHTTP_NO_REFERER = null;
    static string WINHTTP_NO_PROXY_NAME = null;
    static string WINHTTP_NO_PROXY_BYPASS = null;

    public static int TestSsl(string url, short port, int ssl, bool bIgnoreBadCert)
    {
        int iResult = 0;
        IntPtr hSession = WinHttpOpen("WinHTTP SSL Test", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if( hSession != null ) {
            IntPtr hConnect = WinHttpConnect( hSession, url, port, 0 );
            if( hConnect != null ) {
                IntPtr hRequest = WinHttpOpenRequest( hConnect, "GET", "/", null, WINHTTP_NO_REFERER, ref WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (!WinHttpSetOption( hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, BitConverter.GetBytes(ssl), sizeof(int) )) Console.WriteLine( "Failed to set SSL");
                if ( bIgnoreBadCert ) {
                    if (!WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, BitConverter.GetBytes(SECURITY_FLAG_IGNORE_ALL), sizeof(int) )) Console.WriteLine( "Failed to set Ignore Bad Cert");
                    };
                if (!WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ){
                    iResult = Marshal.GetLastWin32Error();
                    Console.Write( "The request returned error {0}. ", iResult);
                    };
                if( hRequest != null ) WinHttpCloseHandle( hRequest );
                };
            if( hConnect != null ) WinHttpCloseHandle( hConnect );
            if( hSession != null ) WinHttpCloseHandle( hSession );
        };
        return iResult;
    }
'@ 

Add-Type -MemberDefinition $WebClientTestSrc  -Namespace WebClientTest -Name WinAPI 

[System.Management.Automation.PSCredential] $altcreds = $null
$auth_ntlm = $false; $auth_nego = $false; $auth_basic =$false; $auth_oauth = $false; $auth_fba = $false
$dblbar = "======================================================"
$wcshellminver7 = "6.1.7601.22498"; $wcminver7 = "6.1.7601.23542"; $winhttpminver7 = "6.1.7601.23375"
$wcminver8GDR = "6.2.9200.17428"; $wcminver8LDR = "6.2.9200.21538"; $winhttpminver8 = "6.2.9200.21797"
$wcminver81 = "6.3.9600.17923"; $wcrecver10 = "10.0.16299.334"
$newlocation = ""
$persistentcookies = ""
$propfindnodecount = 0

function Test-MsDavConnection {
    [CmdletBinding()] 
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true
            )][uri]$WebAddress 
        )
    begin {
        $ProgressPreference = 'SilentlyContinue'
        if ($PSVersionTable.PSVersion.Major -eq 2){ $osverstring = [environment]::OSVersion.Version.ToString() } 
        else { $osverstring = $(Get-CimInstance Win32_OperatingSystem).Version }
        $osver = [int] ([convert]::ToInt32($osverstring.Split('.')[0], 10) + [convert]::ToInt32($osverstring.Split('.')[1], 10))
        $osname = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        if ($osver -eq 10) { $osname = $osname + " " + (Get-ComputerInfo).WindowsVersion }
        $defaultNPO = ('RDPNP,LanmanWorkstation,webclient')
        $WCfilesize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").FileSizeLimitInBytes 
        $WCattribsize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").FileAttributesLimitInBytes 
        $WCtimeout = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").SendReceiveTimeoutInSec  
        $npo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order").ProviderOrder
        $hnpo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder").ProviderOrder
        $WCBasicauth = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").BasicAuthLevel
        $WCAFSL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").AuthForwardServerList
        if ($WCAFSL.length -eq 0 ) {$WCAFSLOut = "Not configured or empty" } else { $WCAFSLOut = $WCAFSL } 
        $sslprotocols=[string]::Join(" ",([enum]::GetNames([System.Security.Authentication.SslProtocols])|Where-Object{$_ -notmatch 'none|default|ssl2'} ) ) #ssl3|tls|tls11|tls12(|tls13)
        $IgnoreBadCert = $true
        $WCuseragent = "Microsoft-WebDAV-MiniRedir/" + $osverstring
        $fso = New-Object -comobject Scripting.FileSystemObject
        $Webclntdll = $fso.GetFileVersion('C:\Windows\System32\webclnt.dll')
        $Davclntdll = $fso.GetFileVersion('C:\Windows\System32\davclnt.dll')
        $Mrxdavsys = $fso.GetFileVersion('C:\Windows\System32\drivers\mrxdav.sys')
        $Shell32dll = $fso.GetFileVersion('C:\Windows\System32\shell32.dll')
        $WinHttpdll = $fso.GetFileVersion('C:\Windows\System32\winhttp.dll')
        $WebIOdll =  $fso.GetFileVersion('C:\Windows\System32\webio.dll')
        $ProgressPreference = 'Continue'
    }

    process {
        $MsDavConnection = @{
            ClientName=[environment]::MachineName
            ClientOS = $osname
            ClientOSVersion = $osverstring
            ClientWebIO=$WebIOdll
            ClientWinHttp=$WinHttpdll
            ClientShell32=$Shell32dll
            ClientWebclnt=$Webclntdll
            ClientDavclnt=$Davclntdll
            ClientMrxdav=$Mrxdavsys
            ClientNetProviders=$npo
            ServerName=$WebAddress.DnsSafeHost
            ServerPort=$WebAddress.Port
            ServerScheme=$WebAddress.Scheme
            TargetUrl=$WebAddress
            AuthForwardServerList = $WCAFSLOut
            BasicAuthLevel=$WCBasicauth
            FileSizeLimitInBytes = $WCfilesize.ToString("N0")
            FileAttributesLimitInBytes = $WCattribsize.ToString("N0")
            SendReceiveTimeoutInSec = $WCtimeout.ToString("N0")
            Currentuser=$([environment]::UserDomainName + "\" + [environment]::UserName)
            }    

            
            foreach ($i in $MsDavConnection.GetEnumerator()) { Write-ToLogVerbose $($i.Key + " : " + $i.Value).ToString() }
            Write-Host "Microsoft WebClient Service Diagnostic check" -ForegroundColor Yellow -BackgroundColor DarkBlue
            Write-Host ("Client Name =         " + [environment]::MachineName)
            Write-Host ("OS =                  " + $osname)
            Write-Host ("OS version =          " + $osverstring )
            Write-Host "Webclnt.dll version ="$Webclntdll
            Write-Host "Davclnt.dll version ="$Davclntdll
            Write-Host "Mrxdav.sys version = "$Mrxdavsys
            Write-Host "Shell32.dll version ="$Shell32dll
            Write-Host "WinHttp.dll version ="$WinHttpdll
            Write-Host "WebIO.dll version =  "$WebIOdll

            Write-Host
            if ($WebAddress.Host.Length -gt 0) {
                Write-Host "TargetUrl ="$WebAddress
                Write-Host "ServerName ="$WebAddress.DnsSafeHost
                Write-Host "ServerPort ="$WebAddress.Port
                Write-Host "ServerScheme ="$WebAddress.Scheme
                Write-Host
            }
            Write-Host "Network Provider Order =`n`t"$npo
            Write-Host "`nWebClient Parameters:`n`tBasicAuthLevel ="$WCBasicauth
            Write-Host "`tAuthForwardServerList ="$WCAFSL
 

            Write-ToLog ("`n" + $dblbar + "`n")
            

# Fail to Connect
#    1.	WebClient not installed or disabled
        $WCSvc = Get-Service | Where-Object { $_.Name -eq 'webclient' }
        if ($null -ne $WCSvc) 
            { 
                $WCStartNum = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\WebClient").Start 
                switch ($WCStartNum) {
                "2"  { $WCStartType = "Automatic" }
                "3"  { $WCStartType = "Manual" }
                "4"  { $WCStartType = "Disabled" }
                }
                Write-ToLog ("The WebClient service StartUp type is: " + $WCStartType)
                if ( ($WCStartType -ne "Manual" ) -and
                    ($WCStartType -ne "Automatic" ) )
                    { Write-ToLogWarning "WebClient service Start Type should be set to Manual or Automatic." }
                Write-ToLog "Manual is default but Automatic is preferred if the service is used frequently"
            } 
            else
            {
                Write-ToLogWarning "WebClient service is not present"
            }
# File version check
        if ( ($WebAddress.Scheme -eq "https") -and (($osver -eq 7) -or ($osver -eq 8)) ){ # https://support.microsoft.com/en-us/help/3140245
            if ($osver -eq 7) { 
                if ( !((Check-Version $WinHttpdll $winhttpminver7 ) -and (Check-Version $WinHttpdll $winhttpminver7 )) ){ 
                    Write-ToLogWarning ("WinHttp.Dll and WebIO.Dll should be updated to allow highest Secure Protocol versions - https://support.microsoft.com/en-us/help/3140245") 
                    }
                if ( !(Check-Version $Shell32dll $wcshellminver7 ) ){ Write-ToLogWarning ("Shell32.dll should be updated to address a known issue") }
                if ( !((Check-Version $Webclntdll $wcminver7 ) -and (Check-Version $Davclntdll $wcminver7 ) -and (Check-Version $Mrxdavsys $wcminver7 )) ){ 
                    Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                    }
                }
            if ($osver -eq 8) { 
                if ( !((Check-Version $WinHttpdll $winhttpminver8 ) -and (Check-Version $WinHttpdll $winhttpminver8 )) ){ 
                    Write-ToLogWarning ("WinHttp.Dll and WebIO.Dll should be updated to allow highest Secure Protocol versions - https://support.microsoft.com/en-us/help/3140245") 
                    }
                if ( [convert]::ToInt32($Webclntdll.Split('.')[0], 10) -lt 20000 ) {
                    if ( !((Check-Version $Webclntdll $wcminver8GDR ) -and (Check-Version $Davclntdll $wcminver8GDR )) ){ 
                        Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                        }
                    } 
                    else {
                        if ( !((Check-Version $Webclntdll $wcminver8LDR ) -and (Check-Version $Davclntdll $wcminver8LDR )) ){ 
                            Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                        }
                    }
                }
            if ($osver -eq 9) { 
                if ( !((Check-Version $Webclntdll $wcminver81 ) -and (Check-Version $Davclntdll $wcminver81 )) ){ 
                            Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                    }
                }
    
            }

        if (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" | Select-Object -ExpandProperty DefaultSecureProtocols -ErrorAction SilentlyContinue | Out-Null){
            $dsp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols 
            if ($osver -eq 10) {
                if ($null -ne $dsp ) {Write-ToLogWarning "WinHttp registry entry is: " + $dsp.ToString('x2').ToUpper() }
            } else {
                if ($null -eq $dsp ) {Write-ToLogWarning "WinHttp registry entry is absent" } else { Write-ToLog ("WinHttp registry entry is: " + $dsp.ToString('x2').ToUpper() ) }
            }
        }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            if (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"){
                if (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" | Select-Object -ExpandProperty DefaultSecureProtocols -ErrorAction SilentlyContinue | Out-Null){
                    $dspwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols
                }
            }
            if ($osver -eq 10) {
                if ($null -ne $dspwow ) {Write-ToLogWarning "WinHttp WOW6432 registry entry is: " + $dspwow.ToString('x2').ToUpper() }
            } else {
                if ($null -eq $dspwow ) {Write-ToLogWarning "WinHttp WOW6432 registry entry is absent" } else { Write-ToLog ("WinHttp WOW6432 registry entry is: " + $dspwow.ToString('x2').ToUpper() ) }
            }
        }  
        
                                   
        $strongcrypt = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
        if ($null -eq $strongcrypt ) {Write-ToLogVerbose "SchUseStrongCrypto registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto registry entry for v4 is: " + $strongcrypt) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $strongcryptwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
            if ($null -eq $strongcryptwow ) {Write-ToLogVerbose "SchUseStrongCrypto WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto WOW6432 registry entry for v4 is: " + $strongcryptwow) }
        }     
           
        $strongcrypt2 = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727").SchUseStrongCrypto
        if ($null -eq $strongcrypt2 ) {Write-ToLogVerbose "SchUseStrongCrypto registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto registry entry for v2 is: " + $strongcrypt2) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $strongcryptwow2 = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727").SchUseStrongCrypto
            if ($null -eq $strongcryptwow2 ) {Write-ToLogVerbose "SchUseStrongCrypto WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto WOW6432 registry entry for v2 is: " + $strongcryptwow2) }
        }        
              
        $sysdeftlsver = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727").SystemDefaultTlsVersions
        if ($null -eq $sysdeftlsver ) {Write-ToLogVerbose "SystemDefaultTlsVersions registry entry is absent" } else { Write-ToLogVerbose ("SystemDefaultTlsVersions registry entry is: " + $sysdeftlsver) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $sysdeftlsverwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727").SystemDefaultTlsVersions
            if ($null -eq $sysdeftlsverwow ) {Write-ToLogVerbose "SystemDefaultTlsVersions WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SystemDefaultTlsVersions WOW6432 registry entry is: " + $sysdeftlsverwow) }
        }          

        Write-ToLog ("Client Secure Protocols enabled for .Net: " + $sslprotocols.ToUpper() ) 
      
#    2.	Bad Network Provider order
#       a.	WebClient missing from provider order
        $npomsg = "`r`nNetwork Provider Order check: "
        $npocheck = 'Good'
        if ($npo.ToLower() -ne $hnpo.ToLower()) { 
            $npocheck = 'HwOrder doesn''t match Order' 
            Write-ToLogWarning ($npocheck +"`r`n`tOrder: " + $npo + "`r`n`tHwOrder: " + $hnpo)
            }
        if ( !("," + $hnpo +",").ToLower().Contains(",webclient,") -or !("," + $npo +",").ToLower().Contains(",webclient,") ) {
            $npocheck = 'WebClient is missing from provider list' 
            Write-ToLogWarning ($npomsg + $npocheck + "`r`n`tOrder: " + $npo )
            }
#       b.	Third-party providers interfering
        if ( ($npocheck -eq "Good") -and ($npo.ToLower() -ne $defaultnpo.ToLower()) ) { 
            $npocheck = 'Order doesn''t match Default' 
            Write-ToLog ($npomsg + $npocheck + "`r`n`tOrder: " + $npo + "`r`n`tDefault order: $defaultnpo")
            }
        if ( $npocheck -eq "Good") { Write-ToLog ($npomsg + $npocheck) }


        if ($WebAddress.Host.Length -eq 0) {Start-Process ($env:windir + "\explorer.exe")  -ArgumentList $((Get-ChildItem $logfile).DirectoryName) ;Exit}
#==========================================================================
#    Only test below if WebAddress is passed

        $rootweb = $WebAddress.Scheme + "://" + $WebAddress.DnsSafeHost; $matchfound = $false
            
#    3.	Port blocked
        $starttime = Get-Date
        # New-Object System.Net.Sockets.TcpClient($WebAddress.DnsSafeHost,$WebAddress.Port)
        $ns = New-Object System.Net.Sockets.TcpClient
        try { $ns.Connect($WebAddress.DnsSafeHost, $WebAddress.Port ) } catch {}
        $rtt = (New-TimeSpan $starttime $(Get-Date) ).Milliseconds
        if( $ns.Connected) {$testconnection = $true; $ns.Close()}
        $davport = $davport + "Connection to " + $WebAddress.DnsSafeHost + " on port " + $WebAddress.Port + " was " 
        if ($testconnection -eq $true ) { $davport = $davport + "successful and took " + $rtt + " milliseconds" }
        else { $davport = $davport + "not successful"; $rtt=0}
        Write-ToLog $davport

# Internet Settings Security Zone information
# https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
        $IEZone = [System.Security.Policy.Zone]::CreateFromUrl($WebAddress).SecurityZone
        $IEPMode = [WebClientTest.WinAPI]::GetProtectedMode($WebAddress)
        if ( $IEPMode -eq 0 ) {$ProtectMode = "Enabled"}
        elseif ( $IEPMode -eq 1 ) {$ProtectMode = "Not Enabled"}
        else {$ProtectMode = "Unknown"}

        Write-ToLog ("$WebAddress is in the $IEZone Security Zone and Protect Mode value is " + $ProtectMode + "`r`n")

        $internettestzone = "http://doesntexist.edbarnes.net"
        if([System.Security.Policy.Zone]::CreateFromUrl($internettestzone).SecurityZone -eq "Internet"){
            if ( [WebClientTest.WinAPI]::GetProtectedMode($internettestzone) -ne 0 ) {
            Write-ToLogWarning ("The Internet Security Zone is not enabled for Protect Mode. This is a security risk!`r`n") }
        }
        
        $ActiveXCheck = $(Get-Item -Path ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)).GetValue('2000')
        if ( $ActiveXCheck -eq 0 ) {$ActiveXEnabled = "Enabled"}
        elseif ( $ActiveXCheck -eq 1 ) {$ActiveXEnabled = "Prompt"}
        elseif ( $ActiveXCheck -eq 3 ) {$ActiveXEnabled = "Disabled"}
        else {$ActiveXEnabled = "Unknown"}
        Write-ToLogVerbose ("Checking if ActiveX is enabled. Value identified: " + $ActiveXEnabled)

        if ((Test-Path ("HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)) -eq $false){
            Write-ToLogVerbose ("No ActiveX Policy found`n")
            }
            else {
            $ActiveXPolicyCheck = $(Get-Item -Path ("HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)).GetValue('2000')
            if ( $ActiveXPolicyCheck -eq 0 ) {$ActiveXPolicyEnabled = "Enabled"}
            elseif ( $ActiveXPolicyCheck -eq 1 ) {$ActiveXPolicyEnabled = "Prompt"}
            elseif ( $ActiveXPolicyCheck -eq 3 ) {$ActiveXPolicyEnabled = "Disabled"}
            else {$ActiveXPolicyCheck = "Unknown"}
            Write-ToLogVerbose ("Checking if ActiveX Policy is enabled. Value identified: " + $ActiveXPolicyEnabled +"`n")
            }
      
#    3.	Version of SSL/TLS not supported by destination server
        if ( ($testconnection -eq $true) -and ($WebAddress.Scheme -eq "https") ) {
            $ServerProtocolsAccepted = $null; [int] $iBestSsl = 0;
            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 32, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports SSL3"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " SSL3" ; $iBestSsl = 32 ; $sBestSsl = "SSL3" } 
            else { Write-ToLog "The server does not support SSL3" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 128, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.0"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS1" ; $iBestSsl = 128 ; $sBestSsl = "TLS1" } 
            else { Write-ToLog "The server does not support TLS 1.0" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 512, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.1"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS11" ; $iBestSsl = 512 ; $sBestSsl = "TLS11" } 
            else { Write-ToLog "The server does not support TLS 1.1" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 2048, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.2"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS12" ; $iBestSsl = 2048 ; $sBestSsl = "TLS12" } 
            else { Write-ToLog "The server does not support TLS 1.2" }

            if ($null -eq $ServerProtocolsAccepted) {Write-ToLog "No attempted protocols succeeded"}
            else {$ServerProtocolsAccepted = $ServerProtocolsAccepted.Substring(1); Write-ToLog ( "Server supports: " + $ServerProtocolsAccepted.ToUpper() ) }


#    4.	Certificate is expired or doesn't match
            $certcheck = [WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, $iBestSsl, $false )
            if ($certcheck -eq 0 ) 
                { Write-ToLogVerbose "No certificate problem observed"} 
            else { 
                switch ($certcheck ) {
                    "12037"  { Write-ToLog "Certificate Error Invalid Date" }
                    "12038"  { Write-ToLog "Certificate Error Invalid Common Name" }
                    "12044"  { Write-ToLog "Client Authentication Certificate Needed" }
                    "12045"  { Write-ToLog "Certificate CA is Invalid" }
                    "12169"  { Write-ToLog "Invalid Certificate" }      
                    "12179"  { Write-ToLog "Invalid Usage for Certificate" }  
                    default  { Write-ToLog "Certificate failure: $certcheck`r`n"}                 
                    }
                }
            Test-SslCert $WebAddress.DnsSafeHost $WebAddress.Port $sBestSsl
            # Optional ToDo - Check cert chain
            }


#    5.	Bad proxy settings
            Write-ToLogVerbose "TODO: Check proxy config"
#        a.	Proxy misdirection
#        b.	Proxy authentication require
#        [net.httpwebRequest]::GetSystemWebProxy
#
# Failure after connect
#    1.	Failing Authentication
        if ( $testconnection ) {
            Write-ToLog ("`n`n" + $dblbar + "`r`n** Determining authentication mode **")
            $global:newlocation = $WebAddress
            $verb = "HEAD"
            $followredirect = $false
            $addcookies = $false
            $credtype = "Anonymous" # 3 choices = "Anonymous", "DefaultCreds", "AlternateCreds"
            $maxtry = 5
            do {
                $responseresult = SendWebRequest -url $global:newlocation -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
                Write-ToLogVerbose ("Result: $responseresult `r`n")
                switch ($responseresult ) {
                    "SwitchToGET" { $verb = "GET" }
                    "AddCookies"  { $addcookies = $true }
                    "AddFollow302"{ $followredirect = $true }            
                    "AddDefCreds" { $credtype = "DefaultCreds" }
                    "AddAltCreds" { $credtype = "AlternateCreds" }
                    "AuthBasic"   { $authbasic = $true }
                    "AuthWinNego" { $authnego = $true }
                    "AuthWinNTLM" { $authntlm = $true }
                    "AuthFBA"     { $addcookies = $true }
                }
                $maxtry = $maxtry - 1
            } while ( ( $responseresult -notlike "Complete*"  ) -and ($maxtry -gt 0 ) )

            }

#        a.	NTLM or Kerberos - AuthForwardServerList
            if (($global:auth_ntlm -or $global:auth_nego) -and ($rootweb.Contains("."))) { 
            Write-ToLog ("`n`n" + $dblbar + "`r`nWindows Authentication accepted with FQDN url : Testing AuthForwardServerList")
                # Validate target url against AuthForwardServerList
                if ($WCAFSL.length -eq 0 ) {Write-ToLogWarning ("AuthForwardServerList registry value is not configured or empty") }
                    else { 
                        $WCAFSL | ForEach-Object -Process {
                                     if ( $rootweb -like $_ ) {
                                        $matchfound = $true
                                        Write-ToLog ("The path $rootweb was matched to " + $_ )
                                        }
                                     }
                        if ( $matchfound -eq $false ) { Write-ToLogWarning ("The path $rootweb was not matched in AuthForwardServerList.") }
                }
                Write-ToLog ($dblbar + "`r`n`n")
            }
#        b.	Basic - not over SSL
            if ($global:auth_basic) { 
                Write-ToLog ("`n`n" + $dblbar + "`r`nBasic Authentication accepted : Testing BasicAuthLevel`r`n")                
                switch ($WCBasicauth) {
                "0"  {Write-ToLogWarning ("BasicAuthLevel is 0; use of Basic Authentication is disabled" ) }
                "1"  {
                        if ($WebAddress.Scheme -eq "http") {
                            Write-ToLogWarning ("BasicAuthLevel is 1; use of Basic Authentication over HTTP is disabled" ) }
                            else { Write-ToLog ("BasicAuthLevel is 1; use of Basic Authentication over HTTPS is enabled" ) }
                        }
                "2"  {Write-ToLogWarning ("BasicAuthLevel is 2; use of Basic Authentication is enabled for both HTTP and HTTPS - This could be a security risk" ) }
                }
                Write-ToLog ("Note: If Basic Authentication is allowed and used, there will always be a credential prompt`r`n" + $dblbar + "`r`n") 
            }

#        c.	Claims/FBA - No persistent cookie passed
            if ($global:auth_fba) { 
                Write-ToLog ("`n`n" + $dblbar + "`r`nFBA or SAML Claims Authentication accepted : Testing Persistent cookies`r`n") 
                Write-ToLog ("This authentication mode requires a persistent, sharable authentication cookie be available") 
#            i.	Cookie not created persistent
#            ii.	Cookie not stored in shareable location
                if ( $IEPMode -eq 0 ) {Write-ToLogWarning ("Protect Mode is enabled for the $IEZone Security Zone so Persistent cookies cannot be shared.")}
                elseif ( $IEPMode -eq 1 )  {Write-ToLog ("Protect Mode is not enabled for the $IEZone Security Zone so Persistent cookies can be shared.")}
                $global:persistentcookies = [WebClientTest.WinAPI]::GetCookieString($WebAddress) 
                if ($global:persistentcookies.length ) {
                    Write-ToLog ("`r`nPersistent Cookies:`n===================")
                    $global:persistentcookies.split("; ") | ForEach-Object{ 
                         $cookie = $_
                         #if ($cookie.Length -gt 7){ if ($cookie.Substring(0,7) -eq "FedAuth") {$fedauth = $cookie.Substring(8)}  }
                         Write-ToLog "`t$cookie"
                    }
                } else { Write-ToLog "`tNo persistent cookies found" }
                Write-ToLog ( $dblbar + "`r`n")
            }

#    2.	OPTIONS and/or PROPFIND verb blocked
        if ( $testconnection ) {
            Write-ToLog ("`n`n" + $dblbar + "`r`n** Check if OPTIONS or PROPFIND are blocked **")
            $verb = "OPTIONS"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
            $verb = "PROPFIND"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
#    3.	PROPFIND returns bad results
#        a.	XML missing
#        b.	XML malformed/gzipped
#        Checked on every PROPFIND response    
#    4.	Custom header name with space 
#        Checked each time headers are read  
#    5.	Root site access
#        a.	No DAV at root
#        b.	No permissions at root
#        c.	Root site missing 
            if ($rootweb -ne $WebAddress ){
                Write-ToLog ("`n`r`n" + $dblbar + "`r`n** Checking root site access **")
                $verb = "PROPFIND"
                $responseresult = SendWebRequest -url $rootweb -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
            }
        }


#
# Performance
            Write-ToLog ("`r`n" + $dblbar + "`r`n** Performance considerations **")
#    1.	Slow to browse
            $verb = "PROPFIND"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect -usecreds $credtype -depth 1
            Write-ToLog "Check browsing performance scenarios (by testing number of discovered items)"

#        a.	Read-Only Win32 attribute on SharePoint folders can cause unnecessary PROPFIND on contents.
#        b.	Too many items in the destination folder will result in slow response in Windows Explorer (may appear empty)
            Write-ToLog "`tNumber of items queried: $global:propfindnodecount `r`n"
            if ($global:propfindnodecount -gt 1000) {
                Write-ToLogWarning ("`tA high number of items in the folder have been detected")
                if (($global:propfindnodecount*1000) -gt $WCattribsize){Write-ToLogWarning ("`tIncrease the FileAttributesLimitInBytes value. See KB 912152")}
            Write-ToLog ("Current setting of FileAttributesLimitInBytes is: " + $WCattribsize.ToString("N0") + " bytes`r`n")
            }

#    2.	Uploads fail to complete or are very slow
#        a.	PUT requests are blocked
            # TODO Test PUT
#        b.	File exceeds file size limit
            Write-ToLog ("Current setting of FileSizeLimitInBytes is: " + $WCfilesize.ToString("N0") + " bytes")
#        c.	Upload takes longer than the Timeout setting
            Write-ToLog ("`tUpload throughput is limited to approximately (Filesize / 8kb * RTT)" )
            if ($rtt -gt 0 ) {
                Write-ToLog ("`tCurrent Round Trip Time estimate is: " + $rtt + " milliseconds")
                $WCesttimeupload = ($WCfilesize / 8192 * $rtt)
                Write-ToLog ("`tEstimated time needed to upload a max file size of " +  $WCfilesize.ToString("N0") + " bytes: " + ($WCesttimeupload/1000).ToString("N0") + " seconds" )
            }
            else { Write-ToLog "`tUnable to determine RTT. Consider using PsPing from SysInternals to find the RTT" }

            Write-ToLog ("The current client setting for SendReceiveTimeoutInSec is: " + $WCtimeout )
#        d.	Number of file causes total attribute to exceeds attribute size limit
#        	See 2b below

#    3.	Slow to connect
#        a.	The WebClient service was not already started
          if ($WCStartType -ne "Automatic") { Write-ToLog "For best performance, set the StartUp Type to 'Automatic'" }
#        b.	SMB attempts receive no response before falling through to WebClient
            Write-ToLog "`nTesting SMB and SMB2 connectivity - using UNC will try SMB before using WebDAV and can cause a delay if blocked improperly"

            # New-Object System.Net.Sockets.TcpClient($WebAddress.DnsSafeHost,$WebAddress.Port)
            $ns = New-Object system.net.sockets.tcpclient

			$starttime = Get-Date
            try { $ns.Connect($WebAddress.DnsSafeHost, 139 ) } catch {}
            $smbresponsetime = (New-TimeSpan $starttime $(Get-Date) ).Seconds
            $ns.Close()

            $smb = "`tSMB test connection took " + $smbresponsetime + " seconds"
			if ($smbresponsetime -gt 30) {Write-ToLogWarning ($smb) }
            else { Write-ToLog ($smb) }

            $ns2 = New-Object system.net.sockets.tcpclient
			$starttime2 = Get-Date
            try { $ns2.Connect($WebAddress.DnsSafeHost, 445 ) } catch {}
            $smb2responsetime = (New-TimeSpan $starttime2 $(Get-Date) ).Seconds
            $ns2.Close()

            $smb2 = "`tSMB2 test connection took " + $smb2responsetime + " seconds"
			if ($smb2responsetime -gt 30) {Write-ToLogWarning ($smb2) }
            else { Write-ToLog ($smb2) }


#        c.	Auto-detect proxy unnecessarily selected
            Write-ToLogVerbose "`nTODO: Auto-detect proxy`n"

#        return New-Object PsObject -Property $MsDavConnection
     }

}


function SendWebRequest([uri] $url, [string] $verb, [string] $useragent, $includecookies = $false, $follow302=$true, [SecureString] $usecreds, $depth=0)
{
    if ($depth){$depthnotice = " with Depth of 1"} else { $depthnotice = ""}
    Write-ToLog ($dblbar + "`r`n`r`n" + $verb + " test to $url" + $depthnotice)
    Write-ToLogVerbose ("`tUserAgent: " + $useragent + " Cookies:" + $includecookies + " Follow302:" + $follow302 + " CredType:" + $usecreds)

    [net.httpWebRequest] $req = [net.webRequest]::Create($url)

    $req.CookieContainer = New-Object System.Net.CookieContainer
    if ( $includecookies -eq $true ) {
        $gcresult = [WebClientTest.WinAPI]::GetCookieString($url); 
        if ($gcresult.Length ){ 
            $cookiesread = $gcresult.Split(";")
            $cookiesread | ForEach-Object { $req.CookieContainer.SetCookies($url,$_.Trim()) }
        }
    }

    switch ($usecreds) 
    { 
        "Anonymous" {$req.Credentials = $null }
        "DefaultCreds" {$req.UseDefaultCredentials = $true }
        "AlternateCreds" {
            if ($null -eq $global:altcreds){$global:altcreds = Get-Credential }

            $req.Credentials = $global:altcreds
            }
    }

	$req.AllowAutoRedirect = $follow302
	$req.Method = $verb
    if ( $useragent -ne $null ) {$req.UserAgent = $useragent}
    if ( $req.Method -eq "PROPFIND" ) { $req.Headers["Depth"] = $depth }

	#Get Response
	try {
		[net.httpWebResponse]$res = $req.GetResponse()
	}
	catch {
        if ( ($Error[0].Exception.InnerException).Status -eq 'ProtocolError' ) {
            [net.httpWebResponse]$res = $Error[0].Exception.InnerException.Response
        }
        else {
            $res = $null
            Write-ToLogWarning ( ($Error[0].Exception.InnerException).status)
        }
    }

    Write-ToLogVerbose ("Request Headers:")
    foreach ($h in $req.Headers) { Write-ToLogVerbose ("`t" + $h + ": " + $req.Headers.GetValues($h)) }

    if ($null -ne $res)
    {
        Write-ToLog ("`tResponse Status Code: " + $res.StatusCode.value__ + " " + $res.StatusCode)
        Write-ToLogVerbose ("`tResponse Cookies: " + $res.Cookies.Count)
        foreach ($c in $res.Cookies) { Write-ToLogVerbose ("`t`t" + $c.Name + " " + $c.Value) }

        Write-ToLogVerbose ("`tResponse Headers: " + $res.Headers.Count)
        foreach ($h in $res.Headers)
        {
            
            switch -Wildcard($h){
                "WWW-Authenticate" { 
                    Write-ToLogVerbose ("`t`t" + $h )
                    foreach ($a in $res.Headers.GetValues($h)) {
                        Write-ToLogVerbose "`t`t`t"$a
                        if ($a -like "NTLM*") { $global:auth_ntlm = $true }
                        if ($a -like "Nego*") { $global:auth_nego = $true }
                        if ($a -like "Basic*") { $global:auth_basic = $true }
                        # WWW-Authenticate: IDCRL Type="BPOSIDCRL", EndPoint="/sites/Classic/_vti_bin/idcrl.svc/", RootDomain="sharepoint.com", Policy="MBI"
                        if ($a -like "IDCRL*") { $global:auth_oauth = $true }
                        }
                    Break
                    }
                "MicrosoftSharePointTeamServices" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Set-Cookie" { 
                    Write-ToLogVerbose ("`t`t" + $h)
                    foreach ($c in $res.Headers.GetValues($h)) {
                        Write-ToLogVerbose ("`t`t`t" + $c)
                        }
                    Break
                    }
                "Allow" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Date" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Location" { $newlocation = $res.Headers.GetValues($h) ;Write-ToLogVerbose ("`t`t" + $h + ":`t" + $newlocation) ; Break }
                "Content-Type" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Content-Encoding" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "request-id" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                # X-MSDAVEXT_Error: 917656; Access+denied.+Before+opening+files+in+this+location%2c+you+must+first+browse+to+the+web+site+and+select+the+option+to+login+automatically.
                "X-MSDAVEXT_Error" { 
                    $global:auth_fba = $true ; 
                    if ($includecookies){
                        Write-ToLogWarning ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h))
                    }
                        Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h))
                    Break 
                    }
                "X-FORMS_BASED_AUTH_REQUIRED" { $global:auth_fba = $true ; Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "FORMS_BASED_AUTH_RETURN_URL" { $global:auth_fba = $true ; Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "*" { Write-ToLogVerbose ("`t`t? " + $h + ": " + $res.Headers.GetValues($h))}
            }
        }
        $statcode = $res.StatusCode.value__ 
        if ( ($verb -eq "PROPFIND") -and (($statcode -eq 200) -or ($statcode -eq 207) ) ) { ReturnBody($res) }

        $res.Close()
    } 

    #Set StatusCheck
    $statuscheck = $null
    if ($statcode -eq 404 ) {
        if ($verb = "HEAD") {$statuscheck = "SwitchToGET" }
        else {$statuscheck = "Complete-404" }
    }
    elseif ($statcode -eq 403 ) {
        if ($includecookies -eq $false ) {$statuscheck = "AddCookies" }
        else {$statuscheck = "Complete-403" }
    }
    elseif ($statcode -eq 401 ) {
        if ($usecreds -eq "Anonymous") {$statuscheck = "AddDefCreds" }
        elseif ($usecreds -eq "DefaultCreds") {$statuscheck = "AddAltCreds" }
        else {$statuscheck = "Complete-401" }
    }
    elseif ($statcode -eq 302 ) { 
        if ($follow302 -eq $false ) {$statuscheck = "AddFollow302" ; Write-ToLog ("Redirected to $newlocation")}
        else {$statuscheck = "Complete-302" }
    }
    elseif ($statcode -eq 200 ) {$statuscheck = "Complete-200" }
    elseif ($statcode -eq 207 ) {$statuscheck = "Complete-207" }
    else {$statuscheck = $("Complete-Unexpected-" + $statcode) }

    return $statuscheck
}


function ReturnBody($response)
{
  if ($response.ContentLength -ge 0) {
        $responsestream = $response.getResponseStream() 
        $streamreader = New-Object IO.StreamReader($responsestream) 
        $body = $streamreader.ReadToEnd() 
        Add-Content $($logpath + "\Response_" + (Get-Date -Format hhmmss) + ".txt")  -Value $body
    }
    # Test if body is valid XML

    # Check for Load or Parse errors when loading the XML file
    $xml = New-Object System.Xml.XmlDocument
    try {
        $xml.LoadXml($body)
        Write-ToLog "`tPROPFIND response is valid XML"
        $nodecnt = $xml.ChildNodes.response.Count - 1
        if ($nodecnt -gt $global:propfindnodecount){
            $global:propfindnodecount = $nodecnt
            Write-ToLogVerbose "`tNumber of items: $nodecnt"
        }
    }
    catch [System.Xml.XmlException] {
        Write-ToLogWarning "PROPFIND response is not valid XML: $($_.toString())"
    }

}

function Check-Version($tval, $bval)
{  $t = $tval.Split("."); $b = $bval.Split(".")
    if ($t[0] -ge $b[0]){
        if ($t[1] -ge $b[1]){
            if ($t[2] -ge $b[2]){
                if ($t[3] -ge $b[3]){ return $true }
            }
        }
    }
    return $false
}

function Test-SslCert {
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true
        )]$destHostName,
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )][int]$destPort,
        [ValidateSet("SSL3", "TLS", "TLS11", "TLS12", IgnoreCase = $true)]
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )]$destProtocol 
    )

    $Callback = { param($sender, $cert, $chain, $errors) return $true }
    $Socket = New-Object System.Net.Sockets.Socket('Internetwork','Stream', 'Tcp')
    $Socket.Connect($destHostName, $destPort)
    try {
        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true, $Callback)
        $SslStream.AuthenticateAsClient($destHostName,  $null, $destProtocol, $false )
        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
        Write-ToLog  ('Cert info - Host name(s): ' + $RemoteCertificate.DnsNameList)
        Write-ToLog  ('Cert info - Not Before: ' + $RemoteCertificate.NotBefore )
        Write-ToLog  ('Cert info - Not After: ' + $RemoteCertificate.NotAfter )
        Write-ToLog  ('Cert info - Subject: ' + $RemoteCertificate.GetNameInfo(3,$false) )
        #Write-ToLog  ('Cert info - Distinguished Name: ' + $RemoteCertificate.SubjectName.Name )
        Write-ToLog  ('Cert info - Issuer: ' + $RemoteCertificate.GetNameInfo(3,$true) )
        Write-ToLog  ('Cert info - Issuer Distinguished Name: ' + $RemoteCertificate.IssuerName.Name )
        Write-ToLog  ('Cert info - Usage: ' + $RemoteCertificate.EnhancedKeyUsageList )
    } 
    catch {
        $_.Exception
    }
    finally {
        $SslStream.Close()
        $NetStream.Close()
    }
    
}

function Write-ToLog()
{   param( $msg = "`n" )
    Write-Host $msg
    Add-Content $logfile -Value $msg
}
function Write-ToLogVerbose()
{   param( $msg = "`n" )
    if ($global:outputverbose ) { Write-Verbose $msg}
    Add-Content $logfile -Value ("VERBOSE:`t"+$msg)
}
function Write-ToLogWarning()
{   param( $msg = " `n" )
    if ($msg) {	#_#
		Write-Warning $msg
		Add-Content $logfile -Value ($global:dblbar)
		Add-Content $logfile -Value ("WARNING:`n`t"+$msg)
		Add-Content $logfile -Value ($global:dblbar)
	}
}

#_# cls

if ($outputverbose) {
    Test-MsDavConnection -WebAddress $testurl -Verbose }
else { Test-MsDavConnection -WebAddress $testurl }


# SIG # Begin signature block
# MIInngYJKoZIhvcNAQcCoIInjzCCJ4sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBc+fufQ6aWHPz1
# CwSE+9YB7woyFl5qfH2MK/QXg9wiVaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZczCCGW8CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgZcs1PwQt
# IZFlPcAMdUDnyApXFPFM53gabE6ZXQeuZoQwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAlM7izNyWMai1I36j0t6fo2s5/QnAXdBhW9SJF8eOw
# ISZEjOei+HIzTx6SaSnkyW3RjvysoX93Keg04tGDqaviDdwYdhi8Z1XCznjf879g
# 42qgbCSH9DAjCyLujvsyDzZdDU+tea0QwSg6ALZIDIALO66otnIGnDmH601VfZ9z
# cstfhgmPqQBlA+06duAFVf5IVL4RBHi0iqcOM/8YMY6JldfjDztXBgP/Tdnue56Q
# 2jy+zjuyAAXX6Cbui52AtgYqNroex5odX/ku1ovH+3J9LT3SeYBzhd/JNgDW0GE3
# l4nxpJt+iL7nD+VFma7SZZNR1J/kPBNNFY4lyCW+C2s1oYIW/TCCFvkGCisGAQQB
# gjcDAwExghbpMIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIGyiurTSz7AnQZIU0uNAFXddoinhLGYiX9BnrUYy
# 58RMAgZi1+wMJz4YEzIwMjIwODE2MDkyMDEyLjgxNVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjQ5QkMtRTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQICEzMAAAGXA89ZnGuJeD8AAQAAAZcw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjExMjAyMTkwNTE0WhcNMjMwMjI4MTkwNTE0WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIz
# M0MxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDtAErqSkFN8/Ce/csrHVWcv1iSjNTA
# rPKEMqKPUTpYJX8TBZl88LNrpw4bEpPimO+Etcli5RBoZEieo+SzYUnb0+nKEWaE
# Ygubgp+HTFZiD85Lld7mk2Xg91KMDE2yMeOIH2DHpTsn5p0Lf0CDlfPE5HOwpP5/
# vsUxNeDWMW6zsSuKU69aL7Ocyk36VMyCKjHNML67VmZMJBO7bX1vYVShOvQqZUkx
# CpCR3szmxHT09s6nhwLeNCz7nMnU7PEiNGVxSYu+V0ETppFpK7THcGYAMa3SYZjQ
# xGyDOc7J20kEud6tz5ArSRzG47qscDfPYqv1+akex81w395E+1kc4uukfn0CeKtA
# Dum7PqRrbRMD7wyFnX2FvyaytGj0uaKuMXFJsZ+wfdk0RsuPeWHtVz4MRCEwfYr1
# c+JTkmS3n/pvHr/b853do28LoPHezk3dSxbniQojW3BTYJLmrUei/n4BHK5mTT8N
# uxG6zoP3t8HVmhCW//i2sFwxVHPsyQ6sdrxs/hapsPR5sti2ITG/Hge4SeH7Sne9
# 42OHeA/T7sOSJXAhhx9VyUiEUUax+dKIV7Gu67rjq5SVr5VNS4bduOpLsWEjeGHp
# Mei//3xd8dxZ42G/EDkr5+L7UFxIuBAq+r8diP/D8yR/du7vc4RGKw1ppxpo4JH9
# MnYfd+zUDuUgcQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG3PAc8o6zBullUL0bG+
# 3X69FQBgMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
# BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQELBQADggIBAARI2GHSJO0zHnshct+Hgu4dsPU0b0yUsDXBhAdAGdH1T+uD
# eq3c3Hp7v5C4QowSEqp0t/eDlFHhH+hkvm8QlVZR8hIf+hJZ3OqtKGpyZPg7HNzY
# IGzRS2fKilUObhbYK6ajeq7KRg+kGgZ16Ku8N13XncDCwmQgyCb/yzEkpsgF5Pza
# 2etSeA2Y2jy7uXW4TSGwwCrVuK9Drd9Aiev5Wpgm9hPRb/Q9bukDeqHihw2OJfpn
# x32SPHwvu4E8j8ezGJ8KP/yYVG+lUFg7Ko/tjl2LlkCeNMNIcxk1QU8e36eEVdRw
# eNc9FEcIyqomDgPrdfpvRXRHztD3eKnAYhcEzM4xA0i0k5F6Qe0eUuLduDouemOz
# RoKjn9GUcKM2RIOD7FXuph5rfsv84pM2OqYfek0BrcG8/+sNCIYRi+ABtUcQhDPt
# YxZJixZ5Q8VkjfqYKOBRjpXnfwKRC0PAzwEOIBzL6q47x6nKSI/QffbKrAOHznYF
# 5abV60X4+TD+3xc7dD52IW7saCKqN16aPhV+lGyba1M30ecB7CutvRfBjxATa2nS
# FF03ZvRSJLEyYHiE3IopdVoMs4UJ2Iuex+kPSuM4fyNsQJk5tpZYuf14S8Ov5A1A
# +9Livjsv0BrwuvUevjtXAnkTaAISe9jAhEPOkmExGLQqKNg3jfJPpdIZHg32MIIH
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
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4
# oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
# IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAYUDSsI2YSTTNTXYN
# g0YxTcHWY9GggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOalWZcwIhgPMjAyMjA4MTYwNzQ3MzVaGA8yMDIyMDgx
# NzA3NDczNVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5qVZlwIBADAHAgEAAgIb
# YjAHAgEAAgIRszAKAgUA5qarFwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AHsDECk20cQTqdYL7LlYvf/BX6c5MWpRw011A3sV7bBSTFygldOcip3cqi8Q1RzQ
# ae7LaHUAB2DcbarlpNZLmNzetfvT59Ic4X8I57gvScOtfYKXqSqpmOdm51ZtEDbj
# SU64vv4f2w5XZ0VNivQU3Yrg+zn2g4qGCue9cPy9bOs0MYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGXA89ZnGuJeD8AAQAA
# AZcwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgUYs/ow4t6900z9Ly6A33gfF3XInQLGynwPoFt2MC
# jMUwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBbe9obEJV6OP4EDMVJ8zF8
# dD5vHGSoLDwuQxj9BnimvzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABlwPPWZxriXg/AAEAAAGXMCIEIK/FiJGxRzC+DY/VencMRjAL
# nd4aTCIqoho+tKf4kDQZMA0GCSqGSIb3DQEBCwUABIICADB1wK6RM+S0fBuJ+M7i
# C60900QJx5qvnrek111D6Pfzk17Xq9N9t1QT4pcWMgkOEH3TN93vB7jzVRt37Ij0
# Q5pgLDFjSc3zrgTeRAMvCfnMUSY/ACOQWKdUXebQiPJezj8rkYmdNi2l1nJF2Drw
# abVpjddvlWiy7YBlOOT7A8dyDnHH78VIFAQ6nfG7ySgDTN+5vKJb+QBipVxggwvY
# HdOkN+YtJtdckxn+X9ZhW2Of0y9NQGkMlavIdkkVgal+aPYV9OuT7WbZC08BSItG
# o8fJG1zrc6QMuQJiDUh7om/dRKDlC4lDX/SHPwHa+G7Dmor1IhIZtLR8oT6bQLtT
# uqbpOUOiIr123y2VeE7F0Aave/N1dG5Rijm8c9jT6Y+lLUKoThW7VeeewIt+UaQb
# xkc3ff+0lr3v/OMtSQfNnSFlPAet18nNYHBTEI+FjfasaA7ONLRGMj0EpRZTuyzN
# DM5bKQZIBllZA5wIWDIzKbWv8gpyrRVfkGmE9+PsLD8z2XsK5w64Go/oEC+yTq/T
# foMpwi7SxkaCYfw0j1QROUySK9AzdV+3UQ0/Rr64CAc2j2GocZhxXC6R42uddLeY
# z0q1ZsQ9I3NHcZNbTRrmi9bKNaZPR45KO91wT946IKS0e8WmWKEcViMtgBX15iVa
# lnSW5YT2tZOqny+A7kjE5G9Z
# SIG # End signature block
