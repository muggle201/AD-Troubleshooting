Basic SSL/TLS flow

https://msdn.microsoft.com/en-us/library/windows/desktop/aa380513(v=vs.85).aspx



How SSL/TLS works

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783349(v=ws.10)?redirectedfrom=MSDN



SSL/TLS Errors Codes

https://blogs.msdn.microsoft.com/kaushal/2012/10/05/ssltls-alert-protocol-the-alert-codes/



Troubleshooting PKI Problems on Windows Vista and above

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749296(v=ws.10)?redirectedfrom=MSDN#BKMK_CAPI2Vista



TLS registry settings

https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

 

TLS best practices with the .NET Framework

https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls

Update to enable TLS 1.1 and TLS 1.2 as default secure protocols in WinHTTP in Windows

https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392

SSL/TLS Alert Protocol and the Alert Codes

https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132



 

Alternative:

If the issue takes a significant amount of time to reproduce and it is difficult to stop the logging (happens at random time at night), using this blog can help in stopping the network trace and schannel ETL.

https://blogs.technet.microsoft.com/keithab/2016/10/30/how-to-configure-data-captures-for-intermittentsporadic-schannel-events/

 

 

 

## **Helpful Links**

 

Manage TLS Configuration / Restrict cipher suites

https://docs.microsoft.com/en-us/windows-server/security/tls/manage-tls

https://blogs.technet.microsoft.com/askds/2015/12/08/speaking-in-ciphers-and-other-enigmatic-tonguesupdate/

https://support.microsoft.com/en-us/help/245030/how-to-restrict-the-use-of-certain-cryptographic-algorithms-and-protoc

[https://blogs.msdn.microsoft.com/friis/2016/07/25/disabling-tls-1-0-on-your-windows-2008-r2-server-just-because-you-still-have-one/](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fblogs.msdn.microsoft.com%2Ffriis%2F2016%2F07%2F25%2Fdisabling-tls-1-0-on-your-windows-2008-r2-server-just-because-you-still-have-one%2F&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116379162&sdata=jggGUa%2BTS%2FafyXXeVB5GmtVpi%2FVNZJMb%2BChCrQ%2FHVe8%3D&reserved=0)

[https://gallery.technet.microsoft.com/Get-SChannelConfig-ae4865bd](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fgallery.technet.microsoft.com%2FGet-SChannelConfig-ae4865bd&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116379162&sdata=NHLKQCVjBADiFkYmHgBb2cO8zbH%2F6gyNVOaWhM%2F9SOE%3D&reserved=0)

 

Enabled Protocols / Cipher Suites Per OS

https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/cipher-suites-in-schannel

[https://docs.microsoft.com/en-us/windows/desktop/secauthn/protocols-in-tls-ssl--schannel-ssp](https://docs.microsoft.com/en-us/windows/desktop/secauthn/protocols-in-tls-ssl--schannel-ssp-)-

 

FIPS Mode and Validation

https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation#id0ezd

https://support.microsoft.com/en-us/help/811833/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashi

 

Troubleshooting Schannel Events

[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn786445(v=ws.11)](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fdocs.microsoft.com%2Fen-us%2Fprevious-versions%2Fwindows%2Fit-pro%2Fwindows-server-2012-R2-and-2012%2Fdn786445(v%3Dws.11)&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116419199&sdata=qrK%2BFKgJbF4ZnhZr0oUezuxyWMC%2FVf5ZVGEJTKethYM%3D&reserved=0)

[https://internal.support.services.microsoft.com/en-us/help/2815108](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Finternal.support.services.microsoft.com%2Fen-us%2Fhelp%2F2815108&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116429203&sdata=%2BoalEwfG3YANMMXm2PK%2B4pIl9AJ3zqV2g%2FooNIRt9OM%3D&reserved=0)

[https://blogs.technet.microsoft.com/askds/2018/04/10/tls-handshake-errors-and-connection-timeouts-maybe-its-the-ctl-engine/](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fblogs.technet.microsoft.com%2Faskds%2F2018%2F04%2F10%2Ftls-handshake-errors-and-connection-timeouts-maybe-its-the-ctl-engine%2F&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116439216&sdata=rBCzdmAxvzxKP2%2BKPa9U25BD4CyLr%2F%2FcyyhbYuogHDk%3D&reserved=0)

 

TLS Support for SQL

[https://support.microsoft.com/en-us/help/3135244/tls-1-2-support-for-microsoft-sql-server](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsupport.microsoft.com%2Fen-us%2Fhelp%2F3135244%2Ftls-1-2-support-for-microsoft-sql-server&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116439216&sdata=iC0EtuGDUIfCE1VB895xNt8IpbhH5BZHwlIjpWuuDyM%3D&reserved=0)

[https://blogs.msdn.microsoft.com/sqlreleaseservices/tls-1-2-support-for-sql-server-2008-2008-r2-2012-and-2014/](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fblogs.msdn.microsoft.com%2Fsqlreleaseservices%2Ftls-1-2-support-for-sql-server-2008-2008-r2-2012-and-2014%2F&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116449220&sdata=wfDzD0oG0uBSjYQwFzT4GiHmhy1LJ741veTLQ3aMMvA%3D&reserved=0)

 

TLS Support for .NET

[https://support.microsoft.com/en-us/help/3154519/support-for-tls-system-default-versions-included-in-the-net-framework](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsupport.microsoft.com%2Fen-us%2Fhelp%2F3154519%2Fsupport-for-tls-system-default-versions-included-in-the-net-framework&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116459232&sdata=WWonnZWCUxxtlepgZIrLb0UYprdJIWlh6m%2Bzw%2Baqc5U%3D&reserved=0)

 

TLS Support for WinHTTP

[https://internal.support.services.microsoft.com/en-us/help/4478875](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Finternal.support.services.microsoft.com%2Fen-us%2Fhelp%2F4478875&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116459232&sdata=L0mZKJQqbDW01AIMS0SypXLzTrL6J7ULrHEYmDopVek%3D&reserved=0)

[https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsupport.microsoft.com%2Fen-us%2Fhelp%2F3140245%2Fupdate-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116469236&sdata=sqDDyHigq%2Frdj%2F7FHqqEBVpFgZIU3hSZM59Xz%2FZO8LA%3D&reserved=0)

[https://internal.support.services.microsoft.com/en-us/help/4467770/update-to-enable-tls-1-1-and-tls-1-2-as-secure-protocols-on-winhttp](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Finternal.support.services.microsoft.com%2Fen-us%2Fhelp%2F4467770%2Fupdate-to-enable-tls-1-1-and-tls-1-2-as-secure-protocols-on-winhttp&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116479249&sdata=8Be4U9iT3DRStFJoomVXqrrLf6LjoKCzk7zBuORYvjk%3D&reserved=0)

 

NPS

[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754822(v=ws.10)](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fdocs.microsoft.com%2Fen-us%2Fprevious-versions%2Fwindows%2Fit-pro%2Fwindows-server-2008-R2-and-2008%2Fcc754822(v%3Dws.10)&data=02|01|Nuno.Mendes@microsoft.com|6d261185a44149dcfd9308d6983dee9a|72f988bf86f141af91ab2d7cd011db47|1|0|636863789116479249&sdata=B%2BpCo2FMS8VBm1TnXect78Va7Zmy1qqEAIpjSmxFEa8%3D&reserved=0)

 

 

 

