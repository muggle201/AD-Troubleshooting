ConvertFrom-StringData @'
id_pagedpoold2dsymevent_sd=This Windows Server 2003 may run out of paged pool due to a version of symevent.sys.
id_kerneltagtokekb982010_sd=This machine have high usage of kernel memory pool tag Toke possibly caused by the DisableWindowsUpdateAccess user policy.
id_kerneltagrxm4setikb2647452_sd=Paged pool leak detected in either the RxM4 or SeTI pool tags possibly due to frequently mapping and disconnecting a network drive
id_kerneltagsslckb2585542_sd=This Windows Server 2008 ksecdd driver leaks SslC paged pool 
id_mpio2k3check_st=A MPIO.SYS with version older than 1.23 was detected and this may cause pool memory leak
id_baspnppleakcheck_st=Non paged pool memory leak detected due to Broadcom Advanced Server Program driver
id_aladdindevicedriverscheck_st=Memory leak and Event ID 333 or 2019 due to Aladdin Knowledge Systems Device Drivers
'@
