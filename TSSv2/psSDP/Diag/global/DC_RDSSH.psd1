ConvertFrom-StringData @'
id_rdsserverprogress=Gathering RDS Information:
id_rdsgetport=Getting RDP-TCP configured port from registry
id_rdslistenport=Connecting to RDP-TCP port.
id_rdslistenporterror=Check if nothing is listening on PortNumber:
id_rdsqwinsta=Getting QWinSta report.
id_rdsrdpcert=Connecting to RDP-TCP listener and getting RDP certificate.
id_rdslicenseserver=Getting configured license server.
id_rdsx509cert=Connecting to RPD-TCP listener and getting RDP certificate.
id_rdslicenseserverconnect=Verifying connectivity to license server:
id_rdslicenseserverconnecterror=Check if there is no connection to a license server
id_rdslicenseserverconnectsolution=Please see is the following configured license server is reachable and working, license server:
id_rdslsconnectinteract=Would you like to to connect to license server to collect licensing information?
id_rdslsconnectinteractdescription=Retrieving the license remotely might take some time. If you are not an administrator on the license server the retrieval will fail.
'@
