ConvertFrom-StringData @'
id_epsconnectingto=Connecting to %Machine%
id_epsconnectingtodesc=Obtaining Operating System information
id_epsconnectingrcperror=Error 0x800706BA - The RPC server is unavailable. One of the possible reasons for this error is when machine does not exist, it is offline or firewall is blocking SMB communications.
id_epsselectnodesobtainingcluster=Obtaining information about cluster service on remote machine
id_epsselectnodesunableservice=Unable to obtain status from cluster service.
id_epsselectnodesnotsupported=The Operating System from %Machine% is %OSName%, which is not supported. Click 'Next' to type the name of a Windows Sever machine with a version of operating system supported
id_machineisnotacluster=This machine is not a cluster node. Please click 'Next' and type a name of a Windows Server that is also a Cluster node
id_epsselectnodesunableobtainnames=Unable to obtain the name of cluster nodes
id_unablequeryregistry=Unable to query registry from %NodeName%. Please check firewall configuration. %ErrorMessage%"
'@
