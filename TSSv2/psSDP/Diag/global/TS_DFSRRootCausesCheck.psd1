ConvertFrom-StringData @'
id_dfsrcheckrc=Check for DFSR issues
id_dfsrcheckpaused=Detect if DFSR is currently paused due to dirty shutdown.
id_dfsrcheckpausedinfo=DFSR on the SysVol disk may be paused.  Time of detected 2213 event: 
id_dfsrcheckpausedsd=DFSR may be in a paused state when an Event ID 2213 is logged without a corresponding 2214 anti-event in the DFSR event log.  Consult the article below for more information.  If DFSR's state has since been reset or reinitialized via a method other than the ResumeReplication method, ignore this alert.
'@
