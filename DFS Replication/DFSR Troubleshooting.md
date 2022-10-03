# Scope



1. Are all related servers in the same domain or across multiple domains?
2. Does the sync failure issue exist only in one of multiple Replication Groups, or in all Replication Groups?
3. Does the sync failure issue exist in all Replication Folders within the Replication Group, or just some of them?
4. Does the sync issue exist among all servers that host those Replication Folders, or only some of all servers?
5. Did the replication work before?
6. Which direction?
7. Replication slow or replication failure?

### Command 

1. Check replication group and status
```powershell
# RGs,RFs
dfsradmin.exe rg list /attr:rename,rguis
dfsradmin.exe rf list /rgname:"Provide the replication group name" /attr:rfname,rfguid
# Displays the pending updates on issued server
dfsrdiag replicate /member:<FQDN of target computer> /all
```


2. Check replication folder status

```powershell
wmic /namespace:\\root\microsoftdfs path dfsrreplicatedfoolderinfo get replicationgroupname,replicatedfoldername,state
```


3. Check current backlog

```powershell
dfsrdiag backlog /sendingmember: /receivingmember: /rgname: /rfname:
```


4. Confirm binary coder version of dfsrs.exe
   DFSR补丁bug很多


### Capture log

- DFSRinfo
- Network Monitor
- Process Monitor
- TTTrace/dump



# Command

1. Force replication between the replicated members
   Run it on 

   ```power
   dfsrdiag syncnow /partner:receivingmember /rgname:
   
   ```

   Powershell

   ```powershell
   sync-DfsReplicationGroup -GroupName "RG" -SourceComputerName "SRV01" -DestinationComputername "SRV02" -DurationInMinuter 5 -Verbose
   ```

   

2. Replication Group
   ```powershell
   Get-DfsReplicationGroup -GroupName RG01
   Get-DfsRepliactionGroup -GroupName *
   Get-DfsReplicationGroup -GroupName * -IncludeSysvol
   ```

   

3. Backlog
   ```powershell
   Get-DfsrBacklog -DestinationComputerName "SRV01" -SourceComputerName "SRV02" -GroupName "RG01" -FolderName "RF1A"
   
   # Unreplicatd Changes Count
   Get-DfsrBacklog -GroupName "RG" -FolderName "RF" -SourceComputer "SRV01" -DestinatinComputerName "SRV02" -Verbose
   ```

   Identifier

   Attributes

   GlobalVersionSequenceNumber

   UpdateSequenceNumber

   Parented

   FileId

   Volume

   Fence

   Clock

   CreateTime

   **UpdateTime**

   FileHash

   FileName

   **FullPathName**

   Index

   ReplicatedFolderId 

4. ResumeReplication

   ```powershell
   wmic /namespace:\\root\microsoftdfs path dfsrVolumeConfig where volumeGuid=”GUID-NUMBER” call ResumeReplication
   ```

   

5. df