USE master
Go
SET NOCOUNT ON   
Go
SELECT GetDate()
Go

--Database Mirroring Endpoint Information
PRINT '==========================='
PRINT 'Database Mirroring Endpoint'
PRINT '==========================='
PRINT ''
select name=cast(name as varchar(30)),
endpoint_id, principal_id, 
protocol_desc=cast(protocol_desc as varchar(20)),
type_desc=cast(type_desc as varchar(30)),
state_desc=cast(state_desc as varchar(20)),
is_admin_endpoint,
role_desc=cast(role_desc as varchar(30)),
is_encryption_enabled,
connection_auth_desc=cast(connection_auth_desc as varchar(30)),
encryption_algorithm_desc=cast(encryption_algorithm_desc as varchar(20))
from sys.database_mirroring_endpoints

PRINT ''


--Availability Group Listeners and IP
PRINT '==================================='
PRINT 'Availability Group Listeners and IP'
PRINT '==================================='
PRINT ''
select l.listener_id,
state_desc=cast(lia.state_desc as varchar(20)),
dns_name=cast(l.dns_name as varchar(30)),
 l.port, l.is_conformant,
ip_configuration_string_from_cluster=cast(l.ip_configuration_string_from_cluster as varchar(40)),
ip_address=cast(lia.ip_address as varchar(30)),
lia.ip_subnet_mask, lia.is_dhcp, 
network_subnet_ip=cast(lia.network_subnet_ip as varchar(30)),
lia.network_subnet_prefix_length,
network_subnet_ipv4_mask=cast(lia.network_subnet_ipv4_mask as varchar(30)),
lia.network_subnet_prefix_length
 from sys.availability_group_listeners l left join
sys.availability_group_listener_ip_addresses lia
on l.listener_id=lia.listener_id

PRINT ''

--AlwaysOn Cluster Information
PRINT '========================'
PRINT 'AlwaysOn Windows Cluster'
PRINT '========================'
PRINT ''
select  cluster_name=cast(c.cluster_name as char(30)), 
quorum_type=cast(c.quorum_type_desc as char(30)), 
quorum_state_desc=cast(c.quorum_state_desc as char(30))
from sys.dm_hadr_cluster c

PRINT ''

-- Implementing changes requested by CMathews as documented in bug 253897
--AlwaysOn Cluster Information
PRINT '================================================'
PRINT 'Windows Cluster Member State, Quorum and Network'
PRINT '================================================'
PRINT ''
select member_name=cast(cm.member_name as varchar(30)), 
member_type_desc=cast(cm.member_type_desc as varchar(30)), 
member_state_desc=cast(cm.member_state_desc as varchar(10)),
cm.number_of_quorum_votes,
(select cast(network_subnet_ip as varchar(40))  from sys.dm_hadr_cluster_networks where member_name=cm.member_name) as 'network_subneet_ip',
(select cast(network_subnet_ipv4_mask as varchar(40))  from sys.dm_hadr_cluster_networks where member_name=cm.member_name) as 'network_subnet_ipv4_mast',
(select network_subnet_prefix_length from sys.dm_hadr_cluster_networks where member_name=cm.member_name) as 'network_subnet_prefix_length',
(select is_public from sys.dm_hadr_cluster_networks where member_name=cm.member_name) as 'is_public',
(select is_ipv4 from sys.dm_hadr_cluster_networks where member_name=cm.member_name) as 'is_ipv4'
from sys.dm_hadr_cluster_members cm 

PRINT ''

--AlwaysOn Availability Group State, Identification and Configuration
PRINT '==================================================================='
PRINT 'AlwaysOn Availability Group State, Identification and Configuration'
PRINT '==================================================================='
PRINT ''
select availability_group=cast(ag.name as varchar(30)), 
primary_replica=cast(ags.primary_replica as varchar(30)),
primary_recovery_health_desc=cast(ags.primary_recovery_health_desc as varchar(30)),
synchronization_health_desc=cast(ags.synchronization_health_desc as varchar(30)),
ag.group_id, ag.resource_id, ag.resource_group_id, ag.failure_condition_level, 
ag.health_check_timeout, 
automated_backup_preference_desc=cast(ag.automated_backup_preference_desc as varchar(10))
from sys.availability_groups ag join sys.dm_hadr_availability_group_states ags
on ag.group_id=ags.group_id

PRINT ''

--AlwaysOn Availability Replica State, Identification and Configuration
PRINT '====================================================================='
PRINT 'AlwaysOn Availability Replica State, Identification and Configuration'
PRINT '====================================================================='
PRINT ''
SELECT 
	group_name=cast(arc.group_name as varchar(30)), 
	replica_server_name=cast(arc.replica_server_name as varchar(30)), 
	node_name=cast(arc.node_name as varchar(30)),
	ars.is_local, 
	role_desc=cast(ars.role_desc as varchar(30)), 
	availability_mode=cast(ar.availability_mode as varchar(30)),
	ar.availability_mode_Desc,
	failover_mode_desc=cast(ar.failover_mode_desc as varchar(30)),
	join_state_desc=cast(arcs.join_state_desc as varchar(30)),
	operational_state_desc=cast(ars.operational_state_desc as varchar(30)), 
	connected_state_desc=cast(ars.connected_state_desc as varchar(30)), 
	recovery_health_desc=cast(ars.recovery_health_desc as varchar(30)), 
	synhcronization_health_desc=cast(ars.synchronization_health_desc as varchar(30)),
	ars.last_connect_error_number, 
	last_connect_error_description=cast(ars.last_connect_error_description as varchar(30)), 
	ars.last_connect_error_timestamp,
	endpoint_url=cast (ar.endpoint_url as varchar(30)),
	ar.session_timeout,
	primary_role_allow_connections_desc=cast(ar.primary_role_allow_connections_desc as varchar(30)),
	secondary_role_allow_connections_desc=cast(ar.secondary_role_allow_connections_desc as varchar(30)),
	ar.create_date,
	ar.modify_date,
	ar.backup_priority, 
	ar.read_only_routing_url,
	arcs.replica_id, 
	arcs.group_id
from sys.dm_hadr_availability_replica_cluster_nodes arc 
join sys.dm_hadr_availability_replica_cluster_states arcs on arc.replica_server_name=arcs.replica_server_name
join sys.dm_hadr_availability_replica_states ars on arcs.replica_id=ars.replica_id
join sys.availability_replicas ar on ars.replica_id=ar.replica_id
join sys.availability_groups ag 
on ag.group_id = arcs.group_id 
and ag.name = arc.group_name 
--dm_hadr_availability_replica_cluster_nodes doesn't have a group_id, so we have to join by name
ORDER BY 
cast(arc.group_name as varchar(30)), 
cast(ars.role_desc as varchar(30))

PRINT ''

--AlwaysOn Availability Database Identification, Configuration, State and Performance
PRINT '==================================================================================='
PRINT 'AlwaysOn Availability Database Identification, Configuration, State and Performance'
PRINT '==================================================================================='
PRINT ''
select 
database_name=cast(drcs.database_name as varchar(30)), 
drs.database_id,
drs.group_id,
drs.replica_id,
drs.is_local,
drcs.is_failover_ready,
drcs.is_pending_secondary_suspend,
drcs.is_database_joined,
drs.is_suspended,
drs.is_commit_participant,
suspend_reason_desc=cast(drs.suspend_reason_desc as varchar(30)),
synchronization_state_desc=cast(drs.synchronization_state_desc as varchar(30)),
synchronization_health_desc=cast(drs.synchronization_health_desc as varchar(30)),
database_state_desc=cast(drs.database_state_desc as varchar(30)),
drs.last_sent_lsn,
drs.last_sent_time,
drs.last_received_lsn,
drs.last_received_time,
drs.last_hardened_lsn,
drs.last_hardened_time,
drs.last_redone_lsn,
drs.last_redone_time,
drs.log_send_queue_size,
drs.log_send_rate,
drs.redo_queue_size,
drs.redo_rate,
drs.filestream_send_rate,
drs.end_of_log_lsn,
drs.last_commit_lsn,
drs.last_commit_time,
drs.low_water_mark_for_ghosts,
drs.recovery_lsn,
drs.truncation_lsn,
pr.file_id,
pr.error_type,
pr.page_id,
pr.page_status,
pr.modification_time
from sys.dm_hadr_database_replica_cluster_states drcs join 
sys.dm_hadr_database_replica_states drs on drcs.replica_id=drs.replica_id
and drcs.group_database_id=drs.group_database_id left outer join
sys.dm_hadr_auto_page_repair pr on drs.database_id=pr.database_id 
order by drs.database_id

PRINT ''
PRINT ''

PRINT '-> dm_os_server_diagnostics_log_configurations'
select * from sys.dm_os_server_diagnostics_log_configurations
