snmp_mon
================================
snmp_mon is a simple application for monitoring different network
devices (servers, switches, routers...) via SNMP (SNMP Notifications or traps).

Each network element must be configured to send traps to the specified server
(with snmp_mon).


Installation
-------------------------
snmp_mon uses PostgreSQL as database and epgsql as dependency.
PostgreSQL must be installed and configured to listen TCP socket.
For example, for using snmp_mon with web frontend snmpview
(http://github.com./avico/snmpview)
PostgreSQL config file pg_hba.conf can contain such lines:
host    snmp             erl_snmp_user             127.0.0.1/32           password
host    django,snmp            webuser             127.0.0.1/32           password

PostgreSQL also must contain database "snmp" and table "alist" with
read/write permissions for user erl_snmp_user
(for creating table look at sql/create_table.sql).

Clone repository (http://github.com/avico/snmp_mon)
$ git clone git://github.com/avico/snmp_mon
$ cd snmp_mon
$ rebar get-deps
$ rebar compile
Change config files in etc/ and manager/conf  directories.

Configuration
-------------------------
SNMP manager config files:

manager/conf/
|-- agents.conf  
|-- manager.conf  
|-- manager.opts  
|-- users.conf  
`-- usm.conf  

manager.conf contains IP address and port (default 162) for listening traps  
manager.opts contains full path to manager/conf and manager/db directories

Application config files:

etc/  
|-- ne.conf  
`-- unknown_traps.conf  

ne.conf contains list of monitored devices (name, IP, options).
Format:
{TargetId, IpAddress,[{Option,Value},{...}]}.
Example:
{"test_server",[10,1,1,15],[{engine_id,"test_server_engineid"},{community,"public"},{version,v2},{max_message_size,484},{timeout,infinity}]}.

unknown_traps.conf contains OID and symbolic name for traps which mibs
for any reasons not included in mib folder
Format:
{OID, Name}.
Example:
{[1,3,6,1,4,1,9,0,1], tcpConnectionClose}.

Start, manage
-------------------------
$ sudo ./snmp_mon.sh {start|stop} - start or stop application
(run as superuser because privileged port 162 is used)

After changes in etc/ne.conf run  
$ ./snmp_mon.sh reload_nes  
After changes in etc/unknown_traps.conf run  
$ ./snmp_mon.sh reload_utraps  
