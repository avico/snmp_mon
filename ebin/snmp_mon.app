{application, snmp_mon,
 [{description, "Application for monitoring SNMP elements, based on Erlang SNMP manager"},
  {vsn, "0.1.2"},
  {modules, [db_interface,
  	    snmp_mon,
  	    snmp_mon_app,
  	    snmp_mon_sup]},
  {registered, [snmp_mon_sup]},
  {applications, [kernel, stdlib]},
  {mod, {snmp_mon_app, []}}
]}.