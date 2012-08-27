#!/bin/bash

#WD=/home/andrew/prog/erlang/snmp/snmp_mon
WD=`dirname $0`
LOG_DIR=/tmp/snmp_mon/

function usage {
	echo "Usage: sudo ./snmp_mon.sh {start|stop|restart|reload_nes|reload_utraps}"
	echo "reload_nes - reloads etc/ne.conf"
	echo "reload_utraps - reloads etc/unknown_traps.conf"
}

cd $WD
case $1 in
	start) 
		run_erl -daemon $LOG_DIR $LOG_DIR "erl -pa ebin/ deps/epgsql/ebin/ -sname snmpmon -eval 'application:start(snmp_mon)'"
	;;
	stop)
		snmp_mon_api.sh stop
	;;
	restart)
		$0 stop
		sleep 2
		$0 start
	;;
	reload_nes)
		snmp_mon_api.sh reload_nes
	;;
	reload_utraps)
		snmp_mon_api.sh reload_utraps
	;;
	*)
		usage
esac
