#!/bin/bash

WD=/home/andrew/prog/erlang/snmp/snmp_mon
LOG_DIR=/tmp/snmp_mon/

function usage {
	echo "Usage: sudo ./snmp_mon.sh {start|stop|restart}"
}

cd $WD
case $1 in
	start) 
		run_erl -daemon $LOG_DIR $LOG_DIR "erl -pa ebin/ deps/epgsql/ebin/ -sname snmpmon -eval 'application:start(snmp_mon)'"
	;;
	stop)
		stop.sh
	;;
	restart)
		$0 stop
		sleep 2
		$0 start
	;;
	*)
		usage
esac
