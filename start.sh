#!/bin/bash
if [ -n "$1" ]
then
  if [ ! -d $1 ] 
  then
    mkdir $1
  fi
  run_erl -daemon $1 $1 "sudo erl -pa ebin/ deps/epgsql/ebin/ -eval 'application:start(snmp_mon)'"
  exit 0
fi
echo "Usage: ./start.sh /path/to/logs/"
echo "Ex.: ./start.sh /tmp/snmp_mon/"
