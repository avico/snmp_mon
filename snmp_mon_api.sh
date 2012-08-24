#!/usr/bin/env escript
%% -*- erlang -*-
%%! -sname snmpmon_kill

main([String]) ->
    {ok, Host} = inet:gethostname(),
    Node = list_to_atom("snmpmon@" ++ Host),
    Cmd = list_to_atom(String),
    case net_adm:ping(Node) of
	pong -> 
	    case Cmd of
		stop -> snmpmon_stop(Node);
		reload_nes -> snmpmon_reload_nes(Node);
		reload_utraps -> snmpmon_reload_utraps(Node);
		_  -> usage()
	    end;
	pang -> io:format("Probably application is not running~n"),
		ok
    end;
main(_) -> 
    usage().


snmpmon_stop(Node) ->
    rpc:call(Node, application, stop, [snmp_mon], 2500),
    timer:sleep(2000),
    rpc:call(Node, init, stop, [], 2500).

snmpmon_reload_nes(Node) ->
    rpc:call(Node, snmp_mon, reload_ne_conf, [], 2500).

snmpmon_reload_utraps(Node) ->
    rpc:call(Node, snmp_mon, reload_utraps, [], 2500).

usage() ->
    io:format("Unknown command~nUsage: snmp_mon_api.sh {stop|reload_nes|reload_utraps}~n").
