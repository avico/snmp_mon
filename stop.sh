#!/usr/bin/env escript
%% -*- erlang -*-
%%! -sname snmpmon_kill

main(_) ->
    {ok, Host} = inet:gethostname(),
    Node = list_to_atom("snmpmon@" ++ Host),
    case net_adm:ping(Node) of
	pong -> snmpmon_stop(Node);
	pang -> ok
    end.

snmpmon_stop(Node) ->
    rpc:call(Node, application, stop, [snmp_mon], 2500),
    timer:sleep(2000),
    rpc:call(Node, init, stop, [], 2500).
