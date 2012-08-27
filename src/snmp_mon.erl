%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 2006-2010. All Rights Reserved.
%% 
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%% 
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%% 
%% %CopyrightEnd%
%%

%% 
%% 
%% based on lib/erlang/lib/snmp-4.21.4/examples/ex2/snmp_ex2_manager.erl
%% (2012-04-16)
%%

-module(snmp_mon).
-author('Andrey V Ivanov <anvivanov@gmail.com>').

-behaviour(gen_server).
-behaviour(snmpm_user).

%% Avoid warning for local function error/1 clashing with autoimported BIF.
-compile({no_auto_import,[error/1]}).
-export([start/0, start_link/0, start_link/1, stop/0,
	 agent/2, 
         sync_get/2, 
         sync_get_next/2, 
         sync_get_bulk/4, 
         sync_set/2, 
	 oid_to_name/1,
	 reload_ne_conf/0,
	 reload_utraps/0
	]).

%% Manager callback API:
-export([handle_error/3,
         handle_agent/5,
         handle_pdu/4,
         handle_trap/3,
         handle_inform/3,
         handle_report/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         code_change/3, terminate/2]).

-include_lib("snmp/include/snmp_types.hrl").

-define(SERVER,   ?MODULE).
-define(USER,     snmp_user).
-define(USER_MOD, ?MODULE).
-define(NE_TABLE, ne_table).
-define(NE_CONFIG, "etc/ne.conf").
-define(UNKNOWN_TRAPS, "etc/unknown_traps.conf").
-define(TRAPS_TABLE, traps_table).
-define(DEF_TRAP_NAME,"UNKNOWN").

%% save_to_table() is a function, realized in module db_interface to save data to the database. 
%% It's possible to write own db_interface to use any SQL or noSQL database.
%% usage: ?SAVE([DateTime, TargetName, Name, Trap, Varbinds])
-define(SAVE, db_interface:save_to_table).

-record(state, {parent}).


%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

start() ->
    start_link().

start_link() ->
    start_link(["manager/conf", ?NE_CONFIG]).

%Opts=[ConfigDir, AgentsConfig,...]
start_link(Opts) when is_list(Opts) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [self(), Opts], []).

stop() ->
    cast(stop).


%% --- Instruct manager to handle an agent ---

agent(TargetName, Conf) ->
    call({agent, TargetName, Conf}).


%% --- Various SNMP operations ----

sync_get(TargetName, Oids) ->
    call({sync_get, TargetName, Oids}).

sync_get_next(TargetName, Oids) ->
    call({sync_get_next, TargetName, Oids}).

sync_get_bulk(TargetName, NR, MR, Oids) ->
    call({sync_get_bulk, TargetName, NR, MR, Oids}).

sync_set(TargetName, VarsAndVals) ->
    call({sync_set, TargetName, VarsAndVals}).


%% --- Misc utility functions ---

oid_to_name(Oid) ->
    call({oid_to_name, Oid}).

%% reload etc/ne.conf and update ETS table
reload_ne_conf() ->
    cast(reload_nes).

%% reload etc/unknown_traps.conf and update ETS table
reload_utraps() ->
    cast(reload_utraps).

%%%-------------------------------------------------------------------
%%% Callback functions from gen_server
%%%-------------------------------------------------------------------

init([Parent, Opts]) ->
    %process_flag(trap_exit, true),
    case (catch do_init(Opts)) of
        {ok, State} ->
            {ok, State#state{parent = Parent}};
        {error, Reason} ->
            {stop, Reason};
	Crap ->
	    {stop, Crap}
    end.

do_init([Dir|Opts]) ->
    MgrConf = read_mgr_config(Dir),
    MgrOpts = lists:append(MgrConf,[{def_user_data,self()}]), %% append Pid to default user data
    [NeFile|_Opt]=Opts,
    read_config(NeFile, ?NE_TABLE, fun save_to_ets/1),  %% read ne.conf and save to ETS
    read_config(?UNKNOWN_TRAPS, ?TRAPS_TABLE, fun save_utraps_to_ets/1), %% unknown_traps.conf used to manually adding OID-Object name if MIB is missing or not loaded
    start_manager(MgrOpts),
    register_user(),
    load_mibs(filelib:wildcard("mib/*.bin")),
    {ok, #state{}}.

%% read manager options, like snmp version, db path...
read_mgr_config(Dir) ->
    case file:consult(Dir ++ "/manager.opts") of
	{ok, Conf} ->
	    Conf;
	Error ->
	    error({failed_read_config}, Error)
    end.

%% read config and put data to ETS table
read_config(Config, Table, FunSave) ->
    case file:consult(Config) of
	{ok,Cfg} ->
	    ets:new(Table, [set,named_table,protected]),
	    FunSave(Cfg);
	Error ->
	    error({failed_read_config},Error)
    end.

%% save ne data to ETS
save_to_ets([]) ->
    io:format("NE config loaded to ETS~n",[]);
save_to_ets([First|Tail]) ->
    {TargetId, Ip, AgentOpts} = First,
    ets:insert(?NE_TABLE,{Ip, {TargetId, AgentOpts}}),
    save_to_ets(Tail).

%% save unknown traps data to ets
save_utraps_to_ets([]) ->
    io:format("etc/unknown_traps.conf loaded to ETS~n",[]);
save_utraps_to_ets([{Trap, Name}|Traps]) ->
    ets:insert(?TRAPS_TABLE, {Trap, Name}),
    save_utraps_to_ets(Traps).

%% remove deleted Agent Ip and Options in ne.conf or OID in unknown_traps.conf from ETS
del_from_ets(_Table, []) ->
    ok;
del_from_ets(Table, [Elem|ElemList]) ->
    ets:delete(Table, Elem),
    del_from_ets(Table, ElemList).

%% internal function used for reload_ne_conf/0, reload_utraps/0
reload_conf(Config, Table, FunSave) ->
    CurrentEtsElem = [ X || {X, _} <- ets:tab2list(Table) ],
    case file:consult(Config) of
	{ok,Cfg} ->
	    %% update ets table with new config data
	    FunSave(Cfg),
	    %% updated IP list
	    UpdatedElemList = case Config of
		?NE_CONFIG -> [ X || {_, X, _} <- Cfg ];
		?UNKNOWN_TRAPS -> [ X || {X, _} <- Cfg ]
	    end,
	    %% if some elements (IP or OID) deleted in config:
	    L = CurrentEtsElem -- UpdatedElemList,
	    if
		%% remove deleted IP (OIDs) from ets table
		L /= [] -> del_from_ets(Table, L);
		true -> ok
	    end;
	Error ->
	    error({failed_reload_conf},Error)
    end.

%% load all compiled MIBs in mib directory
load_mibs([]) ->
    ok;
load_mibs([H|T]) ->
    catch snmpm:load_mib(filename:rootname(H,".bin")),
    load_mibs(T).

start_manager(Opts) ->
    case snmpm:start_link(Opts) of
	ok ->
	    ok; 
	Error ->
	    error({failed_starting_manager, Error})
    end.

register_user() ->
    case snmpm:register_user(?USER, ?USER_MOD, self()) of
	ok ->
	    ok;
	Error ->
	    error({failed_register_user, Error})
    end.


%%--------------------------------------------------------------------
%% Func: handle_call/3
%% Returns: {reply, Reply, State}          |
%%          {reply, Reply, State, Timeout} |
%%          {noreply, State}               |
%%          {noreply, State, Timeout}      |
%%          {stop, Reason, Reply, State}   | (terminate/2 is called)
%%          {stop, Reason, State}            (terminate/2 is called)
%%--------------------------------------------------------------------

handle_call({agent, TargetName, Conf}, _From, S) ->
    Reply = (catch snmpm:register_agent(?USER, TargetName, Conf)),
    {reply, Reply, S};

handle_call({oid_to_name, Oid}, _From, S) ->
    Reply = trap_to_name(Oid),
    {reply, {ok, Reply}, S};

handle_call({sync_get, TargetName, Oids}, _From, S) ->
    Reply = (catch snmpm:sync_get(?USER, TargetName, Oids)),
    {reply, Reply, S};

handle_call({sync_get_next, TargetName, Oids}, _From, S) ->
    Reply = (catch snmpm:sync_get_next(?USER, TargetName, Oids)),
    {reply, Reply, S};

handle_call({sync_get_bulk, TargetName, NR, MR, Oids}, _From, S) ->
    Reply = (catch snmpm:sync_get_bulk(?USER, TargetName, NR, MR, Oids)),
    {reply, Reply, S};

handle_call({sync_set, TargetName, VarsAndVals}, _From, S) ->
    Reply = (catch snmpm:sync_set(?USER, TargetName, VarsAndVals)),
    {reply, Reply, S};

handle_call(Req, From, State) ->
    error_msg("received unknown request ~n~p~nFrom ~p", [Req, From]),
    {reply, {error, {unknown_request, Req}}, State}.


%%--------------------------------------------------------------------
%% Func: handle_cast/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%--------------------------------------------------------------------
handle_cast(stop, S) ->
    (catch snmpm:stop()),
    {stop, normal, S};

handle_cast(reload_nes, S) ->
    reload_conf(?NE_CONFIG, ?NE_TABLE, fun save_to_ets/1),
    {noreply, S};

handle_cast(reload_utraps, S) ->
    reload_conf(?UNKNOWN_TRAPS, ?TRAPS_TABLE, fun save_utraps_to_ets/1),
    {noreply, S};

handle_cast(Msg, State) ->
    error_msg("received unknown message ~n~p", [Msg]),
    {noreply, State}.


%%--------------------------------------------------------------------
%% Func: handle_info/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%--------------------------------------------------------------------
handle_info({snmp_callback, Tag, Info}, State) ->
    handle_snmp_callback(Tag, Info),
    {noreply, State};
handle_info(Info, State) ->
    error_msg("received unknown info:~n~p~n", [Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% Func: terminate/2
%% Purpose: Shutdown the server
%% Returns: any (ignored by gen_server)
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ets:delete(?NE_TABLE),
    ets:delete(?TRAPS_TABLE),
    ok.


code_change({down, _Vsn}, State, _Extra) ->
    {ok, State};

% upgrade
code_change(_Vsn, State, _Extra) ->
    {ok, State}.


%% ========================================================================
%% ========================================================================

handle_snmp_callback(handle_error, {ReqId, Reason}) ->
    io:format("*** FAILURE ***"
	      "~n   Request Id: ~p"
	      "~n   Reason:     ~p"
	      "~n", [ReqId, Reason]),
    ok;
handle_snmp_callback(handle_agent, {Addr, Port, Type, SnmpInfo}) ->
	    io:format("*** UNKNOWN AGENT ***"
	      "~n   Address:   ~p"
	      "~n   Port:      ~p"
	      "~n   Type:      ~p"
	      "~n   SNMP Info: ~p~n",
	      [Addr, Port, Type, SnmpInfo]),
    ok;
handle_snmp_callback(handle_pdu, {TargetName, ReqId, SnmpResponse}) ->
    {ES, EI, VBs} = SnmpResponse, 
    io:format("*** Received PDU ***"
	      "~n   TargetName: ~p"
	      "~n   Request Id: ~p"
	      "~n   SNMP response:"
	      "~n     Error Status: ~w"
	      "~n     Error Index:  ~w"
	      "~n     Varbinds:     ~p"
	      "~n", [TargetName, ReqId, ES, EI, VBs]),
    ok;
handle_snmp_callback(handle_trap, {TargetName, SnmpTrap}) ->
    Result = 
    case SnmpTrap of
	    % snmp v1
	    {Enterprise, Generic, Spec, _Timestamp, Varbinds} ->
		case Generic of
		    % specific trap
		    6 -> Strap = lists:append([Enterprise,[0],[Spec]]),
			 Trap = oid_to_s(Strap),
			 Name = trap_to_name(Strap);
		    % generic trap
		    X -> {Trap,Name1} = generic_trap(X),
			 Name = atom_to_list(Name1)
		end,	
	        Vars = varbinds(Varbinds,[]),
		io:format("*** Received TRAP ***~n~p | ~p | ~p | ~p~nVarbinds: ~p~n",[timestamp(), TargetName, Name, Trap, Vars]),
		[calendar:local_time(), TargetName, Name, Trap, io_lib:format("~p", [Vars])];
	    % snmp v2
	    {ErrorStatus, _ErrorIndex, Varbinds} when ErrorStatus == noError ->
	        %% first element in Varbinds - Timestamp, second - snmpTrapOid, others - snmp varbinds
	        [_Timestamp | [{varbind, _TrapOid, _Type , Strap, _Num} | Varbinds1]] = Varbinds,
	        Trap = oid_to_s(Strap),
	        Name = trap_to_name(Strap),
	        Vars = varbinds(Varbinds1,[]),
		io:format("*** Received TRAP ***~n~p | ~p | ~p | ~p~nVarbinds: ~p~n",[timestamp(), TargetName, Name, Trap, Vars]),
	        [calendar:local_time(), TargetName, Name, Trap, io_lib:format("~p", [Vars])];
	    % snmp v2 ErrorStatus /= noError
	    XX -> error_msg("unknown trap, or error: ~n~p~n",[XX])
    end,
    ?SAVE(Result),
    ok;
handle_snmp_callback(handle_inform, {TargetName, SnmpInform}) ->
    {ES, EI, VBs} = SnmpInform, 
    io:format("*** Received INFORM ***"
	      "~n   TargetName: ~p"
	      "~n   SNMP inform: "
	      "~n     Error Status: ~w"
	      "~n     Error Index:  ~w"
	      "~n     Varbinds:     ~p"
	      "~n", [TargetName, ES, EI, VBs]),
    ok;
handle_snmp_callback(handle_report, {TargetName, SnmpReport}) ->
    {ES, EI, VBs} = SnmpReport, 
    io:format("*** Received REPORT ***"
	      "~n   TargetName: ~p"
	      "~n   SNMP report: "
	      "~n     Error Status: ~w"
	      "~n     Error Index:  ~w"
	      "~n     Varbinds:     ~p"
	      "~n", [TargetName, ES, EI, VBs]),
    ok;
handle_snmp_callback(BadTag, Crap) ->
    io:format("*** Received crap ***"
	      "~n   ~p"
	      "~n   ~p"
	      "~n", [BadTag, Crap]),
    ok.
    
%% ========================================================================
%% internal helper functions
%% ========================================================================
error(Reason) ->
    throw({error, Reason}).


error_msg(F, A) ->
    catch error_logger:error_msg("*** SNMP-MANAGER: " ++ F ++ "~n", A).


call(Req) ->
    gen_server:call(?SERVER, Req, infinity).

cast(Msg) ->
    gen_server:cast(?SERVER, Msg).

timestamp() ->
    {{Y,M,D},{H,Mm,S}} = calendar:local_time(),
    T = io_lib:format('~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b',[Y,M,D,H,Mm,S]),
    lists:flatten(T).

% transform Oid list to string
oid_to_s(List) ->
     [_Dot|Oid] = lists:concat(["." ++ integer_to_list(X) || X <- List]),
     Oid.
%oid_to_s(List) ->
%    Oid = lists:concat([integer_to_list(X) ++ "." || X <- List]),
%    lists:sublist(Oid,length(Oid)-1).

% handle generic trap
generic_trap(Gtrap) ->
    case Gtrap of
	0 ->
	    case snmpm:name_to_oid(coldStart) of
		{ok,[Trap]} -> {oid_to_s(Trap),coldStart};
		{error, _} -> {"1.3.6.1.6.3.1.1.5.1", coldStart}
	    end;
	1 -> 
	    case snmpm:name_to_oid(warmStart) of
		{ok,[Trap]} -> {oid_to_s(Trap),warmStart};
		{error, _} -> {"1.3.6.1.6.3.1.1.5.2", warmStart}
	    end;
	2 ->
	    case snmpm:name_to_oid(linkDown) of
		{ok,[Trap]} -> {oid_to_s(Trap),linkDown};
		{error, _} -> {"1.3.6.1.6.3.1.1.5.3", linkDown}
	    end;
	3 ->
	    case snmpm:name_to_oid(linkUp) of
		{ok,[Trap]} -> {oid_to_s(Trap),linkUp};
		{error, _} -> {"1.3.6.1.6.3.1.1.5.4", linkUp}
	    end;
	4 ->
	    case snmpm:name_to_oid(authenticationFailure) of
		{ok,[Trap]} -> {oid_to_s(Trap),authenticationFailure};
		{error, _} -> {"1.3.6.1.6.3.1.1.5.5", authenticationFailure}
	    end;
	5 ->
	    case snmpm:name_to_oid(egpNeighborLoss) of
		{ok,[Trap]} -> {oid_to_s(Trap),egpNeighborLoss};
		{error, _} -> {"1.3.6.1.2.1.11.0.5", egpNeighborLoss}
	    end
    end.

% get name for trap or puts default value
trap_to_name(Oid) ->
    case snmpm:oid_to_name(Oid) of
	{ok,Name} -> atom_to_list(Name);
	_ -> 
		case ets:lookup(?TRAPS_TABLE, Oid) of
		    [{_, N}] -> atom_to_list(N);
		    [] -> ?DEF_TRAP_NAME
		end
    end.

% transform Varbinds to key-value list
varbinds([],Result) ->
    lists:reverse(Result);
varbinds([Var|Vars],Acc) ->
    {varbind, Oid, _Type , Value, _Num} = Var,
    varbinds(Vars,[{oid_to_s(Oid), Value}|Acc]).


%% ========================================================================
%% SNMPM user callback functions
%% ========================================================================

handle_error(ReqId, Reason, Server) when is_pid(Server) ->
    report_callback(Server, handle_error, {ReqId, Reason}),
    ignore.

%if info from unknow (unregistered) agent received,
%look up agent IP in ETS and register new agent
%(if exist in table) 
handle_agent(Addr, Port, Type, SnmpInfo, Server) when is_pid(Server) ->
    case ets:lookup(?NE_TABLE,tuple_to_list(Addr)) of
	[{_Addr,{TargetId,AgentOpts}}] -> 
	    case lists:member(TargetId,snmpm:which_agents()) of
		true ->
		    % !!!!!
		    % if agent with same TargetId already registered, probably SnmpInfo received from different Port
		    % ***may by unregister and register agent???
		    snmpm:update_agent_info(?USER,TargetId,port,Port);
		false ->
		    snmpm:register_agent(?USER, TargetId, lists:append(AgentOpts,[{address, Addr}, {port, Port}]))
	    end,
	    report_callback(Server,handle_trap, {TargetId, SnmpInfo});
	[] -> 
	    report_callback(Server, handle_agent, {Addr, Port, Type, SnmpInfo})
    end,
    ignore.


handle_pdu(TargetName, ReqId, SnmpResponse, Server) when is_pid(Server) ->
    report_callback(Server, handle_pdu, {TargetName, ReqId, SnmpResponse}),
    ignore.


handle_trap(TargetName, SnmpTrap, Server) when is_pid(Server) ->
    report_callback(Server, handle_trap, {TargetName, SnmpTrap}),
    ok.

handle_inform(TargetName, SnmpInform, Server) when is_pid(Server) ->
    report_callback(Server, handle_inform, {TargetName, SnmpInform}),
    ok.


handle_report(TargetName, SnmpReport, Server) when is_pid(Server) ->
    report_callback(Server, handle_report, {TargetName, SnmpReport}),
    ok.

report_callback(Pid, Tag, Info) ->
    Pid ! {snmp_callback, Tag, Info}.
