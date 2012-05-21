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
%% fork (2012-04-16)
%%

-module(snmp_mon).
-author("Andrey V Ivanov").

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
	 reload_ne_conf/0
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
-define(NE_CONFIG, "ne.conf").
-define(DEF_TRAP_NAME,"TRAPD").

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

reload_ne_conf() ->
    cast(reload_nes).

reload_nes() ->
    AgentIpOrig = [ X || {X,_} <- ets:tab2list(?NE_TABLE) ],
    case file:consult(?NE_CONFIG) of
	{ok,Cfg} ->
	    save_to_ets(Cfg),
	    AgentIpNew = [ X || {_,X,_} <- Cfg ],
	    L=AgentIpOrig--AgentIpNew,
	    if
		L /= [] -> del_from_ets(L);
		true -> ok
	    end;
	Error ->
	    error({failed_reload_ne_conf},Error)
    end.
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
    MgrOpts = lists:append(MgrConf,[{def_user_data,self()}]), %append Pid to default user data
    [NeFile|_Opt]=Opts,
    read_ne_config(NeFile),
    start_manager(MgrOpts),
    register_user(),
    load_mibs(filelib:wildcard("mib/*.bin")),
    {ok, #state{}}.

%read manager options, like snmp version, db path...
read_mgr_config(Dir) ->
    case file:consult(Dir ++ "/manager.opts") of
	{ok, Conf} ->
	    Conf;
	Error ->
	    error({failed_read_config}, Error)
    end.

%read ne.conf and put data to ETS table
read_ne_config(File) ->
    case file:consult(File) of
	{ok,Cfg} ->
	    ets:new(?NE_TABLE,[set,named_table,protected]),
	    save_to_ets(Cfg);
	Error ->
	    error({failed_read_ne_conf},Error)
    end.

%save ne data to ETS
save_to_ets([]) ->
    io:format("NE config loaded to ETS~n",[]);
save_to_ets([First|Tail]) ->
    {TargetId, Ip, AgentOpts} = First,
    ets:insert(?NE_TABLE,{Ip, {TargetId, AgentOpts}}),
    save_to_ets(Tail).

%remove deleted Agent Ip and Options in ne.conf from ETS
del_from_ets([]) ->
    ok;
del_from_ets([Ip|IpList]) ->
    ets:delete(?NE_TABLE,Ip),
    del_from_ets(IpList).

% load all compiled MIBs in mib directory
load_mibs([]) ->
    ok;
load_mibs([H|T]) ->
    catch snmpm:load_mib(filename:rootname(H,".bin")),
    load_mibs(T).

%write_config(Dir, Conf) ->
%    case snmp_config:write_manager_config(Dir, "", Conf) of
%	ok ->
%	    ok;
%	Error ->
%	    error({failed_writing_config, Error})
%    end.

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

%parse_opts(Opts) ->
%    Port     = get_opt(port,             Opts, 5000),
%    EngineId = get_opt(engine_id,        Opts, "mgrEngine"),
%    MMS      = get_opt(max_message_size, Opts, 484),

%    MgrConf = [{port,             Port},
%               {engine_id,        EngineId},
%               {max_message_size, MMS}],

    %% Manager options
%    Mibs      = get_opt(mibs,     Opts, []),
%    Vsns      = get_opt(versions, Opts, [v1, v2, v3]),
%    {ok, Cwd} = file:get_cwd(),
%    Dir       = get_opt(dir, Opts, Cwd),
%    MgrOpts   = [{mibs,     Mibs},
%		 {versions, Vsns}, 
		 %% {server,   [{verbosity, trace}]}, 
%		 {config,   [% {verbosity, trace}, 
%			     {dir, Dir}, {db_dir, Dir}]}],
    
%   {Dir, MgrConf, MgrOpts}.


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
    Reply = (catch snmpm:oid_to_name(Oid)),
    {reply, Reply, S};

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
    reload_nes(),
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
    case SnmpTrap of
	    % snmp v1
	    {Enterprise, Generic, Spec, _Timestamp, Varbinds} ->
		case Generic of
		    % specific trap
		    6 -> Strap = lists:append([Enterprise,[0],[Spec]]),
			 Trap = oid_to_s(Strap),
			 Name = specific_trap(Strap);
		    % generic trap
		    X -> {Trap,Name1} = generic_trap(X),
			 Name = atom_to_list(Name1)
		end,	
	        Vars = varbinds(Varbinds,[]),
		io:format("*** Received TRAP ***~n~p | ~p | ~p | ~p~nVarbinds: ~p~n",[timestamp(), TargetName, Name, Trap, Vars]);
	    % snmp v2
	    {ErrorStatus, _ErrorIndex, Varbinds} when ErrorStatus == noError ->
	        [_Timestamp | [{varbind, _TrapOid, _Type , Strap, _Num} | Varbinds1]] = Varbinds,
	        Trap = oid_to_s(Strap),
	        Name = specific_trap(Strap),
	        Vars = varbinds(Varbinds1,[]),
		io:format("*** Received TRAP ***~n~p | ~p | ~p | ~p~nVarbinds: ~p~n",[timestamp(), TargetName, Name, Trap, Vars]);
	    % snmp v2 ErrorStatus /= noError
	    XX -> error_msg("unknown trap, or error: ~n~p~n",[XX])
    end,
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
    Oid = lists:concat([integer_to_list(X) ++ "." || X <- List]),
    lists:sublist(Oid,length(Oid)-1).

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

% get name for specific trap or puts default value
specific_trap(Oid) ->
    case snmpm:oid_to_name(Oid) of
	{ok,Name} -> atom_to_list(Name);
	{error,_} -> ?DEF_TRAP_NAME
    end.

% transform Varbinds to key-value list
varbinds([],Result) ->
    Result;
varbinds([Var|Vars], Acc) ->
    {varbind, Oid, _Type , Value, _Num} = Var,
    L=lists:append(Acc,[{oid_to_s(Oid), Value}]),
    varbinds(Vars,L).


%% ========================================================================
%% Misc internal utility functions
%% ========================================================================

%% get_opt(Key, Opts) ->
%%     case lists:keysearch(Key, 1, Opts) of
%%         {value, {Key, Val}} ->
%%             Val;
%%         false ->
%%             throw({error, {missing_mandatory, Key}})
%%     end.

%get_opt(Key, Opts, Def) ->
%    case lists:keysearch(Key, 1, Opts) of
%        {value, {Key, Val}} ->
%            Val;
%        false ->
%            Def
%    end.


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
