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
%% My fork (2012-04-16)
%%

-module(snmp_mon).

-behaviour(gen_server).
-behaviour(snmpm_user).

%% Avoid warning for local function error/1 clashing with autoimported BIF.
-compile({no_auto_import,[error/1]}).
-export([start_link/0, start_link/1, stop/0,
	 agent/2, 
         sync_get/2, 
         sync_get_next/2, 
         sync_get_bulk/4, 
         sync_set/2, 
	 oid_to_name/1
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

-record(state, {parent}).


%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

start_link() ->
    start_link(["manager/conf", "ne.conf"]).

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


%%%-------------------------------------------------------------------
%%% Callback functions from gen_server
%%%-------------------------------------------------------------------

init([Parent, Opts]) ->
    process_flag(trap_exit, true),
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
    error_msg("received unknown info: "
              "~n   Info: ~p", [Info]),
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
    {ES, EI, VBs} = SnmpInfo, 
    io:format("*** UNKNOWN AGENT ***"
	      "~n   Address:   ~p"
	      "~n   Port:      ~p"
	      "~n   Type:      ~p"
	      "~n   SNMP Info: "
	      "~n     Error Status: ~w"
	      "~n     Error Index:  ~w"
	      "~n     Varbinds:     ~p"
	      "~n", [Addr, Port, Type, ES, EI, VBs]),
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
    TrapStr = 
	case SnmpTrap of
	    {Enteprise, Generic, Spec, Timestamp, Varbinds} ->
		io_lib:format("~n     Generic:    ~w"
			      "~n     Exterprise: ~w"
			      "~n     Specific:   ~w"
			      "~n     Timestamp:  ~w"
			      "~n     Varbinds:   ~p", 
			      [Generic, Enteprise, Spec, Timestamp, Varbinds]);
	    {ErrorStatus, ErrorIndex, Varbinds} ->
		io_lib:format("~n     Error Status: ~w"
			      "~n     Error Index:  ~w"
			      "~n     Varbinds:     ~p"
			      "~n", [ErrorStatus, ErrorIndex, Varbinds])
	end,
    io:format("*** Received TRAP ***"
	      "~n   TargetName: ~p"
	      "~n   SNMP trap:  ~s"
	      "~n", [TargetName, lists:flatten(TrapStr)]),
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
    


error(Reason) ->
    throw({error, Reason}).


error_msg(F, A) ->
    catch error_logger:error_msg("*** SNMP-MANAGER: " ++ F ++ "~n", A).


call(Req) ->
    gen_server:call(?SERVER, Req, infinity).

cast(Msg) ->
    gen_server:cast(?SERVER, Msg).


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
	[{Addr,{TargetId,AgentOpts}}] -> 
	    agent(TargetId, lists:append(AgentOpts,[{address, Addr}, {port, Port}])),
	    report_callback(Server, handle_trap, {TargetId, SnmpInfo});
	[] -> 
	    io:format("Received info from unknown element. IP: ~p~n",[Addr]),
	    report_callback(Server, handle_agent, {Addr, Port, Type, SnmpInfo})  
    end,
    %report_callback(Server, handle_agent, {Addr, Port, Type, SnmpInfo}),
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
