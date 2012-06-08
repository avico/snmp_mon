%% module provides possibility to save data in the postgresql database  
%% using egpsql driver (https://github.com/wg/epgsql)
%%
%% 2012-06-08

-module(db_interface).
-author("Andrey V Ivanov").

-export([save_to_table/1]).

-include_lib("deps/epgsql/include/pgsql.hrl").

-define(DB, "snmp").
-define(HOST, "localhost").
-define(USER, "erl_snmp_user").
-define(PASSWORD, "snmp_erl_user").

save_to_table([DT, Target, Name, Trap, Vars]) ->
    {ok, C} = pgsql:connect(?HOST, ?USER, ?PASSWORD, [{database, ?DB}]),
    io:format("Connected to DB~n", []),
    {ok, Count} = pgsql:equery(C, "INSERT INTO alist VALUES ($1, $2, $3, $4, $5)", [DT, Target, Name, Trap, Vars]),
    io:format("Inserted ~p row(s)~n", [Count]),
    ok = pgsql:close(C).
