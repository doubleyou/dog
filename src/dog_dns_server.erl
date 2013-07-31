-module(dog_dns_server).

-export([start_link/0]).
-export([init/0, loop/1, process_request/3]).

-include_lib("kernel/src/inet_dns.hrl").

-define(DNS_PORT, 53).
-define(DNS_OPTIONS, [binary, {active, false}]).

start_link() ->
    proc_lib:start_link(?MODULE, init, []).

init() ->
    {ok, Sock} = gen_udp:open(?DNS_PORT, ?DNS_OPTIONS),
    proc_lib:init_ack({ok, self()}),
    ?MODULE:loop(Sock).

loop(Sock) ->
    case gen_udp:recv(Sock, 512) of
        {ok, {Addr, Port, Packet}} ->
            proc_lib:spawn(?MODULE, process_request, [Addr, Port, Packet]);
        {error, timeout} ->
            void
    end,
    ?MODULE:loop(Sock).


process_request(Addr, Port, Packet) ->
    R = dog_dns_packet:decode(Packet),
    Packet = iolist_to_binary(dog_dns_packet:encode(R)),
    lager:info("Record: ~p", [R]),
    ok.
