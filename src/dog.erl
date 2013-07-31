-module(dog).

-export([start/0]).

start() ->
    application:start(dog).
