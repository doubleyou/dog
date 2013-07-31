-module(dog_dns_packet).

-export([encode/1, decode/1]).

-include("dog.hrl").

%%
%% External API
%%

encode(#dns_record{
            header = Header,
            question = Question,
            answer = Answer,
            authority = Authority,
            additional = Additional
        }) ->
    QdCount = length(Question),
    AnCount = length(Answer),
    NsCount = length(Authority),
    ArCount = length(Additional),

    HeaderBlob = encode_header(Header, QdCount, AnCount, NsCount, ArCount),

    QuestionBlob = encode_question(Question),
    AnswerBlob = encode_resource_record(Answer),
    AuthorityBlob = encode_resource_record(Authority),
    AdditionalBlob = encode_resource_record(Additional),

    [HeaderBlob, QuestionBlob, AnswerBlob, AuthorityBlob, AdditionalBlob];
encode(_) ->
    error(badarg).


decode(<<Id:16,
         QR:1, Opcode:4, AA:1, TC:1, RD:1, RA:1, _Z:3, RCode:4,
         QdCount:16,
         AnCount:16,
         NsCount:16,
         ArCount:16,
         Rest/binary>> = Packet) ->
    Header = #dns_header{
        id = Id,
        qr = QR,
        opcode = Opcode,
        aa = AA,
        tc = TC,
        rd = RD,
        ra = RA,
        rcode = RCode
    },

    {Question, Rest2} = 
        parse_sequentially(
            fun (Bin) -> decode_question(Bin, Packet) end,
            Rest,
            QdCount
        ),

    {Answer, Rest3} = 
        parse_sequentially(
            fun (Bin) -> decode_resource_record(Bin, Packet) end,
            Rest2,
            AnCount
        ),

    {Authority, Rest4} = 
        parse_sequentially(
            fun (Bin) -> decode_resource_record(Bin, Packet) end,
            Rest3,
            NsCount
        ),

    {Additional, <<>>} = 
        parse_sequentially(
            fun (Bin) -> decode_resource_record(Bin, Packet) end,
            Rest4,
            ArCount
        ),

    #dns_record{
        header = Header,
        question = Question,
        answer = Answer,
        authority = Authority,
        additional = Additional
    };
decode(_) ->
    error(badarg).


%%
%% Internal functions
%%

encode_question(Qs) ->
    [ 
        [encode_name(Name), <<Type:16, Class:16>>]
            || #dns_question{ name = Name, class = Class, type = Type} <- Qs
    ].

encode_resource_record(RRs) ->
    [
        [encode_name(Name), <<Type:16, Class:16, TTL:32>>, encode_rdata(RData)]
            || #dns_resource_record{ name = Name, type = Type, class = Class,
                                     ttl = TTL, rdata = RData } <- RRs
    ].

encode_header(#dns_header{ id = Id, qr = QR, opcode = Opcode, aa = AA, tc = TC,
                           rd = RD, ra = RA, rcode = RCode }, QdCount, AnCount,
                        NsCount, ArCount) ->
    <<Id:16,
      QR:1, Opcode:4, AA:1, TC:1, RD:1, RA:1, 0:3, RCode:4,
      QdCount:16,
      AnCount:16,
      NsCount:16,
      ArCount:16>>.

encode_name(Name) ->
    [[[byte_size(L), L] || L <- Name], 0].

encode_rdata(RData) ->
    L = byte_size(RData),
    <<L:16, RData/binary>>.
    

decode_question(Bin, Buffer) ->
    {Name, <<QType:16, QClass:16, Rest/binary>>} = decode_name(Bin, Buffer),
    Question = #dns_question{
        name = Name,
        type = QType,
        class = QClass
    },
    {Question, Rest}.

decode_resource_record(Bin, Buffer) ->
    {Name, Rest} = decode_name(Bin, Buffer),
    <<Type:16, Class:16, TTL:32, L:16, RData:L/binary, Rest2/binary>> = Rest,
    Record = #dns_resource_record{
        name = Name,
        type = Type,
        class = Class,
        ttl = TTL,
        rdata = RData
    },
    {Record, Rest2}.

decode_name(Bin, Buffer) ->
    decode_name(Bin, Buffer, Bin, [], 0).

%% If parsing takes too long there's a looped pointer
decode_name(_, Buffer, _, _, Cnt) when Cnt > byte_size(Buffer) ->
    error(looped_pointer);
%% Labels sequence end with a zero octet
decode_name(<<0:8, Rest/binary>>, _Buffer, _Tail, Acc, 0) ->
    {lists:reverse(Acc), Rest};
decode_name(<<0:8, _Rest/binary>>, _Buffer, Tail, Acc, _Cnt) ->
    {lists:reverse(Acc), Tail};
%% 2 zero bits mean a length-encoded label
decode_name(<<0:2, L:6, Label:L/binary, Rest/binary>>, Buffer, _Tail, Acc, 0) ->
    decode_name(Rest, Buffer, Rest, [Label | Acc], 0);
%% Non-zero counter means we came from a pointer
decode_name(<<0:2, L:6, Label:L/binary, Rest/binary>>, Buffer, Tail, Acc, Cnt) ->
    decode_name(Rest, Buffer, Tail, [Label | Acc], Cnt + 2);
%% 2 non-zero bits mean a pointer
decode_name(<<3:2, Offset:14, Rest/binary>>, Buffer, _Tail, Acc, 0) ->
    <<_:Offset/binary, Labels/binary>> = Buffer,
    decode_name(Labels, Buffer, Rest, Acc, 1).


parse_sequentially(Fun, Bin, N) ->
    parse_sequentially(Fun, Bin, N, []).

parse_sequentially(_Fun, Bin, 0, Acc) ->
    {lists:reverse(Acc), Bin};
parse_sequentially(Fun, Bin, N, Acc) ->
    {Result, NewBin} = Fun(Bin),
    parse_sequentially(Fun, NewBin, N - 1, [Result | Acc]).
