-module(be_utils).

-export([batch_pmap/2, pmap/2]).
-export([make_values_list/2]).
-export([flatten_once/1, split_list/2]).
-export([get_last_block_time/0]).
-export([get_max_peer_height/0]).
-export([block_contains_election/1, witnesses_to_json/1]).

%% Added for block age support
-include_lib("blockchain/include/blockchain.hrl").

%% Data minipulation
-define(H3_LOCATION_RES, 8).

-spec calculate_location_hex(h3:h3index()) -> h3:h3index().
calculate_location_hex(Location) ->
    h3:parent(Location, ?H3_LOCATION_RES).

-spec block_contains_election(blockchain_block:block()) -> boolean().
block_contains_election(Block) ->
    lists:any(
        fun(Txn) -> blockchain_txn:type(Txn) == blockchain_txn_consensus_group_v1 end,
        blockchain_block:transactions(Block)
    ).

witnesses_to_json(Witnesses) ->
    maps:fold(
        fun(Key, Witness, Acc) ->
            Acc#{?BIN_TO_B58(Key) => witness_to_json(Witness)}
        end,
        #{},
        Witnesses
    ).

witness_to_json(Witness) ->
    #{
        <<"histogram">> => blockchain_ledger_gateway_v2:witness_hist(Witness),
        <<"first_time">> => ?MAYBE_FN(
            fun(V) -> integer_to_binary(V) end,
            blockchain_ledger_gateway_v2:witness_first_time(Witness)
        ),
        <<"recent_time">> => ?MAYBE_FN(
            fun(V) -> integer_to_binary(V) end,
            blockchain_ledger_gateway_v2:witness_recent_time(Witness)
        )
    }.

append([H | T], L) -> [H | append(T, L)];
append([], L) -> L.

flatten_once(List) ->
    flatten_once(List, []).
flatten_once([H|T], L) ->
    case lists:all(fun(I) -> is_list(I) end, H) of
        true ->
            flatten_once(T, append(H, L));
        false ->
            flatten_once(T, [H | L])
    end;
flatten_once([], L) -> L.

split_list(List, N) ->
    RevList = do_split_list(List, N),
    lists:map(
        fun lists:reverse/1,
        lists:reverse(RevList)
    ).

do_split_list(List, Max) ->
    element(
        1,
        lists:foldl(
            fun
                (E, {[Buff | Acc], C}) when C < Max ->
                    {[[E | Buff] | Acc], C + 1};
                (E, {[Buff | Acc], _}) ->
                    {[[E], Buff | Acc], 1};
                (E, {[], _}) ->
                    {[[E]], 1}
            end,
            {[], 0},
            List
        )
    ).

make_values_list(NumberElements, NumberRows) ->
    make_values_list(NumberElements, NumberRows, 1).

make_values_list(_, 0, _) ->
    [];
make_values_list(NumberElements, NumberRows, Offset) ->
    [
        $(,
        [[$$, integer_to_list(E), $,, $\s] || E <- lists:seq(Offset, Offset + NumberElements - 2)],
        [$$, integer_to_list(Offset + NumberElements - 1), $), [$, || NumberRows /= 1], $\s]
        | make_values_list(NumberElements, NumberRows - 1, Offset + NumberElements)
    ].

batch_pmap(F, L) ->
    Width = cpus(),
    Results = pmap(F, L, Width, true),
    %% If you didn't flatten_once here you'd have a list of lists equal to the # of partitions created
    %% in pmap. You could then send those lists as individual copies to the DB but if one failed it'd
    %% result in a partial upload to the DB. Instead this creates a single copylist from the results.
    flatten_once(Results).

pmap(F, L) ->
    Width = cpus(),
    Results = pmap(F, L, Width, false),
    lists:flatten(Results).

pmap(F, L, Width, Batch) ->
    Parent = self(),
    Len = length(L),
    Min = floor(Len / Width),
    Rem = Len rem Width,
    Lengths = lists:duplicate(Rem, Min + 1) ++ lists:duplicate(Width - Rem, Min),
    OL = partition_list(L, Lengths, []),
    {St, WorkerPids} = lists:foldl(
        fun
            ([], Acc) ->
                Acc;
            (IL, {N, Workers}) ->
                P = spawn_opt(
                    fun() ->
                        process_flag(priority, high),
                        Fun = case Batch of
                            true ->
                                F(IL);
                            _ ->
                                lists:map(F, IL)
                        end,
                        try Fun of
                            Res ->
                                Parent ! {pmap, N, Res}
                        catch
                            What:Why ->
                                lager:info("Pmap what: ~p why: ~p", [What, Why]),
                                Parent ! {pmap_crash, What, Why};
                            What:Why:Stack ->
                                lager:info("Pmap what: ~p why: ~p stack: ~p", [What, Why, Stack]),
                                Parent ! {pmap_crash, What, Why}
                        end
                    end,
                    [{fullsweep_after, 0}]
                ),
                {N + 1, [P | Workers]}
        end,
        {0, []},
        OL
    ),
    L2 = [
        receive
            {pmap_crash, What, Why} ->
                %% kill all the others
                [catch erlang:exit(P, normal) || P <- WorkerPids],
                flush_pmap_messages(),
                erlang:What(Why);
            {pmap, N, R} ->
                {N, R}
        end
     || _ <- lists:seq(1, St)
    ],
    {_, L3} = lists:unzip(lists:keysort(1, L2)),
    L3.

flush_pmap_messages() ->
    receive
        {pmap, _N, _R} ->
            flush_pmap_messages()
    after 0 ->
        ok
    end.

partition_list([], [], Acc) ->
    lists:reverse(Acc);
partition_list(L, [0 | T], Acc) ->
    partition_list(L, T, Acc);
partition_list(L, [H | T], Acc) ->
    {Take, Rest} = lists:split(H, L),
    partition_list(Rest, T, [Take | Acc]).

cpus() ->
    Ct = erlang:system_info(schedulers_online),
    max(2, ceil(Ct / 2) + 1).

get_last_block_time() ->
    Chain = blockchain_worker:blockchain(),
    {ok, #block_info_v2{time=HeadBlockTime, height=HeadBlockHeight}} = blockchain:head_block_info(Chain),
    {ok, #block_info_v2{time=PrevBlockTime}} = blockchain:get_block_info(HeadBlockHeight - 1, Chain),
    max(60, HeadBlockTime - PrevBlockTime).

get_max_peer_height() ->
    %% NOTE: Get the max height from peers with peerbook for auto-catchup functionality
    Book = libp2p_swarm:peerbook(blockchain_swarm:swarm()),
    Peers = [libp2p_peerbook:get(Book, Address) || Address <- libp2p_peerbook:keys(Book)],
    PeersHeights = [ libp2p_peer:signed_metadata_get(Peer, <<"height">>, 0) || {ok, Peer} <- Peers],
    max(1, lists:max(PeersHeights)).