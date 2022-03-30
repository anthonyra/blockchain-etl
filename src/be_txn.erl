-module(be_txn).

-export([to_json/1, to_json/2, to_json/3]).
-export([to_copy_list/3, to_detailed_json/2]).
-export([to_actors_copy_list/2]).

-include("be_db_follower.hrl").

-include_lib("blockchain/include/blockchain_utils.hrl").

append([H | T], L) -> [H | append(T, L)];
append([], L) -> L.

flatten_once(List) ->
    flatten_once(List, []).
flatten_once([H|T], L) ->
    case is_list(lists:last(H)) of
        true ->
            flatten_once(T, append(H, L));
        false ->
            flatten_once(T, [H | L])
    end;
flatten_once([], L) -> L.

to_actors_copy_list(Height, Txns) ->
    [modified_to_actors(Height, Txn) || Txn <- Txns].

modified_to_actors(Height, Txn) ->
    TxnHash = ?BIN_TO_B64(blockchain_txn:hash(Txn)),
    Actors = be_db_txn_actor:to_actors(Txn),
    RawList = [[Height, ?BIN_TO_B58(Key), list_to_binary(Role), TxnHash] || {Role, Key} <- Actors],
    lager:info("RawList Count: ~p", [length(RawList)]),
    FlatList = flatten_once(RawList),
    lager:info("FlatList Count: ~p", [length(FlatList)]).

to_copy_list(Txns, Block, Opts) ->
    Height = blockchain_block_v1:height(Block),
    Time = blockchain_block_v1:time(Block),
    {ledger, Ledger} = lists:keyfind(ledger, 1, Opts),
    AGwCF = blockchain_ledger_v1:active_gateways_cf(Ledger),
    Snapshot = blockchain_ledger_v1:maybe_use_snapshot(Ledger, []),
    {ok, RegionBins} = blockchain_region_v1:get_all_region_bins(Ledger),
    %%TODO - Convert from very hacky approach to a better one in blockchain_region_params_v1
    RegionsParams = [case blockchain_region_params_v1:for_region(Region, Ledger) of
                        {ok, Params} -> {Region, Params};
                        _ -> {Region, not_found}
                    end || {Region, _} <- RegionBins],

    PrefetchedVars = #{
        block_height => Height,
        block_time => Time,
        poc_v4_exclusion_cells => blockchain_ledger_v1:config(poc_v4_exclusion_cells, Ledger),
        poc_distance_limt => blockchain_ledger_v1:config(poc_distance_limt, Ledger),
        data_aggregation_version => blockchain_ledger_v1:config(data_aggregation_version, Ledger),
        fspl_loss => blockchain_ledger_v1:config(fspl_loss, Ledger),
        poc_version => blockchain_ledger_v1:config(poc_version, Ledger),
        discard_zero_frequency => blockchain_ledger_v1:config(discard_zero_freq_witness, Ledger),
        parent_res => blockchain_ledger_v1:config(poc_v4_parent_res, Ledger)
    },
    
    [ txn_to_copy_list(Txn, AGwCF, Snapshot, RegionBins, RegionsParams, PrefetchedVars, Opts) || Txn <- Txns].

txn_to_copy_list(Txn, AGwCF, Snapshot, RegionBins, RegionsParams, PrefetchedVars, Opts) ->
    #{block_height := Height, block_time := Time} = PrefetchedVars,
    case blockchain_txn:json_type(Txn) of
        <<"rewards_v2">> ->
            {chain, Chain} = lists:keyfind(chain, 1, Opts),
            Start = blockchain_txn_rewards_v2:start_epoch(Txn),
            End = blockchain_txn_rewards_v2:end_epoch(Txn),
            {ok, Metadata} = be_db_reward:calculate_rewards_metadata(Start, End, Chain),
            Json = #{type := Type} = blockchain_txn:to_json(Txn, Opts ++ [{rewards_metadata, Metadata}]),
            [Height, ?BIN_TO_B64(blockchain_txn:hash(Txn)), Type, Json, Time];
        Type ->
            Json = blockchain_txn:to_json(Txn, []),
            DetailedJson = data_to_json(Type, Json, AGwCF, Snapshot, RegionBins, RegionsParams, PrefetchedVars),
            [Height, ?BIN_TO_B64(blockchain_txn:hash(Txn)), Type, DetailedJson, Time]
    end.

to_detailed_json(Txns, Opts) ->
    {ledger, Ledger} = lists:keyfind(ledger, 1, Opts),
    AGwCF = blockchain_ledger_v1:active_gateways_cf(Ledger),
    Snapshot = blockchain_ledger_v1:maybe_use_snapshot(Ledger, []),
    {ok, RegionBins} = blockchain_region_v1:get_all_region_bins(Ledger),
    %%TODO - Convert from very hacky approach to a better one in blockchain_region_params_v1
    RegionsParams = [case blockchain_region_params_v1:for_region(Region, Ledger) of
                        {ok, Params} -> {Region, Params};
                        _ -> {Region, not_found}
                    end || {Region, _} <- RegionBins],

    PrefetchedVars = #{
        poc_v4_exclusion_cells => blockchain_ledger_v1:config(poc_v4_exclusion_cells, Ledger),
        poc_distance_limt => blockchain_ledger_v1:config(poc_distance_limt, Ledger),
        data_aggregation_version => blockchain_ledger_v1:config(data_aggregation_version, Ledger),
        fspl_loss => blockchain_ledger_v1:config(fspl_loss, Ledger),
        poc_version => blockchain_ledger_v1:config(poc_version, Ledger),
        discard_zero_frequency => blockchain_ledger_v1:config(discard_zero_freq_witness, Ledger),
        parent_res => blockchain_ledger_v1:config(poc_v4_parent_res, Ledger)
    },
    
    [ txn_to_json(Txn, AGwCF, Snapshot, RegionBins, RegionsParams, PrefetchedVars, Opts) || Txn <- Txns].

txn_to_json(Txn, AGwCF, Snapshot, RegionBins, RegionsParams, PrefetchedVars, Opts) ->
    case blockchain_txn:json_type(Txn) of
        <<"rewards_v2">> ->
            {chain, Chain} = lists:keyfind(chain, 1, Opts),
            Start = blockchain_txn_rewards_v2:start_epoch(Txn),
            End = blockchain_txn_rewards_v2:end_epoch(Txn),
            {ok, Metadata} = be_db_reward:calculate_rewards_metadata(Start, End, Chain),
            blockchain_txn:to_json(Txn, Opts ++ [{rewards_metadata, Metadata}]);
        Type ->
            Json = blockchain_txn:to_json(Txn, []),
            data_to_json(Type, Json, AGwCF, Snapshot, RegionBins, RegionsParams, PrefetchedVars)
    end.

data_to_json(<<"poc_request_v1">>, Json, AGwCF, Snapshot, _RegionBins, _RegionsParams, _PrefetchedVars) ->
    #{challenger := Challenger} = Json,
    {ok, ChallengerInfo} = get_from_rocksdb(Challenger, AGwCF, Snapshot),
    ChallengerOwner = blockchain_ledger_gateway_v2:owner_address(ChallengerInfo),
    ChallengerLoc = blockchain_ledger_gateway_v2:location(ChallengerInfo),
    Json#{
        challenger_owner => ?BIN_TO_B58(ChallengerOwner),
        challenger_location => ?MAYBE_H3(ChallengerLoc)
    };
data_to_json(<<"state_channel_close_v1">>, Json, AGwCF, Snapshot, _RegionBins, _RegionsParams, _PrefetchedVars) ->
    #{state_channel := SCJson} = Json,
    UpdateSummary = fun(Summary = #{client := Client}) ->
        case get_from_rocksdb(Client, AGwCF, Snapshot) of
            {error, _} ->
                Summary;
            {ok, ClientInfo} ->
                ClientLoc = blockchain_ledger_gateway_v2:location(ClientInfo),
                Summary#{
                    owner => ?BIN_TO_B58(blockchain_ledger_gateway_v2:owner_address(ClientInfo)),
                    location => ?MAYBE_H3(ClientLoc)
                }
        end
    end,
    Json#{
        state_channel => SCJson#{
        summaries => [UpdateSummary(S) || S <- maps:get(summaries, SCJson)]
        }
    };
data_to_json(<<"poc_receipts_v1">>, Json, AGwCF, Snapshot, RegionBins, RegionsParams, PrefetchedVars) ->
    #{challenger := Challenger, path := Path} = Json,
    UpdateWitness = fun(WitnessJson = #{gateway := Witness}, ChallengeInfo) ->
        {ok, WitnessInfo} = get_from_rocksdb(Witness, AGwCF, Snapshot),
        WitnessLoc = blockchain_ledger_gateway_v2:location(WitnessInfo),
        WitnessGain = blockchain_ledger_gateway_v2:gain(WitnessInfo),
        case is_valid_witness(WitnessJson#{gain => WitnessGain, h3_index => WitnessLoc}, ChallengeInfo, PrefetchedVars) of
            {true, _} ->
                WitnessJson#{
                    is_valid => true,
                    owner => ?BIN_TO_B58(blockchain_ledger_gateway_v2:owner_address(WitnessInfo)),
                    location => ?MAYBE_H3(WitnessLoc) 
                };
            {false, Reason} ->
                WitnessJson#{
                    is_valid => false,
                    invalid_reason => Reason,
                    owner => ?BIN_TO_B58(blockchain_ledger_gateway_v2:owner_address(WitnessInfo)),
                    location => ?MAYBE_H3(WitnessLoc)
                }
        end
    end,

    UpdatePath = fun(PathJson = #{challengee := Challengee, witnesses := Witnesses, receipt := Receipt}) ->
        %% Need to find the ChallengeeRegionParams since ChannelCount = length(ChallengeeRegionParams)
        {ok, ChallengeeInfo} = get_from_rocksdb(Challengee, AGwCF, Snapshot),
        ChallengeeLoc = blockchain_ledger_gateway_v2:location(ChallengeeInfo),
        
        {ok, ChallengeeRegion, RegionBin} = find_region(ChallengeeLoc, RegionBins),
        {ok, RegionParams} = find_region_params(ChallengeeRegion, RegionsParams),
        FreqEirps = [{blockchain_region_param_v1:channel_frequency(I), blockchain_region_param_v1:max_eirp(I)} || I <- RegionParams],
        {ok, Channels} = recreate_beacon_channels(Json, PrefetchedVars, length(FreqEirps)),
        TxPower = case Receipt of
            undefined -> undefined;
            _ ->
                case maps:find(tx_power,Receipt) of
                    {ok, TxPower0} when TxPower0 == 0 ->
                        undefined;
                    {ok, TxPower0} -> TxPower0;
                    _ ->
                        undefined
                end
        end,

        ChallengeInfo = #{
            tx_power => TxPower,
            challengee_h3_index => ChallengeeLoc,
            challengee_region_bin => RegionBin,
            region_params => RegionParams,
            region_frequencies_eirps => FreqEirps,
            challenge_channels => Channels
            },

        PathJson#{
            challengee_owner => ?BIN_TO_B58(
                blockchain_ledger_gateway_v2:owner_address(ChallengeeInfo)
            ),
            challengee_location => ?MAYBE_H3(ChallengeeLoc),
            witnesses => [UpdateWitness(W, ChallengeInfo) || W <- Witnesses]
        }
    end,

    {ok, ChallengerInfo} = get_from_rocksdb(Challenger, AGwCF, Snapshot),
    ChallengerLoc = blockchain_ledger_gateway_v2:location(ChallengerInfo),
    Json#{
        challenger_owner => ?BIN_TO_B58(blockchain_ledger_gateway_v2:owner_address(ChallengerInfo)),
        challenger_location => ?MAYBE_H3(ChallengerLoc),
        path => [UpdatePath(E) || E <- Path]
    };
data_to_json(_, Json, _AGwCF, _Snapshot, _RegionBins, _RegionsParams, _PrefetchedVars) ->
    Json.

% -spec distance_check(SrcLoc :: h3:h3_index(), DstLoc :: h3:h3_index(), ExclusionCells :: pos_integer()) -> 
%     {true, pos_integer()} | boolean().

is_valid_witness(WitnessJson, ChallengeInfo, PrefetchedVars) ->
    #{h3_index := WitnessH3Index, signal := RSSI, snr := SNR, frequency := Frequency, channel := WitnessChannel}=WitnessJson,
    #{region_frequencies_eirps := FreqEirps, challenge_channels := Channels, challengee_region_bin := RegionBin}=ChallengeInfo,
    #{data_aggregation_version := DAV, poc_version := Version, discard_zero_frequency := DiscardZeroFreq}=PrefetchedVars,
    case discard_for_zero_frequency(DiscardZeroFreq, Frequency) of
        true ->
            {false, <<"witness_zero_freq">>};
        false ->
            case check_valid_frequency(Frequency, FreqEirps, Version) of
                true ->
                    case is_too_far(WitnessJson, ChallengeInfo, PrefetchedVars) of
                        true ->
                            {false, <<"witness_too_far">>};
                        false ->
                            case not_too_close(WitnessJson, ChallengeInfo, PrefetchedVars) of
                                true ->
                                    case check_rssi_signal_strength(WitnessJson, ChallengeInfo, PrefetchedVars) of
                                        true ->
                                            case data_aggregation_check(DAV, RSSI, SNR, Version) of
                                                true ->
                                                    case lists:last(Channels) == WitnessChannel of
                                                        true ->
                                                            check_region(WitnessH3Index, RegionBin);
                                                        false ->
                                                            {false, <<"witness_on_incorrect_channel">>}
                                                    end;
                                                {false, Reason} -> {false, Reason}
                                            end;
                                        false ->
                                            {false, <<"witness_rssi_too_high">>}
                                    end;
                                {false, Reason} -> {false, Reason}
                            end
                    end;
                false ->
                    {false, <<"incorrect_frequency">>}
            end
    end.

% is_valid_witness_old(WitnessJson, ChallengeInfo, PrefetchedVars) ->
%     #{h3_index := WitnessH3Index, signal := RSSI, snr := SNR, frequency := Frequency, channel := WitnessChannel}=WitnessJson,
%     #{challengee_region := ChallengeeRegion, region_frequencies_eirps := FreqEirps, challenge_channels := Channels, challengee_region_bin := RegionBin}=ChallengeInfo,
%     #{data_aggregation_version := DAV, poc_version := Version, discard_zero_frequency := DiscardZeroFreq}=PrefetchedVars,
%     case discard_for_zero_frequency(DiscardZeroFreq, Frequency) of
%         true ->
%             {false, <<"witness_zero_freq">>};
%         false ->
%             case check_region(WitnessH3Index, RegionBin) of
%                 {true, _} ->
%                     case is_too_far(WitnessJson, ChallengeInfo, PrefetchedVars) of
%                         true ->
%                             {false, <<"witness_too_far">>};
%                         false ->
%                             case not_too_close(WitnessJson, ChallengeInfo, PrefetchedVars) of
%                                 true ->
%                                     case check_rssi_signal_strength(WitnessJson, ChallengeInfo, PrefetchedVars) of
%                                         true ->
%                                             case check_valid_frequency(Frequency, FreqEirps, Version) of
%                                                 true ->
%                                                     case data_aggregation_check(DAV, RSSI, SNR, Version) of
%                                                         true ->
%                                                             case lists:last(Channels) == WitnessChannel of
%                                                                 true ->
%                                                                     {true, <<"ok">>};
%                                                                 false ->
%                                                                     {false, <<"witness_on_incorrect_channel">>}
%                                                             end;
%                                                         {false, Reason} -> {false, Reason}
%                                                     end;
%                                                 false ->
%                                                     {false, <<"incorrect_frequency">>}
%                                             end;
%                                         false ->
%                                             {false, <<"witness_rssi_too_high">>}
%                                     end;
%                                 {false, Reason} -> {false, Reason}
%                             end
%                     end;
%                 {false, Reason} -> {false, Reason}
%             end
%     end.

discard_for_zero_frequency(DiscardZeroFreq, Freq) ->
    case {DiscardZeroFreq, Freq} of
        {{ok, true}, 0.0} ->
            true;
        _ ->
            false
    end.

is_too_far(#{h3_index := WitnessH3Index}, #{challengee_h3_index := ChallengeeH3Index}, #{poc_distance_limt := Limit}) ->
    case Limit of
        {ok, L} ->
            Distance = blockchain_utils:distance(ChallengeeH3Index, WitnessH3Index),
            Distance > L;
        _ ->
            false
    end.

not_too_close(#{h3_index := WitnessH3Index}, #{challengee_h3_index := ChallengeeH3Index}, #{poc_v4_exclusion_cells := {ok, ExclusionCells}, parent_res := {ok, ParentRes}}) ->
    ChallengeeParentIndex = h3:parent(ChallengeeH3Index, ParentRes),
    WitnessParentIndex = h3:parent(WitnessH3Index, ParentRes),
    try h3:grid_distance(ChallengeeParentIndex, WitnessParentIndex) of
        GridDistance when GridDistance >= ExclusionCells ->
            true;
        _ ->
            %% too close
            {false, <<"witness_too_close">>}
    catch _:_ ->
        %% pentagonal distortion
        {false, <<"pentagonal_distortion">>}
    end.

check_rssi_signal_strength(WitnessJson, ChallengeInfo, PrefetchedVars) ->
    #{signal := RSSI, gain := WitnessGain, h3_index := WitnessH3Index, frequency := Frequency}=WitnessJson, 
    #{tx_power := TxPower, challengee_h3_index := ChallengeeH3Index, region_frequencies_eirps := FreqEirps}=ChallengeInfo, 
    #{fspl_loss := FSPLLoss, poc_version := Version}=PrefetchedVars,
    MinRcvSig = min_rcv_sig_(ChallengeeH3Index, WitnessH3Index, Frequency, WitnessGain, TxPower, FreqEirps, FSPLLoss, Version),
    RSSI < MinRcvSig.

check_valid_frequency(Frequency, FreqEirps, Version) ->
    %% only check this if poc 11
    case Version of
        V when V >= 11 ->
            ChannelFreqs = [Freq || {Freq, _Eirps} <- FreqEirps],
            lists:any(fun(E) -> abs(E - Frequency*?MHzToHzMultiplier) =< 1000 end, ChannelFreqs);
        _ ->
            %% We're not in poc-v11+
            true
    end.

data_aggregation_check(DAV, RSSI, SNR, Version) ->
    case DAV of
        {ok, DataAggVsn} when DataAggVsn > 1 ->
            case check_rssi_snr_vers(RSSI, SNR, Version) of
                true ->
                    true;
                {false, _LowerBound} ->
                    {false, <<"witness_rssi_below_lower_bound">>}
            end;
        _ ->
            %% SNR+Freq+Channels not collected, nothing else we can check
            {true, <<"insufficient_data">>}
    end.

check_rssi_snr_vers(RSSI, SNR, Version) ->
    case Version of
        {ok, POCVersion} when POCVersion >= 11 ->
            %% no checks
            true;
        _ ->
            {LowerBound, _} = calculate_rssi_bounds_from_snr(SNR),
            case RSSI >= LowerBound of
                true ->
                    true;
                false ->
                    {false, LowerBound}
            end
    end.

check_region(WitnessH3Index, RegionBin) ->
    case h3_in_bin(WitnessH3Index, RegionBin) of
        true ->
            {true, <<"ok">>};
        _ ->
            {false, <<"witness_not_same_region">>}
    end.

%% ------------------------------------------------------------------------------- %%
%%                           rssi_signal_check utils                               %%
%% ------------------------------------------------------------------------------- %%

min_rcv_sig_(ChallengeeH3Index, WitnessH3Index, Frequency, WitnessGain, TxPower0, FreqEirps, FSPLLoss, Version) ->
    %% Receipt can be undefined
    case Version of
        {ok, POCVersion} when POCVersion >= 11 ->
            %% Estimate tx power because there is no receipt with attached tx_power
            TxPower = case TxPower0 of
                undefined -> estimated_tx_power_(Frequency, FreqEirps);
                Value -> Value
            end,
            FSPL = calc_fspl_(ChallengeeH3Index, WitnessH3Index, WitnessGain, Frequency),
            case FSPLLoss of
                {ok, Loss} -> blockchain_utils:min_rcv_sig(FSPL, TxPower) * Loss;
                _ -> blockchain_utils:min_rcv_sig(FSPL, TxPower)
            end;
        _ ->
            %% Prior to poc-v11
            blockchain_utils:min_rcv_sig(
                blockchain_utils:free_space_path_loss(ChallengeeH3Index, WitnessH3Index, Frequency)
            )
    end.

estimated_tx_power_(Frequency, FreqEirps) ->
    %% NOTE: Convert src frequency to Hz before checking freq match for EIRP value
    EIRP = eirp_from_closest_freq_(Frequency * ?MHzToHzMultiplier, FreqEirps),
    EIRP / 10.

eirp_from_closest_freq_(Frequency, [Head | Tail]) ->
    eirp_from_closest_freq_(Frequency, Tail, Head).

eirp_from_closest_freq_(_Freq, [], {_BestFreq, BestEIRP}) -> BestEIRP;
eirp_from_closest_freq_(Freq, [ {NFreq, NEirp} | Rest ], {BestFreq, BestEIRP}) ->
    case abs(Freq - NFreq) =< abs(Freq - BestFreq) of
        true ->
            eirp_from_closest_freq_(Freq, Rest, {NFreq, NEirp});
        false ->
            eirp_from_closest_freq_(Freq, Rest, {BestFreq, BestEIRP})
    end.

calc_fspl_(SourceH3Index, DestinationH3Index, DestinationGain, Frequency) ->
    %% NOTE: Transmit gain is set to 0 when calculating free_space_path_loss
    %% This is because the packet forwarder will be configured to subtract the antenna
    %% gain and miner will always transmit at region EIRP.
    GT = 0,
    GR = DestinationGain / 10,
    blockchain_utils:free_space_path_loss(SourceH3Index, DestinationH3Index, Frequency, GT, GR).

%% ------------------------------------------------------------------------------- %%
%%                             check_channels utils                                %%
%% ------------------------------------------------------------------------------- %%

recreate_beacon_channels(#{challenger := Challenger0, path := Path, secret := Secret0, request_block_hash := BlockHash0 }, #{poc_version := Version}, ChannelCount0) ->
    Secret = ?B64_TO_BIN(Secret0),
    BlockHash = ?B64_TO_BIN(BlockHash0),
    Challenger = ?B58_TO_BIN(Challenger0),
    Entropy = <<Secret/binary, BlockHash/binary, Challenger/binary>>,
    [_ | LayerData] = blockchain_txn_poc_receipts_v1:create_secret_hash(Entropy, length(Path) + 1),
    ChannelCount = case Version of
        {ok, POCVersion} when POCVersion >= 11 ->
            ChannelCount0;
        _ ->
            %% we used to assume 8 channels
            8
    end,
    Channels = recreate_beacon_channels_(ChannelCount, LayerData),
    {ok, Channels}.

recreate_beacon_channels_(ChannelCount, LayerData) ->
    lists:map(fun(Layer) ->
                      <<IntData:16/integer-unsigned-little>> = Layer,
                      IntData rem ChannelCount
              end, LayerData).

calculate_rssi_bounds_from_snr(SNR) ->
        %% keef says rounding up hurts the least
        CeilSNR = ceil(SNR),
        case maps:get(CeilSNR, ?SNR_CURVE, undefined) of
            undefined ->
                scale_unknown_snr(CeilSNR);
            V ->
                V
        end.

scale_unknown_snr(UnknownSNR) ->
    Diffs = lists:map(fun(K) -> {math:sqrt(math:pow(UnknownSNR - K, 2.0)), K} end, maps:keys(?SNR_CURVE)),
    {ScaleFactor, Key} = hd(lists:sort(Diffs)),
    {Low, High} = maps:get(Key, ?SNR_CURVE),
    {Low + (Low * ScaleFactor), High + (High * ScaleFactor)}.

find_region_params(_Region, []) -> {error, not_found};
find_region_params(Region, [{ParamRegion, Params} | Remaining]) ->
    case Region == ParamRegion of
        true -> {ok, Params};
        false -> find_region_params(Region, Remaining)
    end.

-spec bin_to_region(H3 :: h3:h3_index(),
                    RegionBins :: [{atom(), binary() | {error, any()}}]) ->
    {ok, atom()} | {error, any()}.
bin_to_region(H3, []) ->
    {error, {unknown_region, H3}};
bin_to_region(H3, [{Region, RegionBin} | RemainingBins]) ->
    case h3_in_bin(H3, RegionBin) of
        {error, Error} -> Error;
        false -> bin_to_region(H3, RemainingBins);
        true -> {ok, Region, RegionBin}
    end.

-spec h3_in_bin(
    H3 :: h3:h3_index(),
    RegionBin :: binary()
) -> boolean() | {error, any()}.
h3_in_bin(_H3, {error, _}=Error) ->
    Error;
h3_in_bin(H3, RegionBin) ->
    try h3:contains(H3, RegionBin) of
        false ->
            false;
        {true, _Parent} ->
            true
    catch
        What:Why:Stack ->
            lager:error("Unable to get region, What: ~p, Why: ~p, Stack: ~p", [What, Why, Stack]),
            {error, {h3_contains_failed, Why}}
    end.

-spec find_region(
    H3 :: h3:h3_index(),
    RegionBins :: [{atom(), binary() | {error, any()}}]
) -> atom() | {error, any()}.
find_region(H3, RegionBins) ->
    Parent = h3:parent(H3, 7),
    case bin_to_region(Parent, RegionBins) of
        {ok, Region, RegionBin} -> {ok, Region, RegionBin};
        {error, Error} ->
            lager:info("H3 to Region Error: ~p", [Error]),
            {error, Error}
    end.

get_from_rocksdb(Key, {_Name, DB, CF}, Snapshot) ->
    case rocksdb:get(DB, CF, ?B58_TO_BIN(Key), Snapshot) of
        {ok, BinGw} ->
            {ok, blockchain_ledger_gateway_v2:deserialize(BinGw)};
        not_found ->
            {error, not_found};
        Error ->
            Error
    end.

to_json(T) ->
    to_json(T, []).

to_json(T, Opts) ->
    Type = blockchain_txn:json_type(T),
    to_json(Type, T, Opts).

to_json(<<"poc_request_v1">>, T, Opts) ->
    {ledger, Ledger} = lists:keyfind(ledger, 1, Opts),
    Json = #{challenger := Challenger} = blockchain_txn:to_json(T, Opts),
    {ok, ChallengerInfo} = blockchain_ledger_v1:find_gateway_info(?B58_TO_BIN(Challenger), Ledger),
    ChallengerLoc = blockchain_ledger_gateway_v2:location(ChallengerInfo),
    ChallengerOwner = blockchain_ledger_gateway_v2:owner_address(ChallengerInfo),
    Json#{
        challenger_owner => ?BIN_TO_B58(ChallengerOwner),
        challenger_location => ?MAYBE_H3(ChallengerLoc)
    };
to_json(<<"poc_receipts_v1">>, T, Opts) ->
    {ledger, Ledger} = lists:keyfind(ledger, 1, Opts),
    Json = #{challenger := Challenger, path := Path} = blockchain_txn:to_json(T, Opts),
    UpdateWitness = fun(WitnessJson = #{gateway := Witness}) ->
        {ok, WitnessInfo} = blockchain_ledger_v1:find_gateway_info(?B58_TO_BIN(Witness), Ledger),
        WitnessLoc = blockchain_ledger_gateway_v2:location(WitnessInfo),
        WitnessJson#{
            owner => ?BIN_TO_B58(blockchain_ledger_gateway_v2:owner_address(WitnessInfo)),
            location => ?MAYBE_H3(WitnessLoc)
        }
    end,

    UpdatePath = fun(PathJson = #{challengee := Challengee, witnesses := Witnesses}) ->
        {ok, ChallengeeInfo} = blockchain_ledger_v1:find_gateway_info(
            ?B58_TO_BIN(Challengee),
            Ledger
        ),
        ChallengeeLoc = blockchain_ledger_gateway_v2:location(ChallengeeInfo),
        PathJson#{
            challengee_owner => ?BIN_TO_B58(
                blockchain_ledger_gateway_v2:owner_address(ChallengeeInfo)
            ),
            challengee_location => ?MAYBE_H3(ChallengeeLoc),
            witnesses => [UpdateWitness(W) || W <- Witnesses]
        }
    end,

    {ok, ChallengerInfo} = blockchain_ledger_v1:find_gateway_info(?B58_TO_BIN(Challenger), Ledger),
    ChallengerLoc = blockchain_ledger_gateway_v2:location(ChallengerInfo),
    Json#{
        challenger_owner => ?BIN_TO_B58(blockchain_ledger_gateway_v2:owner_address(ChallengerInfo)),
        challenger_location => ?MAYBE_H3(ChallengerLoc),
        path => [UpdatePath(E) || E <- Path]
    };
to_json(<<"state_channel_close_v1">>, T, Opts) ->
    {ledger, Ledger} = lists:keyfind(ledger, 1, Opts),
    Json = #{state_channel := SCJson} = blockchain_txn:to_json(T, Opts),
    UpdateSummary = fun(Summary = #{client := Client}) ->
        case blockchain_ledger_v1:find_gateway_info(?B58_TO_BIN(Client), Ledger) of
            {error, _} ->
                Summary;
            {ok, ClientInfo} ->
                blockchain_ledger_v1:find_gateway_info(?B58_TO_BIN(Client), Ledger),
                ClientLoc = blockchain_ledger_gateway_v2:location(ClientInfo),
                Summary#{
                    owner => ?BIN_TO_B58(blockchain_ledger_gateway_v2:owner_address(ClientInfo)),
                    location => ?MAYBE_H3(ClientLoc)
                }
        end
    end,

    Json#{
        state_channel => SCJson#{
            summaries => [UpdateSummary(S) || S <- maps:get(summaries, SCJson)]
        }
    };
to_json(<<"rewards_v2">>, T, Opts) ->
    {chain, Chain} = lists:keyfind(chain, 1, Opts),
    Start = blockchain_txn_rewards_v2:start_epoch(T),
    End = blockchain_txn_rewards_v2:end_epoch(T),
    {ok, Metadata} = be_db_reward:calculate_rewards_metadata(Start, End, Chain),
    blockchain_txn:to_json(T, Opts ++ [{rewards_metadata, Metadata}]);
to_json(_Type, T, Opts) ->
    blockchain_txn:to_json(T, Opts).
