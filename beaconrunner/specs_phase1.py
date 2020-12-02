from eth2spec.phase0 import spec as phase0
from eth2spec.config.config_util import apply_constants_config
from typing import (
    Any, Dict, Set, Sequence, NewType, Tuple, TypeVar, Callable, Optional
)
from typing import List as PyList

from dataclasses import (
    dataclass,
    field,
)

from lru import LRU

from eth2spec.utils.ssz.ssz_impl import hash_tree_root, copy, uint_to_bytes
from eth2spec.utils.ssz.ssz_typing import (
    View, boolean, Container, List, Vector, uint8, uint32, uint64, bit,
    ByteList, ByteVector, Bytes1, Bytes4, Bytes32, Bytes48, Bytes96, Bitlist, Bitvector,
)
from eth2spec.utils import bls

from eth2spec.utils.hash_function import hash

# Whenever phase 1 is loaded, make sure we have the latest phase0
from importlib import reload
reload(phase0)


SSZVariableName = str
GeneralizedIndex = NewType('GeneralizedIndex', int)
SSZObject = TypeVar('SSZObject', bound=View)

CONFIG_NAME = 'mainnet'


fork = 'phase1'



# def get_current_epoch(state: BeaconState) -> Epoch:

# def get_beacon_proposer_index(state: BeaconState) -> ValidatorIndex:

def slash_validator(state: BeaconState,
                    slashed_index: ValidatorIndex,
                    whistleblower_index: ValidatorIndex=None) -> None:
    """
    Slash the validator with index ``slashed_index``.
    """
    epoch = get_current_epoch(state)
    initiate_validator_exit(state, slashed_index)
    validator = state.validators[slashed_index]
    validator.slashed = True
    validator.withdrawable_epoch = max(validator.withdrawable_epoch, Epoch(epoch + EPOCHS_PER_SLASHINGS_VECTOR))
    state.slashings[epoch % EPOCHS_PER_SLASHINGS_VECTOR] += validator.effective_balance
    decrease_balance(state, slashed_index, validator.effective_balance // MIN_SLASHING_PENALTY_QUOTIENT)

    # Apply proposer and whistleblower rewards
    proposer_index = get_beacon_proposer_index(state)
    if whistleblower_index is None:
        whistleblower_index = proposer_index
    whistleblower_reward = Gwei(validator.effective_balance // WHISTLEBLOWER_REWARD_QUOTIENT)
    proposer_reward = Gwei(whistleblower_reward // PROPOSER_REWARD_QUOTIENT)
    increase_balance(state, proposer_index, proposer_reward)
    increase_balance(state, whistleblower_index, Gwei(whistleblower_reward - proposer_reward))




def is_valid_genesis_state(state: BeaconState) -> bool:
    if state.genesis_time < MIN_GENESIS_TIME:
        return False
    if len(get_active_validator_indices(state, GENESIS_EPOCH)) < MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
        return False
    return True


def state_transition(state: BeaconState, signed_block: SignedBeaconBlock, validate_result: bool=True) -> BeaconState:
    block = signed_block.message
    # Process slots (including those with no blocks) since block
    process_slots(state, block.slot)
    # Verify signature
    if validate_result:
        assert verify_block_signature(state, signed_block)
    # Process block
    process_block(state, block)
    # Verify state root
    if validate_result:
        assert block.state_root == hash_tree_root(state)
    # Return post-state
    return state


def verify_block_signature(state: BeaconState, signed_block: SignedBeaconBlock) -> bool:
    proposer = state.validators[signed_block.message.proposer_index]
    signing_root = compute_signing_root(signed_block.message, get_domain(state, DOMAIN_BEACON_PROPOSER))
    return bls.Verify(proposer.pubkey, signing_root, signed_block.signature)


def process_slots(state: BeaconState, slot: Slot) -> None:
    assert state.slot < slot
    while state.slot < slot:
        process_slot(state)
        # Process epoch on the start slot of the next epoch
        if (state.slot + 1) % SLOTS_PER_EPOCH == 0:
            process_epoch(state)
        state.slot = Slot(state.slot + 1)


def process_slot(state: BeaconState) -> None:
    # Cache state root
    previous_state_root = hash_tree_root(state)
    state.state_roots[state.slot % SLOTS_PER_HISTORICAL_ROOT] = previous_state_root
    # Cache latest block header state root
    if state.latest_block_header.state_root == Bytes32():
        state.latest_block_header.state_root = previous_state_root
    # Cache block root
    previous_block_root = hash_tree_root(state.latest_block_header)
    state.block_roots[state.slot % SLOTS_PER_HISTORICAL_ROOT] = previous_block_root


def process_epoch(state: BeaconState) -> None:
    process_justification_and_finalization(state)
    process_rewards_and_penalties(state)
    process_registry_updates(state)
    process_reveal_deadlines(state)
    process_challenge_deadlines(state)
    process_slashings(state)
    process_final_updates(state)  # phase 0 final updates
    process_phase_1_final_updates(state)


def get_matching_source_attestations(state: BeaconState, epoch: Epoch) -> Sequence[PendingAttestation]:
    assert epoch in (get_previous_epoch(state), get_current_epoch(state))
    return state.current_epoch_attestations if epoch == get_current_epoch(state) else state.previous_epoch_attestations


def get_matching_target_attestations(state: BeaconState, epoch: Epoch) -> Sequence[PendingAttestation]:
    return [
        a for a in get_matching_source_attestations(state, epoch)
        if a.data.target.root == get_block_root(state, epoch)
    ]


def get_matching_head_attestations(state: BeaconState, epoch: Epoch) -> Sequence[PendingAttestation]:
    return [
        a for a in get_matching_target_attestations(state, epoch)
        if a.data.beacon_block_root == get_block_root_at_slot(state, a.data.slot)
    ]


def get_unslashed_attesting_indices(state: BeaconState,
                                    attestations: Sequence[PendingAttestation]) -> Set[ValidatorIndex]:
    output = set()  # type: Set[ValidatorIndex]
    for a in attestations:
        output = output.union(get_attesting_indices(state, a.data, a.aggregation_bits))
    return set(filter(lambda index: not state.validators[index].slashed, output))


def get_attesting_balance(state: BeaconState, attestations: Sequence[PendingAttestation]) -> Gwei:
    """
    Return the combined effective balance of the set of unslashed validators participating in ``attestations``.
    Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    """
    return get_total_balance(state, get_unslashed_attesting_indices(state, attestations))


def process_justification_and_finalization(state: BeaconState) -> None:
    # Initial FFG checkpoint values have a `0x00` stub for `root`.
    # Skip FFG updates in the first two epochs to avoid corner cases that might result in modifying this stub.
    if get_current_epoch(state) <= GENESIS_EPOCH + 1:
        return

    previous_epoch = get_previous_epoch(state)
    current_epoch = get_current_epoch(state)
    old_previous_justified_checkpoint = state.previous_justified_checkpoint
    old_current_justified_checkpoint = state.current_justified_checkpoint

    # Process justifications
    state.previous_justified_checkpoint = state.current_justified_checkpoint
    state.justification_bits[1:] = state.justification_bits[:JUSTIFICATION_BITS_LENGTH - 1]
    state.justification_bits[0] = 0b0
    matching_target_attestations = get_matching_target_attestations(state, previous_epoch)  # Previous epoch
    if get_attesting_balance(state, matching_target_attestations) * 3 >= get_total_active_balance(state) * 2:
        state.current_justified_checkpoint = Checkpoint(epoch=previous_epoch,
                                                        root=get_block_root(state, previous_epoch))
        state.justification_bits[1] = 0b1
    matching_target_attestations = get_matching_target_attestations(state, current_epoch)  # Current epoch
    if get_attesting_balance(state, matching_target_attestations) * 3 >= get_total_active_balance(state) * 2:
        state.current_justified_checkpoint = Checkpoint(epoch=current_epoch,
                                                        root=get_block_root(state, current_epoch))
        state.justification_bits[0] = 0b1

    # Process finalizations
    bits = state.justification_bits
    # The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if all(bits[1:4]) and old_previous_justified_checkpoint.epoch + 3 == current_epoch:
        state.finalized_checkpoint = old_previous_justified_checkpoint
    # The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if all(bits[1:3]) and old_previous_justified_checkpoint.epoch + 2 == current_epoch:
        state.finalized_checkpoint = old_previous_justified_checkpoint
    # The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if all(bits[0:3]) and old_current_justified_checkpoint.epoch + 2 == current_epoch:
        state.finalized_checkpoint = old_current_justified_checkpoint
    # The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if all(bits[0:2]) and old_current_justified_checkpoint.epoch + 1 == current_epoch:
        state.finalized_checkpoint = old_current_justified_checkpoint


def get_base_reward(state: BeaconState, index: ValidatorIndex) -> Gwei:
    total_balance = get_total_active_balance(state)
    effective_balance = state.validators[index].effective_balance
    return Gwei(effective_balance * BASE_REWARD_FACTOR // integer_squareroot(total_balance) // BASE_REWARDS_PER_EPOCH)


def get_proposer_reward(state: BeaconState, attesting_index: ValidatorIndex) -> Gwei:
    return Gwei(get_base_reward(state, attesting_index) // PROPOSER_REWARD_QUOTIENT)


def get_finality_delay(state: BeaconState) -> uint64:
    return get_previous_epoch(state) - state.finalized_checkpoint.epoch


def is_in_inactivity_leak(state: BeaconState) -> bool:
    return get_finality_delay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY


def get_eligible_validator_indices(state: BeaconState) -> Sequence[ValidatorIndex]:
    previous_epoch = get_previous_epoch(state)
    return [
        ValidatorIndex(index) for index, v in enumerate(state.validators)
        if is_active_validator(v, previous_epoch) or (v.slashed and previous_epoch + 1 < v.withdrawable_epoch)
    ]


def get_attestation_component_deltas(state: BeaconState,
                                     attestations: Sequence[PendingAttestation]
                                     ) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Helper with shared logic for use by get source, target, and head deltas functions
    """
    rewards = [Gwei(0)] * len(state.validators)
    penalties = [Gwei(0)] * len(state.validators)
    total_balance = get_total_active_balance(state)
    unslashed_attesting_indices = get_unslashed_attesting_indices(state, attestations)
    attesting_balance = get_total_balance(state, unslashed_attesting_indices)
    for index in get_eligible_validator_indices(state):
        if index in unslashed_attesting_indices:
            increment = EFFECTIVE_BALANCE_INCREMENT  # Factored out from balance totals to avoid uint64 overflow
            if is_in_inactivity_leak(state):
                # Since full base reward will be canceled out by inactivity penalty deltas,
                # optimal participation receives full base reward compensation here.
                rewards[index] += get_base_reward(state, index)
            else:
                reward_numerator = get_base_reward(state, index) * (attesting_balance // increment)
                rewards[index] += reward_numerator // (total_balance // increment)
        else:
            penalties[index] += get_base_reward(state, index)
    return rewards, penalties


def get_source_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for source-vote for each validator.
    """
    matching_source_attestations = get_matching_source_attestations(state, get_previous_epoch(state))
    return get_attestation_component_deltas(state, matching_source_attestations)


def get_target_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for target-vote for each validator.
    """
    matching_target_attestations = get_matching_target_attestations(state, get_previous_epoch(state))
    return get_attestation_component_deltas(state, matching_target_attestations)


def get_head_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for head-vote for each validator.
    """
    matching_head_attestations = get_matching_head_attestations(state, get_previous_epoch(state))
    return get_attestation_component_deltas(state, matching_head_attestations)


def get_inclusion_delay_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return proposer and inclusion delay micro-rewards/penalties for each validator.
    """
    rewards = [Gwei(0) for _ in range(len(state.validators))]
    matching_source_attestations = get_matching_source_attestations(state, get_previous_epoch(state))
    for index in get_unslashed_attesting_indices(state, matching_source_attestations):
        attestation = min([
            a for a in matching_source_attestations
            if index in get_attesting_indices(state, a.data, a.aggregation_bits)
        ], key=lambda a: a.inclusion_delay)
        rewards[attestation.proposer_index] += get_proposer_reward(state, index)
        max_attester_reward = Gwei(get_base_reward(state, index) - get_proposer_reward(state, index))
        rewards[index] += Gwei(max_attester_reward // attestation.inclusion_delay)

    # No penalties associated with inclusion delay
    penalties = [Gwei(0) for _ in range(len(state.validators))]
    return rewards, penalties


def get_inactivity_penalty_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return inactivity reward/penalty deltas for each validator.
    """
    penalties = [Gwei(0) for _ in range(len(state.validators))]
    if is_in_inactivity_leak(state):
        matching_target_attestations = get_matching_target_attestations(state, get_previous_epoch(state))
        matching_target_attesting_indices = get_unslashed_attesting_indices(state, matching_target_attestations)
        for index in get_eligible_validator_indices(state):
            # If validator is performing optimally this cancels all rewards for a neutral balance
            base_reward = get_base_reward(state, index)
            penalties[index] += Gwei(BASE_REWARDS_PER_EPOCH * base_reward - get_proposer_reward(state, index))
            if index not in matching_target_attesting_indices:
                effective_balance = state.validators[index].effective_balance
                penalties[index] += Gwei(effective_balance * get_finality_delay(state) // INACTIVITY_PENALTY_QUOTIENT)

    # No rewards associated with inactivity penalties
    rewards = [Gwei(0) for _ in range(len(state.validators))]
    return rewards, penalties


def get_attestation_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attestation reward/penalty deltas for each validator.
    """
    source_rewards, source_penalties = get_source_deltas(state)
    target_rewards, target_penalties = get_target_deltas(state)
    head_rewards, head_penalties = get_head_deltas(state)
    inclusion_delay_rewards, _ = get_inclusion_delay_deltas(state)
    _, inactivity_penalties = get_inactivity_penalty_deltas(state)

    rewards = [
        source_rewards[i] + target_rewards[i] + head_rewards[i] + inclusion_delay_rewards[i]
        for i in range(len(state.validators))
    ]

    penalties = [
        source_penalties[i] + target_penalties[i] + head_penalties[i] + inactivity_penalties[i]
        for i in range(len(state.validators))
    ]

    return rewards, penalties

# process... code

# starts with: 
# def process_rewards_and_penalties(state: BeaconState) -> None:
#     # No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done in the previous epoch
#     if get_current_epoch(state) == GENESIS_EPOCH:
#         return

#     rewards, penalties = get_attestation_deltas(state)
#     for index in range(len(state.validators)):
#         increase_balance(state, ValidatorIndex(index), rewards[index])
#         decrease_balance(state, ValidatorIndex(index), penalties[index])





def process_block(state: BeaconState, block: BeaconBlock) -> None:
    process_block_header(state, block)
    process_randao(state, block.body)
    process_eth1_data(state, block.body)
    process_light_client_aggregate(state, block.body)
    process_operations(state, block.body)


def process_block_header(state: BeaconState, block: BeaconBlock) -> None:
    # Verify that the slots match
    assert block.slot == state.slot
    # Verify that the block is newer than latest block header
    assert block.slot > state.latest_block_header.slot
    # Verify that proposer index is the correct index
    assert block.proposer_index == get_beacon_proposer_index(state)
    # Verify that the parent matches
    assert block.parent_root == hash_tree_root(state.latest_block_header)
    # Cache current block as the new latest block
    state.latest_block_header = BeaconBlockHeader(
        slot=block.slot,
        proposer_index=block.proposer_index,
        parent_root=block.parent_root,
        state_root=Bytes32(),  # Overwritten in the next process_slot call
        body_root=hash_tree_root(block.body),
    )

    # Verify proposer is not slashed
    proposer = state.validators[block.proposer_index]
    assert not proposer.slashed


# def process_randao(state: BeaconState, body: BeaconBlockBody) -> None:

# def process_eth1_data(state: BeaconState, body: BeaconBlockBody) -> None:



def process_operations(state: BeaconState, body: BeaconBlockBody) -> None:
    # Verify that outstanding deposits are processed up to the maximum number of deposits
    assert len(body.deposits) == min(MAX_DEPOSITS, state.eth1_data.deposit_count - state.eth1_deposit_index)

    def for_ops(operations: Sequence[Any], fn: Callable[[BeaconState, Any], None]) -> None:
        for operation in operations:
            fn(state, operation)

    for_ops(body.proposer_slashings, process_proposer_slashing)
    for_ops(body.attester_slashings, process_attester_slashing)
    # New attestation processing
    for_ops(body.attestations, process_attestation)
    for_ops(body.deposits, process_deposit)
    for_ops(body.voluntary_exits, process_voluntary_exit)

    # See custody game spec.
    process_custody_game_operations(state, body)

    process_shard_transitions(state, body.shard_transitions, body.attestations)

    # TODO process_operations(body.shard_receipt_proofs, process_shard_receipt_proofs)


# def process_proposer_slashing(state: BeaconState, proposer_slashing: ProposerSlashing) -> None:

# def process_attester_slashing(state: BeaconState, attester_slashing: AttesterSlashing) -> None:


def process_attestation(state: BeaconState, attestation: Attestation) -> None:
    validate_attestation(state, attestation)
    # Store pending attestation for epoch processing
    pending_attestation = PendingAttestation(
        aggregation_bits=attestation.aggregation_bits,
        data=attestation.data,
        inclusion_delay=state.slot - attestation.data.slot,
        proposer_index=get_beacon_proposer_index(state),
        crosslink_success=False,  # To be filled in during process_shard_transitions
    )
    if attestation.data.target.epoch == get_current_epoch(state):
        state.current_epoch_attestations.append(pending_attestation)
    else:
        state.previous_epoch_attestations.append(pending_attestation)


def get_validator_from_deposit(state: BeaconState, deposit: Deposit) -> Validator:
    amount = deposit.data.amount
    effective_balance = min(amount - amount % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)
    next_custody_secret_to_reveal = get_custody_period_for_validator(
        ValidatorIndex(len(state.validators)),
        get_current_epoch(state),
    )

    return Validator(
        pubkey=deposit.data.pubkey,
        withdrawal_credentials=deposit.data.withdrawal_credentials,
        activation_eligibility_epoch=FAR_FUTURE_EPOCH,
        activation_epoch=FAR_FUTURE_EPOCH,
        exit_epoch=FAR_FUTURE_EPOCH,
        withdrawable_epoch=FAR_FUTURE_EPOCH,
        effective_balance=effective_balance,
        next_custody_secret_to_reveal=next_custody_secret_to_reveal,
        all_custody_secrets_revealed_epoch=FAR_FUTURE_EPOCH,
    )


def process_deposit(state: BeaconState, deposit: Deposit) -> None:
    # Verify the Merkle branch
    assert is_valid_merkle_branch(
        leaf=hash_tree_root(deposit.data),
        branch=deposit.proof,
        depth=DEPOSIT_CONTRACT_TREE_DEPTH + 1,  # Add 1 for the List length mix-in
        index=state.eth1_deposit_index,
        root=state.eth1_data.deposit_root,
    )

    # Deposits must be processed in order
    state.eth1_deposit_index += 1

    pubkey = deposit.data.pubkey
    amount = deposit.data.amount
    validator_pubkeys = [v.pubkey for v in state.validators]
    if pubkey not in validator_pubkeys:
        # Verify the deposit signature (proof of possession) which is not checked by the deposit contract
        deposit_message = DepositMessage(
            pubkey=deposit.data.pubkey,
            withdrawal_credentials=deposit.data.withdrawal_credentials,
            amount=deposit.data.amount,
        )
        domain = compute_domain(DOMAIN_DEPOSIT)  # Fork-agnostic domain since deposits are valid across forks
        signing_root = compute_signing_root(deposit_message, domain)
        if not bls.Verify(pubkey, signing_root, deposit.data.signature):
            return

        # Add validator and balance entries
        state.validators.append(get_validator_from_deposit(state, deposit))
        state.balances.append(amount)
    else:
        # Increase balance by deposit amount
        index = ValidatorIndex(validator_pubkeys.index(pubkey))
        increase_balance(state, index, amount)


def process_voluntary_exit(state: BeaconState, signed_voluntary_exit: SignedVoluntaryExit) -> None:
    voluntary_exit = signed_voluntary_exit.message
    validator = state.validators[voluntary_exit.validator_index]
    # Verify the validator is active
    assert is_active_validator(validator, get_current_epoch(state))
    # Verify exit has not been initiated
    assert validator.exit_epoch == FAR_FUTURE_EPOCH
    # Exits must specify an epoch when they become valid; they are not valid before then
    assert get_current_epoch(state) >= voluntary_exit.epoch
    # Verify the validator has been active long enough
    assert get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD
    # Verify signature
    domain = get_domain(state, DOMAIN_VOLUNTARY_EXIT, voluntary_exit.epoch)
    signing_root = compute_signing_root(voluntary_exit, domain)
    assert bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)
    # Initiate exit
    initiate_validator_exit(state, voluntary_exit.validator_index)


def get_forkchoice_store(anchor_state: BeaconState, anchor_block: BeaconBlock) -> Store:
    assert anchor_block.state_root == hash_tree_root(anchor_state)
    anchor_root = hash_tree_root(anchor_block)
    anchor_epoch = get_current_epoch(anchor_state)
    justified_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
    finalized_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
    return Store(
        time=anchor_state.genesis_time + SECONDS_PER_SLOT * anchor_state.slot,
        genesis_time=anchor_state.genesis_time,
        justified_checkpoint=justified_checkpoint,
        finalized_checkpoint=finalized_checkpoint,
        best_justified_checkpoint=justified_checkpoint,
        blocks={anchor_root: copy(anchor_block)},
        block_states={anchor_root: anchor_state.copy()},
        checkpoint_states={justified_checkpoint: anchor_state.copy()},
        shard_stores={
            Shard(shard): get_forkchoice_shard_store(anchor_state, Shard(shard))
            for shard in range(get_active_shard_count(anchor_state))
        }
    )


def get_slots_since_genesis(store: Store) -> int:
    return (store.time - store.genesis_time) // SECONDS_PER_SLOT


def get_current_slot(store: Store) -> Slot:
    return Slot(GENESIS_SLOT + get_slots_since_genesis(store))


def compute_slots_since_epoch_start(slot: Slot) -> int:
    return slot - compute_start_slot_at_epoch(compute_epoch_at_slot(slot))


def get_ancestor(store: Store, root: Root, slot: Slot) -> Root:
    block = store.blocks[root]
    if block.slot > slot:
        return get_ancestor(store, block.parent_root, slot)
    elif block.slot == slot:
        return root
    else:
        # root is older than queried slot, thus a skip slot. Return most recent root prior to slot
        return root


def get_latest_attesting_balance(store: Store, root: Root) -> Gwei:
    state = store.checkpoint_states[store.justified_checkpoint]
    active_indices = get_active_validator_indices(state, get_current_epoch(state))
    return Gwei(sum(
        state.validators[i].effective_balance for i in active_indices
        if (i in store.latest_messages
            and get_ancestor(store, store.latest_messages[i].root, store.blocks[root].slot) == root)
    ))


def filter_block_tree(store: Store, block_root: Root, blocks: Dict[Root, BeaconBlock]) -> bool:
    block = store.blocks[block_root]
    children = [
        root for root in store.blocks.keys()
        if store.blocks[root].parent_root == block_root
    ]

    # If any children branches contain expected finalized/justified checkpoints,
    # add to filtered block-tree and signal viability to parent.
    if any(children):
        filter_block_tree_result = [filter_block_tree(store, child, blocks) for child in children]
        if any(filter_block_tree_result):
            blocks[block_root] = block
            return True
        return False

    # If leaf block, check finalized/justified checkpoints as matching latest.
    head_state = store.block_states[block_root]

    correct_justified = (
        store.justified_checkpoint.epoch == GENESIS_EPOCH
        or head_state.current_justified_checkpoint == store.justified_checkpoint
    )
    correct_finalized = (
        store.finalized_checkpoint.epoch == GENESIS_EPOCH
        or head_state.finalized_checkpoint == store.finalized_checkpoint
    )
    # If expected finalized/justified, add to viable block-tree and signal viability to parent.
    if correct_justified and correct_finalized:
        blocks[block_root] = block
        return True

    # Otherwise, branch not viable
    return False


def get_filtered_block_tree(store: Store) -> Dict[Root, BeaconBlock]:
    """
    Retrieve a filtered block tree from ``store``, only returning branches
    whose leaf state's justified/finalized info agrees with that in ``store``.
    """
    base = store.justified_checkpoint.root
    blocks: Dict[Root, BeaconBlock] = {}
    filter_block_tree(store, base, blocks)
    return blocks


def get_head(store: Store) -> Root:
    # Get filtered block tree that only includes viable branches
    blocks = get_filtered_block_tree(store)
    # Execute the LMD-GHOST fork choice
    head = store.justified_checkpoint.root
    justified_slot = compute_start_slot_at_epoch(store.justified_checkpoint.epoch)
    while True:
        children = [
            root for root in blocks.keys()
            if blocks[root].parent_root == head and blocks[root].slot > justified_slot
        ]
        if len(children) == 0:
            return head
        # Sort by latest attesting balance with ties broken lexicographically
        head = max(children, key=lambda root: (get_latest_attesting_balance(store, root), root))


def should_update_justified_checkpoint(store: Store, new_justified_checkpoint: Checkpoint) -> bool:
    """
    To address the bouncing attack, only update conflicting justified
    checkpoints in the fork choice if in the early slots of the epoch.
    Otherwise, delay incorporation of new justified checkpoint until next epoch boundary.

    See https://ethresear.ch/t/prevention-of-bouncing-attack-on-ffg/6114 for more detailed analysis and discussion.
    """
    if compute_slots_since_epoch_start(get_current_slot(store)) < SAFE_SLOTS_TO_UPDATE_JUSTIFIED:
        return True

    justified_slot = compute_start_slot_at_epoch(store.justified_checkpoint.epoch)
    if not get_ancestor(store, new_justified_checkpoint.root, justified_slot) == store.justified_checkpoint.root:
        return False

    return True


def validate_on_attestation(store: Store, attestation: Attestation) -> None:
    target = attestation.data.target

    # Attestations must be from the current or previous epoch
    current_epoch = compute_epoch_at_slot(get_current_slot(store))
    # Use GENESIS_EPOCH for previous when genesis to avoid underflow
    previous_epoch = current_epoch - 1 if current_epoch > GENESIS_EPOCH else GENESIS_EPOCH
    # If attestation target is from a future epoch, delay consideration until the epoch arrives
    assert target.epoch in [current_epoch, previous_epoch]
    assert target.epoch == compute_epoch_at_slot(attestation.data.slot)

    # Attestations target be for a known block. If target block is unknown, delay consideration until the block is found
    assert target.root in store.blocks

    # Attestations must be for a known block. If block is unknown, delay consideration until the block is found
    assert attestation.data.beacon_block_root in store.blocks
    # Attestations must not be for blocks in the future. If not, the attestation should not be considered
    assert store.blocks[attestation.data.beacon_block_root].slot <= attestation.data.slot

    # LMD vote must be consistent with FFG vote target
    target_slot = compute_start_slot_at_epoch(target.epoch)
    assert target.root == get_ancestor(store, attestation.data.beacon_block_root, target_slot)

    # Attestations can only affect the fork choice of subsequent slots.
    # Delay consideration in the fork choice until their slot is in the past.
    assert get_current_slot(store) >= attestation.data.slot + 1


def store_target_checkpoint_state(store: Store, target: Checkpoint) -> None:
    # Store target checkpoint state if not yet seen
    if target not in store.checkpoint_states:
        base_state = copy(store.block_states[target.root])
        if base_state.slot < compute_start_slot_at_epoch(target.epoch):
            process_slots(base_state, compute_start_slot_at_epoch(target.epoch))
        store.checkpoint_states[target] = base_state


def update_latest_messages(store: Store, attesting_indices: Sequence[ValidatorIndex], attestation: Attestation) -> None:
    target = attestation.data.target
    beacon_block_root = attestation.data.beacon_block_root
    # TODO: separate shard chain vote
    shard = attestation.data.shard
    for i in attesting_indices:
        if i not in store.latest_messages or target.epoch > store.latest_messages[i].epoch:
            store.latest_messages[i] = LatestMessage(epoch=target.epoch, root=beacon_block_root)
            shard_latest_message = ShardLatestMessage(epoch=target.epoch, root=attestation.data.shard_head_root)
            store.shard_stores[shard].latest_messages[i] = shard_latest_message


def on_tick(store: Store, time: uint64) -> None:
    previous_slot = get_current_slot(store)

    # update store time
    store.time = time

    current_slot = get_current_slot(store)
    # Not a new epoch, return
    if not (current_slot > previous_slot and compute_slots_since_epoch_start(current_slot) == 0):
        return
    # Update store.justified_checkpoint if a better checkpoint is known
    if store.best_justified_checkpoint.epoch > store.justified_checkpoint.epoch:
        store.justified_checkpoint = store.best_justified_checkpoint


def on_block(store: Store, signed_block: SignedBeaconBlock) -> None:
    block = signed_block.message
    # Parent block must be known
    assert block.parent_root in store.block_states
    # Make a copy of the state to avoid mutability issues
    pre_state = copy(store.block_states[block.parent_root])
    # Blocks cannot be in the future. If they are, their consideration must be delayed until the are in the past.
    assert get_current_slot(store) >= block.slot

    # Check that block is later than the finalized epoch slot (optimization to reduce calls to get_ancestor)
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    assert block.slot > finalized_slot
    # Check block is a descendant of the finalized block at the checkpoint finalized slot
    assert get_ancestor(store, block.parent_root, finalized_slot) == store.finalized_checkpoint.root

    # Check the block is valid and compute the post-state
    state = state_transition(pre_state, signed_block, True)
    # Add new block to the store
    store.blocks[hash_tree_root(block)] = block
    # Add new state for this block to the store
    store.block_states[hash_tree_root(block)] = state

    # Update justified checkpoint
    if state.current_justified_checkpoint.epoch > store.justified_checkpoint.epoch:
        if state.current_justified_checkpoint.epoch > store.best_justified_checkpoint.epoch:
            store.best_justified_checkpoint = state.current_justified_checkpoint
        if should_update_justified_checkpoint(store, state.current_justified_checkpoint):
            store.justified_checkpoint = state.current_justified_checkpoint

    # Update finalized checkpoint
    if state.finalized_checkpoint.epoch > store.finalized_checkpoint.epoch:
        store.finalized_checkpoint = state.finalized_checkpoint

        # Potentially update justified if different from store
        if store.justified_checkpoint != state.current_justified_checkpoint:
            # Update justified if new justified is later than store justified
            if state.current_justified_checkpoint.epoch > store.justified_checkpoint.epoch:
                store.justified_checkpoint = state.current_justified_checkpoint
                return

            # Update justified if store justified is not in chain with finalized checkpoint
            finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
            ancestor_at_finalized_slot = get_ancestor(store, store.justified_checkpoint.root, finalized_slot)
            if ancestor_at_finalized_slot != store.finalized_checkpoint.root:
                store.justified_checkpoint = state.current_justified_checkpoint


def on_attestation(store: Store, attestation: Attestation) -> None:
    """
    Run ``on_attestation`` upon receiving a new ``attestation`` from either within a block or directly on the wire.

    An ``attestation`` that is asserted as invalid may be valid at a later time,
    consider scheduling it for later processing in such case.
    """
    validate_on_attestation(store, attestation)
    store_target_checkpoint_state(store, attestation.data.target)

    # Get state at the `target` to fully validate attestation
    target_state = store.checkpoint_states[attestation.data.target]
    indexed_attestation = get_indexed_attestation(target_state, attestation)
    assert is_valid_indexed_attestation(target_state, indexed_attestation)

    # Update latest messages for attesting indices
    update_latest_messages(store, indexed_attestation.attesting_indices, attestation)


def check_if_validator_active(state: BeaconState, validator_index: ValidatorIndex) -> bool:
    validator = state.validators[validator_index]
    return is_active_validator(validator, get_current_epoch(state))


# def get_committee_assignment(state: BeaconState,
#                              epoch: Epoch,
#                              validator_index: ValidatorIndex
#                              ) -> Optional[Tuple[Sequence[ValidatorIndex], CommitteeIndex, Slot]]:
#
# ...
#
# def get_aggregate_and_proof_signature(state: BeaconState,
#                                       aggregate_and_proof: AggregateAndProof,
#                                       privkey: int) -> BLSSignature:


def pack_compact_validator(index: ValidatorIndex, slashed: bool, balance_in_increments: uint64) -> uint64:
    """
    Create a compact validator object representing index, slashed status, and compressed balance.
    Takes as input balance-in-increments (// EFFECTIVE_BALANCE_INCREMENT) to preserve symmetry with
    the unpacking function.
    """
    return (index << 16) + (slashed << 15) + balance_in_increments


def unpack_compact_validator(compact_validator: uint64) -> Tuple[ValidatorIndex, bool, uint64]:
    """
    Return validator index, slashed, balance // EFFECTIVE_BALANCE_INCREMENT
    """
    return (
        ValidatorIndex(compact_validator >> 16),
        bool((compact_validator >> 15) % 2),
        compact_validator & (2**15 - 1),
    )


def committee_to_compact_committee(state: BeaconState, committee: Sequence[ValidatorIndex]) -> CompactCommittee:
    """
    Given a state and a list of validator indices, outputs the ``CompactCommittee`` representing them.
    """
    validators = [state.validators[i] for i in committee]
    compact_validators = [
        pack_compact_validator(i, v.slashed, v.effective_balance // EFFECTIVE_BALANCE_INCREMENT)
        for i, v in zip(committee, validators)
    ]
    pubkeys = [v.pubkey for v in validators]
    return CompactCommittee(pubkeys=pubkeys, compact_validators=compact_validators)


def compute_shard_from_committee_index(state: BeaconState, index: CommitteeIndex, slot: Slot) -> Shard:
    active_shards = get_active_shard_count(state)
    return Shard((index + get_start_shard(state, slot)) % active_shards)


def compute_offset_slots(start_slot: Slot, end_slot: Slot) -> Sequence[Slot]:
    """
    Return the offset slots that are greater than ``start_slot`` and less than ``end_slot``.
    """
    return [Slot(start_slot + x) for x in SHARD_BLOCK_OFFSETS if start_slot + x < end_slot]


def compute_updated_gasprice(prev_gasprice: Gwei, shard_block_length: uint64) -> Gwei:
    if shard_block_length > TARGET_SHARD_BLOCK_SIZE:
        delta = (prev_gasprice * (shard_block_length - TARGET_SHARD_BLOCK_SIZE)
                 // TARGET_SHARD_BLOCK_SIZE // GASPRICE_ADJUSTMENT_COEFFICIENT)
        return min(prev_gasprice + delta, MAX_GASPRICE)
    else:
        delta = (prev_gasprice * (TARGET_SHARD_BLOCK_SIZE - shard_block_length)
                 // TARGET_SHARD_BLOCK_SIZE // GASPRICE_ADJUSTMENT_COEFFICIENT)
        return max(prev_gasprice, MIN_GASPRICE + delta) - delta


def compute_committee_source_epoch(epoch: Epoch, period: uint64) -> Epoch:
    """
    Return the source epoch for computing the committee.
    """
    source_epoch = Epoch(epoch - epoch % period)
    if source_epoch >= period:
        source_epoch -= period  # `period` epochs lookahead
    return source_epoch


# def get_active_shard_count(state: BeaconState) -> uint64:
#     """
#     Return the number of active shards.
#     Note that this puts an upper bound on the number of committees per slot.
#     """
#     return INITIAL_ACTIVE_SHARDS


def get_online_validator_indices(state: BeaconState) -> Set[ValidatorIndex]:
    active_validators = get_active_validator_indices(state, get_current_epoch(state))
    return set(i for i in active_validators if state.online_countdown[i] != 0)  # non-duplicate


def get_shard_committee(beacon_state: BeaconState, epoch: Epoch, shard: Shard) -> Sequence[ValidatorIndex]:
    """
    Return the shard committee of the given ``epoch`` of the given ``shard``.
    """
    source_epoch = compute_committee_source_epoch(epoch, SHARD_COMMITTEE_PERIOD)
    active_validator_indices = get_active_validator_indices(beacon_state, source_epoch)
    seed = get_seed(beacon_state, source_epoch, DOMAIN_SHARD_COMMITTEE)
    return compute_committee(
        indices=active_validator_indices,
        seed=seed,
        index=shard,
        count=get_active_shard_count(beacon_state),
    )


def get_light_client_committee(beacon_state: BeaconState, epoch: Epoch) -> Sequence[ValidatorIndex]:
    """
    Return the light client committee of no more than ``LIGHT_CLIENT_COMMITTEE_SIZE`` validators.
    """
    source_epoch = compute_committee_source_epoch(epoch, LIGHT_CLIENT_COMMITTEE_PERIOD)
    active_validator_indices = get_active_validator_indices(beacon_state, source_epoch)
    seed = get_seed(beacon_state, source_epoch, DOMAIN_LIGHT_CLIENT)
    return compute_committee(
        indices=active_validator_indices,
        seed=seed,
        index=uint64(0),
        count=get_active_shard_count(beacon_state),
    )[:LIGHT_CLIENT_COMMITTEE_SIZE]


def get_shard_proposer_index(beacon_state: BeaconState, slot: Slot, shard: Shard) -> ValidatorIndex:
    """
    Return the proposer's index of shard block at ``slot``.
    """
    epoch = compute_epoch_at_slot(slot)
    committee = get_shard_committee(beacon_state, epoch, shard)
    seed = hash(get_seed(beacon_state, epoch, DOMAIN_SHARD_COMMITTEE) + uint_to_bytes(slot))
    r = bytes_to_uint64(seed[:8])
    return committee[r % len(committee)]


def get_committee_count_delta(state: BeaconState, start_slot: Slot, stop_slot: Slot) -> uint64:
    """
    Return the sum of committee counts in range ``[start_slot, stop_slot)``.
    """
    return uint64(sum(
        get_committee_count_per_slot(state, compute_epoch_at_slot(Slot(slot)))
        for slot in range(start_slot, stop_slot)
    ))


def get_start_shard(state: BeaconState, slot: Slot) -> Shard:
    """
    Return the start shard at ``slot``.
    """
    current_epoch_start_slot = compute_start_slot_at_epoch(get_current_epoch(state))
    active_shard_count = get_active_shard_count(state)
    if current_epoch_start_slot == slot:
        return state.current_epoch_start_shard
    elif slot > current_epoch_start_slot:
        # Current epoch or the next epoch lookahead
        shard_delta = get_committee_count_delta(state, start_slot=current_epoch_start_slot, stop_slot=slot)
        return Shard((state.current_epoch_start_shard + shard_delta) % active_shard_count)
    else:
        # Previous epoch
        shard_delta = get_committee_count_delta(state, start_slot=slot, stop_slot=current_epoch_start_slot)
        max_committees_per_slot = active_shard_count
        max_committees_in_span = max_committees_per_slot * (current_epoch_start_slot - slot)
        return Shard(
            # Ensure positive
            (state.current_epoch_start_shard + max_committees_in_span - shard_delta)
            % active_shard_count
        )


def get_latest_slot_for_shard(state: BeaconState, shard: Shard) -> Slot:
    """
    Return the latest slot number of the given ``shard``.
    """
    return state.shard_states[shard].slot


def get_offset_slots(state: BeaconState, shard: Shard) -> Sequence[Slot]:
    """
    Return the offset slots of the given ``shard``.
    The offset slot are after the latest slot and before current slot.
    """
    return compute_offset_slots(get_latest_slot_for_shard(state, shard), state.slot)


def is_on_time_attestation(state: BeaconState,
                           attestation_data: AttestationData) -> bool:
    """
    Check if the given ``attestation_data`` is on-time.
    """
    return attestation_data.slot == compute_previous_slot(state.slot)


def is_winning_attestation(state: BeaconState,
                           attestation: PendingAttestation,
                           committee_index: CommitteeIndex,
                           winning_root: Root) -> bool:
    """
    Check if on-time ``attestation`` helped contribute to the successful crosslink of
    ``winning_root`` formed by ``committee_index`` committee.
    """
    return (
        is_on_time_attestation(state, attestation.data)
        and attestation.data.index == committee_index
        and attestation.data.shard_transition_root == winning_root
    )


def optional_aggregate_verify(pubkeys: Sequence[BLSPubkey],
                              messages: Sequence[Bytes32],
                              signature: BLSSignature) -> bool:
    """
    If ``pubkeys`` is an empty list, the given ``signature`` should be a stub ``NO_SIGNATURE``.
    Otherwise, verify it with standard BLS AggregateVerify API.
    """
    if len(pubkeys) == 0:
        return signature == NO_SIGNATURE
    else:
        return bls.AggregateVerify(pubkeys, messages, signature)


def optional_fast_aggregate_verify(pubkeys: Sequence[BLSPubkey], message: Bytes32, signature: BLSSignature) -> bool:
    """
    If ``pubkeys`` is an empty list, the given ``signature`` should be a stub ``NO_SIGNATURE``.
    Otherwise, verify it with standard BLS FastAggregateVerify API.
    """
    if len(pubkeys) == 0:
        return signature == NO_SIGNATURE
    else:
        return bls.FastAggregateVerify(pubkeys, message, signature)


def validate_attestation(state: BeaconState, attestation: Attestation) -> None:
    data = attestation.data
    assert data.index < get_committee_count_per_slot(state, data.target.epoch)
    assert data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))
    assert data.target.epoch == compute_epoch_at_slot(data.slot)
    assert data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot <= data.slot + SLOTS_PER_EPOCH

    committee = get_beacon_committee(state, data.slot, data.index)
    assert len(attestation.aggregation_bits) == len(committee)

    if data.target.epoch == get_current_epoch(state):
        assert data.source == state.current_justified_checkpoint
    else:
        assert data.source == state.previous_justified_checkpoint

    # Type 1: on-time attestations
    if is_on_time_attestation(state, data):
        # Correct parent block root
        assert data.beacon_block_root == get_block_root_at_slot(state, compute_previous_slot(state.slot))
        # Correct shard number
        shard = compute_shard_from_committee_index(state, data.index, data.slot)
        assert data.shard == shard
        # NOTE: We currently set `PHASE_1_FORK_SLOT` to `GENESIS_SLOT` for test vectors.
        if data.slot > GENESIS_SLOT:
            # On-time attestations should have a non-empty shard transition root
            assert data.shard_transition_root != hash_tree_root(ShardTransition())
        else:
            assert data.shard_transition_root == hash_tree_root(ShardTransition())
    # Type 2: no shard transition
    else:
        # Ensure delayed attestation
        assert data.slot < compute_previous_slot(state.slot)
        # Late attestations cannot have a shard transition root
        assert data.shard_transition_root == Root()

    # Signature check
    assert is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))


def apply_shard_transition(state: BeaconState, shard: Shard, transition: ShardTransition) -> None:
    # TODO: only need to check it once when phase 1 starts
    assert state.slot > PHASE_1_FORK_SLOT

    # Correct data root count
    offset_slots = get_offset_slots(state, shard)
    assert (
        len(transition.shard_data_roots)
        == len(transition.shard_states)
        == len(transition.shard_block_lengths)
        == len(offset_slots)
    )
    assert transition.start_slot == offset_slots[0]

    headers = []
    proposers = []
    prev_gasprice = state.shard_states[shard].gasprice
    shard_parent_root = state.shard_states[shard].latest_block_root
    for i, offset_slot in enumerate(offset_slots):
        shard_block_length = transition.shard_block_lengths[i]
        shard_state = transition.shard_states[i]
        # Verify correct calculation of gas prices and slots
        assert shard_state.gasprice == compute_updated_gasprice(prev_gasprice, shard_block_length)
        assert shard_state.slot == offset_slot
        # Collect the non-empty proposals result
        is_empty_proposal = shard_block_length == 0
        if not is_empty_proposal:
            proposal_index = get_shard_proposer_index(state, offset_slot, shard)
            # Reconstruct shard headers
            header = ShardBlockHeader(
                shard_parent_root=shard_parent_root,
                beacon_parent_root=get_block_root_at_slot(state, offset_slot),
                slot=offset_slot,
                shard=shard,
                proposer_index=proposal_index,
                body_root=transition.shard_data_roots[i]
            )
            shard_parent_root = hash_tree_root(header)
            headers.append(header)
            proposers.append(proposal_index)
        else:
            # Must have a stub for `shard_data_root` if empty slot
            assert transition.shard_data_roots[i] == Root()

        prev_gasprice = shard_state.gasprice

    pubkeys = [state.validators[proposer].pubkey for proposer in proposers]
    signing_roots = [
        compute_signing_root(header, get_domain(state, DOMAIN_SHARD_PROPOSAL, compute_epoch_at_slot(header.slot)))
        for header in headers
    ]
    # Verify combined proposer signature
    assert optional_aggregate_verify(pubkeys, signing_roots, transition.proposer_signature_aggregate)

    # Copy and save updated shard state
    shard_state = copy(transition.shard_states[len(transition.shard_states) - 1])
    shard_state.slot = compute_previous_slot(state.slot)
    state.shard_states[shard] = shard_state


def process_crosslink_for_shard(state: BeaconState,
                                committee_index: CommitteeIndex,
                                shard_transition: ShardTransition,
                                attestations: Sequence[Attestation]) -> Root:
    on_time_attestation_slot = compute_previous_slot(state.slot)
    committee = get_beacon_committee(state, on_time_attestation_slot, committee_index)
    online_indices = get_online_validator_indices(state)
    shard = compute_shard_from_committee_index(state, committee_index, on_time_attestation_slot)

    # Loop over all shard transition roots
    shard_transition_roots = set([a.data.shard_transition_root for a in attestations])
    for shard_transition_root in sorted(shard_transition_roots):
        transition_attestations = [a for a in attestations if a.data.shard_transition_root == shard_transition_root]
        transition_participants: Set[ValidatorIndex] = set()
        for attestation in transition_attestations:
            participants = get_attesting_indices(state, attestation.data, attestation.aggregation_bits)
            transition_participants = transition_participants.union(participants)

        enough_online_stake = (
            get_total_balance(state, online_indices.intersection(transition_participants)) * 3 >=
            get_total_balance(state, online_indices.intersection(committee)) * 2
        )
        # If not enough stake, try next transition root
        if not enough_online_stake:
            continue

        # Attestation <-> shard transition consistency
        assert shard_transition_root == hash_tree_root(shard_transition)

        # Check `shard_head_root` of the winning root
        last_offset_index = len(shard_transition.shard_states) - 1
        shard_head_root = shard_transition.shard_states[last_offset_index].latest_block_root
        for attestation in transition_attestations:
            assert attestation.data.shard_head_root == shard_head_root

        # Apply transition
        apply_shard_transition(state, shard, shard_transition)
        # Apply proposer reward and cost
        beacon_proposer_index = get_beacon_proposer_index(state)
        estimated_attester_reward = sum([get_base_reward(state, attester) for attester in transition_participants])
        proposer_reward = Gwei(estimated_attester_reward // PROPOSER_REWARD_QUOTIENT)
        increase_balance(state, beacon_proposer_index, proposer_reward)
        states_slots_lengths = zip(
            shard_transition.shard_states,
            get_offset_slots(state, shard),
            shard_transition.shard_block_lengths
        )
        for shard_state, slot, length in states_slots_lengths:
            proposer_index = get_shard_proposer_index(state, slot, shard)
            decrease_balance(state, proposer_index, shard_state.gasprice * length)

        # Return winning transition root
        return shard_transition_root

    # No winning transition root, ensure empty and return empty root
    assert shard_transition == ShardTransition()
    return Root()


def process_crosslinks(state: BeaconState,
                       shard_transitions: Sequence[ShardTransition],
                       attestations: Sequence[Attestation]) -> None:
    on_time_attestation_slot = compute_previous_slot(state.slot)
    committee_count = get_committee_count_per_slot(state, compute_epoch_at_slot(on_time_attestation_slot))
    for committee_index in map(CommitteeIndex, range(committee_count)):
        # All attestations in the block for this committee/shard and current slot
        shard = compute_shard_from_committee_index(state, committee_index, on_time_attestation_slot)
        # Since the attestations are validated, all `shard_attestations` satisfy `attestation.data.shard == shard`
        shard_attestations = [
            attestation for attestation in attestations
            if is_on_time_attestation(state, attestation.data) and attestation.data.index == committee_index
        ]
        winning_root = process_crosslink_for_shard(
            state, committee_index, shard_transitions[shard], shard_attestations
        )
        if winning_root != Root():
            # Mark relevant pending attestations as creating a successful crosslink
            for pending_attestation in state.current_epoch_attestations:
                if is_winning_attestation(state, pending_attestation, committee_index, winning_root):
                    pending_attestation.crosslink_success = True


def verify_empty_shard_transition(state: BeaconState, shard_transitions: Sequence[ShardTransition]) -> bool:
    """
    Verify that a `shard_transition` in a block is empty if an attestation was not processed for it.
    """
    for shard in range(get_active_shard_count(state)):
        if state.shard_states[shard].slot != compute_previous_slot(state.slot):
            if shard_transitions[shard] != ShardTransition():
                return False
    return True


def process_shard_transitions(state: BeaconState,
                              shard_transitions: Sequence[ShardTransition],
                              attestations: Sequence[Attestation]) -> None:
    # NOTE: We currently set `PHASE_1_FORK_SLOT` to `GENESIS_SLOT` for test vectors.
    if compute_previous_slot(state.slot) > GENESIS_SLOT:
        # Process crosslinks
        process_crosslinks(state, shard_transitions, attestations)

    # Verify the empty proposal shard states
    assert verify_empty_shard_transition(state, shard_transitions)


def process_light_client_aggregate(state: BeaconState, block_body: BeaconBlockBody) -> None:
    committee = get_light_client_committee(state, get_current_epoch(state))
    previous_slot = compute_previous_slot(state.slot)
    previous_block_root = get_block_root_at_slot(state, previous_slot)

    total_reward = Gwei(0)
    signer_pubkeys = []
    for bit_index, participant_index in enumerate(committee):
        if block_body.light_client_bits[bit_index]:
            signer_pubkeys.append(state.validators[participant_index].pubkey)
            if not state.validators[participant_index].slashed:
                increase_balance(state, participant_index, get_base_reward(state, participant_index))
                total_reward += get_base_reward(state, participant_index)

    increase_balance(state, get_beacon_proposer_index(state), Gwei(total_reward // PROPOSER_REWARD_QUOTIENT))

    signing_root = compute_signing_root(previous_block_root,
                                        get_domain(state, DOMAIN_LIGHT_CLIENT, compute_epoch_at_slot(previous_slot)))
    assert optional_fast_aggregate_verify(signer_pubkeys, signing_root, block_body.light_client_signature)


def process_phase_1_final_updates(state: BeaconState) -> None:
    process_custody_final_updates(state)
    process_online_tracking(state)
    process_light_client_committee_updates(state)

    # Update current_epoch_start_shard
    state.current_epoch_start_shard = get_start_shard(state, Slot(state.slot + 1))


def process_online_tracking(state: BeaconState) -> None:
    # Slowly remove validators from the "online" set if they do not show up
    for index in range(len(state.validators)):
        if state.online_countdown[index] != 0:
            state.online_countdown[index] = state.online_countdown[index] - 1

    # Process pending attestations
    for pending_attestation in state.current_epoch_attestations + state.previous_epoch_attestations:
        for index in get_attesting_indices(state, pending_attestation.data, pending_attestation.aggregation_bits):
            state.online_countdown[index] = ONLINE_PERIOD


def process_light_client_committee_updates(state: BeaconState) -> None:
    """
    Update light client committees.
    """
    next_epoch = compute_epoch_at_slot(Slot(state.slot + 1))
    if next_epoch % LIGHT_CLIENT_COMMITTEE_PERIOD == 0:
        state.current_light_committee = state.next_light_committee
        new_committee = get_light_client_committee(state, next_epoch + LIGHT_CLIENT_COMMITTEE_PERIOD)
        state.next_light_committee = committee_to_compact_committee(state, new_committee)


def get_shard_winning_roots(state: BeaconState,
                            attestations: Sequence[Attestation]) -> Tuple[Sequence[Shard], Sequence[Root]]:
    shards = []
    winning_roots = []
    online_indices = get_online_validator_indices(state)
    on_time_attestation_slot = compute_previous_slot(state.slot)
    committee_count = get_committee_count_per_slot(state, compute_epoch_at_slot(on_time_attestation_slot))
    for committee_index in map(CommitteeIndex, range(committee_count)):
        shard = compute_shard_from_committee_index(state, committee_index, on_time_attestation_slot)
        # All attestations in the block for this committee/shard and are "on time"
        shard_attestations = [
            attestation for attestation in attestations
            if is_on_time_attestation(state, attestation.data) and attestation.data.index == committee_index
        ]
        committee = get_beacon_committee(state, on_time_attestation_slot, committee_index)

        # Loop over all shard transition roots, looking for a winning root
        shard_transition_roots = set(a.data.shard_transition_root for a in shard_attestations)  # non-duplicate
        for shard_transition_root in sorted(shard_transition_roots):
            transition_attestations = [
                a for a in shard_attestations
                if a.data.shard_transition_root == shard_transition_root
            ]
            transition_participants: Set[ValidatorIndex] = set()
            for attestation in transition_attestations:
                participants = get_attesting_indices(state, attestation.data, attestation.aggregation_bits)
                transition_participants = transition_participants.union(participants)

            enough_online_stake = (
                get_total_balance(state, online_indices.intersection(transition_participants)) * 3 >=
                get_total_balance(state, online_indices.intersection(committee)) * 2
            )
            if enough_online_stake:
                shards.append(shard)
                winning_roots.append(shard_transition_root)
                break

    return shards, winning_roots


def get_best_light_client_aggregate(block: BeaconBlock,
                                    aggregates: Sequence[LightClientVote]) -> LightClientVote:
    viable_aggregates = [
        aggregate for aggregate in aggregates
        if (
            aggregate.data.slot == compute_previous_slot(block.slot)
            and aggregate.data.beacon_block_root == block.parent_root
        )
    ]

    return max(
        viable_aggregates,
        # Ties broken by lexicographically by hash_tree_root
        key=lambda a: (len([i for i in a.aggregation_bits if i == 1]), hash_tree_root(a)),
        default=LightClientVote(),
    )


def get_shard_transition_fields(
    beacon_state: BeaconState,
    shard: Shard,
    shard_blocks: Sequence[SignedShardBlock],
) -> Tuple[Sequence[uint64], Sequence[Root], Sequence[ShardState]]:
    shard_block_lengths = []  # type: PyList[uint64]
    shard_data_roots = []  # type: PyList[Root]
    shard_states = []  # type: PyList[ShardState]

    shard_state = beacon_state.shard_states[shard]
    shard_block_slots = [shard_block.message.slot for shard_block in shard_blocks]
    offset_slots = compute_offset_slots(
        get_latest_slot_for_shard(beacon_state, shard),
        Slot(beacon_state.slot + 1),
    )
    for slot in offset_slots:
        if slot in shard_block_slots:
            shard_block = shard_blocks[shard_block_slots.index(slot)]
            shard_data_roots.append(hash_tree_root(shard_block.message.body))
        else:
            shard_block = SignedShardBlock(message=ShardBlock(slot=slot, shard=shard))
            shard_data_roots.append(Root())
        shard_state = shard_state.copy()
        process_shard_block(shard_state, shard_block.message)
        shard_states.append(shard_state)
        shard_block_lengths.append(uint64(len(shard_block.message.body)))

    return shard_block_lengths, shard_data_roots, shard_states


def get_shard_transition(beacon_state: BeaconState,
                         shard: Shard,
                         shard_blocks: Sequence[SignedShardBlock]) -> ShardTransition:
    # NOTE: We currently set `PHASE_1_FORK_SLOT` to `GENESIS_SLOT` for test vectors.
    if beacon_state.slot == GENESIS_SLOT:
        return ShardTransition()

    offset_slots = compute_offset_slots(
        get_latest_slot_for_shard(beacon_state, shard),
        Slot(beacon_state.slot + 1),
    )
    shard_block_lengths, shard_data_roots, shard_states = (
        get_shard_transition_fields(beacon_state, shard, shard_blocks)
    )

    if len(shard_blocks) > 0:
        proposer_signatures = [shard_block.signature for shard_block in shard_blocks]
        proposer_signature_aggregate = bls.Aggregate(proposer_signatures)
    else:
        proposer_signature_aggregate = NO_SIGNATURE

    return ShardTransition(
        start_slot=offset_slots[0],
        shard_block_lengths=shard_block_lengths,
        shard_data_roots=shard_data_roots,
        shard_states=shard_states,
        proposer_signature_aggregate=proposer_signature_aggregate,
    )


def is_in_next_light_client_committee(state: BeaconState, index: ValidatorIndex) -> bool:
    next_committee = get_light_client_committee(state, get_current_epoch(state) + LIGHT_CLIENT_COMMITTEE_PERIOD)
    return index in next_committee


def get_light_client_vote_signature(state: BeaconState,
                                    light_client_vote_data: LightClientVoteData,
                                    privkey: int) -> BLSSignature:
    domain = get_domain(state, DOMAIN_LIGHT_CLIENT, compute_epoch_at_slot(light_client_vote_data.slot))
    signing_root = compute_signing_root(light_client_vote_data, domain)
    return bls.Sign(privkey, signing_root)


def get_light_client_slot_signature(state: BeaconState, slot: Slot, privkey: int) -> BLSSignature:
    domain = get_domain(state, DOMAIN_LIGHT_SELECTION_PROOF, compute_epoch_at_slot(slot))
    signing_root = compute_signing_root(slot, domain)
    return bls.Sign(privkey, signing_root)


def is_light_client_aggregator(state: BeaconState, slot: Slot, slot_signature: BLSSignature) -> bool:
    committee = get_light_client_committee(state, compute_epoch_at_slot(slot))
    modulo = max(1, len(committee) // TARGET_LIGHT_CLIENT_AGGREGATORS_PER_SLOT)
    return bytes_to_uint64(hash(slot_signature)[0:8]) % modulo == 0


def get_aggregate_light_client_signature(light_client_votes: Sequence[LightClientVote]) -> BLSSignature:
    signatures = [light_client_vote.signature for light_client_vote in light_client_votes]
    return bls.Aggregate(signatures)


def get_light_aggregate_and_proof(state: BeaconState,
                                  aggregator_index: ValidatorIndex,
                                  aggregate: LightClientVote,
                                  privkey: int) -> LightAggregateAndProof:
    return LightAggregateAndProof(
        aggregator_index=aggregator_index,
        aggregate=aggregate,
        selection_proof=get_light_client_slot_signature(state, aggregate.data.slot, privkey),
    )


def get_light_aggregate_and_proof_signature(state: BeaconState,
                                            aggregate_and_proof: LightAggregateAndProof,
                                            privkey: int) -> BLSSignature:
    aggregate = aggregate_and_proof.aggregate
    domain = get_domain(state, DOMAIN_LIGHT_AGGREGATE_AND_PROOF, compute_epoch_at_slot(aggregate.data.slot))
    signing_root = compute_signing_root(aggregate_and_proof, domain)
    return bls.Sign(privkey, signing_root)


def get_custody_secret(state: BeaconState,
                       validator_index: ValidatorIndex,
                       privkey: int,
                       epoch: Epoch=None) -> BLSSignature:
    if epoch is None:
        epoch = get_current_epoch(state)
    period = get_custody_period_for_validator(validator_index, epoch)
    epoch_to_sign = get_randao_epoch_for_custody_period(period, validator_index)
    domain = get_domain(state, DOMAIN_RANDAO, epoch_to_sign)
    signing_root = compute_signing_root(Epoch(epoch_to_sign), domain)
    return bls.Sign(privkey, signing_root)


def verify_shard_block_message(beacon_parent_state: BeaconState,
                               shard_parent_state: ShardState,
                               block: ShardBlock) -> bool:
    # Check `shard_parent_root` field
    assert block.shard_parent_root == shard_parent_state.latest_block_root
    # Check `beacon_parent_root` field
    beacon_parent_block_header = beacon_parent_state.latest_block_header.copy()
    if beacon_parent_block_header.state_root == Root():
        beacon_parent_block_header.state_root = hash_tree_root(beacon_parent_state)
    beacon_parent_root = hash_tree_root(beacon_parent_block_header)
    assert block.beacon_parent_root == beacon_parent_root
    # Check `slot` field
    shard = block.shard
    next_slot = Slot(block.slot + 1)
    offset_slots = compute_offset_slots(get_latest_slot_for_shard(beacon_parent_state, shard), next_slot)
    assert block.slot in offset_slots
    # Check `proposer_index` field
    assert block.proposer_index == get_shard_proposer_index(beacon_parent_state, block.slot, shard)
    # Check `body` field
    assert 0 < len(block.body) <= MAX_SHARD_BLOCK_SIZE
    return True


def verify_shard_block_signature(beacon_parent_state: BeaconState,
                                 signed_block: SignedShardBlock) -> bool:
    proposer = beacon_parent_state.validators[signed_block.message.proposer_index]
    domain = get_domain(beacon_parent_state, DOMAIN_SHARD_PROPOSAL, compute_epoch_at_slot(signed_block.message.slot))
    signing_root = compute_signing_root(signed_block.message, domain)
    return bls.Verify(proposer.pubkey, signing_root, signed_block.signature)


def shard_state_transition(shard_state: ShardState,
                           signed_block: SignedShardBlock,
                           beacon_parent_state: BeaconState,
                           validate_result: bool = True) -> ShardState:
    assert verify_shard_block_message(beacon_parent_state, shard_state, signed_block.message)

    if validate_result:
        assert verify_shard_block_signature(beacon_parent_state, signed_block)

    process_shard_block(shard_state, signed_block.message)
    return shard_state


def process_shard_block(shard_state: ShardState,
                        block: ShardBlock) -> None:
    """
    Update ``shard_state`` with shard ``block``.
    """
    shard_state.slot = block.slot
    prev_gasprice = shard_state.gasprice
    shard_block_length = len(block.body)
    shard_state.gasprice = compute_updated_gasprice(prev_gasprice, uint64(shard_block_length))
    if shard_block_length != 0:
        shard_state.latest_block_root = hash_tree_root(block)


def is_valid_fraud_proof(beacon_state: BeaconState,
                         attestation: Attestation,
                         offset_index: uint64,
                         transition: ShardTransition,
                         block: ShardBlock,
                         subkey: BLSPubkey,
                         beacon_parent_block: BeaconBlock) -> bool:
    # 1. Check if `custody_bits[offset_index][j] != generate_custody_bit(subkey, block_contents)` for any `j`.
    custody_bits = attestation.custody_bits_blocks
    for j in range(len(custody_bits[offset_index])):
        if custody_bits[offset_index][j] != generate_custody_bit(subkey, block):
            return True

    # 2. Check if the shard state transition result is wrong between
    # `transition.shard_states[offset_index - 1]` to `transition.shard_states[offset_index]`.
    if offset_index == 0:
        shard_states = beacon_parent_block.body.shard_transitions[attestation.data.shard].shard_states
        shard_state = shard_states[len(shard_states) - 1]
    else:
        shard_state = transition.shard_states[offset_index - 1]  # Not doing the actual state updates here.

    process_shard_block(shard_state, block)
    if shard_state != transition.shard_states[offset_index]:
        return True

    return False


def generate_custody_bit(subkey: BLSPubkey, block: ShardBlock) -> bool:
    # TODO
    ...


def get_forkchoice_shard_store(anchor_state: BeaconState, shard: Shard) -> ShardStore:
    return ShardStore(
        shard=shard,
        signed_blocks={
            anchor_state.shard_states[shard].latest_block_root: SignedShardBlock(
                message=ShardBlock(slot=compute_previous_slot(anchor_state.slot), shard=shard)
            )
        },
        block_states={anchor_state.shard_states[shard].latest_block_root: anchor_state.copy().shard_states[shard]},
    )


def get_shard_latest_attesting_balance(store: Store, shard: Shard, root: Root) -> Gwei:
    shard_store = store.shard_stores[shard]
    state = store.checkpoint_states[store.justified_checkpoint]
    active_indices = get_active_validator_indices(state, get_current_epoch(state))
    return Gwei(sum(
        state.validators[i].effective_balance for i in active_indices
        if (
            i in shard_store.latest_messages
            # TODO: check the latest message logic: currently, validator's previous vote of another shard
            # would be ignored once their newer vote is accepted. Check if it makes sense.
            and get_shard_ancestor(
                store,
                shard,
                shard_store.latest_messages[i].root,
                shard_store.signed_blocks[root].message.slot,
            ) == root
        )
    ))


def get_shard_head(store: Store, shard: Shard) -> Root:
    # Execute the LMD-GHOST fork choice
    """
    Execute the LMD-GHOST fork choice.
    """
    shard_store = store.shard_stores[shard]
    beacon_head_root = get_head(store)
    shard_head_state = store.block_states[beacon_head_root].shard_states[shard]
    shard_head_root = shard_head_state.latest_block_root
    shard_blocks = {
        root: signed_shard_block.message for root, signed_shard_block in shard_store.signed_blocks.items()
        if signed_shard_block.message.slot > shard_head_state.slot
    }
    while True:
        # Find the valid child block roots
        children = [
            root for root, shard_block in shard_blocks.items()
            if shard_block.shard_parent_root == shard_head_root
        ]
        if len(children) == 0:
            return shard_head_root
        # Sort by latest attesting balance with ties broken lexicographically
        shard_head_root = max(
            children, key=lambda root: (get_shard_latest_attesting_balance(store, shard, root), root)
        )


def get_shard_ancestor(store: Store, shard: Shard, root: Root, slot: Slot) -> Root:
    shard_store = store.shard_stores[shard]
    block = shard_store.signed_blocks[root].message
    if block.slot > slot:
        return get_shard_ancestor(store, shard, block.shard_parent_root, slot)
    elif block.slot == slot:
        return root
    else:
        # root is older than queried slot, thus a skip slot. Return most recent root prior to slot
        return root


def get_pending_shard_blocks(store: Store, shard: Shard) -> Sequence[SignedShardBlock]:
    """
    Return the canonical shard block branch that has not yet been crosslinked.
    """
    shard_store = store.shard_stores[shard]

    beacon_head_root = get_head(store)
    beacon_head_state = store.block_states[beacon_head_root]
    latest_shard_block_root = beacon_head_state.shard_states[shard].latest_block_root

    shard_head_root = get_shard_head(store, shard)
    root = shard_head_root
    signed_shard_blocks = []
    while root != latest_shard_block_root:
        signed_shard_block = shard_store.signed_blocks[root]
        signed_shard_blocks.append(signed_shard_block)
        root = signed_shard_block.message.shard_parent_root

    signed_shard_blocks.reverse()
    return signed_shard_blocks


def on_shard_block(store: Store, signed_shard_block: SignedShardBlock) -> None:
    shard_block = signed_shard_block.message
    shard = shard_block.shard
    shard_store = store.shard_stores[shard]

    # Check shard parent exists
    assert shard_block.shard_parent_root in shard_store.block_states
    shard_parent_state = shard_store.block_states[shard_block.shard_parent_root]

    # Check beacon parent exists
    assert shard_block.beacon_parent_root in store.block_states
    beacon_parent_state = store.block_states[shard_block.beacon_parent_root]

    # Check that block is later than the finalized shard state slot (optimization to reduce calls to get_ancestor)
    finalized_beacon_state = store.block_states[store.finalized_checkpoint.root]
    finalized_shard_state = finalized_beacon_state.shard_states[shard]
    assert shard_block.slot > finalized_shard_state.slot

    # Check block is a descendant of the finalized block at the checkpoint finalized slot
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    assert (
        get_ancestor(store, shard_block.beacon_parent_root, finalized_slot) == store.finalized_checkpoint.root
    )

    # Check the block is valid and compute the post-state
    shard_state = shard_parent_state.copy()
    shard_state_transition(shard_state, signed_shard_block, beacon_parent_state, validate_result=True)

    # Add new block to the store
    # Note: storing `SignedShardBlock` format for computing `ShardTransition.proposer_signature_aggregate`
    shard_store.signed_blocks[hash_tree_root(shard_block)] = signed_shard_block

    # Add new state for this block to the store
    shard_store.block_states[hash_tree_root(shard_block)] = shard_state


# def replace_empty_or_append(l: List, new_element: Any) -> int:

def legendre_bit(a: int, q: int) -> int:
    if a >= q:
        return legendre_bit(a % q, q)
    if a == 0:
        return 0
    assert(q > a > 0 and q % 2 == 1)
    t = 1
    n = q
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = n % 8
            if r == 3 or r == 5:
                t = -t
        a, n = n, a
        if a % 4 == n % 4 == 3:
            t = -t
        a %= n
    if n == 1:
        return (t + 1) // 2
    else:
        return 0


def get_custody_atoms(bytez: bytes) -> Sequence[bytes]:
    length_remainder = len(bytez) % BYTES_PER_CUSTODY_ATOM
    bytez += b'\x00' * ((BYTES_PER_CUSTODY_ATOM - length_remainder) % BYTES_PER_CUSTODY_ATOM)  # right-padding
    return [
        bytez[i:i + BYTES_PER_CUSTODY_ATOM]
        for i in range(0, len(bytez), BYTES_PER_CUSTODY_ATOM)
    ]


def get_custody_secrets(key: BLSSignature) -> Sequence[int]:
    full_G2_element = bls.signature_to_G2(key)
    signature = full_G2_element[0].coeffs
    signature_bytes = b"".join(x.to_bytes(48, "little") for x in signature)
    secrets = [int.from_bytes(signature_bytes[i:i + BYTES_PER_CUSTODY_ATOM], "little")
               for i in range(0, len(signature_bytes), 32)]
    return secrets


def universal_hash_function(data_chunks: Sequence[bytes], secrets: Sequence[int]) -> int:
    n = len(data_chunks)
    return (
        sum(
            secrets[i % CUSTODY_SECRETS]**i * int.from_bytes(atom, "little") % CUSTODY_PRIME
            for i, atom in enumerate(data_chunks)
        ) + secrets[n % CUSTODY_SECRETS]**n
    ) % CUSTODY_PRIME


def compute_custody_bit(key: BLSSignature, data: ByteList) -> bit:
    custody_atoms = get_custody_atoms(data)
    secrets = get_custody_secrets(key)
    uhf = universal_hash_function(custody_atoms, secrets)
    legendre_bits = [legendre_bit(uhf + secrets[0] + i, CUSTODY_PRIME) for i in range(CUSTODY_PROBABILITY_EXPONENT)]
    return bit(all(legendre_bits))


def get_randao_epoch_for_custody_period(period: uint64, validator_index: ValidatorIndex) -> Epoch:
    next_period_start = (period + 1) * EPOCHS_PER_CUSTODY_PERIOD - validator_index % EPOCHS_PER_CUSTODY_PERIOD
    return Epoch(next_period_start + CUSTODY_PERIOD_TO_RANDAO_PADDING)


def get_custody_period_for_validator(validator_index: ValidatorIndex, epoch: Epoch) -> uint64:
    '''
    Return the reveal period for a given validator.
    '''
    return (epoch + validator_index % EPOCHS_PER_CUSTODY_PERIOD) // EPOCHS_PER_CUSTODY_PERIOD


# def process_custody_game_operations(state: BeaconState, body: BeaconBlockBody) -> None:


def process_custody_key_reveal(state: BeaconState, reveal: CustodyKeyReveal) -> None:
    """
    Process ``CustodyKeyReveal`` operation.
    Note that this function mutates ``state``.
    """
    revealer = state.validators[reveal.revealer_index]
    epoch_to_sign = get_randao_epoch_for_custody_period(revealer.next_custody_secret_to_reveal, reveal.revealer_index)

    custody_reveal_period = get_custody_period_for_validator(reveal.revealer_index, get_current_epoch(state))
    # Only past custody periods can be revealed, except after exiting the exit period can be revealed
    is_past_reveal = revealer.next_custody_secret_to_reveal < custody_reveal_period
    is_exited = revealer.exit_epoch <= get_current_epoch(state)
    is_exit_period_reveal = (
        revealer.next_custody_secret_to_reveal
        == get_custody_period_for_validator(reveal.revealer_index, revealer.exit_epoch - 1)
    )
    assert is_past_reveal or (is_exited and is_exit_period_reveal)

    # Revealed validator is active or exited, but not withdrawn
    assert is_slashable_validator(revealer, get_current_epoch(state))

    # Verify signature
    domain = get_domain(state, DOMAIN_RANDAO, epoch_to_sign)
    signing_root = compute_signing_root(epoch_to_sign, domain)
    assert bls.Verify(revealer.pubkey, signing_root, reveal.reveal)

    # Process reveal
    if is_exited and is_exit_period_reveal:
        revealer.all_custody_secrets_revealed_epoch = get_current_epoch(state)
    revealer.next_custody_secret_to_reveal += 1

    # Reward Block Proposer
    proposer_index = get_beacon_proposer_index(state)
    increase_balance(
        state,
        proposer_index,
        Gwei(get_base_reward(state, reveal.revealer_index) // MINOR_REWARD_QUOTIENT)
    )


def process_early_derived_secret_reveal(state: BeaconState, reveal: EarlyDerivedSecretReveal) -> None:
    """
    Process ``EarlyDerivedSecretReveal`` operation.
    Note that this function mutates ``state``.
    """
    revealed_validator = state.validators[reveal.revealed_index]
    derived_secret_location = uint64(reveal.epoch % EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS)

    assert reveal.epoch >= get_current_epoch(state) + RANDAO_PENALTY_EPOCHS
    assert reveal.epoch < get_current_epoch(state) + EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS
    assert not revealed_validator.slashed
    assert reveal.revealed_index not in state.exposed_derived_secrets[derived_secret_location]

    # Verify signature correctness
    masker = state.validators[reveal.masker_index]
    pubkeys = [revealed_validator.pubkey, masker.pubkey]

    domain = get_domain(state, DOMAIN_RANDAO, reveal.epoch)
    signing_roots = [compute_signing_root(root, domain) for root in [hash_tree_root(reveal.epoch), reveal.mask]]
    assert bls.AggregateVerify(pubkeys, signing_roots, reveal.reveal)

    if reveal.epoch >= get_current_epoch(state) + CUSTODY_PERIOD_TO_RANDAO_PADDING:
        # Full slashing when the secret was revealed so early it may be a valid custody
        # round key
        slash_validator(state, reveal.revealed_index, reveal.masker_index)
    else:
        # Only a small penalty proportional to proposer slot reward for RANDAO reveal
        # that does not interfere with the custody period
        # The penalty is proportional to the max proposer reward

        # Calculate penalty
        max_proposer_slot_reward = (
            get_base_reward(state, reveal.revealed_index)
            * SLOTS_PER_EPOCH
            // len(get_active_validator_indices(state, get_current_epoch(state)))
            // PROPOSER_REWARD_QUOTIENT
        )
        penalty = Gwei(
            max_proposer_slot_reward
            * EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE
            * (len(state.exposed_derived_secrets[derived_secret_location]) + 1)
        )

        # Apply penalty
        proposer_index = get_beacon_proposer_index(state)
        whistleblower_index = reveal.masker_index
        whistleblowing_reward = Gwei(penalty // WHISTLEBLOWER_REWARD_QUOTIENT)
        proposer_reward = Gwei(whistleblowing_reward // PROPOSER_REWARD_QUOTIENT)
        increase_balance(state, proposer_index, proposer_reward)
        increase_balance(state, whistleblower_index, whistleblowing_reward - proposer_reward)
        decrease_balance(state, reveal.revealed_index, penalty)

        # Mark this derived secret as exposed so validator cannot be punished repeatedly
        state.exposed_derived_secrets[derived_secret_location].append(reveal.revealed_index)


# def process_custody_slashing(state: BeaconState, signed_custody_slashing: SignedCustodySlashing) -> None:

def process_reveal_deadlines(state: BeaconState) -> None:
    epoch = get_current_epoch(state)
    for index, validator in enumerate(state.validators):
        deadline = validator.next_custody_secret_to_reveal + 1
        if get_custody_period_for_validator(ValidatorIndex(index), epoch) > deadline:
            slash_validator(state, ValidatorIndex(index))

# def process_custody_slashing(state: BeaconState, signed_custody_slashing: SignedCustodySlashing) -> None:

def process_custody_final_updates(state: BeaconState) -> None:
    # Clean up exposed RANDAO key reveals
    state.exposed_derived_secrets[get_current_epoch(state) % EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS] = []

    # Reset withdrawable epochs if challenge records are empty
    records = state.custody_chunk_challenge_records
    validator_indices_in_records = set(record.responder_index for record in records)  # non-duplicate
    for index, validator in enumerate(state.validators):
        if validator.exit_epoch != FAR_FUTURE_EPOCH:
            not_all_secrets_are_revealed = validator.all_custody_secrets_revealed_epoch == FAR_FUTURE_EPOCH
            if index in validator_indices_in_records or not_all_secrets_are_revealed:
                # Delay withdrawable epochs if challenge records are not empty or not all
                # custody secrets revealed
                validator.withdrawable_epoch = FAR_FUTURE_EPOCH
            else:
                # Reset withdrawable epochs if challenge records are empty and all secrets are revealed
                if validator.withdrawable_epoch == FAR_FUTURE_EPOCH:
                    validator.withdrawable_epoch = Epoch(validator.all_custody_secrets_revealed_epoch
                                                         + MIN_VALIDATOR_WITHDRAWABILITY_DELAY)



