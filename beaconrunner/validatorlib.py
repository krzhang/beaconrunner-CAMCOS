import time
import random
import itertools

from typing import Set, Optional, Sequence, Tuple, Dict, Text
from dataclasses import dataclass, field

from .specs import (
    Slot, Root, Epoch, CommitteeIndex, ValidatorIndex, Store,
    BeaconState, BeaconBlock, BeaconBlockBody, SignedBeaconBlock,
    Attestation, AttestationData, Checkpoint, BLSSignature,
    CustodyChunkChallenge, CustodyChunkResponse, CustodySlashing, MAX_CUSTODY_SLASHINGS,
    MAX_VALIDATORS_PER_COMMITTEE, VALIDATOR_REGISTRY_LIMIT,
    SLOTS_PER_EPOCH, DOMAIN_RANDAO, DOMAIN_BEACON_PROPOSER,
    DOMAIN_BEACON_ATTESTER, MAX_CUSTODY_CHUNK_CHALLENGES, SECONDS_PER_SLOT, 
    get_forkchoice_store, get_current_slot, compute_epoch_at_slot,
    get_head, process_slots, on_tick, get_current_epoch,
    get_committee_assignment, compute_start_slot_at_epoch,
    get_block_root, process_block, process_attestation,
    process_chunk_challenge_response,
    get_block_root_at_slot, get_beacon_proposer_index,
    get_domain, compute_signing_root, state_transition,
    on_block, on_attestation,
)

from eth2spec.utils.ssz.ssz_impl import hash_tree_root
from eth2spec.utils.ssz.ssz_typing import Container, List, uint64
from eth2spec.test.helpers.keys import pubkeys, pubkey_to_privkey

frequency = 1
assert frequency in [1, 10, 100, 1000]

def index_from_attestation(attestation):
    """ Given an attestation, return the committee index and thus its author."""
    bits = attestation.aggregation_bits
    return bits.index(True)

class ValidatorMove(object):
    """
    Internal class recording validator moves: messages sent over the wire by the validator.
    Useful e.g. to avoid double-sending an attestation.
    """

    time: uint64
    """Simulation time (in ms) when move was made."""

    slot: Slot
    """Slot where move was made."""

    move: str
    """Type of move. Currently either 'attest' or 'propose'"""

    def __init__(self, time, slot, move):
        """Initialise ValidatorMove"""

        self.time = time
        self.slot = slot
        self.move = move

class ValidatorData:
    """
    Holds current validator data, to be consumed by BRValidator subclasses.
    """
    slot: Slot
    """Current slot"""

    time_ms: uint64
    """Current simulation time in milliseconds"""

    head_root: Root
    """Current head root, returned by `get_head` on validator's `Store`"""

    current_epoch: Epoch
    """Current epoch"""

    current_attest_slot: Slot
    """Last computed slot to attest in the current epoch"""

    current_committee_index: CommitteeIndex
    """Last computed committee index to attest in the current epoch"""

    current_committee: List[ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE]
    """Last computed committee to attest in the current epoch"""

    next_attest_slot: Slot
    """Last computed slot to attest in the next epoch"""

    next_committee_index: CommitteeIndex
    """Last computed committee index to attest in the next epoch"""

    next_committee: List[ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE]
    """Last computed committee to attest in the next epoch"""

    last_slot_attested: Optional[Slot]
    """
    Last slot where validator attested. Possibly we have
    `self.slot == self.last_slot_attested`
    """

    current_proposer_duties: Sequence[bool]
    """
    For the next SLOTS_PER_EPOCH, up to the beginning of a new epoch,
    is the validator a block proposer?
    """

    last_slot_proposed: Optional[Slot]
    """
    Last slot where validator proposed a block. Possibly we have
    `self.slot == self.last_slot_proposed`
    """

    recorded_attestations: List[Root, VALIDATOR_REGISTRY_LIMIT]
    """
    Hash roots of `Store` recorded attestations. Used for internal cache.
    """

    received_block: bool
    """
    Has the validator received a block for `self.slot`?
    """

    # custody game

    # chunk_challenges_accusations: List[CustodyChunkChallenge]

    # TypeError: cannot unpack non-iterable TypeDefMeta object

    # accusations = *being* challenged

    # chunk_challenge_sent   # different concept from above
    
    # chunk_responses_sent: List[CustodyChunkResponse]

    challenged_attestations: List[Attestation, VALIDATOR_REGISTRY_LIMIT]
    
    sent_bit_challenges: List[CustodySlashing, VALIDATOR_REGISTRY_LIMIT]

class HashableSpecStore(Container):
    """ We cache a map from current state of the `Store` to `head`, since `get_head`
    is computationally intensive. But `Store` is not hashable right off the bat.
    `get_head` only depends on stored blocks and latest messages, so we use that here.
    """

    recorded_attestations: List[Root, VALIDATOR_REGISTRY_LIMIT]
    """Recorded attestations in the `Store`"""

    recorded_blocks: List[Root, VALIDATOR_REGISTRY_LIMIT]
    """Recorded blocks in the `Store`"""

class BRValidator:
    """
    Abstract superclass from which validator behaviours inherit.
    Defines and maintains environment accessor functions (is the validator an attester? proposer?)
    Performs caching to avoid recomputing expensive operations.

    In general, you are not expected to use any of the methods or attributes defined here, _except_
    for `validator.data`, which exposes current simulation environment properties, up-to-date with
    respect to the validator (e.g., proposer and attester duties).

    Subclasses of `BRValidator` must define at least two methods:

    - `attest(self, known_items) -> Optional[Attestation]`
    - `propose(self, known_items) -> Optional[Attestation]`
    """

    validator_index: ValidatorIndex
    """Validator index in the simulation."""

    pubkey: int
    """Validator public key."""

    privkey: int
    """Validator private key."""

    store: Store
    """`Store` objects are defined in the specs."""

    history: List[ValidatorMove, VALIDATOR_REGISTRY_LIMIT]
    """History of `ValidatorMove` by the validator."""

    data: ValidatorData
    """Current validator data. Maintained by the `BRValidator` methods."""

    head_store: Dict[Root, Root] = {}
    """
    Static cache for expensive operations.
    `head_store` stores a map from store hash to head root.
    """

    state_store: Dict[Tuple[Root, Slot], BeaconState] = {}
    """
    Static cache for expensive operations.
    `state_store` stores a map from `(current_state_hash, to_slot)` calling
    `process_slots(current_state, to_slot)`.
    """

    utility: uint64
    
    def __init__(self, validator_index: ValidatorIndex,
                 attest_func=None,
                 propose_func=None,
                 chunk_response_func=None,
                 bit_challenge_func=None):
        """
        Validator constructor
        We preload a bunch of things, to be updated later on as needed
        The validator is initialised from some base state, and given a `validator_index`
        """

        self.validator_index = validator_index
        self.pubkey = pubkeys[validator_index]
        self.privkey = pubkey_to_privkey[self.pubkey].to_bytes(32, 'big')

        self.history = []

        self.data = ValidatorData()

        self.chunk_challenges_accusations = []
        self.chunk_responses_sent = []

        # self.attest = honest_attest_asap
        # self.propose = honest_propose
        # self.chunk_response = honest_chunk_challenge_response
        # self.bit_challenge = honest_bit_challenge
        
        self.attest = attest_func
        self.propose = propose_func
        self.chunk_response = chunk_response_func
        self.bit_challenge = bit_challenge_func

        self.utility = 0
        
        self.validator_behavior = [attest_func.__name__,
                                   propose_func.__name__,
                                   chunk_response_func.__name__,
                                   bit_challenge_func.__name__]

    def load_state(self, state: BeaconState) -> None:
        """
        """

        # TODO: need to put a lot of stuff here whenever we update simulator spec
        
        self.store = get_forkchoice_store(state.copy())

        self.data.time_ms = self.store.time * 1000
        self.data.recorded_attestations = []
        self.data.slot = get_current_slot(self.store)
        self.data.current_epoch = compute_epoch_at_slot(self.data.slot)
        self.data.head_root = self.get_head()

        self.data.sent_bit_challenges = []
        self.data.challenged_attestations = []
        
        current_state = state.copy()
        if current_state.slot < self.data.slot:
            process_slots(current_state, self.data.slot)

        self.update_attester(current_state, self.data.current_epoch)
        self.update_proposer(current_state)
        self.update_data()

    def get_hashable_store(self) -> HashableSpecStore:
        """
        Returns a hash of the current store state.

        Args:
            self (BRValidator): Validator

        Returns:
            HashableSpecStore: A hashable representation of the current `self.store`
        """

        return HashableSpecStore(
            recorded_attestations = self.data.recorded_attestations,
            recorded_blocks = list(self.store.blocks.keys())
        )

    def get_head(self) -> Root:
        """
        Our cached reimplementation of specs-defined `get_head`.

        Args:
            self (BRValidator): Validator

        Returns:
            Root: Current head according to the validator `self.store`
        """

        store_root = hash_tree_root(self.get_hashable_store())

        # If we can get the head from the cache, great!
        if store_root in BRValidator.head_store:
            return BRValidator.head_store[store_root]

        # Otherwise we must compute it again :(
        else:
            head_root = get_head(self.store)
            BRValidator.head_store[store_root] = head_root
            return head_root

    def process_to_slot(self, current_head_root: Root, slot: Slot) -> BeaconState:
        """
        Our cached `process_slots` operation.

        Args:
            self (BRValidator): Validator
            current_head_root (Root): Process to slot from this state root
            slot (Slot): Slot to process to

        Returns:
            BeaconState: Post-state after transition to `slot`
        """

        # If we want to fast-forward a state root to some slot, we check if we have already recorded the
        # resulting state.
        if (current_head_root, slot) in BRValidator.state_store:
            return BRValidator.state_store[(current_head_root, slot)].copy()

        # If we haven't, we need to process it.
        else:
            current_state = self.store.block_states[current_head_root].copy()

            if current_state.slot < slot:
                process_slots(current_state, slot)

            BRValidator.state_store[(current_head_root, slot)] = current_state
            return current_state.copy()

    def update_time(self, frequency: uint64 = frequency) -> None:
        """
        Moving validators' clocks by one step.
        To keep it simple, we assume frequency is a power of ten.

        Args:
            self (BRValidator): Validator
            frequency (uint64): Simulation update rate

        Returns:
            None
        """

        self.data.time_ms = self.data.time_ms + int(1000 / frequency)
        if self.data.time_ms % 1000 == 0:
            # The store is updated each second in the specs
            on_tick(self.store, self.store.time + 1)

            # If a new slot starts, we update
            if get_current_slot(self.store) != self.data.slot:
                self.update_data()

    def forward_by(self, seconds: uint64, frequency: uint64 = frequency) -> None:
        """
        A utility method to forward the clock by a given number of seconds.
        Useful for exposition!

        Args:
            self (BRValidator): Validator
            seconds (uint64): Number of seconds to fast-forward by
            frequency (uint64): Simulation update rate

        Returns:
            None
        """

        number_ticks = seconds * frequency
        for i in range(number_ticks):
            self.update_time(frequency)

    def update_attester(self, current_state: BeaconState, epoch: Epoch) -> None:
        """
        This is a fairly expensive operation, so we try not to call it when we don't have to.
        Update attester duties for the `epoch`.
        This can be queried no earlier than two epochs before
        (e.g., learn about epoch e + 2 duties at epoch t).

        Args:
            self (BRValidator): Validator
            current_state (BeaconState): The state from which proposer duties are computed
            epoch (Epoch): Either `current_epoch` or `current_epoch + 1`

        Returns:
            None
        """

        current_epoch = get_current_epoch(current_state)

        # When is the validator scheduled to attest in `epoch`?
        (committee, committee_index, attest_slot) = get_committee_assignment(
            current_state,
            epoch,
            self.validator_index)
        if epoch == current_epoch:
            self.data.current_attest_slot = attest_slot
            self.data.current_committee_index = committee_index
            self.data.current_committee = committee
        elif epoch == current_epoch + 1:
            self.data.next_attest_slot = attest_slot
            self.data.next_committee_index = committee_index
            self.data.next_committee = committee

    def update_proposer(self, current_state: BeaconState) -> None:
        """
        This is a fairly expensive operation, so we try not to call it when we don't have to.
        Update proposer duties for the current epoch.
        We need to check for each slot of the epoch whether the validator is a proposer or not.

        Args:
            self (BRValidator): Validator
            current_state (BeaconState): The state from which proposer duties are computed

        Returns:
            None
        """

        current_epoch = get_current_epoch(current_state)

        start_slot = compute_start_slot_at_epoch(current_epoch)

        start_state = current_state.copy() if start_slot == current_state.slot else \
        self.store.block_states[get_block_root(current_state, current_epoch)].copy()

        current_proposer_duties = []
        for slot in range(start_slot, start_slot + SLOTS_PER_EPOCH):
            if slot < start_state.slot:
                current_proposer_duties += [False]
                continue

            if start_state.slot < slot:
                process_slots(start_state, slot)

            current_proposer_duties += [get_beacon_proposer_index(start_state) == self.validator_index]

        self.data.current_proposer_duties = current_proposer_duties

    def update_attest_move(self) -> None:
        """
        When was the last attestation by the validator?
        Updates `self.data.last_slot_attested`.

        Args:
            self (BRValidator): Validator

        Returns:
            None
        """

        slots_attested = sorted([log.slot for log in self.history if log.move == "attest"], reverse = True)
        self.data.last_slot_attested = None if len(slots_attested) == 0 else slots_attested[0]

    def update_propose_move(self) -> None:
        """
        When was the last block proposal by the validator?
        Updates `self.data.last_slot_proposed`.

        Args:
            self (BRValidator): Validator

        Returns:
            None
        """

        slots_proposed = sorted([log.slot for log in self.history if log.move == "propose"], reverse = True)
        self.data.last_slot_proposed = None if len(slots_proposed) == 0 else slots_proposed[0]
        
    def update_data(self) -> None:
        """
        The head may change if we recorded a new block/new attestation in the `store`.
        Attester/proposer responsibilities may change if head changes *and*
        canonical chain changes to further back from start current epoch.

        .. code-block:: txt

            ---x------
                \           x is fork point
                 -----

            In the following
              attester = attester responsibilities for current epoch
              proposer = proposer responsibilities for current epoch

            - If x after current epoch change
              (---|--x , | = start current epoch),
              proposer and attester don't change
            - If x between start of previous epoch and
              start of current epoch
              (--||--x---|-- , || = start previous epoch)
              proposer changes but not attester
            - If x before start of previous epoch
              (--x--||-----|----) both proposer and attester change

        Args:
            self (BRValidator): Validator

        Returns:
            None
        """

        slot = get_current_slot(self.store)
        new_slot = self.data.slot != slot

        # Current epoch in validator view
        current_epoch = compute_epoch_at_slot(slot)

        self.update_attest_move()
        self.update_propose_move()

        # Did the validator record a block for this slot?
        received_block = len([block for block_root, block in self.store.blocks.items() if block.slot == slot]) > 0

        if not new_slot:
            # It's not a new slot, we are here because a new block/attestation was received

            # Getting the current state, fast-forwarding from the head
            head_root = self.get_head()

            if self.data.head_root != head_root:
                # New head!
                lca = lowest_common_ancestor(
                    self.store, self.data.head_root, head_root)
                lca_epoch = compute_epoch_at_slot(lca.slot)

                if lca_epoch == current_epoch:
                    # do nothing
                    pass
                else:
                    current_state = self.process_to_slot(head_root, slot)
                    if lca_epoch == current_epoch - 1:
                        self.update_proposer(current_state)
                    else:
                        self.update_proposer(current_state)
                        self.update_attester(current_state, current_epoch)
                self.data.head_root = head_root

        else:
            # It's a new slot. We should update our proposer/attester duties
            # if it's also a new epoch. If not we do nothing.
            if self.data.current_epoch != current_epoch:
                current_state = self.process_to_slot(self.data.head_root, slot)

                # We need to check our proposer role for this new epoch
                self.update_proposer(current_state)

                # We need to check our attester role for this new epoch
                self.update_attester(current_state, current_epoch)

        self.data.slot = slot
        self.data.current_epoch = current_epoch
        self.data.received_block = received_block

    def log_block(self, item: SignedBeaconBlock) -> None:
        """
        Recording 'block proposal' move by the validator in its history.
        """

        self.history.append(ValidatorMove(
            time = self.data.time_ms,
            slot = item.message.slot,
            move = "propose"
        ))
        self.update_propose_move()

    def log_attestation(self, item: Attestation) -> None:
        """
        Recording 'attestation proposal' move by the validator in its history.
        """

        self.history.append(ValidatorMove(
            time = self.data.time_ms,
            slot = item.data.slot,
            move = "attest"
        ))
        self.update_attest_move()
        
    def log_chunk_response(self, item: CustodyChunkResponse) -> None:
        """
        Recording 'chunk response' move by the validator in its history.
        """

        self.history.append(ValidatorMove(
            time = self.data.time_ms,
            slot = None,
            move = "chunk_response"
        ))
        print("chunk response logged")
        # for simplicity we assume it's not important to e.g. make update_chunk_response

    def log_bit_challenge(self, item: CustodySlashing) -> None: 

        self.history.append(ValidatorMove(
                time = self.data.time_ms,
                slot = None, 
                move = "bit_challenge"
                ))
       
    def record_block(self, item: SignedBeaconBlock) -> bool:
        """
        When a validator receives a block from the network, they call `record_block` to see
        whether they should record it.
        """

        # If we already know about the block, do nothing
        if hash_tree_root(item.message) in self.store.blocks:
            return False

        # Sometimes recording the block fails. Examples include:
        # - The block slot is not the current slot (we keep it in memory for later, when we check backlog)
        # - The block parent is not known
        try:
            state = self.process_to_slot(item.message.parent_root, item.message.slot)
            chunk_challenge_count = state.custody_chunk_challenge_index
            on_block(self.store, item, state = state)
            # if the block chunk challenges you, you put it in your active challenges
            new_chunk_challenge_count = state.custody_chunk_challenge_index
            new_chunk_challenges = state.custody_chunk_challenge_records[chunk_challenge_count:]
            for cha in new_chunk_challenges:
                if cha.responder_index == self.validator_index:
#                    print(self.validator_index, "is accused")
                    self.chunk_challenges_accusations.append(cha)

        except AssertionError as e:
            return False

        # If attestations are included in the block, we want to record them
        for attestation in item.message.body.attestations:
            self.record_attestation(attestation)

        return True

    def record_attestation(self, item: Attestation) -> bool:
        """
        When a validator receives an attestation from the network,
        they call `record_attestation` to see whether they should record it.
        """

        att_hash = hash_tree_root(item)

        # If we have already seen this attestation, no need to go further
        if att_hash in self.data.recorded_attestations:
            return False

        # Sometimes recording the attestation fails. Examples include:
        # - The attestation is not for the current slot *PLUS ONE*
        #   (we keep it in memory for later, when we check backlog)
        # - The block root it is attesting for is not known
        try:
            on_attestation(self.store, item)
            self.data.recorded_attestations += [att_hash]
            return True
        except:
            return False
          
          
    def check_backlog(self, known_items: Dict[str, Sequence[Container]]) -> None:
        """
        Called whenever a new event happens on the network that might make a validator update
        their internals.
        We loop over known blocks and attestations to check whether we should record any
        that we might have discarded before, or just received.
        """

        recorded_blocks = 0
        for block in known_items["blocks"]:
            recorded = self.record_block(block.item)
            if recorded:
                recorded_blocks += 1

        recorded_attestations = 0
        for attestation in known_items["attestations"]:
            recorded = self.record_attestation(attestation.item)
            if recorded:
                recorded_attestations += 1

                
        # If we do record anything, update the internals.
        if (recorded_blocks + recorded_attestations) > 0:
            self.update_data()

def lowest_common_ancestor(store, old_head, new_head) -> Optional[BeaconBlock]:
    """
    Find the lowest common ancestor to `old_head` and `new_head` in `store`.
    In most cases, `old_head` is an ancestor to `new_head`.
    We sort of (loosely) optimise for this.
    """

    new_head_ancestors = [new_head]
    current_block = store.blocks[new_head]
    keep_searching = True
    while keep_searching:
        parent_root = current_block.parent_root
        parent_block = store.blocks[parent_root]
        if parent_root == old_head:
            return store.blocks[old_head]
        elif parent_block.slot == 0:
            keep_searching = False
        else:
            new_head_ancestors += [parent_root]
            current_block = parent_block

    # At this point, old_head wasn't an ancestor to new_head
    # We need to find old_head's ancestors
    current_block = store.blocks[old_head]
    keep_searching = True
    while keep_searching:
        parent_root = current_block.parent_root
        parent_block = store.blocks[parent_root]
        if parent_root in new_head_ancestors:
            return parent_block
        elif parent_block.slot == 0:
            print("return none")
            return None
        else:
            current_block = parent_block

