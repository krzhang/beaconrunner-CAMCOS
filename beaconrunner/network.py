import time
from typing import Set, Optional, Sequence, Tuple, Dict
from dataclasses import dataclass, field

from .specs import (
    VALIDATOR_REGISTRY_LIMIT,
    ValidatorIndex, Slot,
    BeaconState, Attestation, SignedBeaconBlock, CustodyChunkResponse, CustodySlashing,
    Store, get_forkchoice_store, on_block, on_attestation
)
from .validatorlib import BRValidator

from eth2spec.utils.ssz.ssz_typing import Container, List, uint64

log = False # set to True to receive an avalanche of messages

class NetworkSetIndex(uint64):
    pass

@dataclass
class NetworkSet(object):
    validators: List[ValidatorIndex, VALIDATOR_REGISTRY_LIMIT]

@dataclass
class NetworkAttestation(object):
    attestor: ValidatorIndex  # why not have them know this?
    item: Attestation
    info_sets: List[NetworkSetIndex, VALIDATOR_REGISTRY_LIMIT]

@dataclass
class NetworkBlock(object):
    item: SignedBeaconBlock
    info_sets: List[NetworkSetIndex, VALIDATOR_REGISTRY_LIMIT]

@dataclass
class NetworkChunkResponse(object):
    responder: ValidatorIndex
    item: CustodyChunkResponse
    info_sets: List[NetworkSetIndex, VALIDATOR_REGISTRY_LIMIT]

@dataclass
class NetworkCustodySlashing(object):
    """ Or "bit challenge" """
    challenger: ValidatorIndex
    item: CustodySlashing
    info_sets: List[NetworkSetIndex, VALIDATOR_REGISTRY_LIMIT]

@dataclass
class Network(object):
    validators: List[BRValidator, VALIDATOR_REGISTRY_LIMIT]
    sets: List[NetworkSet, VALIDATOR_REGISTRY_LIMIT]

    # In a previous implementation, we kept attestations and blocks in the same queue.
    # This was unwieldy. We can extend this easily by adding `Attester/ProposerSlashing`s
    attestations: List[NetworkAttestation, VALIDATOR_REGISTRY_LIMIT] = field(default_factory=list)
    blocks: List[NetworkBlock, VALIDATOR_REGISTRY_LIMIT] = field(default_factory=list)
    chunk_responses: List[NetworkChunkResponse, VALIDATOR_REGISTRY_LIMIT] = field(default_factory=list)
    bit_challenges: List[NetworkCustodySlashing, VALIDATOR_REGISTRY_LIMIT] = field(default_factory=list)
    
    # We have the possibility of malicious validators refusing to propagate messages.
    # Unused so far and untested too.
    malicious: List[ValidatorIndex, VALIDATOR_REGISTRY_LIMIT] = field(default_factory=list)

def get_all_sets_for_validator(network: Network, validator_index: ValidatorIndex) -> Sequence[NetworkSetIndex]:
    """ Return indices of network sets to which the validator belongs """
    return [i for i, s in enumerate(network.sets) if validator_index in s.validators]

def knowledge_set(network: Network, validator_index: ValidatorIndex) -> Dict[str, Sequence[Container]]:
    """
    Known attestations and blocks of validator `validator_index`

    In general, the information a validator uses to make actions (attesting, proposing, etc.)
    """

    # TODO: I think this should be updated instead of recomputed
    
    info_sets = set(get_all_sets_for_validator(network, validator_index))
    known_attestations = [item for item in network.attestations if
                          len(set(item.info_sets) & info_sets) > 0]
    known_blocks = [item for item in network.blocks if len(set(item.info_sets) & info_sets) > 0]
    known_chunk_responses = [item for item in network.chunk_responses if len(set(item.info_sets) &
                                                                             info_sets) > 0]
    known_bit_challenges = [item for item in network.bit_challenges if len(set(item.info_sets) &
                                                                           info_sets) > 0]
    return { "attestations": known_attestations, "blocks": known_blocks,
             "chunk_responses": known_chunk_responses, "bit_challenges": known_bit_challenges}

def ask_to_check_backlog(network: Network,
                         validator_indices: Set[ValidatorIndex]) -> None:
    # Called right after a message (block or attestation) was sent to `validator_indices`
    # Asks validators to check if they can e.g., definitely include attestations in their
    # latest messages or record blocks.
    for validator_index in validator_indices:
        validator = network.validators[validator_index]

        # Check if there are pending attestations/blocks that can be recorded
        known_items = knowledge_set(network, validator_index)
        validator.check_backlog(known_items)

def disseminate_block(network: Network,
                      sender: ValidatorIndex,
                      item: SignedBeaconBlock,
                      to_sets: List[NetworkSetIndex, VALIDATOR_REGISTRY_LIMIT] = None) -> None:
    """
    Disseminate a block through the network.

    `sender` disseminates a block to its information sets, i.e., other validators they are peering
    with.
    """

    # Getting all the sets that `sender` belongs to
    broadcast_list = get_all_sets_for_validator(network, sender) if to_sets is None else to_sets

    # The validator records that they have sent a block
    network.validators[sender].log_block(item)

    # Adding the block to network items
    networkItem = NetworkBlock(item=item, info_sets=broadcast_list)
    network.blocks.append(networkItem)

    # A set of all validators who need to update their internals after reception of the block
    broadcast_validators = set()
    for info_set_index in broadcast_list:
        broadcast_validators |= set(network.sets[info_set_index].validators)

    ask_to_check_backlog(network, broadcast_validators)

def disseminate_attestations(network: Network,
                             items: Sequence[Tuple[ValidatorIndex, Attestation]]) -> None:
    """
    We get a set of attestations and disseminate them over the network
    """
    # Finding out who receives a new attestation
    broadcast_validators = set()
    for item in items:
        sender = item[0]
        attestation = item[1]
        broadcast_list = get_all_sets_for_validator(network, sender)

        # The sender records that they have sent an attestation
        network.validators[sender].log_attestation(attestation)

        # Adding the attestation to network items
        networkItem = NetworkAttestation(attestor=sender,
                                         item=attestation,
                                         info_sets=broadcast_list)
        network.attestations.append(networkItem)

        # Update list of validators who received a new item
        for info_set_index in broadcast_list:
            broadcast_validators |= set(network.sets[info_set_index].validators)

    ask_to_check_backlog(network, broadcast_validators)

def disseminate_chunk_responses(network: Network, items: Sequence[Tuple[ValidatorIndex, CustodyChunkResponse]]) -> None:
    # Finding out who receives a new response
    broadcast_validators = set()
    for item in items:
        sender = item[0]
        response = item[1]
        broadcast_list = get_all_sets_for_validator(network, sender)

        # The sender records that they have sent an attestation
        network.validators[sender].log_chunk_response(response)

        # Adding the attestation to network items
        networkItem = NetworkChunkResponse(responder=sender,
                                           item=response,
                                           info_sets=broadcast_list)
        network.chunk_responses.append(networkItem)

        # Update list of validators who received a new item
        for info_set_index in broadcast_list:
            broadcast_validators |= set(network.sets[info_set_index].validators)

    ask_to_check_backlog(network, broadcast_validators)

def disseminate_bit_challenges(network: Network, items: Sequence[Tuple[ValidatorIndex, CustodySlashing]]) -> None:
    # Finding out who receives a new response
    broadcast_validators = set()
    for item in items:
        sender = item[0]
        challenge = item[1]
        broadcast_list = get_all_sets_for_validator(network, sender)

        # The sender records that they have sent an attestation
        network.validators[sender].log_bit_challenge(challenge)

        # Adding the attestation to network items
        networkItem = NetworkCustodySlashing(challenger=sender,
                                             item=challenge,
                                             info_sets=broadcast_list)
        network.bit_challenges.append(networkItem)

        # Update list of validators who received a new item
        for info_set_index in broadcast_list:
            broadcast_validators |= set(network.sets[info_set_index].validators)

    ask_to_check_backlog(network, broadcast_validators)

def update_network(network: Network) -> None:
    """
    The "heartbeat" of the network. When called, items propagate one step further on the network.
    """

    # We need to propagate both blocks and attestations
    item_sets = [network.blocks, network.attestations]

    # These are the validators who receive a new item (block or attestation)
    broadcast_validators = set()

    for item_set in item_sets:
        for item in item_set:
            # For each item, we find the new validators who hear about it for the first time
            # and the validators who already do. Items propagate from validators who know about them.
            known_validators = set()
            for info_set in item.info_sets:
                known_validators = known_validators.union(set(network.sets[info_set].validators))

            # When a validator belongs to a set A where the item was propagated AND
            # to a set B where it wasn't, the validator propagates the item to set B
            unknown_sets = [i for i, s in enumerate(network.sets) if i not in item.info_sets]
            for unknown_set in unknown_sets:
                new_validators = set(network.sets[unknown_set].validators)
                for new_validator in new_validators:
                    if new_validator in known_validators and new_validator not in network.malicious:
                        item.info_sets.append(unknown_set)
                        broadcast_validators |= new_validators
                        break

    ask_to_check_backlog(network, broadcast_validators)
