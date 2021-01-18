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

import milagro_bls_binding as bls
from eth2spec.utils.ssz.ssz_impl import hash_tree_root
from eth2spec.utils.ssz.ssz_typing import Container, List, uint64, Bitlist
from eth2spec.test.helpers.keys import pubkeys, pubkey_to_privkey

# actually 0.999
ASSIGNED_ATTEST_CHANCE = 0.9 
# probability a dishonest person writes a custody bit
DISHONEST_ATTEST_CHANCE = 0.9


### Attestation strategies

def get_attestation_signature(state: BeaconState, attestation_data: AttestationData, privkey: int) -> BLSSignature:
    domain = get_domain(state, DOMAIN_BEACON_ATTESTER, attestation_data.target.epoch)
    signing_root = compute_signing_root(attestation_data, domain)
    return bls.Sign(privkey, signing_root)

def attest_base(validator, known_items, honesty=True):
    """
    Returns an honest attestation from `validator`.

    This is a "base" function because it does not have timing checks, etc.

    Args:
        validator (BRValidator): The attesting validator
        known_items (Dict): Known blocks and attestations received over-the-wire (but perhaps not included yet in `validator.store`)

    Returns:
        Attestation: The honest attestation
    """

    # quick reminder:
    # you attest if your custody bit is 1
    
    # are you supposed to attest (argh this should be decided earlier)
    should_attest = random.choices(population=[True, False],
                                   weights=[ASSIGNED_ATTEST_CHANCE,
                                            1-ASSIGNED_ATTEST_CHANCE], k=1)[0]
    if honesty:
        will_attest = should_attest
        accuracy = True
    else:
        will_attest = random.choices(population=[True, False],
                                     weights=[DISHONEST_ATTEST_CHANCE,
                                              1-DISHONEST_ATTEST_CHANCE], k=1)[0]
        if will_attest == should_attest:
            accuracy = True
        else:
            accuracy = False

    # we will be attesting

    # Unpacking
    validator_index = validator.validator_index
    store = validator.store
    committee_slot = validator.data.current_attest_slot
    committee_index = validator.data.current_committee_index
    committee = validator.data.current_committee

    # What am I attesting for?
    block_root = validator.get_head()
    head_state = store.block_states[block_root].copy()
    if head_state.slot < committee_slot:
        process_slots(head_state, committee_slot)
    start_slot = compute_start_slot_at_epoch(get_current_epoch(head_state))
    epoch_boundary_block_root = block_root if start_slot == head_state.slot else get_block_root_at_slot(head_state, start_slot)
    tgt_checkpoint = Checkpoint(epoch=get_current_epoch(head_state), root=epoch_boundary_block_root)

    att_data = AttestationData(
        index = committee_index,
        slot = committee_slot,
        beacon_block_root = block_root,
        source = head_state.current_justified_checkpoint,
        target = tgt_checkpoint,
    )

    # Set aggregation bits to myself only
    committee_size = len(committee)
    index_in_committee = committee.index(validator_index)
    aggregation_bits = Bitlist[MAX_VALIDATORS_PER_COMMITTEE](*([0] * committee_size))
    # for sake of this simulation, assume the validator has sent an "empty attest" with the
    # aggregation bit equal to False, as opposed to not sending an attestation at all
    # (this helps us log the validator's decision)
    # aggregation_bits[index_in_committee] = will_attest
    aggregation_bits[index_in_committee] = True # set the aggregation bit of the validator to True
    
    attestation = Attestation(
        aggregation_bits=aggregation_bits,
        accuracy=accuracy,
        data=att_data,
        virtual=not(will_attest)
    )

    if accuracy:
        accustr = "accurate"
    else:
        accustr = "inaccurate"
    if will_attest:
        skipstr = ""
    else:
        skipstr = "skips attest"
        
    if not(will_attest) or not(accuracy):
        print ("%d %s (%s) for [%s]" % (validator.validator_index, skipstr, accustr,
                                        att_data.slot))
    attestation_signature = get_attestation_signature(head_state, att_data, validator.privkey)
    attestation.signature = attestation_signature
    validator.log_attestation(attestation)
    return attestation

def attest(validator, known_items, speed, honesty=True):
    """
    speed = "asap": Returns an honest `Attestation` as soon as at least four seconds (`SECONDS_PER_SLOT / 3`)
    have elapsed into the slot where the validator is supposed to attest or the validator
    has receive a valid block for the attesting slot.
    Checks whether an attestation was produced for the same slot to avoid slashing.
    
    speed = "prudent": Returns an honest `Attestation` as soon as a block was received for the
    attesting slot *or* at least 8 seconds (`2 * SECONDS_PER_SLOT / 3`) have elapsed.
    Checks whether an attestation was produced for the same slot to avoid slashing.

    Args:
        validator: Validator
        known_items (Dict): Known blocks and attestations received over-the-wire (but perhaps not included yet in `validator.store`)
    
    Returns:
        Optional[Attestation]: Either `None` if the validator decides not to attest,
        otherwise an honest `Attestation`
    """
    
    # Not the moment to attest
    if validator.data.current_attest_slot != validator.data.slot:
        return None
    
    time_in_slot = (validator.store.time - validator.store.genesis_time) % SECONDS_PER_SLOT

    if speed == "asap":
        cutoff = 4
    else:
        assert speed == "prudent"
        cutoff = 8
    
    # Too early in the slot / didn't receive block
    if not validator.data.received_block and time_in_slot < cutoff:
        return None
    
    # Already attested for this slot
    if validator.data.last_slot_attested == validator.data.slot:
        # TODO: if already decided to not attest, should not attest!
        return None

    # honest attest
    return attest_base(validator, known_items, honesty)

def honest_attest_asap(validator, known_items):
    return attest(validator, known_items, "asap", honesty=False)

def honest_attest_prudent(validator, known_items):
    return attest(validator, known_items, "prudent", honesty=True)
  
def dishonest_attest_asap(validator, known_items):
    return attest(validator, known_items, "asap", honesty=False)

def dishonest_attest_prudent(validator, known_items):
    return attest(validator, known_items, "prudent", honesty=False)
  
### Aggregation helpers

def get_aggregate_signature(attestations: Sequence[Attestation]) -> BLSSignature:
    signatures = [attestation.signature for attestation in attestations]
    return bls.Aggregate(signatures)

def build_aggregate(attestations):
    """
    Given a set of attestations from the same slot, committee index and vote for
    same source, target and beacon block, return an aggregated attestation.
    """

    if len(attestations) == 0:
        return []

    aggregation_bits = Bitlist[MAX_VALIDATORS_PER_COMMITTEE](*([0] * len(attestations[0].aggregation_bits)))
    for attestation in attestations:
        validator_index_in_committee = attestation.aggregation_bits.index(1)
        aggregation_bits[validator_index_in_committee] = True

    aggregate_attestation = Attestation(
        aggregation_bits=aggregation_bits,
        data=attestations[0].data
    )
    aggregate_signature = get_aggregate_signature(attestations)
    aggregate_attestation.signature = aggregate_signature

    return aggregate_attestation

def aggregate_attestations(attestations):
    """
    Take in a set of attestations. Output aggregated attestations.
    """

    hashes = set([hash_tree_root(att.data) for att in attestations])
    return [build_aggregate(
        [att for att in attestations if att_hash == hash_tree_root(att.data)]
    ) for att_hash in hashes]

### Proposal strategies

def get_block_signature(state: BeaconState, block: BeaconBlock, privkey: int) -> BLSSignature:
    domain = get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(block.slot))
    signing_root = compute_signing_root(block, domain)
    return bls.Sign(privkey, signing_root)

def get_epoch_signature(state: BeaconState, block: BeaconBlock, privkey: int) -> BLSSignature:
    domain = get_domain(state, DOMAIN_RANDAO, compute_epoch_at_slot(block.slot))
    signing_root = compute_signing_root(compute_epoch_at_slot(block.slot), domain)
    return bls.Sign(privkey, signing_root)

def should_process_attestation(state: BeaconState, attestation: Attestation) -> bool:
    try:
        process_attestation(state.copy(), attestation)
        return True
    except:
        return False

def should_process_response(state: BeaconState, response: CustodyChunkResponse) -> bool:
    matching_challenges = [
        record for record in state.custody_chunk_challenge_records
        if (record.challenge_index == response.challenge_index and record.chunk_index == response.chunk_index)]
    if matching_challenges:
        return True
    return False

def honest_propose_base(validator, known_items):
    """
    Returns an honest block, using the current LMD-GHOST head and all known, aggregated, 
    attestations.

    This is a "base" function since it does not do timing checks, rule checks, etc.; for 
    actual validators you probably want a function that uses this as a subroutine

    Args:
        validator (BRValidator): The proposing validator
        known_items (Dict): Known blocks and attestations received over-the-wire (but perhaps not included yet in `validator.store`)

    Returns:
        SignedBeaconBlock: The honest proposed block.
    """

    print(validator.validator_index, "proposing block for slot", validator.data.slot)

    slot = validator.data.slot
    head = validator.data.head_root

    processed_state = validator.process_to_slot(head, slot)

    attestations = [att for att in known_items["attestations"] if should_process_attestation(processed_state, att.item)]
    attestations = aggregate_attestations([att.item for att in attestations if slot <= att.item.data.slot + SLOTS_PER_EPOCH])

    beacon_block = BeaconBlock(
        slot=slot,
        parent_root=head,
        proposer_index = validator.validator_index,
    )

    # publishing chunk challenges
    chunk_challenges = []
    challengeable_attestations = [att for att in known_items['attestations']
                                  if att.attestor != validator.validator_index]
    # need to make this smaller from now on
    num_to_challenge = min(MAX_CUSTODY_CHUNK_CHALLENGES, len(challengeable_attestations))
    network_attestations = random.sample(challengeable_attestations, num_to_challenge)

    for i in range(num_to_challenge):
        attestor_index = network_attestations[i].attestor
        attestation = network_attestations[i].item
        chunk_index = random.randint(1, 4294967296)
        # data_index and chunk_index have real values, but we can ignore for simulations
        cha = CustodyChunkChallenge(
            responder_index=attestor_index,
            attestation=attestation,
            chunk_index=chunk_index
        )
        chunk_challenges.append(cha)

    challenged = " ".join(["%d [%d]" % (cha.responder_index, cha.chunk_index) for cha in chunk_challenges])
    print("  %d chunk challenges" % (validator.validator_index), challenged)

    # publishing chunk challenge responses
    chunk_responses = [i.item for i in known_items["chunk_responses"]
                       if should_process_response(processed_state, i.item)]

    # Publishing Bit Challenges

    # bit_challenges = [b.item for b in known_items["bit_challenges"]
    #                   if should_proceess_bit_challenge(processed_state, b.item)]
    
    # if not bit_challenge_record:
    #     return None
    # bit_challenge_accepted = random.choice(bit_challenge_record)
    # print(bit_challenge_accepted.whistleblower_index, "'s bit challenge to", bit_challenge_accepted.malefactor_index,"got accepted")

    beacon_block_body = BeaconBlockBody(
        attestations=attestations,
        chunk_challenges=chunk_challenges,
        chunk_challenge_responses=chunk_responses,
#        custody_slashings=bit_challenge_accepted
    )
    epoch_signature = get_epoch_signature(processed_state, beacon_block, validator.privkey)
    beacon_block_body.randao_reveal = epoch_signature

    beacon_block.body = beacon_block_body

#    print ("  Validator", validator.validator_index, "  about to process that block w records")
    # for r in processed_state.custody_chunk_challenge_records:
    #     print(r)
    process_block(processed_state, beacon_block)
    state_root = hash_tree_root(processed_state)
    beacon_block.state_root = state_root

    block_signature = get_block_signature(processed_state, beacon_block, validator.privkey)
    signed_block = SignedBeaconBlock(message=beacon_block, signature=block_signature)

    validator.log_block(signed_block)
    return signed_block

def honest_propose(validator, known_items):
    """
    Returns an honest `SignedBeaconBlock` as soon as the slot where
    the validator is supposed to propose starts.
    Checks whether a block was proposed for the same slot to avoid slashing.
    
    Args:
        validator: Validator
        known_items (Dict): Known blocks and attestations received over-the-wire (but perhaps not included yet in `validator.store`)
    
    Returns:
        Optional[SignedBeaconBlock]: Either `None` if the validator decides not to propose,
        otherwise a `SignedBeaconBlock` containing attestations
    """
    
    # Not supposed to propose for current slot
    if not validator.data.current_proposer_duties[validator.data.slot % SLOTS_PER_EPOCH]:
        return None
    
    # Already proposed for this slot
    if validator.data.last_slot_proposed == validator.data.slot:
        return None
    
    # honest propose
    return honest_propose_base(validator, known_items)

def honest_chunk_challenge_response(validator, known_items):
    if validator.chunk_challenges_accusations: # has outstanding accusation
        record = validator.chunk_challenges_accusations[-1]
        response = CustodyChunkResponse(
          challenge_index = record.challenge_index,
          chunk_index = record.chunk_index
        )
        validator.log_chunk_response(response)
        validator.chunk_challenges_accusations = validator.chunk_challenges_accusations[:-1]
#        validator.chunk_challenge_sent.append(response)
        print(validator.validator_index, "responds to challenge", response)
        return response
    return None

def lazy_chunk_challenge_response(validator, known_items):
    return None
  
def bit_challenge_base(validator, known_items, honesty=True):
    """ The base function when we ask someone to produce a challenge """

    if honesty:
        allowed_accuracies = [False]
    else:
        allowed_accuracies = [True, False]
    if not known_items['attestations']:
        return None
    challengeable_attestations = [att for att in known_items['attestations']
                                  if (att.attestor != validator.validator_index and
                                      att.item.accuracy in allowed_accuracies and
                                      att.item not in validator.data.challenged_attestations and
                                      att.item.virtual == False
                                  )]
    # TODO: make sure this isn't already in known_bit_challenges, when that gets implemented
    
    if not challengeable_attestations:
        return None
      
    network_attestation = random.choice(challengeable_attestations)
    attestor_index = network_attestation.attestor
    attestation = network_attestation.item 

    bit_challenge = CustodySlashing(
        #Full CustodySlashing to be added later
        malefactor_index = attestor_index,
        whistleblower_index = validator.validator_index
    )
    validator.log_bit_challenge(bit_challenge)

    # TODO: 
    # bit_challenge_record.append(bit_challenge)
    # instead of something "global," we should have a record like custody_chunk_challenge_records
    # inside BeaconState, and update that with process_custody_slashing

    validator.data.challenged_attestations.append(attestation)
    validator.data.sent_bit_challenges.append(bit_challenge)

    if attestation.accuracy:
        accuracy_text = "(accurate)"
    else:
        accuracy_text = "(inaccurate)"

    print("  ", validator.validator_index, " bit challenging", attestor_index, accuracy_text,
          "[%s]" % attestation.data.slot)
    return bit_challenge

def bit_challenge(validator, known_items, honesty=True):
    """ the function when we ask someone at a particular time about bit challenging"""
    # Not the moment to attest
    
    time_in_slot = (validator.store.time - validator.store.genesis_time) % SECONDS_PER_SLOT

    cutoff = 9
    # the first time in the slot after which the validator considers bit challenging
    # can play around with this later
    
    # Too early in the slot
    if time_in_slot < cutoff:
        return None
    
    # honest attest
    return bit_challenge_base(validator, known_items, honesty)
  
def honest_bit_challenge(validator, known_items):
    return bit_challenge(validator, known_items, honesty=True)

def dishonest_bit_challenge(validator, known_items):
    return bit_challenge(validator, known_items, honesty=False)
  
def lazy_bit_challenge(validator, known_items):
    return None

