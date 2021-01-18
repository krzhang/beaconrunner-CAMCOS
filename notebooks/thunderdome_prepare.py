import beaconrunner as br
import itertools
import random


## Validator makers


def validator_maker(num_validators,
                    attest_funcs,
                    propose_funcs,
                    chunk_response_funcs,
                    bit_challenge_funcs):
    """ 
    make validators out of types that are constructed from the strategies given in terms of 
    "[X]_funcs".

    [X]_funcs: lists of strategy functions (all of type "State -> Any") that tells the validator
               what to produce when queried for a [X]

    Ex. Suppose Attest_funcs = [attest_strategy_1, attest_strategy_2] and
                bit_challenge_funcs = [bcs_1, bcs_2, bcs_3], and
                the other funcs have just one function each

        then the space of validators will be "crossed" into 2x3*1*1 = 6 options from all the ways
        of combining the functions. Then we will take the proposed number of validators, find the
        largest multiple of 6 under it (num_validators), and split them into 6 equal buckets to
        create validators of each Cartesian producted type from the 4 types of functions.

    TODO: eventually, should replace each [X]_funcs by a dictionary of weights, to allow different
          weightings of validators

    TODO: eventually, should allow situations where the distributions are not 'factored', such
          as just taking a list of 4-tuples and their respective weights. 
    """
    validators = []
    
    func_types = list(itertools.product(attest_funcs, propose_funcs, chunk_response_funcs,
                                   bit_challenge_funcs))

    copies = int(num_validators / len(func_types)) # number of validators per cross-type
    num_validators_real = len(func_types)*copies # now it's divisible

    func_types_big = list(func_types)*copies
    random.shuffle(func_types_big)

    # Initiate validators
    for i in range(num_validators_real):
        ft = func_types_big[i]
        new_validator = br.validatorlib.BRValidator(i, attest_func=ft[0], propose_func=ft[1],
                           chunk_response_func=ft[2], bit_challenge_func = ft[3])
        validators.append(new_validator)
    return validators
  
## Observers

# An observer seems to be just a function state -> information

def average_balance_observer(validator_type):
    """ A function factory that returns an observer function"""
    def obs_func(state):
        validators = state["network"].validators
        validator = validators[0]
        head = br.specs.get_head(validator.store)
        current_state = validator.store.block_states[head]
        current_epoch = br.specs.get_current_epoch(current_state)
        indices = [i for i, v in enumerate(validators) if validator_type in v.validator_behavior]
        balances = [b for i, b in enumerate(current_state.balances) if i in indices]
        return br.utils.eth2.gwei_to_eth((sum(balances))/ float(len(indices)))
    return obs_func
  
# def average_balance_prudent(state):
#     validators = state["network"].validators
#     validator = validators[0]
#     head = br.specs.get_head(validator.store)
#     current_state = validator.store.block_states[head]
#     current_epoch = br.specs.get_current_epoch(current_state)
#     prudent_indices = [i for i, v in enumerate(validators) if v.validator_behaviour == "prudent"]
#     prudent_balances = [b for i, b in enumerate(current_state.balances) if i in prudent_indices]
#     return br.utils.eth2.gwei_to_eth(sum(prudent_balances) / float(len(prudent_indices)))

# def average_balance_asap(state):
#     validators = state["network"].validators
#     validator = validators[0]
#     head = br.specs.get_head(validator.store)
#     current_state = validator.store.block_states[head]
#     current_epoch = br.specs.get_current_epoch(current_state)
#     asap_indices = [i for i, v in enumerate(validators) if v.validator_behaviour == "asap"]
#     asap_balances = [b for i, b in enumerate(current_state.balances) if i in asap_indices]
#     return br.utils.eth2.gwei_to_eth(sum(asap_balances) / float(len(asap_indices)))
