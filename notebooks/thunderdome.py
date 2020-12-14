import importlib
import os
import types
import nest_asyncio
nest_asyncio.apply()
from eth2spec.config.config_util import prepare_config
from eth2spec.utils.ssz.ssz_impl import hash_tree_root

import os, sys
sys.path.insert(1, os.path.realpath(os.path.pardir))

print("auxiliary imports loaded!")

import beaconrunner as br
import beaconrunner.validatorlib as brv
import beaconrunner.strategies as brs

import thunderdome_prepare as tp

prepare_config(".", "fast")
br.reload_package(br)

print("beaconrunner loaded!")

# We then create our observers, to allow us to record interesting metrics at each simulation step.

current_slot = lambda s: s["network"].validators[0].data.slot

observers = {
    "current_slot": current_slot,
    "average_balance_prudent": tp.average_balance_observer("honest_attest_prudent"),
    "average_balance_asap": tp.average_balance_observer("honest_attest_asap")
}

print("observers implemented!")

# And define a "main" function -- in this case, simulate_thunderdome -- to run the simulation. The function returns a pandas dataframe containing the metrics recorded throughout the run.

# from beaconrunner.validators.ASAPValidator import ASAPValidator
# from beaconrunner.validators.PrudentValidator import PrudentValidator

attest_funcs = [brs.honest_attest_asap, brs.honest_attest_prudent]
propose_funcs = [brs.honest_propose]
chunk_response_funcs = [brs.honest_chunk_challenge_response]
bit_challenge_funcs = [brs.honest_bit_challenge]

def simulate_once(network_sets, num_run, num_validators, network_update_rate):

    validators = tp.validator_maker(num_validators, attest_funcs, propose_funcs,
                                    chunk_response_funcs, bit_challenge_funcs)
    print("%d validators created!" % len(validators))

    # Create a genesis state
    genesis_state = br.simulator.get_genesis_state(validators)
    
    # Validators load the state
    [v.load_state(genesis_state.copy()) for v in validators]

    br.simulator.skip_genesis_block(validators)

    network = br.network.Network(validators=validators, sets=network_sets)

    parameters = br.simulator.SimulationParameters({
        "num_epochs": 20,
        "num_run": num_run,
        "frequency": 1,
        "network_update_rate": network_update_rate,
    })

    return br.simulator.simulate(network, parameters, observers)

import pandas as pd

num_validators = 12

# Create the network peers
set_a = br.network.NetworkSet(validators=list(range(0, int(num_validators * 2 / 3.0))))
set_b = br.network.NetworkSet(validators=list(range(int(num_validators / 2.0), num_validators)))
network_sets = list([set_a, set_b])

num_runs = 1
# num_runs = 40
network_update_rate = 0.25

print ("simulation ready!")

df = pd.concat([simulate_once(network_sets, num_run, num_validators, network_update_rate) for num_run in range(num_runs)])

# To do a fair amount of runs (40) simulating a good number of epochs (20), we set a low number of validators (12). Since we are more interested in comparing individual rewards between ASAP and prudent validators rather than macro-properties or even scalability of the chain, this is not a bad thing to do (and it speeds things up quite a bit).

# Note here that we keep the same network topology across all our runs. However, validator types are placed randomly over the network with each new run, with always 50% of them Prudent and the other 50% ASAPs.

# Since we have 4 slots per epoch, and 20 epochs, let's read the average balances at slot 81, after the 20th epoch rewards and penalties were computed.

print ("simulation done!")

df[df.current_slot == 81][['average_balance_prudent', 'average_balance_asap']].describe()
