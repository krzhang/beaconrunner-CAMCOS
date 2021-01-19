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
    "average_balance_honest_attestors": tp.average_balance_observer("honest_attest_asap"),
    "average_balance_dishonest_attestors": tp.average_balance_observer("dishonest_attest_asap")
}

print("observers implemented!")

# And define a "main" function -- in this case, simulate_thunderdome -- to run the simulation. The function returns a pandas dataframe containing the metrics recorded throughout the run.

attest_funcs = [brs.honest_attest_asap, brs.dishonest_attest_asap]
propose_funcs = [brs.honest_propose]
chunk_response_funcs = [brs.honest_chunk_challenge_response]
bit_challenge_funcs = [brs.honest_bit_challenge, brs.dishonest_bit_challenge, brs.lazy_bit_challenge]

SIMULATION_NUM_EPOCHS = 3 # 40
SIMULATION_NUM_VALIDATORS = 12

def simulate_once(network_sets, num_run, num_validators, network_update_rate):

    validators = tp.validator_maker(num_validators, attest_funcs, propose_funcs,
                                    chunk_response_funcs, bit_challenge_funcs)
    print("%d validators created!" % len(validators))
    for v in validators:
        print(v)
    # Create a genesis state
    genesis_state = br.simulator.get_genesis_state(validators)
    
    # Validators load the state
    [v.load_state(genesis_state.copy()) for v in validators]

    br.simulator.skip_genesis_block(validators)

    network = br.network.Network(validators=validators, sets=network_sets)

    parameters = br.simulator.SimulationParameters({
        "num_epochs": SIMULATION_NUM_EPOCHS,
        "num_run": num_run,
        "frequency": 1,
        "network_update_rate": network_update_rate,
    })

    return br.simulator.simulate(network, parameters, observers)

import pandas as pd

# Create the network peers
set_a = br.network.NetworkSet(validators=list(range(0, int(SIMULATION_NUM_VALIDATORS * 2 / 3.0))))
set_b = br.network.NetworkSet(validators=list(range(int(SIMULATION_NUM_VALIDATORS / 2.0), SIMULATION_NUM_VALIDATORS)))
network_sets = list([set_a, set_b])

num_runs = 1
# num_runs = 40
network_update_rate = 0.25 # how quickly messages go around the network (?)

print ("simulation ready!")

df = pd.concat([simulate_once(network_sets,
                              num_run,
                              SIMULATION_NUM_VALIDATORS,
                              network_update_rate) for num_run in range(num_runs)])

# the shape of our df is (721, 10). To break it down:
# there are 10 columns; the columns interesting to us are ["average_balance_honest_attestors", "average_balance_dishonest_attestors", "current_slot"]]
# there are 721 rows (why?)

# we have steps = num_slots * SECONDS_PER_SLOT * parameters.frequency
#   so in this case (3*4) * 12 * 1 = 144
#   where the hell is the 5x coming from? # guess might be the 5 psubs?
# the 5x is also the thing that seems to average over a count of 60

print ("simulation done!")

# Since we have 4 slots per epoch, we read the average balances at slot 81, after the last epoch
# rewards and penalties were computed.

slot_to_check = SIMULATION_NUM_EPOCHS * 4 + 1

result = df[df.current_slot == slot_to_check][["average_balance_honest_attestors", 'average_balance_dishonest_attestors']].describe()

print (result)
