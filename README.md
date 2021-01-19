# Beacon Runner (CAMCOS)

An agent-based model of [eth2](https://github.com/ethereum/eth2.0-specs), forked from Barnabe (https://github.com/barnabemonnot/beaconrunner).

## Starting up

You can simply run the following commands in a terminal, assuming `pipenv` is installed on your machine.

```
git clone https://github.com/krzhang/beaconrunner-CAMCOS.git
cd beaconrunner-CAMCOS
git clone https://github.com/danlessa/cadCAD.git
cd cadCAD
git checkout tweaks
cd ..
pipenv install
pipenv shell
```

Once you enter the shell, you can run `thunderdome.py`, which is a variant of the (unchanged) Jupyter notebook `thunderdome.pynb`.

```
jupyter lab
```
