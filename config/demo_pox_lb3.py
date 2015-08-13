from config.experiment_config_lib import ControllerConfig
from sts.topology import MeshTopology
from sts.topology import GridTopology
from sts.control_flow.fuzzer import Fuzzer
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.control_flow.interactive import Interactive

from sts.topology import StarTopology, BufferedPatchPanel
from sts.topology import PatchPanel
from sts.controller_manager import UserSpaceControllerPatchPanel

from sts.control_flow.replayer import Replayer

from sts.happensbefore.hb_logger import HappensBeforeLogger

#
# Running this demo:
# 
# Run STS with this config:
# - ./simulator.py -L logging.cfg -c config/demo_pox_lb3.py
#
# Send a packet from H1 to the VIP address (hardcoded 198.51.100.1)
# - dpp2 1 "198.51.100.1"
#   (Note: dpp2 not dpp. dpp2 sends to arbitrary IP addresses, dpp to other hosts only)
#   -> A packet with VIP dst is sent to SW1. This will trigger installation of replica1
#      and will forward the packet to SW2. There a race occurs between the packet read
#      and the installation of the replica1 rule on SW2.
#
# For a better idea of the topology, take a look at the source code of lb3.py
#
# Note:
#  - cwd should be set to the POX root path.
#

# Use POX as our controller
start_cmd = ('''./pox.py --verbose '''
             '''forwarding.lb3 '''
             '''openflow.of_01 --address=__address__ --port=__port__''')

controllers = [ControllerConfig(start_cmd, cwd="pox/")]

# Each host is connected to a switch, which is connected to each other switch
topology_class = MeshTopology
topology_params = "num_switches=3"

# Where should the output files be written to
results_dir = "experiments/demo_pox_lb3"

simulation_config = SimulationConfig(controller_configs=controllers,
                                     topology_class=topology_class,
                                      topology_params=topology_params,
                                     patch_panel_class=BufferedPatchPanel,
                                     kill_controllers_on_exit=True,
                                     interpose_on_controllers=False,
                                     ignore_interposition=False,
                                     multiplex_sockets=False,
                                     hb_logger_class=HappensBeforeLogger,
                                     hb_logger_params=results_dir)

# Manual, interactive mode
control_flow = Interactive(simulation_config, input_logger=InputLogger())
