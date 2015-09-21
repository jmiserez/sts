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
# see sts/HBREADME.md for usage
#

# Use POX as our controller
start_cmd = ('''./pox.py --verbose '''
             '''forwarding.te '''
             '''openflow.of_01 --address=__address__ --port=__port__''')

controllers = [ControllerConfig(start_cmd, cwd="pox/")]

topology_class = GridTopology
topology_params = "num_rows=2"

# Where should the output files be written to
results_dir = "experiments/demo_pox_te"

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
