
from config.experiment_config_lib import ControllerConfig
from sts.topology import MeshTopology, BinaryLeafTreeTopology
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

start_cmd = ('''./pox.py --verbose '''
              '''forwarding.l2_learning '''
             '''openflow.of_01 --address=__address__ --port=__port__ ''')

controllers = [ControllerConfig(start_cmd, cwd="pox/")]

topology_class = BinaryLeafTreeTopology
topology_params = "num_levels=1"

results_dir = "experiments/demo_pox_l2_learning"

apps = None

simulation_config = SimulationConfig(controller_configs=controllers,
                                     topology_class=topology_class,
                                     topology_params=topology_params,
                                     patch_panel_class=BufferedPatchPanel,
                                     controller_patch_panel_class=UserSpaceControllerPatchPanel,
                                     dataplane_trace=None,
                                     snapshot_service=None,
                                     multiplex_sockets=False,
                                     violation_persistence_threshold=None,
                                     kill_controllers_on_exit=True,
                                     interpose_on_controllers=False,
                                     ignore_interposition=False,
                                     hb_logger_class=HappensBeforeLogger,
                                     hb_logger_params=results_dir,
                                     apps=apps)

control_flow = Fuzzer(simulation_config,
                      input_logger=InputLogger(),
                      initialization_rounds=20,
                      send_all_to_all=False,
                      check_interval=1,
                      delay=0.1,
                      steps=100, # uncomment this line to let the simulation run indefinitely
                      halt_on_violation=True,
                      invariant_check_name="InvariantChecker.check_liveness",
                      apps=apps)