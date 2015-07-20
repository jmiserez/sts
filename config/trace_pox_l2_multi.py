from config.experiment_config_lib import ControllerConfig
from sts.topology import StarTopology, BufferedPatchPanel, MeshTopology, GridTopology, BinaryLeafTreeTopology
from sts.controller_manager import UserSpaceControllerPatchPanel
from sts.control_flow.fuzzer import Fuzzer
from sts.control_flow.interactive import Interactive
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.happensbefore.hb_logger import HappensBeforeLogger
from config.application_events import AppCircuitPusher



# Use POX as our controller
start_cmd = ('''./pox.py --verbose '''
              '''openflow.discovery forwarding.l2_multi '''
             '''openflow.of_01 --address=__address__ --port=__port__ ''')

controllers = [ControllerConfig(start_cmd, cwd="pox/")]

topology_class = StarTopology
topology_params = "num_hosts=3"
# topology_class = MeshTopology
# topology_params = "num_switches=5"

# Where should the output files be written to
results_dir = "traces/pox_l2_multi-star3-traffic-failures"

apps = None

# include all defaults
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

# Manual, interactive mode
# control_flow = Interactive(simulation_config, input_logger=InputLogger())

control_flow = Fuzzer(simulation_config,
                      input_logger=InputLogger(),
                      initialization_rounds=20,
                      send_all_to_all=False,
                      check_interval=1,
                      delay=0.1,
                      halt_on_violation=True,
#                       invariant_check_name="check_everything",
                      invariant_check_name="InvariantChecker.check_liveness",
                      apps=apps)