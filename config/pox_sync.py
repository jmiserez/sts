from config.experiment_config_lib import ControllerConfig
from sts.control_flow.fuzzer import Fuzzer
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.invariant_checker import InvariantChecker
from sts.topology import MeshTopology, BufferedPatchPanel
from sts.happensbefore.hb_logger import HappensBeforeLogger
from sts.control_flow.interactive import Interactive

# Use POX as our controller
start_cmd = ('''./pox.py --verbose --no-cli sts.syncproto.pox_syncer --blocking=False '''
                '''forwarding.l2_learning '''
                '''sts.util.socket_mux.pox_monkeypatcher '''
                '''openflow.of_01 --address=/tmp/sts_socket_pipe''')


controllers = [ControllerConfig(start_cmd, address="/tmp/sts_socket_pipe", cwd="pox", sync="tcp:localhost:18899")]

topology_class = MeshTopology
topology_params = "num_switches=2"



results_dir = "experiments/pox_sync"

simulation_config = SimulationConfig(controller_configs=controllers,
                                     topology_class=topology_class,
                                     topology_params=topology_params,
                                     multiplex_sockets=True,
                                     violation_persistence_threshold=None,
                                     kill_controllers_on_exit=True,
                                     hb_logger_class=HappensBeforeLogger,
                                     hb_logger_params=results_dir)

# Manual, interactive mode
control_flow = Interactive(simulation_config, input_logger=InputLogger())

