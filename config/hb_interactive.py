
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



# Use POX as our controller
start_cmd = ('''./pox.py forwarding.l2_learning '''
             '''openflow.of_01 --address=__address__ --port=__port__''')


start_cmd = ('''./pox.py --verbose '''
             #'''sts.syncproto.pox_syncer --blocking=False '''
             '''pox.forwarding.lb'''
            # '''sts.util.socket_mux.pox_monkeypatcher '''
             '''openflow.of_01 --address=__address__ --port=__port__''')

start_cmd = ('''./pox.py --verbose '''
             '''forwarding.lb2 '''
             '''openflow.of_01 --address=__address__ --port=__port__''')


controllers = [ControllerConfig(start_cmd, cwd="pox/")]
#controllers = [ControllerConfig(start_cmd, cwd="pox", sync="tcp:localhost:18899")]


topology_class = MeshTopology
topology_params = "num_switches=3"




results_dir = "experiments/hb_test"

simulation_config = SimulationConfig(controller_configs=controllers,
                                     topology_class=topology_class,
                                     topology_params=topology_params,
                                     patch_panel_class=BufferedPatchPanel,
                                     kill_controllers_on_exit=True,
                                     interpose_on_controllers=False,
                                     ignore_interposition=False,
                                     hb_logger_class=HappensBeforeLogger,
                                     hb_logger_params=None)

control_flow = Interactive(simulation_config, input_logger=InputLogger())
"""
control_flow = Fuzzer(simulation_config,
                      input_logger=InputLogger(),
                      #invariant_check_name="InvariantChecker.python_save_tf",
                      invariant_check_name="check_everything",
                      initialization_rounds=10,
                      check_interval=10,
                      delay=0.3,
                      halt_on_violation=True)
"""