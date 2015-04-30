from config.experiment_config_lib import ControllerConfig
from sts.topology import StarTopology, BufferedPatchPanel, MeshTopology, GridTopology
from sts.controller_manager import UserSpaceControllerPatchPanel
from sts.control_flow.fuzzer import Fuzzer
from sts.control_flow.interactive import Interactive
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.happensbefore.hb_logger import HappensBeforeLogger 

#
# NOTE JM: don't forget to run ./ant in the floodlight directory to recompile any changes 

# start_cmd = ('''java -ea -Dlogback.configurationFile=./src/main/resources/logback-test-trace.xml -jar '''
start_cmd = ('''java -ea -Dlogback.configurationFile=./src/main/resources/logback-test.xml -jar '''
             '''./target/floodlight.jar '''
#               '''-cf ./src/main/resources/hbtest.properties''')
              '''-cf ./src/main/resources/hb.properties''')
# start_cmd = '''echo "no start_cmd"'''

controllers = [ControllerConfig(start_cmd, cwd='../floodlight', address="127.0.0.1", port=6633)]

topology_class = StarTopology
topology_params = "num_hosts=2"

# topology_class = GridTopology
# topology_params = "num_rows=3, num_columns=3"

# topology_class = MeshTopology
# topology_params = "num_switches=8"

results_dir = "experiments/floodlight_config"

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
                                     hb_logger_params=results_dir)

control_flow = Interactive(simulation_config, input_logger=InputLogger())

# control_flow = Fuzzer(simulation_config,
#                       input_logger=InputLogger(),
#                       invariant_check_name="InvariantChecker.python_save_tf",
#                       #invariant_check_name="check_everything",
#                       initialization_rounds=10,
#                       check_interval=10,
#                       delay=0.3,
#                       halt_on_violation=True)

# control_flow = Fuzzer(simulation_config,
#                       input_logger=InputLogger(),
#                       initialization_rounds=1,
#                       check_interval=100,
#                       delay=0.1,
#                       halt_on_violation=False,
# #                       invariant_check_name="check_everything")
#                       invariant_check_name="InvariantChecker.check_liveness")
