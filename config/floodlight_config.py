from config.experiment_config_lib import ControllerConfig
from sts.topology import StarTopology, BufferedPatchPanel
from sts.controller_manager import UserSpaceControllerPatchPanel
from sts.control_flow.fuzzer import Fuzzer
from sts.control_flow.interactive import Interactive
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.happensbefore.hb_logger import HappensBeforeLogger 

# Use POX as our controller
start_cmd = ('''java -ea -Dlogback.configurationFile=/home/jeremie/mscthesis/floodlight/src/main/resources/logback-test-trace.xml -jar '''
             '''/home/jeremie/mscthesis/floodlight/target/floodlight-flawedfirewall.jar '''
             '''-cf /home/jeremie/mscthesis/floodlight/src/main/resources/flawedfirewall.properties''')
controllers = [ControllerConfig(start_cmd, cwd="/home/jeremie/mscthesis/floodlight", address="127.0.0.1", port=6633)]

topology_class = StarTopology
topology_params = "num_hosts=2"

#simulation_config = SimulationConfig(controller_configs=controllers,
#                                     topology_class=topology_class,
#                                     topology_params=topology_params)
#
#control_flow = Fuzzer(simulation_config,
#                      input_logger=InputLogger(),
#                      invariant_check_name="InvariantChecker.check_blackholes",
#                      check_interval=5,
#                      halt_on_violation=True)


# simulation_config = SimulationConfig(controller_configs=controllers,
#                                      topology_class=topology_class,
#                                      topology_params=topology_params)


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
                                     hb_logger_params=None)

control_flow = Interactive(simulation_config, input_logger=InputLogger())


