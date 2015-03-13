from config.experiment_config_lib import ControllerConfig
from sts.topology import StarTopology, BufferedPatchPanel
from sts.controller_manager import UserSpaceControllerPatchPanel
from sts.control_flow.fuzzer import Fuzzer
from sts.control_flow.interactive import Interactive
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.happensbefore.hb_logger import HappensBeforeLogger 

#
# NOTE JM: don't forget to run ./ant in the floodlight directory to recompile any changes 

start_cmd = ('''java -ea -Dlogback.configurationFile=./src/main/resources/logback-test-trace.xml -jar '''
             '''./target/floodlight.jar '''
             '''-cf ./src/main/resources/hb.properties''')
# start_cmd = "sleep 1"

controllers = [ControllerConfig(start_cmd, cwd='../floodlight', address="127.0.0.1", port=6633)]

topology_class = StarTopology
topology_params = "num_hosts=2"

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


