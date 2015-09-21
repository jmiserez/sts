from config.experiment_config_lib import ControllerConfig
from sts.topology import StarTopology, BufferedPatchPanel, MeshTopology, GridTopology, BinaryLeafTreeTopology
from sts.controller_manager import UserSpaceControllerPatchPanel
from sts.control_flow.fuzzer import Fuzzer
from sts.control_flow.interactive import Interactive
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.happensbefore.hb_logger import HappensBeforeLogger
from config.application_events import AppCircuitPusher

#
# see sts/HBREADME.md for usage
#

start_cmd = ('''java -ea -Dlogback.configurationFile=./src/main/resources/logback-trace.xml -jar '''
             '''./target/floodlight.jar '''
              '''-cf ./src/main/resources/demo_circuitpusher.properties''')

controllers = [ControllerConfig(start_cmd, cwd='../floodlight', address="127.0.0.1", port=6633)]

topology_class = BinaryLeafTreeTopology
topology_params = "num_levels=3"

results_dir = "experiments/demo_floodlight_circuitpusher"

apps = [AppCircuitPusher('circuitpusher', cwd='../floodlight/apps/circuitpusher', runtime='python', script='circuitpusher.py', controller='localhost:8080')]

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
                      send_all_to_all=True, # needs to be True otherwise circuitpusher will throw errors.
                      check_interval=1,
                      delay=0.1,
                      steps=400, # if no circuits are installed, increase this number.
                      halt_on_violation=True,
                      invariant_check_name="InvariantChecker.check_liveness",
                      apps=apps)