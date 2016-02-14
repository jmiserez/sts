from config.experiment_config_lib import ControllerConfig
from sts.topology import StarTopology, BufferedPatchPanel, MeshTopology, GridTopology, BinaryLeafTreeTopology
from sts.controller_manager import UserSpaceControllerPatchPanel
from sts.control_flow.fuzzer import Fuzzer
from sts.control_flow.interactive import Interactive
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.happensbefore.hb_logger import HappensBeforeLogger
from config.application_events import AppFloodlightLoadBalancer

# This starts a Floodlight process in a separate process. The .properties file referenced here
# contains the parameters used by Floodlight.

start_cmd = ('''java -ea -Dlogback.configurationFile=./src/main/resources/logback-test-trace.xml -jar '''
             '''./target/floodlight.jar '''
              '''-cf ./src/main/resources/trace_loadbalancer.properties''')

# This specifies the controller that STS should use.
controllers = [ControllerConfig(start_cmd, cwd='../floodlight', address="127.0.0.1", port=6633)]

# Uncomment this if you are running Floodlight separately, e.g. for debugging in Eclipse. There must be a controller listening on port 6633.
# start_cmd = '''echo "no-op"'''
# controllers = [ControllerConfig(start_cmd, cwd='../floodlight', address="127.0.0.1", port=6633, controller_type='dummy')]

#################################
# Topologies used in PLDI paper #
#################################

# Uncomment exactly one of the topologies below to use it..

############
# "Single" #
# ############
# num = 2
# topology_class = StarTopology #
# topology_params = "num_hosts=%d" % num

#############
# "Single4" #
#############
# num = 4
# topology_class = StarTopology #
# topology_params = "num_hosts=%d" % num

############
# "Linear" #
############
#num = 2
#topology_class = MeshTopology
#topology_params = "num_switches=%d" % num

############
# "BinTree" #
############
num = 2
topology_class = BinaryLeafTreeTopology
topology_params = "num_levels=%d" % num

# Increase this value to get longer traces
steps = 200

# This folder will be placed in the root STS directory
# To see the exact parameters used for each trace, refer to the "orig_config.py" in each trace directory.
# This file will be copied to the results_dir, along with the results themselves.

results_dir = "plditraces/trace_floodlight_loadbalancer-%s%d-steps%s" % (topology_class.__name__, num, steps)

apps = [AppFloodlightLoadBalancer('loadbalancer', cwd='./', controller='localhost:8080')]

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
                      send_all_to_all=True, # needs to be True otherwise loadbalancer will throw errors.
                      check_interval=10,
                      delay=0.1,
                      halt_on_violation=True,
                      send_init_packets=False,
                      steps=steps, # if no circuits are installed, increase this number.
#                       invariant_check_name="check_everything",
                      invariant_check_name="InvariantChecker.check_liveness",
                      apps=apps)
