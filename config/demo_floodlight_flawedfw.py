from config.experiment_config_lib import ControllerConfig
from sts.topology import StarTopology, BufferedPatchPanel, MeshTopology, GridTopology
from sts.controller_manager import UserSpaceControllerPatchPanel
from sts.control_flow.fuzzer import Fuzzer
from sts.control_flow.interactive import Interactive
from sts.input_traces.input_logger import InputLogger
from sts.simulation_state import SimulationConfig
from sts.happensbefore.hb_logger import HappensBeforeLogger 

#
# see sts/HBREADME.md for usage
#

#
# Running this demo:
# 
# Compile the Floodlight .jar:
# - cd floodlight/
# - ./ant
# 
# Run STS with this config:
# - ./simulator.py -L logging.cfg -c config/demo_floodlight_fw.py
#
# Send a packet from H2 to H1
# - dpp 2 1
#   -> DENY, drop rule will be installed for H2 to H1 (reverse rules are not installed)
#
# Alternatively, send a packet from H1 to H2
# - dpp 1 2
#   -> ALLOW, fwd rules will be installed H1 to H2 and H2 to H1. Packet out to H2.
#      H2 will generate a echo reply, and send it to H1.
#      
# To enable/disable adding barrier messages:
#  - edit the file floodlight/src/main/java/net/floodlightcontroller/happensbefore/FlawedFirewall.java
#  - set the USE_BARRIERS variable to true or false towards the top of the file
#  - recompile by calling ./ant
#  - rerun
#
#
# Note:
#  - Print Floodlight debug output: Use logback-test-trace.xml instead of logback-test.xml
#  - floodlight.jar must point to the compiled Floodlight jar file. The cwd parameter of 
#    the ControllerConfig class can be used to specify the path where the start_cmd is run.
#    By default, this file is generated in the /target directory.
#  - hb.properties must point to the corresponding file in the Floodlight source.
#    -> Thus, cwd should be set to the Floodlight root path.
#
start_cmd = ('''java -ea -Dlogback.configurationFile=./src/main/resources/logback-test-trace.xml -jar '''
             '''./target/floodlight.jar '''
              '''-cf ./src/main/resources/hb_minimal_flawedfw.properties''')

# Uncomment this if you are running Floodlight separately, e.g. for debugging in Eclipse. There must be a controller listening on port 6633.
# start_cmd = '''echo "no-op"'''

controllers = [ControllerConfig(start_cmd, cwd='../floodlight', address="127.0.0.1", port=6633)]

# One switch, with multiple hosts connected to it
topology_class = StarTopology
topology_params = "num_hosts=2"

# Where should the output files be written to
results_dir = "experiments/demo_floodlight_flawedfw"

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

# Manual, interactive mode
control_flow = Interactive(simulation_config, input_logger=InputLogger())

# Uncomment this if you want to run a replay (not working 100%)
# control_flow = Replayer(simulation_config, "experiments/demo_floodlight_flawedfw/events.trace",
#                         input_logger=InputLogger(),
#                         wait_on_deterministic_values=False,
#                         allow_unexpected_messages=False,
#                         delay_flow_mods=False,
#                         default_dp_permit=True,
#                         pass_through_whitelisted_messages=False,
#                         invariant_check_name="",
#                         bug_signature="")
