### Running SDNRacer and example scenarios.

This document will describe how to run the scenarios currently available for SDNRacer.

### Prerequisites

These instructions were tested on a fresh install of Ubuntu 14.04.3 LTS 64bit inside a VM.

- VM parameters: 
  - VirtualBox 4.3.30
  - 2GB RAM, 32GB HDD, default settings unless noted otherwise
  - Installation of Ubuntu 14.04.03 LTS 64bit using default settings, updates enabled
  - Latest updates installed (apt-get update; apt-get upgrade)

- Install the following packages on top of the fresh install:

```
$ sudo apt-get install git build-essential python-dev ant openjdk-7-jdk python-docutils python-networkx xdot graphviz
```

Dependencies due to:
- General: git, build-essential
- Hassel: python-dev
- Floodlight: ant, openjdk-7-jdk
- STS: python-docutils
- SDNRacer: python-networkx
- Viewing .dot files: xdot, graphviz

### Installation

This assumes an install in the home directory, but any other directory works just as well.

- Checkout STS and POX, install hassel:

```
$ cd ~
$ git clone https://github.com/jmiserez/sts.git
$ cd sts
$ git checkout hb
$ git submodule update --init --recursive
$ ./tools/install_hassel_python.sh
```

- Checkout Floodlight, and build the jar file:

```
$ cd ~
$ git clone https://github.com/jmiserez/floodlight.git
$ cd floodlight
$ git checkout hb
$ ant
```

### Scenarios

In the following chapters, the following scenarios are described:

Fuzzer:
- demo_floodlight_circuitpusher.py
- demo_pox_l2_learning.py

Interactive (specific scenarios/races from the paper):
- demo_floodlight_flawedfw.py

The first scenario is described in detail, the following ones only where the procedure is different.

#### Scenario #1: Running the Floodlight circuitpusher scenario

The circuitpusher scenario uses an external Floodlight process as the controller, and adds/removes circuits through the REST interface exposed by Floodlight. The topology used here is that of a binary tree, where the nodes are switches and the leaves are hosts. The BinaryLeafTreeTopology tree in this example has 3 levels of switches under the root, resulting in a total of 1+2+4+8=15 switches and 8*2=16 hosts.

- Run the config (demo_floodlight_circuitpusher.py).

```
$ cd ~/sts
$ ./simulator.py -L logging.cfg -c config/demo_floodlight_circuitpusher.py
```

- The prompt asking for Github credentials can be ignored (just press ENTER).

- The simulation will terminate automatically after 100 rounds, this can be disabled by removing the steps=200 parameter to the Fuzzer object in the config file.

- The trace directory is: sts/experiments/demo_floodlight_circuitpusher/
- The trace file we are interested in is named 'hb.json'.

- Run the race detection: on the hb.json file:

```
$ ./sts/happensbefore/hb_graph.py experiments/demo_floodlight_circuitpusher/hb.dot
```

- The console output shows:
  * Each individual race, with details for the involved operations
  * A list of event ids that contain operations (reads/writes)
  * A summary of the number of races.

- A graphviz file is written to experiments/demo_floodlight_circuitpusher/hb.dot

Viewing the graphviz file is possible in several ways:

- Recommended: view the file directly using 'xdot':

```
$ xdot experiments/demo_floodlight_circuitpusher/hb.json
```

- Alternatively: create a PDF using 'dot'. Note that some viewers struggle a bit with large graphs.

```
$ dot -Tpdf experiments/demo_floodlight_circuitpusher/hb.dot -o experiments/demo_floodlight_circuitpusher/hb.pdf
```

#### Scenario #2: Running the POX learning switch

The graph from this scenario is a bit more interesting to look at. Again this simulation will terminate after 100 rounds, which can be disabled by uncommenting the corresponding line in the configuration file. The BinaryLeafTreeTopology tree in this example has 1 level of switches under the root, resulting in a total of 1+2=3 switches and 2*2=4 hosts.

```
$ cd ~/sts
$ ./simulator.py -L logging.cfg -c config/demo_pox_l2_learning.py
$ ./sts/happensbefore/hb_graph.py experiments/demo_pox_l2_learning/hb.json
$ xdot experiments/demo_pox_l2_learning/hb.dot
```

#### Scenario #3: Interactively running the flawed firewall described in the paper.

Topology:
```
h1 -- s1 -- h2
```

This runs through the scenario described in the paper interactively. Thus, in order to reproduce the races described in the paper, the following steps must be followed.

- Check that the currently checked out version of the FlawedFirewall.java does not make use of barrier requests:

```
$ cd ~/floodlight
$ fgrep "USE_BARRIER =" src/main/java/net/floodlightcontroller/happensbefore/FlawedFirewall.java
```

The output should contain:
```
protected final static boolean USE_BARRIER = false;
```

Now we can run the firewall example and produce a race.

```
$ cd ~/sts
$ ./simulator.py -L logging.cfg -c config/demo_floodlight_flawedfw.py
```

You will be dropped into interactive mode. Press ENTER once or twice until initialization is done. Then:

- Send a packet from H2 to H1 (from outside of the FW to the firewalled host H2)
```
STS [next] > dpp 2 1
```

Press ENTER a few times until everything is done. You should see this line somewhere:

```
[c1] INFO [n.f.h.FlawedFirewall:New I/O server worker #2-1] Firewall on 1: DENY  Incoming traffic from 123.123.1.2 to 123.123.1.1
```

Thus, a DENY, drop rule was installed for H2 -> H1 (reverse rules are not installed).

- Now, send a packet from H1 to H2
```
STS [next] > dpp 1 2
```

Similarly, you should see the following line:

```
[c1] INFO [n.f.h.FlawedFirewall:New I/O server worker #2-1] Firewall on 1: ALLOW Outgoing traffic from 123.123.1.1 to 123.123.1.2
```

An ALLOW, fwd rule was installed for H1 to H2 and H2 to H1. The Packet-Out was sent to H2. H2 will generate a echo reply, and send it to H1. H1 will receive the echo reply and not respond further. These new rules have higher priority than the previous DENY rule. All further traffic will be able to pass through in both directions.

Note that it is possible that the echo reply will not be received by H1 due to the race described in the paper, however due to the long delays in interactive mode this never happens. The race can be forced by setting INDUCE_RACE_CONDITION to True in FlawedFirewall.java, but this is not well-tested and does not affect the race detection.

- Running the race detection:

```
$ ./sts/happensbefore/hb_graph.py experiments/demo_floodlight_flawedfw/hb.json
```

should give us the race described in the paper: If only the second part is run (dpp 1 2), there should be 2 harmful and 2 commuting races. If both (dpp 2 1 and dpp 1 2) are run, this number goes up to 4 harmful and 7 commuting races (as there are no barriers and the two flow mods race with the read.

The graph visualizes both scenarios very nicely (red lines without arrows are harmful races, dotted lines are commuting races):

```
$ xdot experiments/demo_floodlight_flawedfw/hb.dot
```

- Now, we can "fix" the FlawedFirewall to use barriers:

```
$ cd ~/floodlight
$ sed -i 's/USE_BARRIER = false/USE_BARRIER = true/g' src/main/java/net/floodlightcontroller/happensbefore/FlawedFirewall.java
```

- Verify:

```
$ fgrep "USE_BARRIER =" src/main/java/net/floodlightcontroller/happensbefore/FlawedFirewall.java
```

The output should be:

```
protected final static boolean USE_BARRIER = true;
```

- Recompile Floodlight (do not forget this step!):

```
$ ant
```

Then, rerun the above steps (dpp 1 2) and take a look at the resulting output. The result should be 1 commuting, 1 harmful (dpp 1 2), and 5 commuting, 3 harmful (dpp 2 1, dpp 1 2). Looking at the graph it can be seen that the race described in the paper has disappeared. 

The remaining races are due to insufficient filtering of r/w races: Using the (very crude) filter_rw commandline option gets rid of these:

```
$ ./sts/happensbefore/hb_graph.py experiments/demo_floodlight_flawedfw/hb.json --filter_rw
```

Now there should be 1 commuting, 0 harmful (dpp 1 2), and 3 commuting, 0 harmful (dpp 2 1, dpp 1 2) races. The filtering method is currently being improved to use a superior method.

Additional note: To get more detailed Floodlight debug output, the use of 'logback-test.xml' in the config file can be replaced with 'logback-test-trace.xml'.

#### Scenario #4: Interactively running the flawed load balancer as described in the paper.

This runs through the load balancing scenario described in the paper interactively.

Recall the topology:
```
 h1--s1 ----- s2--replica1
      \      /
       \   < > link never used
        \  /
         s3--replica2
```

And the race described in the paper:

1. h1 sends a packet to the VIP address (in this scenario 198.51.100.1)
2. At s1, the controller installs flows on all switches to replica1
3. The packet is forwarded from s1 to s2, where the race happens.

- Start the simulator:
```
$ cd ~/sts
$ ./simulator.py -L logging.cfg -c config/demo_pox_lb3.py
```

- Send a packet from H1 to the VIP address (hardcoded 198.51.100.1). "dpp2" sends a packet to an arbitrary IP address, rather than a specific host.
```
STS [next] > dpp2 1 "198.51.100.1"
```

- Continue pressing ENTER a few times.

- Run the race detection:
```
$ ./sts/happensbefore/hb_graph.py experiments/demo_pox_lb3/hb.json
```

There should be 5 commuting, 4 harmful races. Using the '--filter-rw' parameter, this is reduced to 5 commuting, 1 harmful race:

```
$ ./sts/happensbefore/hb_graph.py experiments/demo_pox_lb3/hb.json --filter-rw
```

- The single race described in the paper should be very visible in the visualization, as it is the only red line in the graph.

```
$ xdot experiments/demo_pox_lb3/hb.dot
```

### More: Flags supported by the race detector

The analyzer supports a few arguments that can be passed to create smaller .dot files for viewing. The complete list is defined at the very bottom of the hb_graph.py file, a few useful ones are:

- ```--pkt```: Print packet headers in the graph
- ```--racing```: Print only races in the graph
- ```--harmful```: Print only harmful races (lines) in the graph
- ```--ignore_ethertypes```: Ignore specified ethertypes, by default LLDP and 0x8942 (BigSwitchNetwork) packets.



