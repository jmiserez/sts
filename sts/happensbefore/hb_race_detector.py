import itertools

from pox.openflow.flow_table import TableEntry
from pox.openflow.libopenflow_01 import ofp_match

from hb_utils import ofp_flow_mod_command_to_str
from hb_utils import nCr

from hb_comute_check import CommutativityChecker


# Sanity check! This is a mapping of all predecessor types that make sense.
predecessor_types = {
  'HbAsyncFlowExpiry': [
    'HbMessageSend',
  ],
  'HbPacketHandle': [
    'HbPacketSend',
    'HbHostSend',
  ],
  'HbPacketSend': [
    'HbPacketHandle',
    'HbMessageHandle',
  ],
  'HbMessageHandle': [
    'HbMessageHandle',
    'HbControllerSend',
    'HbPacketHandle', # buffer put -> buffer get!
    'HbMessageSend', # merged controller edges
  ],
  'HbMessageSend': [
    'HbAsyncFlowExpiry',
    'HbPacketHandle',
    'HbMessageHandle',
  ],
  'HbHostHandle': [
    'HbPacketSend'
  ],
  'HbHostSend': [
    'HbHostHandle',
  ],
  'HbControllerHandle': [
    'HbMessageSend',
  ],
  'HbControllerSend': [
    'HbControllerHandle',
  ],
}


class RaceDetector(object):

  # TODO(jm): make filter_rw a config option
  def __init__(self, graph, filter_rw=False):
    self.graph = graph

    self.read_operations = []
    self.write_operations = []
    self.races_harmful = []
    self.races_commute = []
    self.racing_events = set()
    self.racing_events_harmful = set()
    self.total_operations = 0
    self.total_harmful = 0
    self.total_commute = 0
    self.total_filtered = 0
    self.total_races = 0

    self.commutativity_checker = CommutativityChecker()

    self.filter_rw = filter_rw # Filter events with no common ancestor if True.

  def is_reachable(self, source, target, visited=None):
    if visited is None:
      visited = set()
    visited.add(source)
    parents = self.graph.predecessors[source]
    if target in parents:
      return True
    for p in parents:
      if p not in visited:
        if self.is_reachable(p, target, visited):
          return True
    return False

  def is_ordered(self, event, other):
    # TODO(jm): horribly inefficient, this should be done the right way
    older = event if event.eid < other.eid else other
    newer = event if event.eid > other.eid else other
    if self.is_reachable(newer, older):
      return True
    if self.is_reachable(older, newer): # need to check due to async controller instrumentation # TODO(jm): change numbering of controller events so that we can finally remove this
      return True
    return False

  def get_ancestors(self, event):
    visited = set()
    visited.add(event)

    parents = self.graph.predecessors[event]

    while len(parents) > 0:
      nextp = set()
      for p in parents:
        visited.add(p)
        nextp.update(self.graph.predecessors[p])

      nextp.difference_update(visited) #remove already visited
      parents = nextp

    visited_ids = set()
    for i in visited:
      visited_ids.add(i.eid)
    return visited_ids

  def has_common_ancestor(self, event, other):
    # TODO(jm): horribly inefficient, this should be done the right way. But it works for now.
    event_ancs = self.get_ancestors(event)
    other_ancs = self.get_ancestors(other)

    isdisjoint = event_ancs.isdisjoint(other_ancs)
    if isdisjoint:
      return False
    else:
      return True

  def read_ops(self):
    """
    Helper method to extract read and write operations from the HB graph.
    MUST be called before detect_rw and detect_ww. But detect_races calls it
    automatically.
    """
    self.read_operations = []
    self.write_operations = []

    for i in self.graph.events:
      if hasattr(i, 'operations'):
        for k in i.operations:
          if k.type == 'TraceSwitchFlowTableWrite':
            assert hasattr(k, 'flow_table')
            assert hasattr(k, 'flow_mod')
            dbg_fm = k.flow_mod
            dbg_str = "Write: "+str("None" if dbg_fm is None else ofp_flow_mod_command_to_str(dbg_fm.command) + " => " +TableEntry.from_flow_mod(
                                        dbg_fm
                                        ).show())
            op = (i, k.flow_table, k.flow_mod, dbg_str)
            self.write_operations.append(op)
          elif k.type == 'TraceSwitchFlowTableRead':
            assert hasattr(k, 'flow_table')
            assert hasattr(k, 'flow_mod')
            assert hasattr(i, 'packet')
            assert hasattr(i, 'in_port')
#             dbg_table = decode_flow_table(k.flow_table)
            dbg_fm_retval = k.flow_mod
            dbg_packet = i.packet
            dbg_m_pkt = ofp_match.from_packet(dbg_packet, i.in_port)

            dbg_str = "Read rule: "+str("None" if dbg_fm_retval is None else TableEntry.from_flow_mod(dbg_fm_retval).show()
                                        ) + "\n| For packet: " + str(dbg_m_pkt)
            op = (i, k.flow_table, k.flow_mod, i.packet, i.in_port, dbg_str)
            self.read_operations.append(op)

  def detect_ww_races(self, event=None, verbose=False):
    count = 0
    percentage_done = 0

    ww_combination_count = nCr(len(self.write_operations),2)

    if verbose:
      print "Processing {} w/w combinations".format(ww_combination_count)
    # write <-> write
    for i, k in itertools.combinations(self.write_operations,2):
      i_event, i_flow_table, i_flow_mod, i_dbg_str = i
      k_event, k_flow_table, k_flow_mod, k_dbg_str = k
      if verbose:
        count += 1
        percentage = int(((count / float(ww_combination_count)) * 100)) // 10 * 10
        if percentage > percentage_done:
          percentage_done = percentage
          print "{}% ".format(percentage)
      if (i_event != k_event and
          (event is None or event == i_event or event == k_event) and
          i_event.dpid == k_event.dpid and
          not self.is_ordered(i_event, k_event)):

        if self.commutativity_checker.check_commutativity_ww(i,k):
          self.races_commute.append(('w/w',i_event,k_event,i_dbg_str,k_dbg_str))
        else:
          self.races_harmful.append(('w/w',i_event,k_event,i_dbg_str,k_dbg_str))
          self.racing_events_harmful.add(i_event)
          self.racing_events_harmful.add(k_event)
        self.racing_events.add(i_event)
        self.racing_events.add(k_event)

  def detect_rw_races(self, event=None, verbose=False):
    percentage_done = 0
    count = 0
    rw_combination_count = len(self.read_operations)*len(self.write_operations)

    if verbose:
      print "Processing {} r/w combinations".format(rw_combination_count)
    # read <-> write
    for i in self.read_operations:
      for k in self.write_operations:
        if verbose:
          count += 1
          percentage = int(((count / float(rw_combination_count)) * 100)) // 10 * 10
          if percentage > percentage_done:
            percentage_done = percentage
            print "{}% ".format(percentage)
        i_event, i_flow_table, i_flow_mod, i_packet, i_in_port, i_dbg_str = i
        k_event, k_flow_table, k_flow_mod, k_dbg_str = k
        if (i_event != k_event and
            (event is None or event == i_event or event == k_event) and
            i_event.dpid == k_event.dpid and
            not self.is_ordered(i_event, k_event)):

          if self.filter_rw and not self.has_common_ancestor(i_event, k_event):
            self.total_filtered += 1
          else:
            if self.commutativity_checker.check_commutativity_rw(i,k):
              self.races_commute.append(('r/w',i_event,k_event,i_dbg_str,k_dbg_str))
            else:
              self.races_harmful.append(('r/w',i_event,k_event,i_dbg_str,k_dbg_str))
              self.racing_events_harmful.add(i_event)
              self.racing_events_harmful.add(k_event)
            self.racing_events.add(i_event)
            self.racing_events.add(k_event)

  # TODO(jm): make verbose a config option
  def detect_races(self, event=None, verbose=False):
    """
    Detect all races that involve event.
    Detect all races for all events if event is None.
    """
    self.read_ops()

    if verbose:
      print "Total write operations: {}".format(len(self.write_operations))
      print "Total read operations: {}".format(len(self.read_operations))

    self.races_harmful = []
    self.races_commute = []
    self.racing_events = set()
    self.racing_events_harmful = set()
    self.total_filtered = 0

    self.detect_ww_races(event, verbose)

    self.detect_rw_races(event, verbose)

    self.total_operations = len(self.write_operations) + len(self.read_operations)
    self.total_harmful = len(self.races_harmful)
    self.total_commute = len(self.races_commute)
    self.total_races = self.total_harmful + self.total_commute

  def print_races(self):
    for race in self.races_commute:
      print "+-------------------------------------------+"
      print "| Commuting ({}):     {:>4} <---> {:>4}      |".format(race[0], race[1].eid, race[2].eid)
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[1].eid)
      print "+-------------------------------------------+"
      print "| " + race[3]
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[2].eid)
      print "+-------------------------------------------+"
      print "| " + race[4]
      print "+-------------------------------------------+"
    for race in self.races_harmful:
      print "+-------------------------------------------+"
      print "| Harmful   ({}):     {:>4} >-!-< {:>4}      |".format(race[0], race[1].eid, race[2].eid)
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[1].eid)
      print "+-------------------------------------------+"
      print "| " + race[3]
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[2].eid)
      print "+-------------------------------------------+"
      print "| " + race[4]
      print "+-------------------------------------------+"
    print "+-------------------------------------------+"
    for ev in self.read_operations:
      print "| {:>4}: {:28} (read) |".format(ev[0].eid, ev[0].type)
    for ev in self.write_operations:
      print "| {:>4}: {:27} (write) |".format(ev[0].eid, ev[0].type)
    print "| Total operations:      {:<18} |".format(self.total_operations)
    print "|-------------------------------------------|"
    print "| Total commuting races: {:<18} |".format(self.total_commute)
    print "| Total harmful races:   {:<18} |".format(self.total_harmful)
    print "| Total filtered races:  {:<18} |".format(self.total_filtered)
    print "+-------------------------------------------+"
