from collections import namedtuple
import itertools
import networkx as nx

from hb_utils import op_to_str
from hb_utils import nCr

from hb_commute_check import CommutativityChecker


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


# Define race type
Race = namedtuple('Race', ['rtype', 'i_event', 'i_op', 'k_event', 'k_op'])


class RaceDetector(object):

  # TODO(jm): make filter_rw a config option
  def __init__(self, graph, filter_rw=False, add_hb_time=False, rw_delta=5,
               ww_delta=1):
    self.graph = graph

    self.read_operations = []
    self.write_operations = []
    self.all_races = []
    self.found_races_harmful = []
    self._races_harmful = []
    self.filtered_by_time = set()
    self.races_commute = []
    self.racing_events = set()
    self.racing_events_harmful = set()
    self.total_filtered = 0
    self.covered_races = []

    self.commutativity_checker = CommutativityChecker()

    self.filter_rw = filter_rw # Filter events with no common ancestor if True.
    self.ww_delta = ww_delta
    self.rw_delta = rw_delta
    self.add_hb_time = add_hb_time
    # Just to keep track of how many HB edges where added based on time
    self._time_edges_counter = 0


  @property
  def total_operations(self):
    return len(self.write_operations) + len(self.read_operations)

  @property
  def total_harmful(self):
    return len(self.races_harmful)

  @property
  def total_commute(self):
    return len(self.races_commute)

  @property
  def total_covered(self):
    return len(self.covered_races)

  @property
  def total_races(self):
    assert len(self.all_races) == self.total_harmful + self.total_commute + self.total_time_filtered_races + self.total_covered
    return len(self.all_races)

  @property
  def total_time_filtered_races(self):
    return len(self.filtered_by_time)

  @property
  def races_harmful(self):
    return self._races_harmful

  @property
  def races_harmful_with_covered(self):
    return list(set(self.races_harmful).union(set(self.covered_races)))
  
  @property
  def time_edges_counter(self):
    return self._time_edges_counter

  def is_ordered(self, event, other):
    """
    It only matters that there is an ordering in the graph between the two events,
    but it is irrelevant in which direction.
    """
    return self.graph.has_path(event.eid, other.eid, bidirectional=True)

  def has_common_ancestor(self, event, other):
    """
    Returns true the two events have a common ancestor or they're ancestors of
    each other.
    """
    event_ancs = nx.ancestors(self.graph.g, event.eid)
    other_ancs = nx.ancestors(self.graph.g, other.eid)
    event_ancs.add(event.eid)
    other_ancs.add(other.eid)
    return not event_ancs.isdisjoint(other_ancs)

  def read_ops(self):
    """
    Helper method to extract read and write operations from the HB graph.
    MUST be called before detect_rw and detect_ww. But detect_races calls it
    automatically.
    """
    self.read_operations = []
    self.write_operations = []

    for eid in self.graph.events_with_reads_writes:
      i = self.graph.events_by_id[eid]
      if hasattr(i, 'operations'):
        for k in i.operations:
          if k.type == 'TraceSwitchFlowTableWrite':
            assert hasattr(k, 'flow_table')
            assert hasattr(k, 'flow_mod')
            self.write_operations.append((i, k))
          elif k.type == 'TraceSwitchFlowTableRead':
            assert hasattr(k, 'flow_table')
            assert hasattr(k, 'flow_mod')
            assert hasattr(i, 'packet')
            assert hasattr(i, 'in_port')
            self.read_operations.append((i, k))
          # TODO(jm): Do we need to consider TraceSwitchFlowTableEntryExpiry here as well??? Probably yes?
          #           However, for expiry, the flow_table is the table *after* the operation, so some changes are needed.

  def detect_ww_races(self, event=None, verbose=False):
    count = 0
    percentage_done = 0

    ww_combination_count = nCr(len(self.write_operations),2)

    if verbose:
      print "Processing {} w/w combinations".format(ww_combination_count)
    # write <-> write
    for (i_event, i_op), (k_event, k_op) in itertools.combinations(self.write_operations, 2):
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
        race = Race('w/w', i_event, i_op, k_event, k_op)
        self.all_races.append(race)
        if self.commutativity_checker.check_commutativity_ww(i_event, i_op,
                                                             k_event, k_op):
          self.races_commute.append(race)
        else:
          self.found_races_harmful.append(race)
        self.racing_events.add(i_event)
        self.racing_events.add(k_event)

  def detect_rw_races(self, event=None, verbose=False):
    percentage_done = 0
    count = 0
    rw_combination_count = len(self.read_operations)*len(self.write_operations)

    if verbose:
      print "Processing {} r/w combinations".format(rw_combination_count)
    # read <-> write
    for i_event, i_op in self.read_operations:
      for k_event, k_op in self.write_operations:
        if verbose:
          count += 1
          percentage = int(((count / float(rw_combination_count)) * 100)) // 10 * 10
          if percentage > percentage_done:
            percentage_done = percentage
            print "{}% ".format(percentage)
        if (i_event != k_event and
            (event is None or event == i_event or event == k_event) and
            i_event.dpid == k_event.dpid and
            not self.is_ordered(i_event, k_event)):

          if self.filter_rw and not self.has_common_ancestor(i_event, k_event):
            self.total_filtered += 1
          else:
            race = Race('r/w',i_event, i_op, k_event, k_op)
            self.all_races.append(race)
            if self.commutativity_checker.check_commutativity_rw(i_event, i_op,
                                                                 k_event, k_op):
              self.races_commute.append(race)
            else:
              self.found_races_harmful.append(race)
            self.racing_events.add(i_event)
            self.racing_events.add(k_event)

  def apply_time_filter(self, delta):
    self._time_edges_counter = 0
    self.filtered_by_time = set()
    for race in self.found_races_harmful:
      d = abs(race.i_op.t - race.k_op.t)
      if d > delta:
        self.filtered_by_time.add(race)
        first = race.i_event if race.i_op.t < race.k_op.t else race.k_event
        second = race.k_event if first == race.i_event else race.i_event
        assert first != second
        # update_path_cache is False: This edge will not be considered until the path_cache is updated
        self.graph._add_edge(first, second, sanity_check=False, update_path_cache=False, rel='time')
        self._time_edges_counter += 1

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

    self.found_races_harmful = []
    self.races_commute_count = []
    self.racing_events = set()
    self.racing_events_harmful = set()
    self.total_filtered = 0

    self.detect_ww_races(event, verbose)

    self.detect_rw_races(event, verbose)

    if self.add_hb_time:
      self.apply_time_filter(self.rw_delta)

    # Calculate true harmful
    # TODO(jm): This line of code eats memory like crazy, and takes forever! Change this!
    self._races_harmful = [race for race in self.found_races_harmful if race not in self.filtered_by_time]

    self.racing_events_harmful = set()
    for race in self.races_harmful:
      self.racing_events_harmful.add(race.i_event)
      self.racing_events_harmful.add(race.k_event)


  def print_races(self, verbose=False, print_races=False):
    if verbose:
#       for race in self.races_commute:
#         print "+-------------------------------------------+"
#         print "| Commuting ({}):     {:>4} <---> {:>4}      |".format(race.rtype, race.i_event.eid, race.k_event.eid)
#         print "+-------------------------------------------+"
#         print "| op # {:<8} t={:<26}|".format(race.i_op.eid, race.i_op.t)
#         print "+-------------------------------------------+"
#         print "| " + op_to_str(race.i_op)
#         print "+-------------------------------------------+"
#         print "| op # {:<8} t={:<26}|".format(race.k_op.eid, race.k_op.t)
#         print "+-------------------------------------------+"
#         print "| " + op_to_str(race.k_op)
#         print "+-------------------------------------------+"
      for race in self.found_races_harmful:
        print "+-------------------------------------------+"
        print "| Harmful   ({}):     {:>4} >-!-< {:>4}      |".format(race.rtype, race.i_event.eid, race.k_event.eid)
        print "+-------------------------------------------+"
        print "| op # {:<8} t={:<26}|".format(race.i_op.eid, race.i_op.t)
        print "+-------------------------------------------+"
        print "| " + op_to_str(race.i_op)
        print "+-------------------------------------------+"
        print "| op # {:<8} t={:<26}|".format(race.k_op.eid, race.k_op.t)
        print "+-------------------------------------------+"
        print "| " + op_to_str(race.k_op)
        print "+-------------------------------------------+"
      print "+-------------------------------------------+"
      for ev in self.read_operations:
        print "| {:>4}: {:28} (read) |".format(ev[0].eid, ev[0].type)
      for ev in self.write_operations:
        print "| {:>4}: {:27} (write) |".format(ev[0].eid, ev[0].type)
    if print_races:
      print "+-------------------------------------------+"
      print "| Total operations:      {:<18} |".format(self.total_operations)
      print "| Total write operations: {:<17} |".format(len(self.write_operations))
      print "| Total read operations:  {:<17} |".format(len(self.read_operations))
      print "+-------------------------------------------+"
      print "| Total commuting races: {:<18} |".format(self.total_commute)
      print "| Total harmful races:   {:<18} |".format(self.total_harmful)
      print "| Total filtered races:  {:<18} |".format(self.total_filtered)
      print "| Total Time Filtered races:  {:<13} |".format(self.total_time_filtered_races)
      print "| Total Time Edges:      {:<18} |".format(self.time_edges_counter)
      print "+-------------------------------------------+"
