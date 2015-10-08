from collections import namedtuple
import itertools
import networkx as nx

from hb_utils import op_to_str
from hb_utils import nCr

from hb_commute_check import CommutativityChecker

from hb_json_event import *
from hb_events import *
from hb_sts_events import *


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
               ww_delta=1, data_deps=False):
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
    self.ww_delta = ww_delta
    self.rw_delta = rw_delta
    self.add_hb_time = add_hb_time
    # Just to keep track of how many HB edges where added based on time
    self._time_hb_rw_edges_counter = 0
    self._time_hb_ww_edges_counter = 0
    
    self.data_deps = data_deps
    self._dep_raw_edges_counter = 0

  @property
  def time_hb_rw_edges_counter(self):
    return self._time_hb_rw_edges_counter

  @property
  def time_hb_ww_edges_counter(self):
    return self._time_hb_ww_edges_counter
  
  @property
  def dep_raw_edges_counter(self):
    return self._dep_raw_edges_counter
  
  def is_ordered(self, eid, other_eid):
    """
    It only matters that there is an ordering in the graph between the two events,
    but it is irrelevant in which direction.
    """
    # TODO(jm): Remove this assert once it's tested with data dependencies!
#     assert self.graph.has_path(eid, other_eid, bidirectional=True, use_path_cache=True) == self.graph.has_path(eid, other_eid, bidirectional=True, use_path_cache=False)
    return self.graph.has_path(eid, other_eid, bidirectional=True, use_path_cache=True)

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

  def update_ops_lists(self):
    """
    Helper method to extract read and write operations from the HB graph.
    MUST be called before detect_rw and detect_ww. But detect_races calls it
    automatically.
    """
    self.read_operations = []
    self.write_operations = []

    for eid in self.graph.events_with_reads_writes:
      event = self.graph.events_by_id[eid]
      assert hasattr(event, 'operations')
      for op in event.operations:
        if type(op) == TraceSwitchFlowTableWrite:
          assert hasattr(op, 'flow_table')
          assert hasattr(op, 'flow_mod')
          self.write_operations.append((event, event.dpid, eid, op))
        elif type(op) == TraceSwitchFlowTableRead:
          assert hasattr(op, 'flow_table')
          assert hasattr(op, 'flow_mod')
          assert hasattr(event, 'packet')
          assert hasattr(event, 'in_port')
          self.read_operations.append((event, event.dpid, eid, op))
        elif type(op) == TraceSwitchFlowTableEntryExpiry:
          pass # for now
          # TODO(jm): Do we need to consider TraceSwitchFlowTableEntryExpiry here as well??? Probably yes?
          #           However, for expiry, the flow_table is the table *after* the operation, so some changes are needed.


  def detect_races_all(self, all_operations, ops_to_check=None, verbose=True):
    racing_events = set()
    racing_events_harmful = set()
    commuting_races = []
    harmful_races = []
    
    ops_by_dpid = dict()
    ops_to_check_by_dpid = dict()
    
    for xop in all_operations:
      event,dpid,eid,op = xop
      if dpid not in ops_by_dpid:
        ops_by_dpid[dpid] = dict()
      if eid not in ops_by_dpid[dpid]:
        ops_by_dpid[dpid][eid] = list()
      ops_by_dpid[dpid][eid].append(xop)
    
    if ops_to_check is not None:
      for xop in ops_to_check:
        event,dpid,eid,op = xop
        if dpid not in ops_to_check_by_dpid:
          ops_to_check_by_dpid[dpid] = dict()
        if eid not in ops_to_check_by_dpid[dpid]:
          ops_to_check_by_dpid[dpid][eid] = list()
        ops_to_check_by_dpid[dpid][eid].append(xop)
      
    if ops_to_check is not None:
      dpids = list(set(ops_by_dpid.keys()).intersection(set(ops_to_check_by_dpid.keys())))
    else:
      dpids = ops_by_dpid.keys()
    
    if verbose:
      print "Race detection for {} dpids:".format(len(dpids))
    
    for dpid in dpids:
      if verbose:
        print "  dpid {}".format(dpid)
      assert dpid in ops_by_dpid
      if ops_to_check is not None:
        assert dpid in ops_to_check_by_dpid
        eids_a = ops_to_check_by_dpid[dpid].keys()
        eids_b = ops_by_dpid[dpid].keys()
        
        # remove all in eids_a from eids_b 
        eids_b = list(set(eids_b).difference(set(eids_a)))
        
        # each eid_a with each eid_b
        iter_func = itertools.product(eids_a, eids_b)
        iter_func_len = len(eids_a) * len(eids_b)
      else:
        eids_ab = ops_by_dpid[dpid].keys()

        # each combination of length 2 in eids_ab (without (self, self))
        iter_func = itertools.combinations(eids_ab, 2)
        iter_func_len = nCr(len(eids_ab),2)
      
      for count, (i_eid, k_eid) in itertools.izip(itertools.count(),iter_func):
        assert i_eid != k_eid
        if not self.is_ordered(i_eid, k_eid):
          
          if ops_to_check is not None:
            # check all pairs of ops of the two eids
            ops_a = ops_to_check_by_dpid[dpid][i_eid]
            ops_b = ops_by_dpid[dpid][k_eid]
          else:
            # check all pairs of ops of the two eids
            ops_a = ops_by_dpid[dpid][i_eid]
            ops_b = ops_by_dpid[dpid][k_eid]
            
          def is_write(op):
            return op in self.write_operations
          def is_read(op):
            return op in self.read_operations
          
          writes_a = filter(is_write,ops_a)
          reads_a = filter(is_read,ops_a)
          writes_b = filter(is_write,ops_b)
          reads_b = filter(is_read,ops_b)
          
          # write-write races
          inner_iter = itertools.product(writes_a, writes_b)
          inner_iter_len = len(writes_a) * len(writes_b)
          
          for inner_count, ((i_event,i_dpid,i_eid,i_op), (k_event,k_dpid,k_eid,k_op)) in itertools.izip(itertools.count(),inner_iter):
            if self.commutativity_checker.check_commutativity_ww(i_event, i_op, k_event, k_op):
              commuting_races.append(Race('w/w', i_event, i_op, k_event, k_op))
            else:
              delta = abs(i_op.t - k_op.t)
              if delta < self.ww_delta or not self.add_hb_time:
                harmful_races.append(Race('w/w', i_event, i_op, k_event, k_op))
                racing_events_harmful.add(i_event)
                racing_events_harmful.add(k_event)
              else:
                self._time_hb_ww_edges_counter += 1
                first = i_eid if i_op.t < k_op.t else k_eid
                second = k_eid if first == i_eid else i_eid
                assert first != second
                self.graph._add_edge(first, second, sanity_check=False, rel='time')
            racing_events.add(i_event)
            racing_events.add(k_event)
          
          # read-write races
          inner_iter = itertools.chain(itertools.product(reads_a, writes_b), itertools.product(reads_b, writes_a))
          inner_iter_len = (len(reads_a) * len(writes_b)) + (len(writes_a) * len(reads_b))
          
          for inner_count, ((i_event,i_dpid,i_eid,i_op), (k_event,k_dpid,k_eid,k_op)) in itertools.izip(itertools.count(),inner_iter):
            if self.filter_rw and not self.has_common_ancestor(i_event, k_event):
              self.total_filtered += 1
            else:
              if self.commutativity_checker.check_commutativity_rw(i_event, i_op, k_event, k_op):
                commuting_races.append(Race('r/w',i_event, i_op, k_event, k_op))
                commuting_races.append(Race('w/w', i_event, i_op, k_event, k_op))
              else:
                delta = abs(i_op.t - k_op.t)
                if delta < self.rw_delta or not self.add_hb_time:
                  harmful_races.append(Race('r/w',i_event, i_op, k_event, k_op))
                  racing_events_harmful.add(i_event)
                  racing_events_harmful.add(k_event)
                else:
                  self._time_hb_rw_edges_counter += 1
                  first = i_event if i_op.t < k_op.t else k_event
                  second = k_event if first == i_event else i_event
                  assert first != second
                  self.graph._add_edge(first, second, sanity_check=False, rel='time')
            racing_events.add(i_event)
            racing_events.add(k_event)
          
    return (racing_events, racing_events_harmful, commuting_races, harmful_races)
            
  # TODO(jm): make verbose a config option
  def detect_races(self, event=None, verbose=False, data_deps=False):
    """
    Detect all races that involve event.
    Detect all races for all events if event is None.
    """
    self.update_ops_lists()

    if verbose:
      print "Total write operations: {}".format(len(self.write_operations))
      print "Total read operations: {}".format(len(self.read_operations))

    all_operations = list()
    all_operations.extend(self.write_operations)
    all_operations.extend(self.read_operations)
    
    racing_events, racing_events_harmful, commuting_races, harmful_races = self.detect_races_all(all_operations)

    self.races_harmful = harmful_races
    self.races_commute = commuting_races
    self.racing_events = racing_events
    self.racing_events_harmful = racing_events_harmful
    self.total_filtered = 0

    self.total_operations = len(self.write_operations) + len(self.read_operations)
    self.total_harmful = len(self.races_harmful)
    self.total_commute = len(self.races_commute)
    self.total_races = self.total_harmful + self.total_commute

  def print_races(self, verbose=False):
    if verbose:
      for race in self.races_commute:
        print "+-------------------------------------------+"
        print "| Commuting ({}):     {:>4} <---> {:>4}      |".format(race.rtype, race.i_event.eid, race.k_event.eid)
        print "+-------------------------------------------+"
        print "| op # {:<8} t={:<26}|".format(race.i_op.eid, race.i_op.t)
        print "+-------------------------------------------+"
        print "| " + op_to_str(race.i_op)
        print "+-------------------------------------------+"
        print "| op # {:<8} t={:<26}|".format(race.k_op.eid, race.k_op.t)
        print "+-------------------------------------------+"
        print "| " + op_to_str(race.k_op)
        print "+-------------------------------------------+"
      for race in self.races_harmful:
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
    print "+-------------------------------------------+"
    print "| Total operations:      {:<18} |".format(self.total_operations)
    print "| Total write operations: {:<17} |".format(len(self.write_operations))
    print "| Total read operations:  {:<17} |".format(len(self.read_operations))
    print "+-------------------------------------------+"
    print "| Total commuting races: {:<18} |".format(self.total_commute)
    print "| Total harmful races:   {:<18} |".format(self.total_harmful)
    print "| Total filtered races:  {:<18} |".format(self.total_filtered)
    print "| Total Time RW  Filtered races:  {:<9} |".format(self.time_hb_rw_edges_counter)
    print "| Total Time WW  Filtered races:  {:<9} |".format(self.time_hb_ww_edges_counter)
    print "+-------------------------------------------+"
