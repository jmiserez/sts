"""
Shadow flow table for tracking read-after-write dependencies
"""

from collections import defaultdict
from bisect import bisect_left

from pox.openflow.flow_table import FlowTableModification

from hb_json_event import *
from hb_events import *
from hb_sts_events import *

from hb_utils import compare_flow_table
from hb_utils import read_flow_table
from hb_utils import write_flow_table
from hb_utils import find_entries_in_flow_table


class ShadowFlowTable(object):

  def __init__(self, dpid, is_minimized_trace=False):
    self._ids = itertools.count(0)
    self.dpid = dpid
    self.is_minimized_trace = is_minimized_trace
    self.table = SwitchFlowTable()
    
    self.latest_event_eid = None
    self.latest_event_was_async_expiry = False
    
    # entry -> entry id
    self.entry_ids = dict()
    
    # event eid -> entry ids
    self.read_entries = defaultdict(list)
    
    # entry id -> event eid
    self.adding_eid = dict()
    self.removing_eid = dict()
    # entry id -> [event eids]
    self.modifying_eids = defaultdict(list)
    
    # event eid (read) -> event eid (relevant write)
    self.data_deps = defaultdict(list)
    
    self.table.addListener(FlowTableModification, self._on_flow_table_write)
    
  def _on_flow_table_write(self, table_mod):
    for entry in table_mod.added:
      entry_id = self._ids.next()
      self.entry_ids[entry] = entry_id
      self.adding_eid[entry_id] = self.latest_event_eid
    for entry in table_mod.removed:
      self.removing_eid[self.entry_ids[entry]] = self.latest_event_eid
    for entry in table_mod.modified:
      self.modifying_eids[self.entry_ids[entry]].append(self.latest_event_eid)
      
  def _on_flow_table_read(self, entry):
    self.read_entries[self.latest_event_eid].append(self.entry_ids[entry])

  def get_RaW_data_dependencies(self, eid):
    """
    For a given read, find the events that wrote/modified the rules that were read.
    
    As MODIFY flow mods can act as ADDs if the rule does not exists yet, it suffices
    to return the latest ADD or MODIFY, and it is not necessary to return all of
    them.    
    """
    # event has to have been applied already
    assert eid <= self.latest_event_eid
    
    deps = []
    
    for read_entry_id in self.read_entries[eid]:
      
      # which event added this rule that we just read?
      assert read_entry_id in self.adding_eid
      adding_eid = self.adding_eid[read_entry_id]
      
      modifying_eids = []
      
      # which events modified this rule that we just read?
      if read_entry_id in self.modifying_eids:
        modifying_eids = self.modifying_eids[read_entry_id]
      
      if modifying_eids:
        # only consider events that happened before this read, i.e. strictly less than eid
        i = bisect_left(modifying_eids, eid)
        if i:
          deps.append(modifying_eids[i-1])
      else:
        assert adding_eid <= eid # possible if add+read happens in same event
        if adding_eid < eid: # but we ignore a dependency on "itself" as the event is atomic
          deps.append(adding_eid)
    return deps

  def get_WaR_data_dependencies(self, eid):
    # TODO(jm): Is this also a thing for us?
    pass
  def get_WaW_data_dependencies(self, eid):
    # TODO(jm): Is this also a thing for us?
    pass

  def apply_event(self, event):
    # TODO(jm): hb_logger prints out higher eids for HbAsyncExpiry events than the ones that follow.
    #           The trace order as it appears in the file is the correct order.
    #           TODO: Fix this in hb_logger, so that the eids assigned to expiry events are correct.
    assert event.eid > self.latest_event_eid or self.latest_event_was_async_expiry
    self.latest_event_eid = event.eid
    assert type(event) in [HbPacketHandle, HbMessageHandle, HbAsyncFlowExpiry]
    assert hasattr(event, "operations")
    for op in event.operations:
      if type(op) in [TraceSwitchFlowTableRead, TraceSwitchFlowTableWrite, TraceSwitchFlowTableEntryExpiry]:
        if not self.is_minimized_trace:
          assert hasattr(op, "flow_table")
        assert hasattr(op, "flow_mod")
        if type(op) == TraceSwitchFlowTableRead:
          self.latest_event_was_async_expiry = False
          assert hasattr(op, "packet")
          assert hasattr(op, "in_port")
          assert hasattr(op, "entry")
          # shadow table should agree with trace before op
          if not self.is_minimized_trace:
            assert compare_flow_table(self.table, op.flow_table)
          
          entry = read_flow_table(self.table, event.packet, event.in_port)
          
          if entry is not None:
            this_entry = ofp_flow_mod()
            this_entry.unpack(entry.to_flow_mod().pack())
            this_entry.xid = 0
            if op.entry is None:
              print "Error: Possible problem with the instrumentation: shadow table and event have matching entry but it was not read in the trace!"
              # TODO(jm): fix the above problem (bug?). However, we know that this particular case has no ill-effects.
            else:
              trace_entry = ofp_flow_mod()
              trace_entry.unpack(op.entry.pack())
              trace_entry.xid = 0
              assert this_entry == trace_entry
              
              self._on_flow_table_read(entry)
              # TODO(jm): Would it make sense to add an edge from this read to all
              #          later write that could match this??? (WaR?)
          else:
            assert op.entry == None
          
        elif type(op) == TraceSwitchFlowTableWrite:
          self.latest_event_was_async_expiry = False
          # shadow table should agree with trace before op
          if not self.is_minimized_trace:
            assert compare_flow_table(self.table, op.flow_table)
          write_flow_table(self.table, op.flow_mod)

        elif type(op) == TraceSwitchFlowTableEntryExpiry:
          self.latest_event_was_async_expiry = True
          if not self.is_minimized_trace:
            if not compare_flow_table(self.table, op.flow_table):
              print self.table.table
              print "--------------------"
              print op.flow_table.table
            assert compare_flow_table(self.table, op.flow_table)
          exact_matches = find_entries_in_flow_table(self.table, op.flow_mod)
          # it is impossible to add two entries with the *exact* same match and
          # priority to the flow table, so we should always get exactly one entry
          if len(exact_matches) != 1:
            print exact_matches
          assert len(exact_matches) == 1
          
          # TODO(jm): Instead of merely removing entries, we should also add a
          #           data dependency edge here like for reads and writes.
          #           Also see TODOs in hb_logger and hb_graph on how to do this
          #           correctly for both regular timeouts as wella s explicit 
          #           DELETES.
          self.table.remove_entries(exact_matches)

    deps = self.get_RaW_data_dependencies(event.eid)
    if deps > 0:
      self.data_deps[event.eid].extend(deps)
#       print "RaW dependencies (r <- [w]): {}  [{}]".format(event.eid,', '.join(str(k) for k in deps))
