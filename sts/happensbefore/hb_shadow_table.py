"""
Shadow flow table for tracking read-after-write dependencies
"""

from collections import defaultdict
from bisect import bisect

from pox.openflow.flow_table import FlowTableModification

from hb_json_event import *
from hb_events import *
from hb_sts_events import *

from hb_utils import compare_flow_table
from hb_utils import read_flow_table
from hb_utils import write_flow_table
from hb_utils import find_entries_in_flow_table


class ShadowFlowTable(object):

  def __init__(self, dpid):
    self._ids = itertools.count(0)
    self.dpid = dpid
    self.table = SwitchFlowTable()
    
    self.latest_event_eid = None
    
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
        i = bisect.bisect_left(modifying_eids, eid)
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
    assert event.eid > self.latest_event_eid
    self.latest_event_eid = event.eid
    assert type(event) in [HbPacketHandle, HbMessageHandle, HbAsyncFlowExpiry]
    assert hasattr(event, "operations")
    for op in event.operations:
      if type(op) in [TraceSwitchFlowTableRead, TraceSwitchFlowTableWrite, TraceSwitchFlowTableEntryExpiry]:
        assert hasattr(op, "flow_table")
        assert hasattr(op, "flow_mod")
        if type(op) == TraceSwitchFlowTableRead:
          assert hasattr(op, "packet")
          assert hasattr(op, "in_port")
          assert hasattr(op, "entry")
          # shadow table should agree with trace before op
          assert compare_flow_table(self.table, op.flow_table)
          
          entry = read_flow_table(self.table, event.packet, event.in_port)
          
          if entry is not None:
            this_entry = ofp_flow_mod()
            this_entry.unpack(entry.to_flow_mod().pack())
            this_entry.xid = 0
            assert op.entry is not None
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
          # shadow table should agree with trace before op
          assert compare_flow_table(self.table, op.flow_table)
          write_flow_table(self.table, op.flow_mod)

        elif type(op) == TraceSwitchFlowTableEntryExpiry:
          exact_matches = find_entries_in_flow_table(self.table, op.flow_mod)

          # it is impossible to add two entries with the *exact* same match and
          # priority to the flow table, so we should always get exactly one entry
          assert len(exact_matches) == 1
          
          self.table.remove_entries(exact_matches)

          # shadow table should now agree with trace after op
          assert compare_flow_table(self.table, op.flow_table)
          
    deps = self.get_RaW_data_dependencies(event.eid)
    if deps > 0:
      self.data_deps[event.eid].extend(deps)
      print "RaW dependencies (r <- [w]): {}  [{}]".format(event.eid,', '.join(str(k) for k in deps))

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
=======
      print "RaW dependencies: {} > [{}]".format(event.eid,', '.join(str(dep) for dep in deps))
>>>>>>> 064afba29746b517372d8e11c90a8abb8bb2f844
