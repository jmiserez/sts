#!/usr/bin/env python
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "../../pox"))

import argparse
from collections import defaultdict
import networkx as nx

from pox.lib.packet.ethernet import ethernet
from pox.openflow.libopenflow_01 import ofp_flow_mod_command_rev_map
from pox.openflow.libopenflow_01 import OFPT_HELLO
from pox.openflow.libopenflow_01 import OFPT_FEATURES_REQUEST
from pox.openflow.libopenflow_01 import OFPT_FEATURES_REPLY
from pox.openflow.libopenflow_01 import OFPT_SET_CONFIG
from pox.openflow.libopenflow_01 import OFPFC_DELETE_STRICT
from pox.openflow.libopenflow_01 import OFPT_STATS_REQUEST
from pox.openflow.libopenflow_01 import OFPT_VENDOR
from pox.openflow.libopenflow_01 import OFPT_GET_CONFIG_REQUEST
from pox.openflow.libopenflow_01 import OFPT_GET_CONFIG_REPLY
from pox.openflow.libopenflow_01 import OFPT_STATS_REPLY

from hb_utils import pkt_info

from hb_shadow_table import ShadowFlowTable

from hb_race_detector import RaceDetector
from hb_race_detector import predecessor_types

# To make sure all events are registered
from hb_json_event import *
from hb_events import *
from hb_sts_events import *
from hb_utils import dfs_edge_filter
from hb_utils import just_mid_iter
from hb_utils import pretty_match

#
# Do not import any STS types! We would like to be able to run this offline
# from a trace file without having to depend on STS.
#


OFP_COMMANDS = {v: k for k, v in ofp_flow_mod_command_rev_map.iteritems()}

# OF Message types to skip from the trace
SKIP_MSGS = [OFPT_HELLO, OFPT_VENDOR, OFPT_FEATURES_REQUEST, OFPT_FEATURES_REPLY,
             OFPT_SET_CONFIG, OFPT_GET_CONFIG_REQUEST, OFPT_GET_CONFIG_REPLY,
             OFPT_STATS_REQUEST, OFPT_STATS_REPLY]


class HappensBeforeGraph(object):
 
  def __init__(self, results_dir=None, add_hb_time=False, rw_delta=5,
               ww_delta=1, filter_rw=False, ignore_ethertypes=None,
               no_race=False, alt_barr=False, disable_path_cache=True, data_deps=False):
    self.results_dir = results_dir
    
    self.g = nx.DiGraph()
    
    self.disable_path_cache = disable_path_cache
    self._cached_paths = None
    self._cached_reverse_paths = None

    self.events_by_id = dict()
    self.events_with_reads_writes = list()

    self.events_by_pid_out = defaultdict(list)
    self.events_by_mid_out = defaultdict(list)
    
    # events that have a mid_in/mid_in and are still looking for a pid_out/mid_out to match 
    self.events_pending_pid_in = defaultdict(list)
    self.events_pending_mid_in = defaultdict(list)
    
    # for barrier pre rule
    self.events_before_next_barrier = defaultdict(list)
    
    # for barrier post rule
    self.most_recent_barrier = dict()
    
    # for races
    self.race_detector = RaceDetector(
      self, filter_rw=filter_rw, add_hb_time=add_hb_time, ww_delta=ww_delta,
      rw_delta=rw_delta)

    self.ww_delta = ww_delta
    self.rw_delta = rw_delta
    # Only mark time edges in the RaceDetetcor
    self.add_hb_time = False
    # Just to keep track of how many HB edges where added based on time
    self._time_hb_rw_edges_counter = 0
    self._time_hb_ww_edges_counter = 0

    self.ignore_ethertypes = check_list(ignore_ethertypes)
    self.no_race = no_race
    self.packet_traces = None
    self.host_sends = {}
    # Handled messages from the controller to the switch
    self.msg_handles = {}
    # Messages from the switch to the controller
    self.msgs = {}
    
    self.alt_barr = alt_barr
    self.versions = {}
    
    # add read-after-write dependency edges
    self.data_deps = data_deps
    self.shadow_tables = dict()
    
    self.covered_races = dict()

  @property
  def events(self):
    for _, data in self.g.nodes_iter(True):
      yield data['event']

  @property
  def predecessors(self):
    """Get predecessor events for all events. """
    for eid, data in self.g.nodes(data=True):
      this_predecessors = set()
      for pred in self.g.predecessors_iter(eid):
        this_predecessors.add(self.g.node[pred]['event'])
      yield (data['event'],this_predecessors)

  def _add_to_lookup_tables(self, event):
    if hasattr(event, 'pid_out'):
      for x in event.pid_out:
        self.events_by_pid_out[x].append(event)
    if hasattr(event, 'mid_out'):
      for x in event.mid_out:
        self.events_by_mid_out[x].append(event)

    self.lookup_tables = [ #( field name,
                           #  condition to be included,
                           #  search key
                           #),
                           (self.events_pending_pid_in, 
                            lambda x: hasattr(x, 'pid_in'), 
                            lambda x: x.pid_in ),
                           (self.events_pending_mid_in, 
                            lambda x: hasattr(x, 'mid_in'), 
                            lambda x: x.mid_in ),
                           ]
    for entry in self.lookup_tables:
      table, condition, key = entry
      if condition(event):
        table[key(event)].append(event)
    
  def _update_event_is_linked_pid_in(self, event):
    if event in self.events_pending_pid_in[event.pid_in]:
      self.events_pending_pid_in[event.pid_in].remove(event)
  def _update_event_is_linked_mid_in(self, event):
    if event in self.events_pending_mid_in[event.mid_in]:
      self.events_pending_mid_in[event.mid_in].remove(event)
      
  def has_path(self, src_eid, dst_eid, bidirectional=True):  
    return nx.has_path(self.g, src_eid, dst_eid) or (bidirectional and nx.has_path(self.g, dst_eid, src_eid))
  
  def _add_edge(self, before, after, sanity_check=True, **attrs):

    if sanity_check and before.type not in predecessor_types[after.type]:
      print "Warning: Not a valid HB edge: "+before.typestr+" ("+str(before.eid)+") < "+after.typestr+" ("+str(after.eid)+")"
      assert False 
    src, dst = before.eid, after.eid
    if self.g.has_edge(src, dst):
      rel = self.g.edge[src][dst]['rel']
      # Allow edge to be added multiple times because of the same relation
      # This is useful for time based edges
      if rel != attrs['rel']:
        raise ValueError(
          "Edge already added %d->%d and relation: %s" % (src, dst, rel))
    self.g.add_edge(before.eid, after.eid, attrs)

  def _rule_01_pid(self, event):
    # pid_out -> pid_in
    if hasattr(event, 'pid_in'):
      if event.pid_in in self.events_by_pid_out:
        for other in self.events_by_pid_out[event.pid_in]: 
          self._add_edge(other, event, rel='pid')
          self._update_event_is_linked_pid_in(event)
    # TODO(jm): remove by reordering first
    # recheck events added in an order different from the trace order
    if hasattr(event, 'pid_out'):
      for pid_out in event.pid_out:
        if pid_out in self.events_pending_pid_in:
          for other in self.events_pending_pid_in[pid_out][:]: # copy list [:], so we can remove from it
            self._add_edge(event, other, rel='pid')
            self._update_event_is_linked_pid_in(other)
            
  def _rule_02_mid(self, event):
    # mid_out -> mid_in
    if hasattr(event, 'mid_in'):
      if event.mid_in in self.events_by_mid_out:
        for other in self.events_by_mid_out[event.mid_in]:
          self._add_edge(other, event, rel='mid')
          self._update_event_is_linked_mid_in(event)
    # TODO(jm): remove by reordering first
    # recheck events added in an order different from the trace order (mainly controller events as they are asynchronously logged)
    if hasattr(event, 'mid_out'):
      for mid_out in event.mid_out:
        if mid_out in self.events_pending_mid_in:
          for other in self.events_pending_mid_in[mid_out][:]: # copy list [:], so we can remove from it
            self._add_edge(event, other, rel='mid')
            self._update_event_is_linked_mid_in(other)
  
  def _rule_03_barrier_pre(self, event):
    if event.type == 'HbMessageHandle':
      if event.msg_type_str == "OFPT_BARRIER_REQUEST":
        for other in self.events_before_next_barrier[event.dpid]:
          self._add_edge(other, event, rel='barrier_pre')
        del self.events_before_next_barrier[event.dpid]
      else:
        self.events_before_next_barrier[event.dpid].append(event)
        
  def _rule_04_barrier_post(self, event):
    if event.type == 'HbMessageHandle':
      if event.msg_type_str == "OFPT_BARRIER_REQUEST":
        self.most_recent_barrier[event.dpid] = event
      else:
        if event.dpid in self.most_recent_barrier:
          other = self.most_recent_barrier[event.dpid]
          self._add_edge(other, event, rel='barrier_post')
  
  def _find_triggering_HbControllerHandle_for_alternative_barrier(self, event):
    """
    Returns the HbControllerHandle that is responsible for triggering this event
    
    event (HbMessageHandle) <- (HbControllerSend) <- trigger (HbControllerHandle)
    """
    preds = self.g.predecessors(event.eid)
    if len(preds) > 0:
      candidates = filter(lambda x: self.g.node[x]['event'].type == "HbControllerSend", preds)
      assert len(candidates) <= 1 # at most one HbControllerSend exists
      if len(candidates) == 1:
        send_event_eid = candidates[0]
        assert self.g.node[send_event_eid]['event'].type == "HbControllerSend"
        preds = self.g.predecessors(send_event_eid)
        candidates = filter(lambda x: self.g.node[x]['event'].type == "HbControllerHandle", preds)
        assert len(candidates) <= 1 # at most one HbControllerHandle exists
        if len(candidates) == 1:
          handle_event_eid = candidates[0]  
          assert self.g.node[handle_event_eid]['event'].type == "HbControllerHandle"
          return handle_event_eid
    return None
    
  def _rule_03b_alternative_barrier_pre(self, event):
    """
    Instead of using the dpid for barriers, this uses the eid of the predecessor HbControllerSend (if it exists).
    """
    if event.type == 'HbMessageHandle':
      ctrl_handle_eid = self._find_triggering_HbControllerHandle_for_alternative_barrier(event)
      if ctrl_handle_eid is not None:
        if event.msg_type_str == "OFPT_BARRIER_REQUEST":
          for other in self.events_before_next_barrier[ctrl_handle_eid]:
            self._add_edge(other, event, rel='barrier_pre')
          del self.events_before_next_barrier[ctrl_handle_eid]
        else:
          self.events_before_next_barrier[ctrl_handle_eid].append(event)
    elif event.type == 'HbControllerSend':
      succ = self.g.successors(event.eid)
      for i in succ:
        self._rule_03b_alternative_barrier_pre(self.g.node[i]['event'])
        self._rule_04b_alternative_barrier_post(self.g.node[i]['event'])
          
  def _rule_04b_alternative_barrier_post(self, event):
    """
    Instead of using the dpid for barriers, this uses the eid of the predecessor HbControllerSend (if it exists).
    """
    if event.type == 'HbMessageHandle':
      ctrl_handle_eid = self._find_triggering_HbControllerHandle_for_alternative_barrier(event)
      if ctrl_handle_eid is not None:
        if event.msg_type_str == "OFPT_BARRIER_REQUEST":
          self.most_recent_barrier[ctrl_handle_eid] = event
        else:
          if ctrl_handle_eid in self.most_recent_barrier:
            other = self.most_recent_barrier[ctrl_handle_eid]
            self._add_edge(other, event, rel='barrier_post')
    elif event.type == 'HbControllerSend':
      succ = self.g.successors(event.eid)
      for i in succ:
        self._rule_03b_alternative_barrier_pre(self.g.node[i]['event'])
        self._rule_04b_alternative_barrier_post(self.g.node[i]['event'])
        
  def _rule_05_flow_removed(self, event):
    if isinstance(event, HbAsyncFlowExpiry):
      assert len(event.operations) == 1
      expiry = event.operations[0]
      flow_table = expiry.flow_table # the flow table before the removal
      flow_mod = expiry.flow_mod # the removed entry
      reason = expiry.reason # Either idle or hard timeout. Deletes are not handled
      duration = expiry.duration_sec*10^9 + expiry.duration_nsec      
      
      # create "dummy" operation that acts as a strict delete 
      del_event = ofp_flow_mod(match=flow_mod.match,priority=flow_mod.priority,command=OFPFC_DELETE_STRICT)
      
      i_ops = [expiry]
  
      # Find other write events in the graph.
      for e in self.events:
        if e == del_event:
          continue
        # Skip none switch event
        if type(e) != HbMessageHandle:
          continue
        kw_ops = []
        kr_ops = []
        # Find the write ops
        for op in e.operations:
          if type(op) == TraceSwitchFlowTableWrite:
            kw_ops.append(op)
          elif type(op) == TraceSwitchFlowTableRead:
            kr_ops.append(op)
        if (not kw_ops) and (not kr_ops):
          continue
        # Make the edge
        done = False
        for i_op in i_ops:
          if done:
            break
          for kw_op in kw_ops:
            # Skip if events commute anyway
            if self.race_detector.commutativity_checker.check_commutativity_ww(
                    del_event, i_op, e, kw_op):
              continue
            delta = abs(i_op.t - kw_op.t)
            if delta > self.ww_delta:
              self._time_hb_ww_edges_counter += 1
              self._add_edge(e, event, sanity_check=False, rel='time')
              done = True
              break
          if done:
            break
          for kr_op in kr_ops:
            # Skip if events commute anyway
            if self.race_detector.commutativity_checker.check_commutativity_rw(
                    del_event, i_op, e, kr_op):
              continue
            delta = abs(i_op.t - kr_op.t)
            if delta > self.ww_delta:
              self._time_hb_rw_edges_counter += 1
              self._add_edge(e, event, sanity_check=False, rel='time')
              done = True
              break
    
  def _rule_06_time_rw(self, event):
    if type(event) not in [HbPacketHandle]:
      return
    packet_match = ofp_match.from_packet(event.packet, event.in_port)
    operations = []
    # Get all the read operations in the event
    # For OF 1.0 should be only one op, but more for OF1.3
    for op in event.operations:
      if type(op) ==  TraceSwitchFlowTableRead:
        operations.append(op)
    for e in self.events:
      if type(e) != HbMessageHandle:
        continue
      for op in e.operations:
        if type(op) != TraceSwitchFlowTableWrite:
          continue
        if not op.flow_mod.match.matches_with_wildcards(packet_match, consider_other_wildcards=False):
          continue
        delta = abs(op.t - operations[0].t)
        if (delta > self.rw_delta):
          self._time_hb_rw_edges_counter += 1
          self._add_edge(e, event, sanity_check=False, rel='time')
        break

  def _rule_07_time_ww(self, event):
    if type(event) not in [HbMessageHandle]:
      return
    i_ops = []

    # Get all the write operations in the event
    # For OF 1.0 should be only one op, but more for OF1.3
    for op in event.operations:
      if type(op) ==  TraceSwitchFlowTableWrite:
        i_ops.append(op)
    # No write operations in the event, just skip
    if not i_ops:
      return

    # Find other write events in the graph.
    for e in self.events:
      if e == event:
        continue
      # Skip none switch event
      if type(e) != HbMessageHandle:
        continue
      k_ops = []
      # Find the write ops
      for op in e.operations:
        if type(op) == TraceSwitchFlowTableWrite:
          k_ops.append(op)
      if not k_ops:
        continue
      # Make the edge
      for i_op in i_ops:
        for k_op in k_ops:
          # Skip if events commute anyway
          if self.race_detector.commutativity_checker.check_commutativity_ww(
                  event, i_op, e, k_op):
            continue
          delta = abs(i_op.t - k_op.t)
          if delta > self.ww_delta:
            self._time_hb_ww_edges_counter += 1
            self._add_edge(e, event, sanity_check=False, rel='time')
          break

  def _update_edges(self, event):
    self._rule_01_pid(event)
    self._rule_02_mid(event)
    if self.alt_barr:
      self._rule_03b_alternative_barrier_pre(event)
      self._rule_04b_alternative_barrier_post(event)
    else:
      self._rule_03_barrier_pre(event)
      self._rule_04_barrier_post(event)
    self._rule_05_flow_removed(event)
    if self.add_hb_time:
      self._rule_06_time_rw(event)
      self._rule_07_time_ww(event)

  def _update_shadow_tables(self, event):
    if event.dpid not in self.shadow_tables:
      self.shadow_tables[event.dpid] = ShadowFlowTable(event.dpid)
    self.shadow_tables[event.dpid].apply_event(event)

  def unpack_line(self, line):
    # Skip empty lines and the ones start with '#'
    if not line or line.startswith('#'):
      return

    # TODO(jm): I did some tests to see why loading events is so slow.
    #           JsonEvent.from_json is the slow part, everything else
    #           (including json.loads()) is blazing fast.
    #           We might want to speed that up a bit.
    event = JsonEvent.from_json(json.loads(line))
    return event

  def add_line(self, line):
    event = self.unpack_line(line)
    if event:
      self.add_event(event)

  def add_event(self, event):
    assert event.eid not in self.events_by_id
    if self.ignore_ethertypes:
      packet = None
      if hasattr(event, 'packet'):
        packet = event.packet
      if type(event) == HbMessageHandle and getattr(event.msg, 'data', None):
        packet = ethernet(event.msg.data)
      if packet and packet.type in self.ignore_ethertypes:
        return

    msg_type = getattr(event, 'msg_type', None)
    if msg_type in SKIP_MSGS:
      return
    self.g.add_node(event.eid, event=event)
    self.events_by_id[event.eid] = event
    self._add_to_lookup_tables(event)
    
    if hasattr(event, 'operations'):
      for op in event.operations:
        if type(op) in [TraceSwitchFlowTableRead, TraceSwitchFlowTableWrite, TraceSwitchFlowTableEntryExpiry]:
          self.events_with_reads_writes.append(event.eid)

    def _handle_HbAsyncFlowExpiry(event):
      if self.data_deps:
        self._update_shadow_tables(event)
      self._update_edges(event)
    def _handle_HbPacketHandle(event):
      if self.data_deps:
        self._update_shadow_tables(event)
      self._update_edges(event)
    def _handle_HbPacketSend(event):
      self._update_edges(event)
    def _handle_HbMessageHandle(event):
      if self.data_deps:
        self._update_shadow_tables(event)
      self._update_edges(event)
      self.msg_handles[event.eid] = event
    def _handle_HbMessageSend(event):
      self._update_edges(event)
      self.msgs[event.eid] = event
    def _handle_HbHostHandle(event):
      self._update_edges(event)
    def _handle_HbHostSend(event):
      self._update_edges(event)
      self.host_sends[event.eid] = event
    def _handle_HbControllerHandle(event):
      self._update_edges(event)
    def _handle_HbControllerSend(event):
      self._update_edges(event)
    def _handle_default(event):
      assert False
      pass
    
    handlers = {'HbAsyncFlowExpiry':   _handle_HbAsyncFlowExpiry,
                'HbPacketHandle':      _handle_HbPacketHandle,
                'HbPacketSend':        _handle_HbPacketSend,
                'HbMessageHandle':     _handle_HbMessageHandle,
                'HbMessageSend':       _handle_HbMessageSend,
                'HbHostHandle':        _handle_HbHostHandle,
                'HbHostSend':          _handle_HbHostSend,
                'HbControllerHandle':  _handle_HbControllerHandle,
                'HbControllerSend':    _handle_HbControllerSend,
                 }
    handlers.get(event.type, _handle_default)(event)

  def load_trace(self, filename):
    self.g = nx.DiGraph()
    self.events_by_id = dict()
    unpacked_events = list()
    with open(filename) as f:
      for line in f:
        event = self.unpack_line(line)
        if event:
          unpacked_events.append(event)
    print "Read " + str(len(unpacked_events)) + " events."
    for event in unpacked_events:
      self.add_event(event)
    print "Added " + str(len(list(self.events))) + " events."

    
  def store_graph(self, filename="hb.dot",  print_packets=False, print_only_racing=False, print_only_harmful=False):
    if self.results_dir is not None:
      filename = os.path.join(self.results_dir,filename)

    self.prep_draw(self.g, print_packets)
    nx.write_dot(self.g, os.path.join(self.results_dir, "g.dot"))

    interesting_msg_types = ['OFPT_PACKET_IN',
                            'OFPT_FLOW_REMOVED',
                            'OFPT_PACKET_OUT',
                            'OFPT_FLOW_MOD',
                            'OFPT_BARRIER_REQUEST',
                            'OFPT_BARRIER_REPLY',
                            'OFPT_HELLO',
                            ]
        
    pruned_events = []
    
    if print_only_racing:
      for i in self.events:
        if i not in self.race_detector.racing_events:
          pruned_events.append(i)
        else:
          if print_only_harmful and i not in self.race_detector.racing_events_harmful:
            pruned_events.append(i)
            
    dot_lines = []
    dot_lines.append("digraph G {\n");
    for i in self.events:
      if i not in pruned_events:
        optype = ""
        shape = ""
        if hasattr(i, 'operations'):
          for x in i.operations:
            if x.type == 'TraceSwitchFlowTableWrite':
              optype = 'FlowTableWrite'
              shape = '[shape=box style="bold"]'
              break
            if x.type == 'TraceSwitchFlowTableRead':
              optype = 'FlowTableRead'
              shape = '[shape="box"]'
              break
        
        event_info_lines = []
        if optype != "":
          event_info_lines.append("Op: " + optype)
        if (hasattr(i, 'msg_type')):
          event_info_lines.append("MsgType: " + i.msg_type_str)
        if (hasattr(i, 'in_port')):
          event_info_lines.append("InPort: " + str(i.in_port))
        if (hasattr(i, 'buffer_id')):
          event_info_lines.append("BufferId: " + str(i.buffer_id))
        if hasattr(i, 'packet'):
          if print_packets:
            pkt = pkt_info(i.packet)
            event_info_lines.append("Pkt: " + pkt)
        if not hasattr(i, 'msg_type') or i.msg_type_str in interesting_msg_types:
            event_info_lines_str = ""
            for x in event_info_lines:
              event_info_lines_str += '\n'
              event_info_lines_str += str(x)
            dot_lines.append('{0} [label="ID: {0}\\nDPID: {1}\\nEvent: {2}\\n{3}"] {4};\n'.format(
                i.eid, 
                "" if not hasattr(i, 'dpid') else i.dpid,
                i.type,
                event_info_lines_str,
                shape))
    for k,v in self.predecessors:
      if k not in pruned_events:
        for i in v:
          if i not in pruned_events and (not hasattr(i, 'msg_type') or i.msg_type_str in interesting_msg_types):
            dot_lines.append('    {} -> {};\n'.format(i.eid,k.eid))
    dot_lines.append('edge[constraint=false arrowhead="none"];\n')
    if not self.no_race:
      if not print_only_harmful:
        for race in self.race_detector.races_commute:
          if race[1] not in pruned_events and race[2] not in pruned_events:
            dot_lines.append('    {1} -> {2} [style="dotted"];\n'.format(race.rtype, race.i_event.eid, race.k_event.eid))
      for race in self.race_detector.races_harmful:
        if race[1] not in pruned_events and race[2] not in pruned_events:
            dot_lines.append('    {1} -> {2} [style="bold", color="red"];\n'.format(race.rtype, race.i_event.eid, race.k_event.eid))
    dot_lines.append("}\n");
    with open(filename, 'w') as f:
      f.writelines(dot_lines)

  @staticmethod
  def prep_draw(g, print_packets):
    """
    Adds proper annotation for the graph to make drawing it more pleasant.
    """
    for eid, data in g.nodes_iter(data=True):
      event = data['event']
      label = "ID %d \\n %s" % (eid, event.type)
      if hasattr(event, 'hid'):
        label += "\\nHID: " + str(event.hid)
      if hasattr(event, 'dpid'):
        label += "\\nDPID: " + str(event.dpid)

      shape = "oval"
      op = None
      if hasattr(event, 'operations'):
        for x in event.operations:
          if x.type == 'TraceSwitchFlowTableWrite':
            op = "FlowTableWrite"
            op += "\\nCMD: " + OFP_COMMANDS[x.flow_mod.command]
            op += "\\nMatch: " + pretty_match(x.flow_mod.match)
            op += "\\nActions: " + str(x.flow_mod.actions)
            label += "\\nt: " + repr(x.t)
            shape = 'box'
            g.node[eid]['style'] = 'bold'
            break
          if x.type == 'TraceSwitchFlowTableRead':
            op = "FlowTableRead"
            label += "\\nt: " + repr(x.t)
            shape = 'box'
            break
      cmd_type = data.get('cmd_type')
      if cmd_type:
        label += "\\n%s" % cmd_type
      if op:
        label += "\\nOp: %s" % op
      if hasattr(event, 'msg_type'):
        label += "\\nMsgType: " + event.msg_type_str
      if getattr(event, 'msg', None):
        label += "\\nXID: %d" % event.msg.xid
      if hasattr(event, 'in_port'):
        label += "\\nInPort: " + str(event.in_port)
      if hasattr(event, 'out_port') and not isinstance(event.out_port, basestring):
        label += "\\nOut Port: " + str(event.out_port)
      if hasattr(event, 'buffer_id'):
        label += "\\nBufferId: " + str(event.buffer_id)
      if print_packets and hasattr(event, 'packet'):
        pkt = pkt_info(event.packet)
        label += "\\nPkt: " + pkt
      if print_packets and getattr(event, 'msg', None):
        if getattr(event.msg, 'data', None):
          pkt = pkt_info(ethernet(event.msg.data))
          label += "\\nPkt: " + pkt
      g.node[eid]['label'] = label
      g.node[eid]['shape'] = shape
    for src, dst, data in g.edges_iter(data=True):
      g.edge[src][dst]['label'] = data['rel']
      if data['rel'] == 'race':
        if data['harmful']:
          g.edge[src][dst]['color'] = 'red'
          g.edge[src][dst]['style'] = 'bold'
        else:
          g.edge[src][dst]['style'] = 'dotted'

  def extract_traces(self, g):
    """
    Given HB graph g, this method return a list of subgraph starting from
    a HostSend event and all the subsequent nodes that happened after it.

    This method will exclude all the nodes connected because of time and the
    nodes connected after HostHandle.
    """
    traces = []
    # Sort host sends by eid, this will make the output follow the trace order
    eids = self.host_sends.keys()
    eids = sorted(eids)
    for eid in eids:
      nodes = list(nx.dfs_preorder_nodes(g, eid))
      # Remove other HostSends
      for node in nodes:
        if eid != node and isinstance(g.node[node]['event'], HbHostSend):
          nodes.remove(node)
      subg = nx.DiGraph(g.subgraph(nodes), host_send=g.node[eid]['event'])
      traces.append(subg)
    for i, subg in enumerate(traces):
      for src, dst, data in subg.edges(data=True):
        if data['rel'] in ['time', 'race']:
          subg.remove_edge(src, dst)
      # Remove disconnected subgraph
      host_send = subg.graph['host_send']
      nodes = nx.dfs_preorder_nodes(subg, host_send.eid)
      traces[i] = nx.DiGraph(subg.subgraph(nodes), host_send=host_send)
    self.packet_traces = traces
    return traces

  def store_traces(self, results_dir, print_packets=True, subgraphs=None):
    if not subgraphs:
      subgraphs = self.extract_traces(self.g)
    for i in range(len(subgraphs)):
      subg = subgraphs[i]
      send = subg.graph['host_send']
      HappensBeforeGraph.prep_draw(subg, print_packets)
      nx.write_dot(subg, "%s/trace_%s_%s_%04d.dot" % (results_dir,
                                                      str(send.packet.src),
                                                      str(send.packet.dst), send.eid))

  def add_harmful_edges(self, bidir=False):
    for race in self.race_detector.races_harmful:
      props = dict(rel='race', rtype=race.rtype, harmful=True)
      self.g.add_edge(race.i_event.eid, race.k_event.eid, attr_dict=props)
      if bidir:
        self.g.add_edge(race.k_event.eid, race.i_event.eid, attr_dict=props)

  def add_commute_edges(self, bidir=False):
    for race in self.race_detector.races_commute:
      props = dict(rel='race', rtype=race.rtype, harmful=False)
      self.g.add_edge(race.i_event.eid, race.k_event.eid, attr_dict=props)
      if bidir:
        self.g.add_edge(race.k_event.eid, race.i_event.eid, attr_dict=props)

  def get_racing_events(self, trace, ignore_other_traces=True):
    """
    For a given packet trace, return all the races that races with its events
    """
    # Set of all events that are part of a harmful race
    all_harmful = set([event.eid for event in
                   self.race_detector.racing_events_harmful])
    # Set of event ids of a packet trace
    eids = set(trace.nodes())
    # All events in packet trace that are also part of a race
    racing_eids = sorted(list(eids.intersection(all_harmful)))
    # Get the actual reported race;
    # will get us the other event that has been part of the race
    
    rw_races_with_trace = list()
    for race in self.race_detector.races_harmful:
      if race.rtype == 'r/w':
        # i_event is read, k_event is write
        if race.i_event.eid in racing_eids or race.k_event.eid in racing_eids:
          # We don't care about write on the packet trace that races with reads
          # on other packet traces. The other traces will be reported anyway.
          # logical implication: ignore_other_traces ==> race.i_event.eid in racing_eids
          if (not ignore_other_traces) or (race.i_event.eid in racing_eids):
            rw_races_with_trace.append(race)
          
    # make sure the races are sorted first by read, then by write. The default
    # sort on the namedtuple already does this
    return sorted(rw_races_with_trace)

  def get_all_packet_traces_with_races(self):
    """
    Finds all the races related each packet trace
    """
    races = list()
    for trace in self.packet_traces:
      racing_events = self.get_racing_events(trace, True)
      if len(racing_events) > 0:
        races.append((trace, racing_events,))
    return races

  def summarize_per_packet_inconsistent(self, traces_races):
    """
    If two packets are inconsistent, but they race with the same set of writes,
    then only one will be reported
    """
    # TODO(jm): This does not take into account the order of the writes or the path the packets took. Do we care?
    result = {}
    removed = defaultdict(list)
    for trace, races, versions in traces_races:
      # First get the writes
      writes = []
      for race in races:
        if isinstance(race.i_op, TraceSwitchFlowTableWrite):
          writes.append(race.i_op.eid)
        if isinstance(race.k_op, TraceSwitchFlowTableWrite):
          writes.append(race.k_op.eid)
      key = (tuple(sorted(writes)))
      if key in result:
        removed[key].append((trace, races, versions))
      else:
        result[key] = (trace, races, versions)
    return result.values()

  def print_racing_packet_trace(self, trace, races, label):
    """
    first is the trace
    second is the list of races
    """
    host_send = trace.graph['host_send']
    g = nx.DiGraph(trace, host_send= host_send)
    for race in races:
      if not g.has_node(race.i_event.eid):
        g.add_node(race.i_event.eid, event=race.i_event)
      if not g.has_node(race.k_event.eid):
        g.add_node(race.k_event.eid, event=race.k_event)
      g.add_edge(race.i_event.eid, race.k_event.eid, rel='race', harmful=True)

    self.prep_draw(g, TraceSwitchPacketUpdateBegin)
    src = str(host_send.packet.src)
    dst = str(host_send.packet.dst)
    name = "%s_%s_%s_%s.dot" %(label, src, dst, host_send.eid)
    name = os.path.join(self.results_dir, name)
    print "Storing packet %s for %s->%s in %s " % (label, src, dst, name)
    nx.write_dot(g, name)

  def races_graph(self):
    races = self.race_detector.races_harmful
    races_graph = nx.DiGraph()
    for rtype, i_event, i_op, k_event, k_op in races:
      races_graph.add_node(i_event.eid, event=i_event)
      races_graph.add_node(k_event.eid, event=k_event)
      races_graph.add_edge(i_event.eid, k_event.eid, rel='race', harmful=True)
    return races_graph

  def save_races_graph(self, print_pkts=True, name=None):
    if not name:
      name = "just_races.dot"
    graph = self.races_graph()
    self.prep_draw(graph, print_pkts)
    print "Saving all races graph in", name
    nx.write_dot(graph, os.path.join(self.results_dir, name))

  def find_covered_races(self):
    """
    Go through events in trace order, add a RaW dependency and then check if 
    there are any races that are part of:
     - the set of predecessors of W, and
     - the set of successors of R
    
    These are now ordered so we can add them to the list.
    """
    
    if self.covered_races:
      return self.covered_races
    
    covered_races = dict()
    data_dep_races = set()
    
    # check for monotonically increasing eids, i.e. the list must be sorted
    assert all(x <= y for x, y in zip(self.events_with_reads_writes,
                                      self.events_with_reads_writes[1:]))
    
    for eid in self.events_with_reads_writes:
      event = self.events_by_id[eid]
      dpid = event.dpid
      shadow_table = self.shadow_tables[dpid]
      
      if hasattr(event, 'operations'):
        has_reads = False
        for op in event.operations:
          if type(op) in [TraceSwitchFlowTableRead]:
            has_reads = True
        if has_reads:
          # add RaW dependencies (HB edge from event containing W -> event containing R)
          for write_eid in shadow_table.data_deps[event.eid]:
            write_event = self.events_by_id[write_eid]
            if self.g.has_edge(write_event.eid, event.eid):
              assert self.g.get_edge_data(write_event.eid, event.eid)['rel'] == 'time'
            else:
              self._add_edge(write_event, event, sanity_check=False, rel='dep_raw', update_path_cache=True)
            
            # Should we check this after adding *all* dependencies or after each. E.g. for events with a read and a write.
            
            # includes write_eid itself
            write_succs = set(nx.dfs_preorder_nodes(self.g, write_eid))
            
            for r in self.race_detector.races_harmful: # TODO(jm): get rid of this loop here, lots of unnecessary looping
              # is there a path from our write to the the race
              if r.i_event.eid in write_succs or r.k_event.eid in write_succs:
                # ignore races that we just removed using the data dep edge.
                if (r.i_event == event and r.k_event == write_event) or (r.i_event == write_event and r.k_event == event):
                  data_dep_races.add(r)
                else:
                  # only add a covered race the first time
                  if r not in covered_races and r not in data_dep_races:
                    if self.has_path(r.i_event.eid, r.k_event.eid, bidirectional=True):
                      # race is not a race anymore
                      covered_races[r] = (eid, write_eid)
    self.covered_races = covered_races
    return self.covered_races

  def find_per_packet_inconsistent(self, covered_races=None, summarize=True):
    """
    Returns the following sets of packet traces.
      1) all packet traces that race with a write event
      2) all per-packet inconsistent traces (covered and uncovered)
      3) Covered packet traces (trace with races cannot happen because of HB)
      4) Packet traces with races with first switch on version update
      5) Summarize traces after removing covered and trimming traces that races with the same writes

    all packet traces = all per-packet inconsistent traces +  Packet traces with races with first switch on version update
    summazied = all per-packet inconsistent traces - repeatd all per-packet inconsistent traces
    """
    
    # list of (trace, races), ordered by trace order
    packet_races = self.get_all_packet_traces_with_races()
    inconsistent_packet_traces = []
    inconsistent_packet_traces_covered = []
    inconsistent_packet_entry_version = []
    summarized = []

    dpids_for_version = {}
    for version, cmds in self.versions.iteritems():
      dpids_for_version[version] = set([getattr(self.g.node[cmd]['event'], 'dpid', None) for cmd in cmds])

    def get_versions_for_races(races):
      # assume races is ordered!
      assert all(races[i] < races[i+1] for i in xrange(len(races)-1))
      versions_for_race = defaultdict(set)
      for race in races:
        # get versions for each race
        for version, cmds in self.versions.iteritems():
          if race.i_event.eid in cmds or race.k_event.eid in cmds:
            versions_for_race[race].add(version)
      return versions_for_race # TODO(jm): should change this to ordered set, or make the requirement otherwise explicit
    
    def is_inconsistent_packet_entry_version(trace, races, versions_for_race, covered_races=None):
      if covered_races is None:
        covered_races = set()
      else:
        covered_races = set(covered_races) # set of all keys of the dict covered_races
        
      # all elements of covered_races are of type Race()
      assert type(covered_races) == set and all(type(i).__name__ == 'Race' for i in covered_races)
        
      # at most 1 uncovered race in races
      assert len(set(races).difference(set(covered_races))) == 1
      
      uncovered_race = set(races).difference(covered_races).pop()
      trace_nodes = nx.dfs_preorder_nodes(trace, trace.graph['host_send'].eid)
      trace_dpids = [getattr(self.g.node[node]['event'], 'dpid', None) for node in trace_nodes]
      racing_dpid = uncovered_race.i_event.dpid
      
      # which switches/nodes does the packet traverse before hitting this 1 uncovered race?
      none_racing_dpids = set([x for x in trace_dpids[:trace_dpids.index(racing_dpid)] if x is not None])
      
      # which version(s) is the write of this uncovered race part of?
      versions_for_uncovered_race = versions_for_race[uncovered_race]
      # as there is one write, this should be 1
      assert len(versions_for_uncovered_race) == 1
      racing_version = versions_for_uncovered_race.pop()
      
      # which dpids were affected by this version?
      dpids_affected = set(dpids_for_version[racing_version])
      
      # is one of those dpids affected the one uncovered race (same dpids)?
      # Check with the race on the first switch of the update
      print dpids_affected, none_racing_dpids # TODO(jm): remove debug line
      if dpids_affected.intersection(none_racing_dpids):
        return True # inconsistent, the covered race is part of an update that affected earlier nodes
      else:
        return False # either inconsistent or consistent
      
    for trace, races in packet_races:
      versions_for_race = get_versions_for_races(races)
      racing_versions = sorted(list(set(versions_for_race.keys())))
      
      if len(races) == 0:
        assert False
      else:
        if covered_races is not None:
          # We consider a packet trace consistent if:
          # 1. Contains at most one uncovered race
          # 2. The uncovered race (if it exists) is the first one
          # 3. The first uncovered race is not already inconsistent
          # We need not check why the race is covered, i.e. which race covers it.
          at_most_first_uncovered = True
          all_including_first_covered = True
          for idx,race in enumerate(races):
            if race not in covered_races:
              all_including_first_covered = False
              if idx > 0:
                at_most_first_uncovered = False
                break
          if all_including_first_covered:
            # this is a consistent trace
            inconsistent_packet_traces_covered.append((trace, races, racing_versions))
          elif at_most_first_uncovered:
            if is_inconsistent_packet_entry_version(trace, races, versions_for_race, covered_races):
              # the packet sees other versions before the first race, which makes it inconsistent
              inconsistent_packet_entry_version.append((trace, races, racing_versions))
            else:
              # consistent due to covered races
              inconsistent_packet_traces_covered.append((trace, races, racing_versions))
          else:
            inconsistent_packet_traces.append((trace, races, racing_versions))
        else:
          if is_inconsistent_packet_entry_version(trace, races, versions_for_race):
            inconsistent_packet_entry_version.append((trace, races, racing_versions))
          else:
            inconsistent_packet_traces.append((trace, races, racing_versions))

    if summarize:
      summarized = self.summarize_per_packet_inconsistent(inconsistent_packet_traces)
    return packet_races, inconsistent_packet_traces, \
           inconsistent_packet_traces_covered, \
           inconsistent_packet_entry_version, summarized

  def find_barrier_replies(self):
    barrier_replies = []
    for eid in self.msgs:
      if self.msgs[eid].msg_type_str != 'OFPT_BARRIER_REPLY':
        continue
      nodes = []
      # TODO(jm): Are we sure just_mid_iter is correct? What about packets sent 
      # out by a PACKET_OUT that then trigger a PACKET_IN -> ... -> BARRIER_REPLY?find_barrier_replies 
      edges = dfs_edge_filter(self.g, eid, just_mid_iter)
      for src, dst in edges:
        src_event = self.g.node[src]['event']
        dst_event = self.g.node[dst]['event']
        if isinstance(src_event, HbMessageHandle):
          nodes.append(src_event)
          #self.g.node[src]['cmd_type'] = "Reactive to %d" % eid
        if isinstance(dst_event, HbMessageHandle):
          nodes.append(dst_event)
          #self.g.node[dst]['cmd_type'] = "Reactive to %d" % eid
      # Get unique and sort by time
      nodes = sorted(list(set(nodes)),
                     key=lambda n: n.operations[0].t if n.operations else 0)
      barrier_replies.append((self.msgs[eid], nodes))
    return barrier_replies

  def find_reactive_versions(self):
    cmds = []
    for eid in self.msgs:
      if self.msgs[eid].msg_type_str == 'OFPT_BARRIER_REPLY':
        continue
      nodes = []
      # TODO(jm): Are we sure just_mid_iter is correct? What about packets sent 
      # out by a PACKET_OUT that then trigger a PACKET_IN -> ... -> BARRIER_REPLY?find_barrier_replies
      edges = dfs_edge_filter(self.g, eid, just_mid_iter)
      for src, dst in edges:
        src_event = self.g.node[src]['event']
        dst_event = self.g.node[dst]['event']
        if isinstance(src_event, HbMessageHandle):
          nodes.append(src_event)
          self.g.node[src]['cmd_type'] = "Reactive to %d" % eid
        if isinstance(dst_event, HbMessageHandle):
          nodes.append(dst_event)
          self.g.node[dst]['cmd_type'] = "Reactive to %d" % eid
      # Get unique and sort by time
      nodes = sorted(list(set(nodes)),
                     key=lambda n: n.operations[0].t if n.operations else 0)
      cmds.append((self.msgs[eid], nodes))
    return cmds

  def find_proactive_cmds(self, reactive_versions=None):
    """
    Proactive is all the cmds that were not in the reactive set
    """
    # TODO(jm): At the end of the trace, some of the controller instrumentation might not be there, so some of the commands at the very end could be reactive. Cut them off somehow?
    if not reactive_versions:
      reactive_versions = self.find_reactive_versions()
    reactive_cmds = []
    for msgs, cmds in reactive_versions:
      for cmd in cmds:
        reactive_cmds.append(cmd.eid)
    proactive_eid = set(self.msg_handles.keys()).difference(set(reactive_cmds))
    proactive = [self.g.node[eid]['event'] for eid in list(proactive_eid)]
    for cmd in proactive:
      self.g.node[cmd.eid]['cmd_type'] = 'Proactive'
    proactive.sort(key=lambda n: n.operations[0].t)
    return proactive

  def cluster_cmds(self, cmds):
    """
    Cluster the update commands by time.
    """
    # Cluster by time
    from scipy.cluster.hierarchy import fclusterdata
    # TODO(jm): Should we add a setting for the threshold, or use STS rounds instead of time?
    features = [[e.operations[0].t] for e in cmds]
    result = fclusterdata(features, 1, criterion="distance")
    clustered = defaultdict(list)
    for i in range(len(cmds)):
      clustered[result[i]].append(cmds[i])
    # just trying to order the versions
    ordered = sorted(clustered.keys(), key= lambda i: clustered[i][0].operations[0].t)
    clustered_ordered = dict()
    for i in range(len(ordered)):
      clustered_ordered[i] = clustered[ordered[i]]
    self.clustered_cmds = clustered_ordered
    return clustered_ordered

  def find_versions(self):
    """
    Find all versions, reactive or proactive
    """
    if self.versions:
      return self.versions

    reactive = self.find_reactive_versions()
    proactive = self.find_proactive_cmds(reactive)
    self.cluster_cmds(proactive)
    # Consider all proactive and reactive versions
    versions = {}
    for version, events in self.clustered_cmds.iteritems():
      versions[version] = list(set([event.eid for event in events]))
    for pktin, events in reactive:
      versions[pktin] = list(set([event.eid for event in events]))

    # Now merge versions if one contains a response to a barrier request
    # from previous version
    # TODO(jm): Perhaps we should not just consider barrier replies, but also flow removed messages for explicit deletes? Are there more such replies?
    barrier_replies = self.find_barrier_replies()
    replies_by_xid = {} # (dpid, xid) -> cmds
    replies_by_xid_versions = {}  # (dpid, xid) -> versions
    requests_by_xid = {} # (dpid, xid) -> version

    # Sort replies by dpid and xid
    for rep, cmds in barrier_replies:
      key = (rep.dpid, rep.msg.xid)
      replies_by_xid[key] = [event.eid for event in cmds]
      replies_by_xid_versions[key] = []
      reactive_cmds = set(replies_by_xid[key])
      for v, v_cmds in versions.iteritems():
        if reactive_cmds.intersection(v_cmds):
          replies_by_xid_versions[key].append(v)

    # Sort requests by dpid and xid
    for v, v_cmds in versions.iteritems():
      for v_cmd in v_cmds:
        event = self.g.node[v_cmd]['event']
        if event.msg_type_str == 'OFPT_BARRIER_REQUEST':
          requests_by_xid[(event.dpid, event.msg.xid)] = v

    for key, version in requests_by_xid.iteritems():
      if version not in versions:
        continue # already merged
      if key not in replies_by_xid:
        continue
      new_cmds = versions[version]
      for v in replies_by_xid_versions[key]:
        if v == version:
          continue # we already considered the first version
        if v not in versions:
          continue # already merged
        new_cmds += versions[v]
        del versions[v]

    # Sort cmds by time, just to make it nicer
    for version in versions:
      versions[version].sort(key=lambda x: self.g.node[x]['event'].operations[0].t)
    self.versions = versions
    return versions

  def find_inconsistent_updates(self):
    """Try to find if two versions race with each other"""
    versions = self.find_versions()

    # TODO(jm): Could we check the races directly instead of creating the ww_races variable?
    
    ww_races = defaultdict(list)
    for race in self.race_detector.races_harmful:
      if race.rtype == 'w/w':
        ww_races[race.i_event.eid].append(race.k_event.eid)
        ww_races[race.k_event.eid].append(race.i_event.eid)

    racing_events = []
    for version, cmds in versions.iteritems():
      for cmd in cmds:
        if cmd in ww_races:
          for other in ww_races[cmd]:
            if other not in cmds:
              racing_events.append((cmd, other))
    racing_versions = []
    for eid1, eid2 in racing_events:
      v1 = None
      v2 = None
      for version, cmds in versions.iteritems():
        if eid1 in cmds:
          v1 = version
        if eid2 in cmds:
          v2 = version
      racing_versions.append((v1, v2, (eid1, eid2), (versions[v1], versions[v2])))
    return racing_versions

  def print_versions(self, versions):
    # Printing versions
    for v, cmds in versions.iteritems():
      print "IN Version", v
      if isinstance(v, HbMessageSend):
        print "React to Msg: ", v.msg_type_str
      for cmd in cmds:
        node =  self.g.node[cmd]['event']
        match = ''
        if getattr(node.msg, 'match', None):
          match = node.msg.show().replace('\n', ' ')
        of_cmd = ''
        if hasattr(node.msg, 'command'):
          of_cmd = OFP_COMMANDS[node.msg.command]
        print "\t eid", node.eid, " dpid:", node.dpid, " xid:", node.msg.xid ,\
          " cmd:", node.msg_type_str, of_cmd, ' ',\
          pretty_match(getattr(node.msg, 'match', None)),\
          getattr(node.msg, 'actions', None)

  def print_covered_races(self):
    print "Covered races"
    eids = []
    race_edges = []
    nodes_on_path = []
    for r,v in self.covered_races.iteritems():
      print "Race (r/w): ", r.rtype, r.i_event.eid, r.k_event.eid, ", covered by data dep w -> r: ", v
      eids.append(r.i_event.eid)
      eids.append(r.k_event.eid)
      race_edges.append((r.i_event.eid, r.k_event.eid))
      eids.append(v[0])
      eids.append(v[1])
      for path in nx.all_simple_paths(self.g, r.i_event.eid, r.k_event.eid):
        nodes_on_path.extend(path)
      for path in nx.all_simple_paths(self.g, r.k_event.eid, r.i_event.eid):
        nodes_on_path.extend(path)
    nodes_on_path = list(set(nodes_on_path))
    sub_nodes = nodes_on_path + eids
    subg = self.g.subgraph(list(set(sub_nodes)))
    for i, k in race_edges:
      subg.add_edge(k, i, rel='covered')
    self.prep_draw(subg, True)
    nx.write_dot(subg, os.path.join(self.results_dir, 'covered_races.dot'))


class Main(object):
  
  def __init__(self, filename, print_pkt, print_only_racing, print_only_harmful,
               add_hb_time=True, rw_delta=5, ww_delta=5, filter_rw=False,
               ignore_ethertypes=None, no_race=False, alt_barr=False,
               verbose=True, ignore_first=False, disable_path_cache=False, data_deps=False):
    self.filename = os.path.realpath(filename)
    self.results_dir = os.path.dirname(self.filename)
    self.output_filename = self.results_dir + "/" + "hb.dot"
    self.print_pkt = print_pkt
    self.print_only_racing = print_only_racing
    self.print_only_harmful = print_only_harmful
    self.add_hb_time = add_hb_time
    self.rw_delta = rw_delta
    self.ww_delta = ww_delta
    self.filter_rw = filter_rw
    self.ignore_ethertypes = ignore_ethertypes
    self.no_race = no_race
    self.alt_barr = alt_barr
    self.verbose = verbose
    self.ignore_first = ignore_first
    self.disable_path_cache = disable_path_cache
    self.data_deps = data_deps

  def run(self):
    self.graph = HappensBeforeGraph(results_dir=self.results_dir,
                                    add_hb_time=self.add_hb_time,
                                    rw_delta=self.rw_delta,
                                    ww_delta=self.ww_delta,
                                    filter_rw=self.filter_rw,
                                    ignore_ethertypes=self.ignore_ethertypes,
                                    no_race=self.no_race,
                                    alt_barr=self.alt_barr,
                                    disable_path_cache=self.disable_path_cache,
                                    data_deps=self.data_deps)
    t0 = time.time()    

    self.graph.load_trace(self.filename)
    t1 = time.time()
    
    self.graph.race_detector.detect_races(verbose=True)
    t2 = time.time()
    
    packet_traces = self.graph.extract_traces(self.graph.g)
    t3 = time.time()

    reactive_cmds = self.graph.find_reactive_versions()
    t4 = time.time()

    proactive_cmds = self.graph.find_proactive_cmds(reactive_cmds)
    versions = self.graph.find_versions()
    t5 = time.time()

    if self.data_deps:
      covered_races = self.graph.find_covered_races()
    else:
      covered_races = dict()
    t6 = time.time()

    packet_races, inconsistent_packet_traces, \
           inconsistent_packet_traces_covered, \
           inconsistent_packet_entry_version, summarized = \
      self.graph.find_per_packet_inconsistent(covered_races, True)
    t7 = time.time()

    racing_versions = self.graph.find_inconsistent_updates()
    t8 = time.time()
    
    

    self.graph.race_detector.print_races(self.verbose)
    self.graph.store_traces(self.results_dir, print_packets=True, subgraphs=packet_traces)
    self.graph.store_graph(self.output_filename, self.print_pkt, self.print_only_racing, self.print_only_harmful)


    # Print traces
    for trace, races in packet_races:
      self.graph.print_racing_packet_trace(trace, races, label='race')
    for trace, races, _ in inconsistent_packet_traces:
      self.graph.print_racing_packet_trace(trace, races, label='inconsistent')
    for trace, races, _ in inconsistent_packet_traces_covered:
      self.graph.print_racing_packet_trace(trace, races, label='covered')
    for trace, races, _ in inconsistent_packet_entry_version:
      self.graph.print_racing_packet_trace(trace, races, label='entry')
    for trace, races, _ in summarized:
      self.graph.print_racing_packet_trace(trace, races, label='summarized')
    self.graph.save_races_graph(self.print_pkt)


    self.graph.print_versions(versions)
    self.graph.print_covered_races()

    print "Number of packet traces with races:", len(packet_races)
    print "Number of packet inconsistencies: ", len(inconsistent_packet_traces)
    print "Number of packet inconsistencies that are actually consistent (covered): ", len(inconsistent_packet_traces_covered)
    print "Number of packet inconsistencies the first race is already inconsistent: ", len(inconsistent_packet_entry_version)
    print "Number of packet inconsistencies after trimming repeated races: ", len(summarized)
    print "Number of packet inconsistent updates: ", len(racing_versions)
    print "Number of races: ", str(len(self.graph.race_detector.races_commute)+len(self.graph.race_detector.races_harmful))
    print "Number of commuting races: ", len(self.graph.race_detector.races_commute)
    print "Number of harmful races: ", len(self.graph.race_detector.races_harmful)
    print "Number of covered races: ", len(covered_races)
    print "Inconsistent updates:", len(racing_versions)

    load_time = t1 - t0
    detect_races_time = t2 - t1
    extract_traces_time = t3 - t2
    find_reactive_cmds_time = t4 - t3
    find_proactive_cmds_time = t5 - t4
    find_covered_races_time = t6 - t5
    per_packet_inconsistent_time = t7 - t6
    find_inconsistent_update_time = t7 - t8



    t_final = time.time()
    total_time = t_final - t0
    print "Done. Time elapsed:",total_time,"s"
    print "load_trace:", load_time, "s"
    print "detect_races:", detect_races_time, "s"
    print "extract_traces_time:", extract_traces_time, "s"
    print "per_packet_inconsistent_time:", per_packet_inconsistent_time, "s"
    print "find_reactive_cmds_time:", find_reactive_cmds_time, "s"
    print "find_proactive_cmds_time:", find_proactive_cmds_time, "s"
    print "find_inconsistent_update_time:", find_inconsistent_update_time, "s"
    print "find_covered_races_time:", find_covered_races_time, "s"
    #print "print_races:"+(str(t3-t2))+"s"
    #print "store_graph:"+(str(t4-t3))+"s"
    #print "Extracting Packet traces time: "+ (str(t5 - t4)) + "s"
    #print "Finding inconsistent traces time: "+ (str(t6 - t5)) + "s"


    # Printing dat file
    hbt = self.add_hb_time
    rw_delta = self.rw_delta if self.add_hb_time else 'inf'
    ww_delta = self.ww_delta if self.add_hb_time else 'inf'
    file_name = "results_hbt_%s_rw_%s_ww_%s.dat" % (hbt, rw_delta, ww_delta)
    file_name = os.path.join(self.results_dir, file_name)
    timings_file_name = "timings_hbt_%s_rw_%s_ww_%s.dat" % (hbt, rw_delta, ww_delta)
    timings_file_name = os.path.join(self.results_dir, timings_file_name)


    num_writes = len(self.graph.race_detector.write_operations)
    num_read = len(self.graph.race_detector.read_operations)
    num_ops = num_writes + num_read

    num_harmful = len(self.graph.race_detector.races_harmful)
    num_commute = len(self.graph.race_detector.races_commute)
    num_races = num_harmful + num_commute

    num_rw_time_edges = self.graph.race_detector.time_hb_rw_edges_counter
    num_ww_time_edges = self.graph.race_detector.time_hb_ww_edges_counter
    num_time_edges = num_rw_time_edges + num_ww_time_edges

    num_per_pkt_races = len(packet_races)
    num_per_pkt_inconsistent = len(inconsistent_packet_traces)
    num_per_pkt_inconsistent_covered = len(inconsistent_packet_traces_covered)
    num_per_pkt_race_version = len(inconsistent_packet_entry_version)
    num_per_pkt_inconsistent_no_repeat = len(summarized)

    def write_general_info_to_file(f):
      # General info
      f.write('key,value\n')
      f.write('rw_delta,%s\n' % rw_delta)
      f.write('ww_delta,%s\n' % ww_delta)
      f.write('alt_barrier,%s\n' % self.alt_barr)

    with open(file_name, 'w') as f:
      write_general_info_to_file(f)

      # Operations
      f.write('num_read,%d\n' % num_read)
      f.write('num_writes,%d\n' % num_writes)
      f.write('num_ops,%d\n' % num_ops)

      # HB time edges
      f.write('num_rw_time_edges,%d\n' % num_rw_time_edges)
      f.write('num_ww_time_edges,%d\n' % num_ww_time_edges)
      f.write('num_time_edges,%d\n' % num_time_edges)

      # Races info
      f.write('num_harmful,%d\n' % num_harmful)
      f.write('num_commute,%d\n' % num_commute)
      f.write('num_races,%d\n' % num_races)

      # Inconsistency
      f.write('num_per_pkt_races,%d\n' % num_per_pkt_races)
      f.write('num_per_pkt_inconsistent,%d\n' % num_per_pkt_inconsistent)
      f.write('num_per_pkt_inconsistent_covered,%d\n' % num_per_pkt_inconsistent_covered)
      f.write('num_per_pkt_race_version,%d\n' % num_per_pkt_race_version)
      f.write('num_per_pkt_inconsistent_no_repeat,%d\n' % num_per_pkt_inconsistent_no_repeat)

    with open(timings_file_name, 'w') as f:
      write_general_info_to_file(f)
      
      # Times
      f.write('total_time_sec,%f\n'% total_time)
      f.write('load_time_sec,%f\n' % load_time )
      f.write('detect_races_time_sec,%f\n' % detect_races_time )
      f.write('extract_traces_time_sec,%f\n' % extract_traces_time )
      f.write('per_packet_inconsistent_time_sec,%f\n' % per_packet_inconsistent_time )
      f.write('find_reactive_cmds_time_sec,%f\n' % find_reactive_cmds_time )
      f.write('find_proactive_cmds_time_sec,%f\n' % find_proactive_cmds_time )
      f.write('find_inconsistent_update_time_sec,%f\n' % find_inconsistent_update_time )



def auto_int(x):
  return int(x, 0)


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('trace_file')
  parser.add_argument('--pkt', dest='print_pkt', action='store_true', default=False,
                      help="Print packet headers in the graph")
  parser.add_argument('--racing', dest='print_only_racing', action='store_true', default=False,
                      help="Print only races in the graph")
  parser.add_argument('--harmful', dest='print_only_harmful', action='store_true', default=False,
                      help="Print only harmful races (lines) in the graph")
  parser.add_argument('--hbt', dest='hbt', action='store_true', default=False,
                      help="Add HB edges based on tqime")
  parser.add_argument('--rw_delta', dest='rw_delta', default=5, type=int,
                      help="delta time (in secs) for adding HB edges based on time")
  parser.add_argument('--ww_delta', dest='ww_delta', default=5, type=int,
                      help="delta time (in secs) for adding HB edges based on time")
  parser.add_argument('--filter_rw', dest='filter_rw', action='store_true', default=False,
                      help="Filter Read/Write operations with HB relations")
  parser.add_argument('--ignore_ethertypes', dest='ignore_ethertypes', nargs='*',
                      type=auto_int, default=[ethernet.LLDP_TYPE, 0x8942],
                      help='Ether types to ignore from the graph')
  parser.add_argument('--no-race', dest='no_race', action='store_true', default=False,
                      help="Don't add edge between racing events in the graph")
  parser.add_argument('--alt-barr', dest='alt_barr', action='store_true', default=False,
                      help="Use alternative barrier rules for purely reactive controllers")
  parser.add_argument('-v', dest='verbose', action='store_true', default=False,
                      help="Print all commute and harmful races")
  parser.add_argument('--ignore-first', dest='ignore_first', action='store_true',
                      default=False, help="Ignore the first race for per-packet consistency check")
  parser.add_argument('--disable-path-cache', dest='disable_path_cache', action='store_true',
                      default=False, help="Disable using all_pairs_shortest_path_length() preprocessing.")
  parser.add_argument('--data-deps', dest='data_deps', action='store_true',
                      default=False, help="Use shadow tables for adding data dependency edges between reads/writes.")

  # TODO(jm): Make option naming consistent (use _ everywhere, not a mixture of - and _).

  args = parser.parse_args()
  main = Main(args.trace_file, args.print_pkt, args.print_only_racing, args.print_only_harmful,
              add_hb_time=args.hbt, rw_delta=args.rw_delta, ww_delta=args.ww_delta,
              filter_rw=args.filter_rw, ignore_ethertypes=args.ignore_ethertypes,
              no_race=args.no_race, alt_barr=args.alt_barr, verbose=args.verbose,
              ignore_first=args.ignore_first, disable_path_cache=args.disable_path_cache, 
              data_deps=args.data_deps)
  main.run()
