#!/usr/bin/env python
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../../pox"))

import argparse
from collections import defaultdict
import networkx as nx

from hb_utils import pkt_info

from hb_race_detector import RaceDetector
from hb_race_detector import predecessor_types

# To make sure all events are registered
from hb_json_event import *
from hb_events import *
from hb_sts_events import *

#
# Do not import any STS types! We would like to be able to run this offline
# from a trace file without having to depend on STS.
#


class HappensBeforeGraph(object):
 
  def __init__(self, results_dir=None):
    self.results_dir = results_dir
    
    self.g = nx.DiGraph()

    self.events_by_id = dict()
    self.pruned_events = set()

    self.events_by_pid_out = defaultdict(list)
    self.events_by_mid_out = defaultdict(list)
    
    # events that have a mid_in/mid_in and are still looking for a pid_out/mid_out to match 
    self.events_pending_pid_in = defaultdict(list)
    self.events_pending_mid_in = defaultdict(list)
    
    # for flow mod rule
    self.events_flowmod_by_dpid_match = defaultdict(list)
    
    # for barrier pre rule
    self.events_before_next_barrier = defaultdict(list)
    
    # for barrier post rule
    self.most_recent_barrier = defaultdict()
    
    # for races
    self.race_detector = RaceDetector(self)

  @property
  def events(self):
    for _, data in self.g.nodes_iter(True):
      yield data['event']

  @property
  def predecessors(self):
    """Horribly inefficient!!!!!"""
    predecessors = defaultdict(set)
    for eid, data in self.g.nodes(data=True):
      event = data['event']
      predecessors[event] = set()
      for pred in self.g.predecessors_iter(eid):
        predecessors[event].add(self.g.node[pred]['event'])
    return predecessors

  @property
  def successors(self):
    """Horribly inefficient!!!!!"""
    successors = defaultdict(set)
    for eid, data in self.g.nodes(data=True):
      event = data['event']
      successors[event] = set()
      for pred in self.g.successors_iter(eid):
        successors[event].add(self.g.node[pred]['event'])
    return successors

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
                           (self.events_flowmod_by_dpid_match, 
                            lambda x: (x.type == 'HbMessageHandle' and
                                       hasattr(x, 'msg_type_str') and 
                                       x.msg_type == "OFPT_FLOW_MOD" and
                                       hasattr(x, 'dpid') and
                                       hasattr(x, 'msg_flowmod')
                                       ),
                            lambda x: (x.dpid, x.msg_flowmod) ),
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
  def _update_event_has_no_further_successors_pid_out(self, event):
    if event in self.events_by_pid_out[event.pid_out]:
      self.events_by_pid_out[event.pid_out].remove(event)
  def _update_event_has_no_further_successors_mid_out(self, event):
    if event in self.events_by_mid_out[event.mid_out]:
      self.events_by_mid_out[event.mid_out].remove(event)
  
  def _add_edge(self, before, after, sanity_check=True):
    if sanity_check and before.type not in predecessor_types[after.type]:
      print "Warning: Not a valid HB edge: "+before.typestr+" ("+str(before.eid)+") < "+after.typestr+" ("+str(after.eid)+")"
      assert False 
    #self.predecessors[after].add(before)
    #self.successors[before].add(after)
    self.g.add_edge(before.eid, after.eid)
    
  def _rule_01_pid(self, event):
    # pid_out -> pid_in
    if hasattr(event, 'pid_in'):
      if event.pid_in in self.events_by_pid_out:
        for other in self.events_by_pid_out[event.pid_in]: 
          self._add_edge(other, event)
          self._update_event_is_linked_pid_in(event)
    # TODO(jm): remove by reordering first
    # recheck events added in an order different from the trace order
    if hasattr(event, 'pid_out'):
      for pid_out in event.pid_out:
        if pid_out in self.events_pending_pid_in:
          for other in self.events_pending_pid_in[pid_out][:]: # copy list [:], so we can remove from it
            self._add_edge(event, other)
            self._update_event_is_linked_pid_in(other)
            
  def _rule_02_mid(self, event):
    # mid_out -> mid_in
    if hasattr(event, 'mid_in'):
      if event.mid_in in self.events_by_mid_out:
        for other in self.events_by_mid_out[event.mid_in]:
          self._add_edge(other, event)
          self._update_event_is_linked_mid_in(event)
    # TODO(jm): remove by reordering first
    # recheck events added in an order different from the trace order (mainly controller events as they are asynchronously logged)
    if hasattr(event, 'mid_out'):
      for mid_out in event.mid_out:
        if mid_out in self.events_pending_mid_in:
          for other in self.events_pending_mid_in[mid_out][:]: # copy list [:], so we can remove from it
            self._add_edge(event, other)
            self._update_event_is_linked_mid_in(other)
  
  def _rule_03_barrier_pre(self, event):
    if event.type == 'HbMessageHandle':
      if event.msg_type_str == "OFPT_BARRIER_REQUEST":
        for other in self.events_before_next_barrier[event.dpid]:
          self._add_edge(other, event)
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
          self._add_edge(other, event)
        
  def _rule_05_flow_removed(self, event):
    # TODO(jm): This is not correct. Flow removed messages do not necessarily contain the exact same flowmod message as was installed.
    # TODO(jm): Rather, we should match only on (match, cookie, priority), not also on actions
    #          and also only consider flow mods where the OFPFF_SEND_FLOW_REM flag was set
    if event.type == 'HbMessageHandle' and event.msg_type_str == "OFPT_FLOW_REMOVED":
      search_key = (event.dpid, event.msg_flowmod)
      # TODO(jm): here: check for all self.events_flowmod_by_dpid_match, generate search_key2 by removing actions and then compare
      # TODO(jm): better yet, add a new self.events_flowremoved_mcp_by_dpid_match dict  
      if search_key in self.events_flowmod_by_dpid_match:
        for other in self.events_flowmod_by_dpid_match[search_key]:
          self._add_edge(other, event)
          # do not remove, one flow mod could have installed multiple rules
  
  def _update_edges(self, event):
    self._rule_01_pid(event)
    self._rule_02_mid(event)
    self._rule_03_barrier_pre(event)
    self._rule_04_barrier_post(event)
    self._rule_05_flow_removed(event)
  
  def _add_transitive_edges(self, event):
    """
    Add transitive edges: A->x->B will add edge A->B
    """
    out_events = set(self.successors[event])
    in_events = set(self.predecessors[event])
    
    for in_evt in in_events:
      for out_evt in out_events:
        self._add_edge(in_evt, out_evt, sanity_check=False)
  
  # TODO(jm): make online_update a config option
  def add_line(self, line, online_update=False):
    # Skip empty lines and the ones start with '#'
    if not line or line.startswith('#'):
      return

    event = JsonEvent.from_json(json.loads(line))
    self.add_event(event)
    if online_update:
      self.race_detector.detect_races(event)
      has_new_races = self.race_detector.total_races > 0
      self.race_detector.detect_races()
      if has_new_races:
        self.race_detector.print_races()
      self.store_graph()

  def add_event(self, event):
    #self.events.append(event)
    assert event.eid not in self.events_by_id
    self.g.add_node(event.eid, event=event)
    self.events_by_id[event.eid] = event
    self._add_to_lookup_tables(event)

    def _handle_HbAsyncFlowExpiry(event):
      self._update_edges(event)
    def _handle_HbPacketHandle(event):
      self._update_edges(event)
    def _handle_HbPacketSend(event):
      self._update_edges(event)
    def _handle_HbMessageHandle(event):
      self._update_edges(event)
    def _handle_HbMessageSend(event):
      self._update_edges(event)
    def _handle_HbHostHandle(event):
      self._update_edges(event)
    def _handle_HbHostSend(event):
      self._update_edges(event)
    def _handle_HbControllerHandle(event):
      self._update_edges(event)
    def _handle_HbControllerSend(event):
      self._update_edges(event)
    def _handle_default(event):
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
    with open(filename) as f:
      for line in f:
        self.add_line(line, online_update=False)
    print "Read in " + str(len(list(self.events))) + " events."
    #self.events.sort(key=lambda i: i.eid)

  def store_graph(self, filename="hb.dot",  print_packets=False, print_only_racing=False, print_only_harmful=False):
    if self.results_dir is not None:
      filename = os.path.join(self.results_dir,filename)
    
    interesting_msg_types = ['OFPT_PACKET_IN',
                            'OFPT_FLOW_REMOVED',
                            'OFPT_PACKET_OUT',
                            'OFPT_FLOW_MOD',
                            'OFPT_BARRIER_REQUEST',
                            'OFPT_BARRIER_REPLY',
                            'OFPT_HELLO',
                            ]
        
#     prunable_types =  [
#                        EventType.HbPacketSend,
#                        EventType.HbHostHandle,
#                        EventType.HbHostSend,
#                        EventType.HbControllerHandle,
#                        EventType.HbControllerSend,
#                       ]
    
    prunable_types =  []

    # make a copy of self.predecessors, and then add transitive edges
    # this way we can customize the output of the graphviz file without affecting
    # the graph itself
    pruned_events = []
    transitive_predecessors = defaultdict(set)
    for k,v in self.predecessors.iteritems():
      transitive_predecessors[k].update(v)
    for i in self.events:
      if i.type in prunable_types:
        out_events = set(self.successors[i])
        in_events = set(self.predecessors[i])
        for in_evt in in_events:
          for out_evt in out_events:
            transitive_predecessors[out_evt].add(in_evt)
        pruned_events.append(i)
    
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
    for k,v in transitive_predecessors.iteritems():
      if k not in pruned_events:
        for i in v:
          if i not in pruned_events and (not hasattr(i, 'msg_type') or i.msg_type_str in interesting_msg_types):
            dot_lines.append('    {} -> {};\n'.format(i.eid,k.eid))
    dot_lines.append('edge[constraint=false arrowhead="none"];\n')
    if not print_only_harmful:
      for race in self.race_detector.races_commute:
        if race[1] not in pruned_events and race[2] not in pruned_events:
          dot_lines.append('    {1} -> {2} [style="dotted"];\n'.format(race[0], race[1].eid, race[2].eid))
    for race in self.race_detector.races_harmful:
      if race[1] not in pruned_events and race[2] not in pruned_events:
          dot_lines.append('    {1} -> {2} [style="bold"];\n'.format(race[0], race[1].eid, race[2].eid))
    dot_lines.append("}\n");
    with open(filename, 'w') as f:
      f.writelines(dot_lines)

  
class Main(object):
  
  def __init__(self, filename, print_pkt, print_only_racing, print_only_harmful):
    self.filename = os.path.realpath(filename)
    self.results_dir = os.path.dirname(self.filename)
    self.output_filename = self.results_dir + "/" + "hb.dot"
    self.print_pkt = print_pkt
    self.print_only_racing = print_only_racing
    self.print_only_harmful = print_only_harmful
    
  def run(self):
    import time
    self.graph = HappensBeforeGraph(results_dir=self.results_dir)
    t0 = time.time()    
    self.graph.load_trace(self.filename)
    t1 = time.time()
    self.graph.race_detector.detect_races(verbose=True)
    t2 = time.time()
    self.graph.race_detector.print_races()
    t3 = time.time()
    self.graph.store_graph(self.output_filename, self.print_pkt, self.print_only_racing, self.print_only_harmful)
    t4 = time.time()
    
    print "Done. Time elapsed: "+(str(t4-t0))+"s"
    print "load_trace: "+(str(t1-t0))+"s"
    print "detect_races: "+(str(t2-t1))+"s"
    print "print_races: "+(str(t3-t2))+"s"
    print "store_graph: "+(str(t4-t3))+"s"
    
    
if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('trace_file')
  parser.add_argument('--pkt', dest='print_pkt', action='store_true', default=False,
                      help="Print packet headers in the graph")
  parser.add_argument('--racing', dest='print_only_racing', action='store_true', default=False,
                      help="Print only races in the graph")
  parser.add_argument('--harmful', dest='print_only_harmful', action='store_true', default=False,
                      help="Print only harmful races (lines) in the graph")
  args = parser.parse_args()
  main = Main(args.trace_file, args.print_pkt, args.print_only_racing, args.print_only_harmful)
  main.run()
