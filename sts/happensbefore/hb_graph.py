#!/usr/bin/env python
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../../pox"))

import argparse
from collections import defaultdict
import networkx as nx

from pox.lib.packet.ethernet import ethernet
from pox.openflow.libopenflow_01 import ofp_flow_mod_command_rev_map

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


OFP_COMMANDS = {v: k for k, v in ofp_flow_mod_command_rev_map.iteritems()}


class HappensBeforeGraph(object):
 
  def __init__(self, results_dir=None, add_hb_time=False, rw_delta=5,
               ww_delta=1, filter_rw=False, ignore_ethertypes=None,
               no_race=False):
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
    self.msg_handles = {}

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
  
  def _add_edge(self, before, after, sanity_check=True, **attrs):
    if sanity_check and before.type not in predecessor_types[after.type]:
      print "Warning: Not a valid HB edge: "+before.typestr+" ("+str(before.eid)+") < "+after.typestr+" ("+str(after.eid)+")"
      assert False 
    #self.predecessors[after].add(before)
    #self.successors[before].add(after)
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
          self._add_edge(other, event, rel='flow_removed')
          # do not remove, one flow mod could have installed multiple rules

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
    self._rule_03_barrier_pre(event)
    self._rule_04_barrier_post(event)
    self._rule_05_flow_removed(event)
    if self.add_hb_time:
      self._rule_06_time_rw(event)
      self._rule_07_time_ww(event)

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
    if self.ignore_ethertypes:
      packet = None
      if hasattr(event, 'packet'):
        packet = event.packet
      if type(event) == HbMessageHandle and getattr(event.msg, 'data', None):
        packet = ethernet(event.msg.data)
      if packet and packet.type in self.ignore_ethertypes:
        return

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
      self.msg_handles[event.eid] = event
    def _handle_HbMessageSend(event):
      self._update_edges(event)
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
    def pretty_match(match):
      lines = match.show()
      output = ''
      for line in lines.split('\n'):
        if not line.startswith('wildcards: '):
          output += line + ' '
      output = output.rstrip()
      if output == '':
        output = '*'
      return output.rstrip()

    for eid, data in g.nodes_iter(data=True):
      event = data['event']
      label = "ID %d \\n %s" % (eid, event.type)
      shape = "oval"
      op = None
      if hasattr(event, 'operations'):
        for x in event.operations:
          if x.type == 'TraceSwitchFlowTableWrite':
            op = "FlowTableWrite"
            op += "\\nCMD: " + OFP_COMMANDS[x.flow_mod.command]
            op += "\\nMatch: " + pretty_match(x.flow_mod.match)
            label += "\\nt: " + repr(x.t)
            shape = 'box'
            g.node[eid]['style'] = 'bold'
            break
          if x.type == 'TraceSwitchFlowTableRead':
            op = "FlowTableRead"
            label += "\\nt: " + repr(x.t)
            shape = 'box'
            break
      if op:
        label += "\\nOp: %s" % op
      if hasattr(event, 'hid'):
        label += "\\nHID: " + str(event.hid)
      if hasattr(event, 'dpid'):
        label += "\\nDPID: " + str(event.dpid)
      if hasattr(event, 'msg_type'):
        label += "\\nMsgType: " + event.msg_type_str
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
      nodes = nx.dfs_preorder_nodes(g, eid)
      traces.append(nx.DiGraph(g.subgraph(nodes), host_send=g.node[eid]['event']))
    for subg in traces:
      # Remove nodes added because of time
      removed_nodes = []
      for src, dst, data in subg.edges(data=True):
        if data['rel'] in ['time', 'race']:
          subg.remove_edge(src, dst)
          if subg.has_node(dst) and not subg.neighbors(dst):
            removed_nodes.append(dst)
        elif isinstance(subg.node[src]['event'], HbHostHandle):
          subg.remove_edge(src, dst)
          if subg.has_node(dst):
            removed_nodes.append(dst)
      # Remove disconnected subgraph
      removed_nodes = list(set(removed_nodes))
      for eid in removed_nodes:
        if not subg.has_node(eid):
          continue
        nodes = list(nx.dfs_preorder_nodes(subg, eid))
        for node in nodes:
          if subg.has_node(node):
            subg.remove_node(node)
    return traces

  def store_traces(self, results_dir, print_packets=True):
    subgraphs = self.extract_traces(self.g)
    self.packet_traces = subgraphs
    for i in range(len(subgraphs)):
      subg = subgraphs[i]
      send = subg.graph['host_send']
      HappensBeforeGraph.prep_draw(subg, print_packets)
      nx.write_dot(subg, "%s/trace_%s_%s_%04d.dot" % (results_dir,
                                                      str(send.packet.src),
                                                      str(send.packet.dst), i))

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

  def get_racing_events(self, trace):
    """
    For a given packet trace, return all the races that races with its events
    """
    # Set of all events that are part of a harmful race
    all_harmful = set([event.eid for event in
                   self.race_detector.racing_events_harmful])
    # Set of event ids of a packet trace
    eids = set(trace.nodes())
    # All events in packet trace that are also part of a race
    racing = list(eids.intersection(all_harmful))
    # Get the actual reported race;
    # will get us the other event that has been part of the race
    races = [race for race in self.race_detector.races_harmful
             if race.i_event.eid in racing or race.k_event.eid in racing]
    return races

  def find_inconsistent(self):
    """
    Finds all the races related each packet trace
    """
    races = []
    for trace in self.packet_traces:
      tmp = self.get_racing_events(trace)
      if not tmp:
        continue
      if len(tmp) == 1:
        send = trace.graph['host_send']
        if trace.has_edge(send.eid, tmp[0].i_event.eid) or\
            trace.has_edge(send.eid, tmp[0].k_event.eid):
          print "Ignoring race for on the first switch: for %s->%s" % (str(send.packet.src), str(send.packet.dst))
          continue
      races.append((trace, tmp))
    return races

  def print_racing_packet_trace(self, result_dir, trace, races):
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
    nx.write_dot(g, "/%s/race_%s_%s_%d.dot" % (result_dir,
                                               str(host_send.packet.src),
                                               str(host_send.packet.dst),
                                               host_send.eid))

  def cluster_cmds(self):
    """
    Cluster the update commands by time.
    """
    # Set of flowMods
    fmods = []
    for event in self.msg_handles.itervalues():
      if event.msg_type_str == 'OFPT_FLOW_MOD':
        fmods.append(event)
    # Cluster by time
    from scipy.cluster.hierarchy import fclusterdata
    features = [[e.operations[0].t] for e in fmods]
    result = fclusterdata(features, 1, criterion="distance")
    clustered = defaultdict(list)
    for i in range(len(fmods)):
      clustered[result[i]].append(fmods[i])
    # just trying to order the versions
    ordered = sorted(clustered.keys(), key= lambda i: clustered[i][0].operations[0].t)
    clustered_ordered = dict()
    for i in range(len(ordered)):
      clustered_ordered[i] = clustered[ordered[i]]
    self.clustered_cmds = clustered_ordered
    return clustered_ordered

  def find_inconsistent_updates(self):
    """Try to find if two versions race with each other"""
    ww_races = defaultdict(list)
    for race in self.race_detector.races_harmful:
      if race.rtype == 'w/w':
        ww_races[race.i_event.eid].append(race.k_event.eid)
        ww_races[race.k_event.eid].append(race.i_event.eid)

    self.cluster_cmds()
    for version, events in self.clustered_cmds.iteritems():
      cmds = [e.eid for e in events]
      for cmd in cmds:
        if cmd in ww_races:
          for other in ww_races[cmd]:
            if other not in cmds:
              print "RACE version", version, " eid: ", cmd, " other eid", other


class Main(object):
  
  def __init__(self, filename, print_pkt, print_only_racing, print_only_harmful,
               add_hb_time=True, rw_delta=5, ww_delta=5, filter_rw=False,
               ignore_ethertypes=None, no_race=False):
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

  def run(self):
    import time
    self.graph = HappensBeforeGraph(results_dir=self.results_dir,
                                    add_hb_time=self.add_hb_time,
                                    rw_delta=self.rw_delta,
                                    ww_delta=self.ww_delta,
                                    filter_rw=self.filter_rw,
                                    ignore_ethertypes=self.ignore_ethertypes,
                                    no_race=self.no_race)
    t0 = time.time()    
    self.graph.load_trace(self.filename)
    t1 = time.time()
    self.graph.race_detector.detect_races(verbose=True)
    t2 = time.time()
    self.graph.race_detector.print_races()
    t3 = time.time()
    self.graph.store_graph(self.output_filename, self.print_pkt, self.print_only_racing, self.print_only_harmful)
    t4 = time.time()
    self.graph.store_traces(self.results_dir)
    t5 = time.time()
    packet_races = self.graph.find_inconsistent()
    for trace, races in packet_races:
      self.graph.print_racing_packet_trace(self.results_dir, trace, races)
    self.graph.find_inconsistent_updates()
    t6 = time.time()
    
    print "Done. Time elapsed: "+(str(t4-t0))+"s"
    print "load_trace: "+(str(t1-t0))+"s"
    print "detect_races: "+(str(t2-t1))+"s"
    print "print_races: "+(str(t3-t2))+"s"
    print "store_graph: "+(str(t4-t3))+"s"
    print "Extracting Packet traces time: "+ (str(t5 - t4)) + "s"
    print "Finding inconsistent traces time: "+ (str(t6 - t5)) + "s"


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


  args = parser.parse_args()
  main = Main(args.trace_file, args.print_pkt, args.print_only_racing, args.print_only_harmful,
              add_hb_time=args.hbt, rw_delta=args.rw_delta, ww_delta=args.ww_delta,
              filter_rw=args.filter_rw, ignore_ethertypes=args.ignore_ethertypes,
              no_race=args.no_race)
  main.run()
