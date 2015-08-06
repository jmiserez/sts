#!/usr/bin/env python
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../../pox"))
from pox.openflow.libopenflow_01 import *
from pox.openflow.flow_table import FlowTable, TableEntry, SwitchFlowTable
from pox.openflow.software_switch import OFConnection
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import _type_to_name as icmp_names
from pox.lib.packet.packet_utils import ipproto_to_str

import argparse
import json
from collections import namedtuple, defaultdict, deque, OrderedDict
import itertools
import pprint
import base64
from copy import copy

from hb_comute_check import CommutativityChecker
from hb_utils import decode_flow_mod
from hb_utils import decode_packet
from hb_utils import pkt_info
from hb_utils import ofp_flow_mod_command_to_str
from hb_utils import nCr
from hb_utils import enum

#
# Do not import any STS types! We would like to be able to run this offline
# from a trace file without having to depend on STS.
#

def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    @classmethod
    def _names(cls): # returns dict: ordinal -> string
      return reverse
    enums['_names'] = _names
    @classmethod
    def _ordinals(cls): # returns dict: string -> ordinal
      # filter _names, _ordinals
      return {k: v for k, v in enums.items() if not k.startswith('_')}
    enums['_ordinals'] = _ordinals
    return type('Enum', (), enums)
 
EventType = enum('HbPacketHandle',
                 'HbPacketSend',
                 'HbMessageHandle',
                 'HbMessageSend', 
                 'HbHostHandle', 
                 'HbHostSend', 
                 'HbControllerHandle', 
                 'HbControllerSend',
                 'HbAsyncFlowExpiry',
                 )

OpType = enum('TraceSwitchFlowTableRead',
              'TraceSwitchFlowTableWrite',
              'TraceSwitchBufferPut', 
              'TraceSwitchBufferGet', 
              )

# Sanity check! This is a mapping of all predecessor types that make sense.
predecessor_types = {EventType.HbAsyncFlowExpiry:  [EventType.HbMessageSend,
                                                    ],
                     EventType.HbPacketHandle:     [EventType.HbPacketSend,
                                                    EventType.HbHostSend,
                                                   ],
                     EventType.HbPacketSend:       [EventType.HbPacketHandle,
                                                    EventType.HbMessageHandle,
                                                   ],
                     EventType.HbMessageHandle:    [EventType.HbMessageHandle,
                                                    EventType.HbControllerSend,
                                                    EventType.HbPacketHandle, # buffer put -> buffer get!
                                                    EventType.HbMessageSend, # merged controller edges
                                                   ],
                     EventType.HbMessageSend:      [EventType.HbAsyncFlowExpiry,
                                                    EventType.HbPacketHandle,
                                                    EventType.HbMessageHandle,
                                                   ], 
                     EventType.HbHostHandle:       [EventType.HbPacketSend], 
                     EventType.HbHostSend:         [EventType.HbHostHandle], 
                     EventType.HbControllerHandle: [EventType.HbMessageSend], 
                     EventType.HbControllerSend:   [EventType.HbControllerHandle],
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
  
  
  # TODO(jm): make verbose a config option
  def detect_races(self, event=None, verbose=False):
    """
    Detect all races that involve event.
    Detect all races for all events if event is None.
    """
    self.read_operations = []
    self.write_operations = []
    
    for i in self.graph.events:
      if hasattr(i, 'operations'):
        for k in i.operations:
          if k.type == OpType.TraceSwitchFlowTableWrite:
            assert hasattr(k, 'flow_table')
            assert hasattr(k, 'flow_mod')
            dbg_fm = decode_flow_mod(k.flow_mod)
            dbg_str = "Write: "+str("None" if dbg_fm is None else ofp_flow_mod_command_to_str(dbg_fm.command) + " => " +TableEntry.from_flow_mod(
                                        dbg_fm
                                        ).show())
            op = (i, k.flow_table, k.flow_mod, dbg_str)
            self.write_operations.append(op)
          elif k.type == OpType.TraceSwitchFlowTableRead:
            assert hasattr(k, 'flow_table')
            assert hasattr(k, 'flow_mod')
            assert hasattr(i, 'packet')
            assert hasattr(i, 'in_port')
#             dbg_table = decode_flow_table(k.flow_table)
            dbg_fm_retval = decode_flow_mod(k.flow_mod)
            dbg_packet = decode_packet(i.packet)
            dbg_m_pkt = ofp_match.from_packet(dbg_packet, i.in_port)
            
            dbg_str = "Read rule: "+str("None" if dbg_fm_retval is None else TableEntry.from_flow_mod(dbg_fm_retval).show()
                                        ) + "\n| For packet: " + str(dbg_m_pkt)
            op = (i, k.flow_table, k.flow_mod, i.packet, i.in_port, dbg_str)
            self.read_operations.append(op)
    
    
    if verbose:
      print "Total write operations: {}".format(len(self.write_operations))
      print "Total read operations: {}".format(len(self.read_operations))
    
    self.races_harmful = []
    self.races_commute = []
    self.racing_events = set()
    self.racing_events_harmful = set()
    self.total_filtered = 0
    
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
      print "| {:>4}: {:28} (read) |".format(ev[0].eid, EventType._names()[ev[0].type])
    for ev in self.write_operations:
      print "| {:>4}: {:27} (write) |".format(ev[0].eid, EventType._names()[ev[0].type])
    print "| Total operations:      {:<18} |".format(self.total_operations)
    print "|-------------------------------------------|"
    print "| Total commuting races: {:<18} |".format(self.total_commute)
    print "| Total harmful races:   {:<18} |".format(self.total_harmful)
    print "| Total filtered races:  {:<18} |".format(self.total_filtered)
    print "+-------------------------------------------+"
    
class HappensBeforeGraph(object):
 
  def __init__(self, results_dir=None):
    self.results_dir = results_dir
    
    self.events = []
    self.events_by_id = dict()
    self.pruned_events = set()
    
    self.predecessors = defaultdict(set)
    self.successors = defaultdict(set)
    
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
                            lambda x: (x.type == EventType.HbMessageHandle and
                                       hasattr(x, 'msg_type_str') and 
                                       x.msg_type_str == "OFPT_FLOW_MOD" and
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
    self.predecessors[after].add(before)
    self.successors[before].add(after)
    
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
    if event.type == EventType.HbMessageHandle:
      if event.msg_type_str == "OFPT_BARRIER_REQUEST":
        for other in self.events_before_next_barrier[event.dpid]:
          self._add_edge(other, event)
        del self.events_before_next_barrier[event.dpid]
      else:
        self.events_before_next_barrier[event.dpid].append(event)
        
  def _rule_04_barrier_post(self, event):
    if event.type == EventType.HbMessageHandle:
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
    if event.type == EventType.HbMessageHandle and event.msg_type_str == "OFPT_FLOW_REMOVED":
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
    if len(line) > 1 and not line.startswith('#'):
      
      def lists_to_tuples(dct):
        '''
        Convert all lists to tuples so that the resulting objects are 
        hashable later on.
        '''
        for k,v in dct.copy().iteritems():
          if isinstance(v, list):
            dct[k] = tuple(v)
        return dct
      
      event_json = json.loads(line, object_hook=lists_to_tuples)
      event_typestr = event_json['type']
      
      assert event_typestr in EventType._ordinals()
      event_json['typestr'] = event_typestr
      event_json['type'] = EventType._ordinals()[event_typestr]
      if 'msg_type' in event_json:
        msg_type_str = event_json['msg_type']
        event_json['msg_type_str'] = msg_type_str
        event_json['msg_type'] = ofp_type_rev_map[msg_type_str]
        
      if 'operations' in event_json:
        ops = []
        for i in event_json['operations']:
          op_json = json.loads(i, object_hook=lists_to_tuples)
          op_typestr = op_json['type']
          assert op_typestr in OpType._ordinals()
          op_json['typestr'] = op_typestr
          op_json['type'] = OpType._ordinals()[op_typestr]
          
          op = namedtuple('Op', op_json)(**op_json)
          ops.append(op)
#           print str(event_json['id']) + ': ' + event_typestr + ' -> ' + op_typestr
        event_json['operations'] = tuple(ops)
        
      event = namedtuple('Event', event_json)(**event_json)
      self.add_event(event)
      
      if online_update:
        self.race_detector.detect_races(event)
        has_new_races = self.race_detector.total_races > 0
        self.race_detector.detect_races()
        if has_new_races:
          self.race_detector.print_races()
        self.store_graph()
  
  def add_event(self, event):
    self.events.append(event)
    assert event.eid not in self.events_by_id
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
    
    handlers = { EventType.HbAsyncFlowExpiry:   _handle_HbAsyncFlowExpiry,
                 EventType.HbPacketHandle:      _handle_HbPacketHandle,
                 EventType.HbPacketSend:        _handle_HbPacketSend,
                 EventType.HbMessageHandle:     _handle_HbMessageHandle,
                 EventType.HbMessageSend:       _handle_HbMessageSend,
                 EventType.HbHostHandle:        _handle_HbHostHandle,
                 EventType.HbHostSend:          _handle_HbHostSend,
                 EventType.HbControllerHandle:  _handle_HbControllerHandle,
                 EventType.HbControllerSend:    _handle_HbControllerSend,
                 }
    handlers.get(event.type, _handle_default)(event)
  
  def load_trace(self, filename):
    self.events = []
    self.events_by_id = dict()
    with open(filename) as f:
      for line in f:
        self.add_line(line, online_update=False)
    print "Read in " + str(len(self.events)) + " events." 
    self.events.sort(key=lambda i: i.eid)

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
            if x.type == OpType.TraceSwitchFlowTableWrite:
              optype = 'FlowTableWrite'
              shape = '[shape=box style="bold"]'
              break
            if x.type == OpType.TraceSwitchFlowTableRead:
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
                EventType._names()[i.type],
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
