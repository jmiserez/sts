#!/usr/bin/env python
import os
import sys
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__) + "/../../"), "pox"))

from pox.openflow.libopenflow_01 import *

import json
from collections import namedtuple, defaultdict, deque, OrderedDict
import itertools
import pprint

#
# Do not import any STS types! We would like to be able to run this offline
# from a trace file as well.
#

def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    @classmethod
    def keys(cls):
      return reverse
    enums['keys'] = keys
    @classmethod
    def values(cls):
      return enums
    enums['values'] = values
    return type('Enum', (), enums)
 
EventType = enum('HbPacketHandle',
                 'HbPacketSend',
                 'HbMessageHandle',
                 'HbMessageSend', 
                 'HbHostHandle', 
                 'HbHostSend', 
                 'HbControllerHandle', 
                 'HbControllerSend',
                 )

OpType = enum('TraceSwitchFlowTableRead',
              'TraceSwitchFlowTableWrite',
              'TraceSwitchFlowTableEntryExpiry',
              'TraceSwitchBufferPut', 
              'TraceSwitchBufferGet', 
              )

# sanity check:
predecessor_types = {EventType.HbPacketHandle:     [EventType.HbPacketSend,
                                                    EventType.HbHostSend,
                                                   ],
                     EventType.HbPacketSend:       [EventType.HbPacketHandle,
                                                    EventType.HbMessageHandle,
                                                   ],
                     EventType.HbMessageHandle:    [EventType.HbMessageHandle,
                                                    EventType.HbControllerSend,
                                                    EventType.HbPacketHandle, # buffer put -> buffer get!
                                                   ],
                     EventType.HbMessageSend:      [EventType.HbPacketHandle,
                                                    EventType.HbMessageHandle,
                                                   ], 
                     EventType.HbHostHandle:       [EventType.HbPacketSend], 
                     EventType.HbHostSend:         [EventType.HbHostHandle], 
                     EventType.HbControllerHandle: [EventType.HbMessageSend], 
                     EventType.HbControllerSend:   [EventType.HbControllerHandle],
                    }

def ofp_type_to_string(t):
  return ofp_type_rev_map.keys()[ofp_type_rev_map.values().index(t)]

class HappensBeforeGraph(object):
 
  def __init__(self, results_dir=None):
    self.results_dir = results_dir
    
    self.events = []
    self.events_by_id = dict()
    
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

  def _add_edge(self, before, after):
    if not before.type in predecessor_types[after.type]:
      print "Not a valid HB edge: "+before.typestr+" < "+after.typestr
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
    # TODO JM: This is not correct. Flow removed messages do not contain the exact same flowmod message as was installed.
    # TODO JM: Rather, we should match on (ofp_match, cookie, priority)
    #          and also only consider flow mods where the OFPFF_SEND_FLOW_REM flag was set
    if event.type == EventType.HbMessageHandle and event.msg_type_str == "OFPT_FLOW_REMOVED":
      search_key = (event.dpid, event.msg_flowmod)
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
  
  def add_line(self, line):
    if len(line) > 0 and not line.startswith('#'):
      
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
      
      assert event_typestr in EventType.values()
      event_json['typestr'] = event_typestr
      event_json['type'] = EventType.values()[event_typestr]
      if 'msg_type' in event_json:
        msg_type_str = event_json['msg_type']
        event_json['msg_type_str'] = msg_type_str
        event_json['msg_type'] = ofp_type_rev_map[msg_type_str]
        
      if 'operations' in event_json:
        ops = []
        for i in event_json['operations']:
          op_json = json.loads(i, object_hook=lists_to_tuples)
          op_typestr = op_json['type']
          assert op_typestr in OpType.values()
          op_json['typestr'] = op_typestr
          op_json['type'] = OpType.values()[op_typestr]
          op = namedtuple('Op', op_json)(**op_json)
          ops.append(op)
          print str(event_json['id']) + ': ' + event_typestr + ' -> ' + op_typestr
        event_json['operations'] = tuple(ops)
        
      event = namedtuple('Event', event_json)(**event_json)
      self.add_event(event)
  
  def add_event(self, event):
    self.events.append(event)
    assert event.id not in self.events_by_id
    self.events_by_id[event.id] = event
    self._add_to_lookup_tables(event)
    
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
    
    handlers = { EventType.HbPacketHandle:      _handle_HbPacketHandle,
                 EventType.HbPacketSend:        _handle_HbPacketSend,
                 EventType.HbMessageHandle:     _handle_HbMessageHandle,
                 EventType.HbMessageSend:       _handle_HbMessageSend,
                 EventType.HbHostHandle:        _handle_HbHostHandle,
                 EventType.HbHostSend:          _handle_HbHostSend,
                 EventType.HbControllerHandle:  _handle_HbControllerHandle,
                 EventType.HbControllerSend:    _handle_HbControllerSend,
                 }
    handlers.get(event.type, _handle_default)(event)
    
    self.store_graph()
    
  def detect_races(self):
    pass
  
  def load_trace(self, filename):
    self.events = []
    self.events_by_id = dict()
    with open(filename) as f:
      for line in f:
        self.add_line(line)
    print "Read in " + str(len(self.events)) + " events." 
    self.events.sort(key=lambda i: i.id)
    
  def store_graph(self, filename="hb.dot"):
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
    
    dot_lines = []
    edges = 0
    dot_lines.append("digraph G {\n");
    for i in self.events:
      optype = ""
      shape = ""
      if hasattr(i, 'operations'):
        for x in i.operations:
          if x.type == OpType.TraceSwitchFlowTableWrite:
            optype = "FlowTableWrite"
            shape = "[shape=box]"
            break
          if x.type == OpType.TraceSwitchFlowTableRead:
            optype = "FlowTableRead"
            shape = "[shape=box]"
            break
      if not hasattr(i, 'msg_type') or i.msg_type_str in interesting_msg_types:
        try:
          dot_lines.append('{0} [label="{0}\\n{1}\\n{2}\\n{3}"] {4};\n'.format(i.id,EventType.keys()[i.type],i.msg_type_str,optype,shape))
        except:
          dot_lines.append('{0} [label="{0}\\n{1}\\n{2}"]{3};\n'.format(i.id,EventType.keys()[i.type],optype,shape))
    for (k,v) in self.predecessors.iteritems():
      for i in v:
        if not hasattr(i, 'msg_type') or i.msg_type_str in interesting_msg_types:
          dot_lines.append('    {} -> {};\n'.format(i.id,k.id))
          edges += 1
    dot_lines.append("}\n");
#     pprint.pprint(dot_lines)
    with open(filename, 'w') as f:
      f.writelines(dot_lines)
#     print "Wrote out " + str(edges) + " edges."
  
class Main(object):
  
  def __init__(self,filename):
    self.filename = filename
    self.results_dir = os.path.dirname(os.path.realpath(self.filename))
    self.output_filename = self.results_dir + "/" + "hb.dot"
  
  def run(self):
    self.graph = HappensBeforeGraph(results_dir=self.results_dir)
    self.graph.load_trace(self.filename)
    self.graph.store_graph(self.output_filename)
    
if __name__ == '__main__':
  if len(sys.argv) < 2:
    print "Usage: read_trace.py <file>"
  else:
    print "Using file {0}".format(sys.argv[1])
    main = Main(sys.argv[1])
    main.run()
