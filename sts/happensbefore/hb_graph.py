#!/usr/bin/env python
import os
import sys
from curses.ascii import ctrl
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__) + "/../../"), "pox"))

from pox.openflow.libopenflow_01 import *
from pox.openflow.flow_table import FlowTable, TableEntry, SwitchFlowTable
from pox.openflow.software_switch import OFConnection

import json
from collections import namedtuple, defaultdict, deque, OrderedDict
import itertools
import pprint
import base64

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
                 )

OpType = enum('TraceSwitchFlowTableRead',
              'TraceSwitchFlowTableWrite',
              'TraceSwitchFlowTableEntryExpiry',
              'TraceSwitchBufferPut', 
              'TraceSwitchBufferGet', 
              )

# Sanity check! This is a mapping of all predecessor types that make sense.
predecessor_types = {EventType.HbPacketHandle:     [EventType.HbPacketSend,
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

class RaceDetector(object):
  
  def __init__(self, graph):
    self.graph = graph
    
    self.read_operations = []
    self.write_operations = []
    self.races_harmful = []
    self.races_commute = []
    self.total_operations = 0
    self.total_harmful = 0
    self.total_commute = 0
    self.total_races = 0
  
  @classmethod
  def decode_flow_mod(cls, data):
    bits = base64.b64decode(data)
    fm = ofp_flow_mod()
    fm.unpack(bits)
    return fm
  
  @classmethod
  def decode_packet(cls, data):
    bits = base64.b64decode(data)
    p = ethernet()
    p.unpack(bits)
    return p
  
  @classmethod
  def decode_flow_table(cls, data):
    table = SwitchFlowTable()
    for row in data:
      flow_mod = RaceDetector.decode_flow_mod(row)
      entry = TableEntry.from_flow_mod(flow_mod)
      table.add_entry(entry)
    return table
  
  @classmethod
  def compare_flow_table(cls, table, other):
    fm1 = []
    for i in table.table:
      fm1.append(i.to_flow_mod())
    fm2 = []
    for i in other.table:
      fm2.append(i.to_flow_mod())
      
    for i in fm1:
      if i not in fm2:
        return False
    for i in fm2:
      if i not in fm1:
        return False
    return True
  
  @classmethod
  def read_flow_table(cls, table, packet, in_port):
    p = RaceDetector.decode_packet(packet)
    return table.entry_for_packet(p, in_port)
  
  @classmethod
  def write_flow_table(cls, table, flow_mod):
    fm = RaceDetector.decode_flow_mod(flow_mod)
    return table.process_flow_mod(fm)

  def is_reachable(self, source, target):
    parents = self.graph.predecessors[source]
    if target in parents:
      return True
    for p in parents:
      if self.is_reachable(p, target):
        return True 
    return False
  
  def is_ordered(self, event, other):
    older = event if event.id < other.id else other
    newer = event if event.id > other.id else other
    if self.is_reachable(newer, older):
      return True
    if self.is_reachable(older, newer): # need to check due to async controller instrumentation
      return True
    return False
  
  def detect_races(self, event=None):
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
            op = (i, k.flow_table, k.flow_mod)
            self.write_operations.append(op)
          elif k.type == OpType.TraceSwitchFlowTableRead:
            assert hasattr(k, 'flow_table')
            assert hasattr(i, 'packet')
            assert hasattr(i, 'in_port')
            op = (i, k.flow_table, i.packet, i.in_port)
            self.read_operations.append(op)
    
    self.races_harmful = []
    self.races_commute = []
    
    # write <-> write
    for i, k in itertools.combinations(self.write_operations,2):
      i_event, i_flow_table, i_flow_mod = i
      k_event, k_flow_table, k_flow_mod = k
      if (i_event != k_event and
          (event is None or event == i_event or event == k_event) and
          i_event.dpid == k_event.dpid and
          not self.is_ordered(i_event, k_event)):
        ik_table = self.decode_flow_table(i_flow_table)
        self.write_flow_table(ik_table, i_flow_mod)
        self.write_flow_table(ik_table, k_flow_mod)
        
        ki_table = self.decode_flow_table(k_flow_table)
        self.write_flow_table(ki_table, k_flow_mod)
        self.write_flow_table(ki_table, i_flow_mod)
        
        if self.compare_flow_table(ik_table, ki_table):
          self.races_commute.append(('w/w',i_event,k_event))
        else:
          self.races_harmful.append(('w/w',i_event,k_event))
    
    # read <-> write
    for i in self.read_operations:
      for k in self.write_operations:
        i_event, i_flow_table, i_packet, i_in_port = i
        k_event, k_flow_table, k_flow_mod = k
        if (i_event != k_event and
            (event is None or event == i_event or event == k_event) and
            i_event.dpid == k_event.dpid and
            not self.is_ordered(i_event, k_event)):
          ik_table = self.decode_flow_table(i_flow_table)
          ik_retval = self.read_flow_table(ik_table, i_packet, i_in_port)
          self.write_flow_table(ik_table, k_flow_mod)
          
          ki_table = self.decode_flow_table(k_flow_table)
          self.write_flow_table(ki_table, k_flow_mod)
          ki_retval = self.read_flow_table(ki_table, i_packet, i_in_port)
          
          ik_fm = None if ik_retval is None else ik_retval.to_flow_mod()
          ki_fm = None if ki_retval is None else ki_retval.to_flow_mod()
          
          if (ik_fm == ki_fm and self.compare_flow_table(ik_table, ki_table)):
            self.races_commute.append(('r/w',i_event,k_event))
          else:
            self.races_harmful.append(('r/w',i_event,k_event))
    
    self.total_operations = len(self.write_operations) + len(self.read_operations)
    self.total_harmful = len(self.races_harmful)
    self.total_commute = len(self.races_commute)
    self.total_races = self.total_harmful + self.total_commute
            
  def print_races(self):
    print "+-------------------------------------------+"
    for ev in self.read_operations:
      print "| {:>4}: {:28} (read) |".format(ev[0].id, EventType._names()[ev[0].type])
    for ev in self.write_operations:
      print "| {:>4}: {:27} (write) |".format(ev[0].id, EventType._names()[ev[0].type])
    print "| Total operations:      {:<18} |".format(self.total_operations)
    print "|-------------------------------------------|"
    for race in self.races_commute:
      print "| Commuting ({}):     {:>4} <---> {:>4}      |".format(race[0], race[1].id, race[2].id)
    for race in self.races_harmful:
      print "| Harmful   ({}):     {:>4} >-!-< {:>4}      |".format(race[0], race[1].id, race[2].id)
    print "|-------------------------------------------|"
    print "| Total commuting races: {:<18} |".format(self.total_races)
    print "| Total harmful races:   {:<18} |".format(self.total_harmful)
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
    # TODO(jm): This is not correct. Flow removed messages do not contain the exact same flowmod message as was installed.
    # TODO(jm): Rather, we should match on (ofp_match, cookie, priority)
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
  
  def _add_transitive_edges(self, event):
    """
    Add transitive edges: A->x->B will add edge A->B
    """
    out_events = set(self.successors[event])
    in_events = set(self.predecessors[event])
    
    for in_evt in in_events:
      for out_evt in out_events:
        self._add_edge(in_evt, out_evt, sanity_check=False)
        
  def add_line(self, line):
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
  
  def add_event(self, event, prune_graph=True, store_graph=True, detect_races=True):
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
    
    if detect_races:
      self.race_detector.detect_races(event)
      if self.race_detector.total_races > 0:
        self.race_detector.detect_races()
        self.race_detector.print_races()
    
    if store_graph:
      self.store_graph()
  
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
    
    prunable_types = [
                      EventType.HbPacketSend,
                      EventType.HbHostHandle,
                      EventType.HbHostSend,
                      EventType.HbControllerHandle,
                      EventType.HbControllerSend,
                     ]
    pruned_events = []
    for i in self.events:
      if i.type in prunable_types:
        self._add_transitive_edges(i)
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
        if not hasattr(i, 'msg_type') or i.msg_type_str in interesting_msg_types:
          try:
            dot_lines.append('{0} [label="{0}\\n{1}\\n{2}\\n{3}\\n{4}"] {5};\n'.format(i.id,"" if not hasattr(i, 'dpid') else i.dpid,EventType._names()[i.type],i.msg_type_str,optype,shape))
          except:
            dot_lines.append('{0} [label="{0}\\n{1}\\n{2}\\n{3}"]{4};\n'.format(i.id,"" if not hasattr(i, 'dpid') else i.dpid,EventType._names()[i.type],optype,shape))
    for (k,v) in self.predecessors.iteritems():
      if k not in pruned_events:
        for i in v:
          if i not in pruned_events and (not hasattr(i, 'msg_type') or i.msg_type_str in interesting_msg_types):
            dot_lines.append('    {} -> {};\n'.format(i.id,k.id))
    dot_lines.append('edge[constraint=false arrowhead="none"];\n')
    for race in self.race_detector.races_commute:
      dot_lines.append('    {1} -> {2} [style="dotted"];\n'.format(race[0], race[1].id, race[2].id))
    for race in self.race_detector.races_harmful:
      dot_lines.append('    {1} -> {2} [style="bold"];\n'.format(race[0], race[1].id, race[2].id))
    dot_lines.append("}\n");
    with open(filename, 'w') as f:
      f.writelines(dot_lines)
  
class Main(object):
  
  def __init__(self,filename):
    self.filename = filename
    self.results_dir = os.path.dirname(os.path.realpath(self.filename))
    self.output_filename = self.results_dir + "/" + "hb.dot"
  
  def run(self):
    self.graph = HappensBeforeGraph(results_dir=self.results_dir)
    self.graph.load_trace(self.filename)
    self.graph.race_detector.detect_races()
    self.graph.race_detector.print_races()
    self.graph.store_graph(self.output_filename)
    
if __name__ == '__main__':
  if len(sys.argv) < 2:
    print "Usage: read_trace.py <file>"
  else:
    print "Using file {0}".format(sys.argv[1])
    main = Main(sys.argv[1])
    main.run()
