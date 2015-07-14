#!/usr/bin/env python
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../../pox"))
from pox.openflow.libopenflow_01 import *
from pox.openflow.flow_table import FlowTable, TableEntry, SwitchFlowTable
from pox.openflow.software_switch import OFConnection

import json
from collections import namedtuple, defaultdict, deque, OrderedDict
import itertools
import pprint
import base64
from copy import copy

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

def ofp_type_to_string(t):
  return ofp_type_rev_map.keys()[ofp_type_rev_map.values().index(t)]

def ofp_flow_mod_command_to_string(t):
  return ofp_flow_mod_command_rev_map.keys()[ofp_flow_mod_command_rev_map.values().index(t)]

class CommutativityChecker(object):
  
  # TODO(jm): make use_comm_spec a config option
  def __init__(self, use_comm_spec=True):
    self.use_comm_spec = use_comm_spec # Use commutativity spec if True
    
  @classmethod
  def decode_flow_mod(cls, data):
    if data is None:
      return None
    bits = base64.b64decode(data)
    fm = ofp_flow_mod()
    fm.unpack(bits) # NOTE: unpack IS in-situ for ofp_flow_mod() type
    return fm
  
  @classmethod
  def decode_packet(cls, data):
    bits = base64.b64decode(data)
    p = ethernet()
    p = p.unpack(bits) # NOTE: unpack IS NOT in-situ for ethernet() type
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
      
    # TODO(jm): This could be improved by using anewer version of POX, where flow table entries are always in priority order. Then only one pass would be necessary.
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
  
  def is_flowmod_subset(self,e1,e2,strict=False):
    """
    Check if flow mod e1 is a subset of flow mod e2, with different semantics
    if the strict flag is True.
    """
    if strict:
      return e1.match == e2.match and e1.priority == e2.priority
    else:
      return e2.match.matches_with_wildcards(e1.match)
    
  def is_match_subset(self, m1, m2):
    """
    Check if match m1 is a subset of flow mod m2.
    """
    return m2.matches_with_wildcards(m1)
  
  def is_match_intersection_nonempty(self, m1, m2):
    """
    Check if there is a packet that can match both matches at the same time.
    
    This is implemented as described in "Header Space Analysis: Static 
    Checking for Networks", http://dl.acm.org/citation.cfm?id=2228298.2228311
    
    "For two headers to have a non-empty intersection, both headers must have 
    the same bit value at every position that is not a wildcard.
    
    Note: This is not currently supported by any version of POX, see the 
          Github issue here for updates on the implementation: 
          
          https://github.com/noxrepo/pox/issues/142

    """
    if isinstance(m1, ofp_flow_mod) and isinstance(m2, ofp_flow_mod):
      return m1.match.check_overlap(m2.match)
    if isinstance(m1, ofp_match) and isinstance(m2, ofp_match):
      return m1.check_overlap(m2)
    assert False
  
  def uses_outport(self, out_port, e):
    """
    Is out_port in any of the actions of e_actions?
    """
    if e.actions is not None:
      for a in e.actions:
        if hasattr(a, "type"):
          if a.type in (OFPAT_ENQUEUE, OFPAT_OUTPUT):
            if hasattr(a, "port"):
              if a.port == out_port:
                return True
    return False
      
  
  def deletes(self, edel, e, strict=False):
    """
    Does edel delete e?
    
    Note: If e is None then the answer is always False.
    
    DELETE and DELETE STRICT commands can be optionally filtered by out-
    put port. If the out_port field contains a value other than OFPP_NONE, it intro-
    duces a constraint when matching. This constraint is that the rule must contain
    an output action directed at that port. This field is ignored by ADD, MODIFY,
    and MODIFY STRICT messages.
    """
    if e is None:
      return False # TODO(jm): add documentation for this special case
    if e.out_port != OFPP_NONE:
      has_outport = self.uses_outport(e.out_port, edel)
      return self.is_flowmod_subset(e, edel, strict) and has_outport
    else:
      return self.is_flowmod_subset(e, edel, strict)
    
  def is_add(self, fm):
    return fm.command == OFPFC_ADD
  def is_del(self, fm):
    return fm.command in (OFPFC_DELETE, OFPFC_DELETE_STRICT)
  def is_mod(self, fm):
    return fm.command in (OFPFC_MODIFY, OFPFC_MODIFY_STRICT)
  def is_strict(self, fm):
    return fm.command in (OFPFC_DELETE_STRICT, OFPFC_MODIFY_STRICT)
  def is_check_overlap_flag(self, fm):
    if (fm.flags & OFPFF_CHECK_OVERLAP):
      return True
    return False
  
  def nocommute_read_add(self, pkt, eread, eadd, read_id, add_id):
    if add_id < read_id:
      if eread is None:
        return False
      else:
        # only compare select fields, we don't want to compare statistics
        return (
        eread.priority == eadd.priority and
        eread.match == eadd.match and
        eread.actions == eadd.actions
        )
    else:
      if eread is None:
        return self.is_match_subset(pkt, eadd.match)
      else:
        return self.is_match_subset(pkt, eadd.match) and eread.priority <= eadd.priority and eread.actions != eadd.actions

  def nocommute_read_mod(self, pkt, eread, emod, read_id, mod_id):
    if mod_id < read_id:
      if eread is None:
        return False
      else:
        return self.is_flowmod_subset(eread, emod, self.is_strict(emod)) and eread.actions == emod.actions
    else:
      if eread is None:
        return False
      else:
        return self.is_match_subset(pkt, emod.match) and eread.actions != emod.actions
      
  def nocommute_read_del(self, pkt, eread, edel, read_id, del_id):
    if del_id < read_id:
      return self.is_match_subset(pkt, edel.match)
    else:
      return self.deletes(edel,eread,self.is_strict(edel)) # False if eread is None
    
  def nocommute_del_mod(self, edel, emod):
    if self.is_strict(emod):
      return self.deletes(edel, emod, True)
    else:
      return self.is_match_intersection_nonempty(edel.match, emod.match)
  
  def nocommute_add_del(self, eadd, edel):
    return (
            self.deletes(edel, eadd, self.is_strict(edel)) or
            (self.is_check_overlap_flag(eadd) and self.is_match_intersection_nonempty(eadd, edel))
            )
    
  def nocommute_mod_mod(self, e1, e2):
    strict1 = self.is_strict(e1)
    strict2 = self.is_strict(e2)
    if not strict1 and not strict2:
      return (self.is_match_intersection_nonempty(e1, e2) and
              e1.actions != e2.actions              
              )
    if strict1 and strict2:
      return (e1.match == e2.match and
              e1.priority == e2.priority and
              e1.actions != e2.actions
              )
    return ((self.is_flowmod_subset(e1, e2, strict2) or self.is_flowmod_subset(e2, e1, strict1)) and
            e1.actions != e2.actions
            )
  
  def nocommute_add_mod(self, eadd, emod):
    if not self.is_check_overlap_flag(eadd):
      return self.is_flowmod_subset(eadd, emod, self.is_strict(emod)) and eadd.actions != emod.actions
    else:
      return self.is_match_intersection_nonempty(eadd, emod)
  
  def nocommute_add_add(self, e1, e2, no_overlap1=False, no_overlap2=False):
    if no_overlap1 or no_overlap2:
      return self.is_match_intersection_empty(e1,e2) and e1.priority == e2.priority
    else:
      return e1.match == e2.match and e1.priority == e2.priority and e1.actions != e2.actions
    
  def check_comm_spec_ww(self, i, k):
    i_event, i_flow_table, i_flow_mod, i_dbg_str = i
    k_event, k_flow_table, k_flow_mod, k_dbg_str = k
    
    i_fm = CommutativityChecker.decode_flow_mod(i_flow_mod)
    i_fm.match.wildcards = i_fm.match._unwire_wildcards(i_fm.match.wildcards)
    i_fm.match.wildcards = i_fm.match._normalize_wildcards(i_fm.match.wildcards)
    
    k_fm = CommutativityChecker.decode_flow_mod(k_flow_mod)
    k_fm.match.wildcards = k_fm.match._unwire_wildcards(k_fm.match.wildcards)
    k_fm.match.wildcards = k_fm.match._normalize_wildcards(k_fm.match.wildcards)
    
    # del mod
    if self.is_del(i_fm) and self.is_mod(k_fm):
      return not self.nocommute_del_mod(i_fm, k_fm)
    if self.is_mod(i_fm) and self.is_del(k_fm):
      return not self.nocommute_del_mod(k_fm, i_fm)

    # add del
    if self.is_add(i_fm) and self.is_del(k_fm):
      return not self.nocommute_add_del(i_fm, k_fm)
    if self.is_del(i_fm) and self.is_add(k_fm):
      return not self.nocommute_add_del(k_fm, i_fm)
    
    # mod mod
    if self.is_mod(i_fm) and self.is_mod(k_fm):
      return not self.nocommute_mod_mod(i_fm, k_fm)
    
    # add mod
    if self.is_add(i_fm) and self.is_mod(k_fm):
      return not self.nocommute_add_mod(i_fm, k_fm)
    if self.is_mod(i_fm) and self.is_add(k_fm):
      return not self.nocommute_add_mod(k_fm, i_fm)
    
    # add add
    if self.is_add(i_fm) and self.is_add(k_fm):
      return not self.nocommute_add_add(i_fm, k_fm)
    
    print "Warning: Unhandled w/w commutativity case!"
    assert False
  
  def check_comm_spec_rw(self, i, k):
    i_event, i_flow_table, i_flow_mod, i_packet, i_in_port, i_dbg_str = i
    k_event, k_flow_table, k_flow_mod, k_dbg_str = k
    
    pkt_match = ofp_match.from_packet(self.decode_packet(i_packet), i_in_port)
    
    pkt_match.wildcards = pkt_match._unwire_wildcards(pkt_match.wildcards)
    pkt_match.wildcards = pkt_match._normalize_wildcards(pkt_match.wildcards)
    
    # may be None
    i_retval = CommutativityChecker.decode_flow_mod(i_flow_mod)
    if i_retval is not None:
      i_retval.match.wildcards = i_retval.match._unwire_wildcards(i_retval.match.wildcards)
      i_retval.match.wildcards = i_retval.match._normalize_wildcards(i_retval.match.wildcards)
    
    k_fm = CommutativityChecker.decode_flow_mod(k_flow_mod)
    k_fm.match.wildcards = k_fm.match._unwire_wildcards(k_fm.match.wildcards)
    k_fm.match.wildcards = k_fm.match._normalize_wildcards(k_fm.match.wildcards)
    
    # add
    if self.is_add(k_fm):
      return not self.nocommute_read_add(pkt_match, i_retval, k_fm, i_event.id, k_event.id)
    
    # mod
    if self.is_del(k_fm):
      return not self.nocommute_read_del(pkt_match, i_retval, k_fm, i_event.id, k_event.id)
    
    # del
      return not self.nocommute_read_mod(pkt_match, i_retval, k_fm, i_event.id, k_event.id)
  
    print "Warning: Unhandled r/w commutativity case!"
    assert False
      
  def check_commutativity_ww(self, i, k):
    i_event, i_flow_table, i_flow_mod, i_dbg_str = i
    k_event, k_flow_table, k_flow_mod, k_dbg_str = k
    
    if self.use_comm_spec:
      return self.check_comm_spec_ww(i,k)
    
    # TODO(jm): Add flag so that we can also check the simulation, and verify
    #           or compare the spec with the simulated/simple version.
    #           Note that in some cases the spec may be more accurate!
    
    ik_table = self.decode_flow_table(i_flow_table)
    self.write_flow_table(ik_table, i_flow_mod)
    self.write_flow_table(ik_table, k_flow_mod)
    
    ki_table = self.decode_flow_table(k_flow_table)
    self.write_flow_table(ki_table, k_flow_mod)
    self.write_flow_table(ki_table, i_flow_mod)
    
    if self.compare_flow_table(ik_table, ki_table):
      return True
    else:
      return False
  
  def check_commutativity_rw(self, i, k):
    i_event, i_flow_table, i_flow_mod, i_packet, i_in_port, i_dbg_str = i
    k_event, k_flow_table, k_flow_mod, k_dbg_str = k
    
    if self.use_comm_spec:
      return self.check_comm_spec_rw(i,k)
    
    if i_event.id < k_event.id: # read occurred first in trace
      ik_table = self.decode_flow_table(i_flow_table)
      ki_table = self.decode_flow_table(i_flow_table)
    else: # write occurred first in trace
      ik_table = self.decode_flow_table(k_flow_table)
      ki_table = self.decode_flow_table(k_flow_table)
    
    ik_retval = self.read_flow_table(ik_table, i_packet, i_in_port)
    self.write_flow_table(ik_table, k_flow_mod)
    
    self.write_flow_table(ki_table, k_flow_mod)
    ki_retval = self.read_flow_table(ki_table, i_packet, i_in_port)
    
    ik_fm = None if ik_retval is None else ik_retval.to_flow_mod()
    ki_fm = None if ki_retval is None else ki_retval.to_flow_mod()
    
    if (ik_fm == ki_fm and self.compare_flow_table(ik_table, ki_table)):
      return True
    else:
      return False

class RaceDetector(object):
  
  # TODO(jm): make filter_rw a config option
  def __init__(self, graph, filter_rw=True):
    self.graph = graph
    
    self.read_operations = []
    self.write_operations = []
    self.races_harmful = []
    self.races_commute = []
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
    older = event if event.id < other.id else other
    newer = event if event.id > other.id else other
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
      visited_ids.add(i.id)
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
            dbg_fm = CommutativityChecker.decode_flow_mod(k.flow_mod)
            dbg_str = "Write: "+str("None" if dbg_fm is None else ofp_flow_mod_command_to_string(dbg_fm.command) + " => " +TableEntry.from_flow_mod(
                                        dbg_fm
                                        ).show())
            op = (i, k.flow_table, k.flow_mod, dbg_str)
            self.write_operations.append(op)
          elif k.type == OpType.TraceSwitchFlowTableRead:
            assert hasattr(k, 'flow_table')
            assert hasattr(k, 'flow_mod')
            assert hasattr(i, 'packet')
            assert hasattr(i, 'in_port')
#             dbg_table = self.decode_flow_table(k.flow_table)
            dbg_fm_retval = CommutativityChecker.decode_flow_mod(k.flow_mod)
            dbg_packet = CommutativityChecker.decode_packet(i.packet)
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
    self.total_filtered = 0
    
    count = 0
    
    # write <-> write
    for i, k in itertools.combinations(self.write_operations,2):
      i_event, i_flow_table, i_flow_mod, i_dbg_str = i
      k_event, k_flow_table, k_flow_mod, k_dbg_str = k
      if verbose:
        count += 1
        print "Processing w/w combination {} ".format(count)
      if (i_event != k_event and
          (event is None or event == i_event or event == k_event) and
          i_event.dpid == k_event.dpid and
          not self.is_ordered(i_event, k_event)):   
        
        if self.commutativity_checker.check_commutativity_ww(i,k):
          self.races_commute.append(('w/w',i_event,k_event,i_dbg_str,k_dbg_str))
        else:
          self.races_harmful.append(('w/w',i_event,k_event,i_dbg_str,k_dbg_str))
    
    if verbose:
      print "Processed {} w/w races".format(self.total_operations)
    
    # read <-> write
    for i in self.read_operations:
      for k in self.write_operations:
        i_event, i_flow_table, i_flow_mod, i_packet, i_in_port, i_dbg_str = i
        k_event, k_flow_table, k_flow_mod, k_dbg_str = k
        if verbose:
          count += 1
          print "Processing r/w combination {} ".format(count)
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
    
    if verbose:
      print "Processed {} r/w races".format(self.total_operations)
    
    self.total_operations = len(self.write_operations) + len(self.read_operations)
    self.total_harmful = len(self.races_harmful)
    self.total_commute = len(self.races_commute)
    self.total_races = self.total_harmful + self.total_commute
            
  def print_races(self):
    for race in self.races_commute:
      print "+-------------------------------------------+"
      print "| Commuting ({}):     {:>4} <---> {:>4}      |".format(race[0], race[1].id, race[2].id)
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[1].id)
      print "+-------------------------------------------+"
      print "| " + race[3]
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[2].id)
      print "+-------------------------------------------+"
      print "| " + race[4]
      print "+-------------------------------------------+"
    for race in self.races_harmful:
      print "+-------------------------------------------+"
      print "| Harmful   ({}):     {:>4} >-!-< {:>4}      |".format(race[0], race[1].id, race[2].id)
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[1].id)
      print "+-------------------------------------------+"
      print "| " + race[3]
      print "+-------------------------------------------+"
      print "| op # {:<37}|".format(race[2].id)
      print "+-------------------------------------------+"
      print "| " + race[4]
      print "+-------------------------------------------+"
    print "+-------------------------------------------+"
    for ev in self.read_operations:
      print "| {:>4}: {:28} (read) |".format(ev[0].id, EventType._names()[ev[0].type])
    for ev in self.write_operations:
      print "| {:>4}: {:27} (write) |".format(ev[0].id, EventType._names()[ev[0].type])
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
      print "Warning: Not a valid HB edge: "+before.typestr+" ("+str(before.id)+") < "+after.typestr+" ("+str(after.id)+")"
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
    assert event.id not in self.events_by_id
    self.events_by_id[event.id] = event
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
    for k,v in transitive_predecessors.iteritems():
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
    import time
    self.graph = HappensBeforeGraph(results_dir=self.results_dir)
    t0 = time.time()    
    self.graph.load_trace(self.filename)
    t1 = time.time()
    self.graph.race_detector.detect_races(verbose=False)
    t2 = time.time()
    self.graph.race_detector.print_races()
    t3 = time.time()
    self.graph.store_graph(self.output_filename)
    t4 = time.time()
    
    print "Done. Time elapsed: "+(str(t4-t0))+"s"
    print "load_trace: "+(str(t1-t0))+"s"
    print "detect_races: "+(str(t2-t1))+"s"
    print "print_races: "+(str(t3-t2))+"s"
    print "store_graph: "+(str(t4-t3))+"s"
    
    
if __name__ == '__main__':
  if len(sys.argv) < 2:
    print "Usage: read_trace.py <file>"
  else:
    print "Using file {0}".format(sys.argv[1])
    main = Main(sys.argv[1])
    main.run()
