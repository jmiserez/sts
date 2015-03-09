from pox.openflow.software_switch import DpPacketOut, SoftwareSwitch
from pox.openflow.flow_table import FlowTableModification
from sts.openflow_buffer import PendingMessage, PendingReceive, PendingSend
from sts.topology import BufferedPatchPanel
from sts.util.convenience import base64_encode, base64_decode, base64_decode_openflow
from sts import openflow_buffer

from pox.lib.revent import Event, EventMixin
from pox.openflow.libopenflow_01 import ofp_phy_port
from sts.happensbefore.hb_events import *

from sts.entities.hosts import Host, HostInterface

from pox.lib.util import assert_type, dpidToStr
from pox.lib.revent import Event, EventMixin
from pox.lib.packet import *
from pox.openflow.software_switch import DpPacketOut
from pox.openflow.libopenflow_01 import *
from pox.lib.addresses import IPAddr

from sts.util.convenience import object_fullname
from sts.util.convenience import class_fullname
from sts.util.convenience import load_class
from sts.util.convenience import get_json_attr

import sys
import time
import logging
import json
import base64
import collections
import itertools
from functools import partial
from __builtin__ import list
from collections import OrderedDict, defaultdict

class TraceEvent(object):
  _ids = itertools.count(0)
  
  def __init__(self):
    Event.__init__(self)
    self.id = self._ids.next()
    self.type = self.__class__.__name__
      
  def to_json(self):
    """
    Serialize every field that exists, optionally using an encoding function.
    """  
    attrs = [ 'id', # int
              'type', # str
              'dpid',
              'hid',
              'cid',
              'mid_in',
              'mid_out',
              'pid_in',
              'pid_out',
              'msg_type',
              'msg_reason',
              'msg_xid',
              'in_port',
              'out_port',
              ('table_reads_writes', lambda xs: [x.to_json() for x in xs])
#               ('packet', lambda packet: base64.b64encode(packet.pack()).replace("\n", "")),
#               ('msg', lambda msg: base64.b64encode(msg.pack()).replace("\n", "")),
#               ('flow_mod', lambda flow_mod: base64.b64encode(flow_mod.pack()).replace("\n", "")),
#               ('flow_table', 
#                  lambda flow_table: [base64.b64encode(entry.to_flow_mod().pack()).replace("\n", "") for entry in flow_table.table]),
#               ('expired_flows',
#                  lambda expired_flows: [base64.b64encode(entry.to_flow_mod().pack()).replace("\n", "") for entry in expired_flows]),
#               ('matched_flow',
#                  lambda matched_flow: base64.b64encode(matched_flow.to_flow_mod().pack()).replace("\n", "")),
#               ('touched_flow',
#                  lambda touched_flow: base64.b64encode(touched_flow.to_flow_mod().pack()).replace("\n", "")),
#               'touched_flow_bytes',
#               ('touched_flow_now', lambda fp: repr(fp)), # str() is not precise for floating point numbers in Python < v3.2
#               ('action', lambda action: base64.b64encode(action.pack()).replace("\n", "")),
#               ('actions', 
#                  lambda actions: [base64.b64encode(action.pack()).replace("\n", "") for action in actions])
             ]
    json_dict = OrderedDict()
    for i in attrs:
      if isinstance(i, tuple):
        attr = i[0]
        fun = i[1]
        if hasattr(self, attr):
          json_dict[attr] = fun(getattr(self, attr))
      elif hasattr(self, i):
        json_dict[i] = getattr(self, i)
        
    return json.dumps(json_dict, sort_keys=False)

class PacketHandle(TraceEvent):
  def __init__(self, dpid, pid_in, pid_out, packet):
    self.dpid = dpid
    self.pid_in = pid_in
    self.pid_out = pid_out
    self.mid_out = None
    
    self.packet = packet
    
class PacketSend(TraceEvent):
  def __init__(self, dpid, pid_in, pid_out, packet):
    self.dpid = dpid
    self.pid_in = pid_in
    self.pid_out = pid_out
    
    self.packet = packet
      
class MessageHandle(TraceEvent):
  def __init__(self):
    self.dpid = None
    self.pid_in = None
    self.pid_out = None
    self.mid_in = None
    self.mid_out = None
    self.msg_type = None
    
class MessageSend(TraceEvent):
  def __init__(self):
    self.mid_in = None
    
class HostHandle(TraceEvent):
  def __init__(self):
    self.pid_in = None
    self.pid_out = None

class HostSend(TraceEvent):
  def __init__(self):
    self.pid_in = None
    self.pid_out = None

class HappensBeforeLogger(EventMixin):
  '''
  Listens to and logs the following events:
  - Data plane:
   * receive dataplane (switches)
   * receive dataplane (hosts)
   * send dataplane (hosts+switches)
  - Control plane:
   * receive Openflow msgs (controller to switch)
   * send Openflow msgs (switch to controller)
  - Switch:
   * internal processing
  
  Logs the following operations:
   * Flow table read
   * Flow table touch
   * Flow table modify
   '''
  
  def __init__(self, patch_panel, event_listener_priority=100):
    self.output = None
    self.output_path = ""
    self.patch_panel = patch_panel
    self.event_listener_priority = event_listener_priority
    self.log = logging.getLogger("hb_logger")
    self._subscribe_to_PatchPanel(patch_panel)
    
    # State
    self._pid_it = itertools.count(0)
    self._mid_it = itertools.count(0)
    self.pids = dict() # packet obj -> pid
    self.mids = dict() # message obj -> mid
    self.curr_switch_event = dict() # dpid -> event
    self.curr_host_event = dict() # hid -> event
    self.queued_switch_events = defaultdict(list)
    self.queued_host_events = defaultdict(list)
    self.pending_packet_update = dict() # dpid -> packet
    
  def _get_pid(self, packet):
    """ Get the pid for a packet or assign a new pid.
    """
    if packet in self.pids:
      return self.pids[packet]
    else:
      pid = self._pid_it.next()
      self.pids[packet] = pid
      return pid
    
  def _new_pid(self, packet):
    """ Assign a new pid for the packet.
    """
    if packet in self.pids:
      del self.pids[packet]
    return self._get_pid(packet)
  
    
  def open(self, results_dir=None, output_filename="hb_trace.json"):
    '''
    Start a trace
    '''
    if results_dir is not None:
      self.output_path = results_dir + "/" + output_filename
    else:
      raise ValueError("Default results_dir currently not supported")
    self.output = open(self.output_path, 'w')
    
  def close(self):
    '''
    End a trace
    '''
    # Flush the log
    self.output.close()
    # TODO JM: remove listeners for all connection objects.
  
  def debug(self,msg):
    print "HappensBeforeLogger debug {1}".format(str(msg))
    
  def write(self,msg):
    self.log.info(msg)
    if not self.output:
      raise Exception("Not opened -- call HappensBeforeLogger.open()")
    if not self.output.closed:
      self.output.write(str(msg) + '\n')
      self.output.flush() # TODO JM remove eventually
  
  def subscribe_to_DeferredOFConnection(self, connection):
    connection.addListener(SwitchMessageSend, self.handle_switch_ms)
      
  def _subscribe_to_PatchPanel(self, patch_panel):
    for host in patch_panel.hosts:
        host.addListener(HostPacketHandleBegin, self.handle_host_ph_begin)
        host.addListener(HostPacketHandleEnd, self.handle_host_ph_end)
        host.addListener(HostPacketSend, self.handle_host_ps)
    
    for s in patch_panel.switches:
      s.addListener(SwitchPacketHandleBegin, self.handle_switch_ph_begin)
      s.addListener(SwitchPacketHandleEnd, self.handle_switch_ph_end)
      s.addListener(SwitchMessageHandleBegin, self.handle_switch_mh_begin)
      s.addListener(SwitchMessageHandleEnd, self.handle_switch_mh_end)
      s.addListener(SwitchPacketSend, self.handle_switch_ps)
      s.addListener(SwitchFlowTableRead, self.handle_switch_read)
      s.addListener(SwitchFlowTableWrite, self.handle_switch_write)
      s.addListener(SwitchFlowTableRuleExpired, self.handle_switch_expiry)
      s.addListener(SwitchBufferPut, self.handle_switch_put)
      s.addListener(SwitchBufferGet, self.handle_switch_get)
      s.addListener(SwitchPacketUpdateBegin, self.handle_switch_pu_begin)
      s.addListener(SwitchPacketUpdateEnd, self.handle_switch_pu_end)
  
  
  
  def write_event_to_trace(self, event):
    #self.write(event.to_json())
    pass
    
  def end_switch_event(self,event):
    self.write_event_to_trace(self.curr_switch_event[event.dpid])
    self.curr_switch_event[event.dpid] = None
    for i in self.queued_switch_events[event.dpid]:
      self.write_event_to_trace(i)
    self.write_event_to_trace(event)
  def end_host_event(self, event):
    self.write_event_to_trace(self.curr_host_event[event.hid])
    self.curr_host_event[event.hid] = None
    for i in self.queued_host_events[event.hid]:
      self.write_event_to_trace(i)
    self.write_event_to_trace(event)
  
  def handle_switch_ph_begin(self, event):
    assert len(self.queued_switch_events[event.dpid]) == 0
    pid_in = self._get_pid(event.packet)
    pid_out = self._new_pid(event.packet)
    self.curr_switch_event[event.dpid] = PacketHandle(event.dpid, pid_in, pid_out, event.packet)
  def handle_switch_ph_end(self, event):
    self.end_host_event(event)
  def handle_switch_mh_begin(self, event):
    pass
  def handle_switch_mh_end(self, event):
    self.end_host_event(event)
  def handle_switch_ms(self, event):
    pass
  def handle_switch_ps(self, event):
    pid_in = self._get_pid(event.packet)
    pid_out = self._new_pid(event.packet)
    self.queued_switch_events[event.dpid].append(PacketSend(event.dpid, pid_in, pid_out, event.packet))
  def handle_switch_read(self, event):
    # TODO add to operations list
    pass
  def handle_switch_write(self, event):
    # TODO add to operations list
    pass
  def handle_switch_expiry(self, event):
    pass
  def handle_switch_put(self, event):
    pid_in = self._get_pid(event.packet)
    pid_out = self._new_pid(event.packet)
    
  def handle_switch_get(self, event):
    pid_in = self._get_pid(event.packet)
    pid_out = self._new_pid(event.packet)
    pass
  
  def handle_switch_pu_begin(self, event):
    assert event.packet in self.pids
    pid = self.pids[event.packet]
    del self.pids[event.packet]
    self.pending_packet_update[event.dpid] = pid
    
  def handle_switch_pu_end(self, event):
    self.pids[event.packet] = self.pending_packet_update[event.dpid] 
      
  def handle_host_ph_begin(self, event):
    pass
  def handle_host_ph_end(self, event):
    pass
  def handle_host_ps(self, event):
    pass
  


