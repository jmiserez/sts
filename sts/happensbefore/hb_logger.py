from _collections import defaultdict
import logging

from pox.lib.revent.revent import EventMixin
from sts.happensbefore.hb_sts_events import *
from sts.happensbefore.hb_tags import ObjectRegistry
from sts.happensbefore.hb_trace_events import *

# from pox.openflow.software_switch import DpPacketOut, SoftwareSwitch
# from pox.openflow.flow_table import FlowTableModification
# from sts.openflow_buffer import PendingMessage, PendingReceive, PendingSend
# from sts.topology import BufferedPatchPanel
# from sts.util.convenience import base64_encode, base64_decode, base64_decode_openflow
# from sts import openflow_buffer
# 
# from pox.lib.revent import Event, EventMixin
# from pox.openflow.libopenflow_01 import ofp_phy_port
# from sts.happensbefore.hb_trace_events import *
# 
# from sts.entities.hosts import Host, HostInterface
# 
# from pox.lib.util import assert_type, dpidToStr
# from pox.lib.revent import Event, EventMixin
# from pox.lib.packet import *
# from pox.openflow.software_switch import DpPacketOut
# from pox.openflow.libopenflow_01 import *
# from pox.lib.addresses import IPAddr
# 
# from sts.util.convenience import object_fullname
# from sts.util.convenience import class_fullname
# from sts.util.convenience import load_class
# from sts.util.convenience import get_json_attr
# 
# import sys
# import time
# import logging
# import json
# import base64
# import collections
# import itertools
# from functools import partial
# from __builtin__ import list
# from collections import OrderedDict, defaultdict


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
    
    # State
    self.pids = ObjectRegistry() # packet obj -> pid
    self.mids = ObjectRegistry() # message obj -> mid
    self.curr_switch_event = dict() # dpid -> event
    self.curr_host_event = dict() # hid -> event
    self.queued_switch_events = defaultdict(list)
    self.queued_host_events = defaultdict(list)
    self.pending_packet_update = dict() # dpid -> packet
    
    self._subscribe_to_PatchPanel(patch_panel)


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
  
  def _handle_no_exceptions(self, event):
    """ Handle event, catch exceptions before they go back to STS/POX
    """
    event_handlers = {
        HostPacketHandleBegin: self.handle_host_ph_begin,
        HostPacketHandleEnd: self.handle_host_ph_end,
        HostPacketSend: self.handle_host_ps,
        SwitchPacketHandleBegin: self.handle_switch_ph_begin,
        SwitchPacketHandleEnd: self.handle_switch_ph_end,
        SwitchMessageHandleBegin: self.handle_switch_mh_begin,
        SwitchMessageHandleEnd: self.handle_switch_mh_end,
        SwitchMessageSend: self.handle_switch_ms,
        SwitchPacketSend: self.handle_switch_ps,
        SwitchFlowTableRead: self.handle_switch_read,
        SwitchFlowTableWrite: self.handle_switch_write,
        SwitchFlowTableRuleExpired: self.handle_switch_expiry,
        SwitchBufferPut: self.handle_switch_put,
        SwitchBufferGet: self.handle_switch_get,
        SwitchPacketUpdateBegin: self.handle_switch_pu_begin,
        SwitchPacketUpdateEnd: self.handle_switch_pu_end
    }

    handler = None
    if type(event) in event_handlers:
      handler = event_handlers[type(event)]
    try:
#       handler(event) # TODO JM: enable when fixed
        pass
    except Exception as e:
      self.log.error(e)
  
  def subscribe_to_DeferredOFConnection(self, connection):
    connection.addListener(SwitchMessageSend, self._handle_no_exceptions)
      
  def _subscribe_to_PatchPanel(self, patch_panel):
    for host in patch_panel.hosts:
      host.addListener(HostPacketHandleBegin, self._handle_no_exceptions)
      host.addListener(HostPacketHandleEnd, self._handle_no_exceptions)
      host.addListener(HostPacketSend, self._handle_no_exceptions)
    
    for s in patch_panel.switches:
      s.addListener(SwitchPacketHandleBegin, self._handle_no_exceptions)
      s.addListener(SwitchPacketHandleEnd, self._handle_no_exceptions)
      s.addListener(SwitchMessageHandleBegin, self._handle_no_exceptions)
      s.addListener(SwitchMessageHandleEnd, self._handle_no_exceptions)
      s.addListener(SwitchPacketSend, self._handle_no_exceptions)
      s.addListener(SwitchFlowTableRead, self._handle_no_exceptions)
      s.addListener(SwitchFlowTableWrite, self._handle_no_exceptions)
      s.addListener(SwitchFlowTableRuleExpired, self._handle_no_exceptions)
      s.addListener(SwitchBufferPut, self._handle_no_exceptions)
      s.addListener(SwitchBufferGet, self._handle_no_exceptions)
      s.addListener(SwitchPacketUpdateBegin, self._handle_no_exceptions)
      s.addListener(SwitchPacketUpdateEnd, self._handle_no_exceptions)
  
  
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
    pid_in = self.pids.get_tag(event.packet)
    pid_out = self.pids.new_tag(event.packet)
#     mid
#     self.curr_switch_event[event.dpid] = PacketHandle(event.dpid, pid_in, pid_out, event.packet)
  def handle_switch_ph_end(self, event):
#     self.end_switch_event(event)
    pass
  def handle_switch_mh_begin(self, event):
    assert len(self.queued_switch_events[event.dpid]) == 0
#     mid_in = None
#     mid_out = None
#     msg_type = event.
    
#     pid_in = self.pids.get_tag(event.packet)
#     pid_out = self.pids.new_tag(event.packet)
#     self.curr_switch_event[event.dpid] = MessageHandle(event.dpid, pid_in, pid_out, event.packet)
    pass
  def handle_switch_mh_end(self, event):
#     self.end_switch_event(event)
    pass
  def handle_switch_ms(self, event):
    pass
  def handle_switch_ps(self, event):
    pid_in = self.curr_switch_event[event.dpid].pid_out
    pid_out = self.pids.new_tag(event.packet)
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
    pid_in = self.pids.get_tag(event.packet)
    pid_out = self.pids.new_tag(event.packet)
    
  def handle_switch_get(self, event):
    pid_in = self.pids.get_tag(event.packet)
    pid_out = self.pids.new_tag(event.packet)
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
  


