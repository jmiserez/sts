from pox.openflow.software_switch import DpPacketOut, SoftwareSwitch
from pox.openflow.flow_table import FlowTableModification
from sts.openflow_buffer import PendingMessage, PendingReceive, PendingSend
from sts.topology import BufferedPatchPanel
from sts.util.convenience import base64_encode, base64_decode, base64_decode_openflow
from sts import openflow_buffer

from pox.lib.revent import Event, EventMixin
from pox.openflow.libopenflow_01 import ofp_phy_port
from sts.happensbefore.hb_events import *

import sys
import time
import logging
import json
from sts.entities.hosts import Host, HostInterface

class HappensBeforeLogger(EventMixin):
  '''
  Listens to and logs the following events:
  - Dataplane:
   * receive dataplane (switches)
   * receive dataplane (hosts)
   * send dataplane (hosts+switches)
  - Control plane:
   * receive Openflow msgs (controller to switch)
   * send Openflow msgs (switch to controller)
  - Switch:
   * internal processing
   '''
  
  _eventMixin_events = set([TraceDpPacketOutSwitch, TraceDpPacketOutHost])
  
  def __init__(self, patch_panel, event_listener_priority=100):
    self.output = None
    self.output_path = ""
    self.patch_panel = patch_panel
    self.event_listener_priority = event_listener_priority
    self.counter = 0
    self.log = logging.getLogger("hb_logger")
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
  
  def _get_connected_port(self, node, port):
    '''
    (Description copied from sts.topology.LinkTracker)
    Given a node and a port, return a tuple (node, port) that is directly
    connected to the port.
 
    This can be used in 2 ways
    - node is a Host type and port is a HostInterface type
    - node is a Switch type and port is a ofp_phy_port type.
    '''
    assert((isinstance(node, Host) and isinstance(port, HostInterface)) or
           (isinstance(node, SoftwareSwitch) and isinstance(port, ofp_phy_port)))
    try:
      (connected_node, connected_port) = self.patch_panel.get_connected_port(node, port)
    except ValueError:
      # this packet is going nowhere
      is_connected = False
      connected_node = None
      connected_port = None
      connected_is_switch = None
    else:
      is_connected = True
      connected_is_switch = isinstance(connected_node, SoftwareSwitch)
      if connected_is_switch:
        connected_node = connected_node.dpid
        if type(connected_port) != int:
          connected_port = connected_port.port_no
      else:
        connected_node = connected_node.hid
        connected_port = connected_port.port_no
    return (is_connected, connected_is_switch, connected_node, connected_port)
   
  
  def subscribe_to_DeferredOFConnection(self, connection):
    # TODO JM: store association connection -> (eventType,eid) for later removal
    connection.addListener(TraceOfMessageToController, self._handle_trace_event)
      
  def _subscribe_to_PatchPanel(self, patch_panel):
    
    def inject_register_packet(packet):
      reg_event = TracePacketRegister(packet)
      self._handle_trace_event(reg_event)
      return reg_event.id
     
    def inject_deregister_packet(reg_event_id, packet=None):
      self._handle_trace_event(TracePacketDeregister(reg_event_id,packet))
    
    def handle_TraceDpPacket(event):
      # topology information is missing, so we add it as a backup
      (is_connected, connected_is_switch, connected_node, connected_port) = self._get_connected_port(event._node, event._port)
      event.is_connected = is_connected
      event.connected_is_switch = connected_is_switch
      event.connected_node = connected_node
      event.connected_port = connected_port
      self._handle_trace_event(event)
    
    def handle_DpPacketOut_host(event):
      # packet registry information is missing, so we add it
      reg_event_id = inject_register_packet(event.packet)
      new_event = TraceDpPacketOutHost(event.node, event.port, event.packet, reg_event_id)
      handle_TraceDpPacket(new_event)
     
    def handle_DpPacketOut_switch(event):
      # packet registry information is missing, so we add it
      reg_event_id = inject_register_packet(event.packet)
      new_event = TraceDpPacketOutSwitch(event.node, event.port, event.packet, reg_event_id)
      handle_TraceDpPacket(new_event)
      
    def handle_DpPacketIn(event):
      # packet registry information is missing, so we add it
      packet = event.packet
      handle_TraceDpPacket(event)
      inject_deregister_packet(None, packet)
     
    for host in patch_panel.hosts:
      host.addListener(TracePacketRegister, self._handle_trace_event)
      host.addListener(TracePacketDeregister, self._handle_trace_event)
      host.addListener(DpPacketOut, handle_DpPacketOut_host, priority=self.event_listener_priority)
      host.addListener(TraceDpPacketInHost, handle_DpPacketIn)
    
    for s in patch_panel.switches:
      s.addListener(TracePacketRegister, self._handle_trace_event)
      s.addListener(TracePacketDeregister, self._handle_trace_event)
      s.addListener(DpPacketOut, handle_DpPacketOut_switch, priority=self.event_listener_priority)
      s.addListener(TraceDpPacketInSwitch, handle_DpPacketIn)
      s.addListener(TraceOfHandleFlowMod, self._handle_trace_event)
      s.addListener(TraceOfHandleFlowModFromBuffer, self._handle_trace_event)
      s.addListener(TraceOfHandlePacketOutFromRaw, self._handle_trace_event)
      s.addListener(TraceOfHandlePacketOutFromBuffer, self._handle_trace_event)
      s.addListener(OfHandleVendorHb, self._handle_trace_event)
      s.addListener(TraceOfGeneratePacketIn, self._handle_trace_event)                    
      s.addListener(TraceOfMessageFromController, self._handle_trace_event)                    
      s.addListener(TracePacketActionOutput, self._handle_trace_event)
      s.addListener(TracePacketActionResubmit, self._handle_trace_event)
      s.addListener(TracePacketActionModificationBegin, self._handle_trace_event)
      s.addListener(TracePacketBufferReadPacket, self._handle_trace_event)
      s.addListener(TracePacketBufferError, self._handle_trace_event)
      s.addListener(TracePacketBufferWritePacket, self._handle_trace_event)
      s.addListener(TracePacketBufferFlushPacket, self._handle_trace_event)
      s.addListener(TraceFlowTableMatch, self._handle_trace_event)
      s.addListener(TraceFlowTableTouch, self._handle_trace_event)
      s.addListener(TraceFlowTableModificationBefore, self._handle_trace_event)
      s.addListener(TraceFlowTableModificationAfter, self._handle_trace_event)
      s.addListener(TraceFlowTableModificationExpired, self._handle_trace_event)
      
  def _handle_trace_event(self, event):
    self.write(event.to_json())


