from pox.openflow.software_switch import DpPacketOut
from pox.openflow.flow_table import FlowTableModification
from sts.openflow_buffer import PendingMessage, PendingReceive, PendingSend
from sts.topology import BufferedPatchPanel
from sts.util.convenience import base64_encode, base64_decode, base64_decode_openflow
from sts import openflow_buffer

from pox.lib.revent import Event, EventMixin
from sts.happensbefore.hb_events import *

import sys
import time
import logging
import json


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
  
  _eventMixin_events = set([TraceSwitchDpPacketOut, TraceHostDpPacketOut])
  
  def __init__(self, patch_panel, event_listener_priority=100):
    self.output = None
    self.output_path = ""
    self.patch_panel = patch_panel
    self.event_listener_priority = event_listener_priority
    self._subscribe_to_PatchPanel(patch_panel)
    self.counter = 0
    self.log = logging.getLogger("hb_logger")

    
  def open(self, results_dir=None, output_filename="hb.trace"):
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
      self.output.write(msg + '\n')
      self.output.flush() # TODO JM remove eventually
      
  def subscribe_to_DeferredOFConnection(self, connection):
    # TODO JM: store association connection -> (eventType,eid) for later removal
    connection.addListener(TraceOfMessageOut, self._handle_trace_event)
      
  def _subscribe_to_PatchPanel(self, patch_panel):
    
    def generate_TraceHostDpPacketOut(event):
      self._handle_trace_event(TraceHostDpPacketOut(event.node, event.port, event.packet))
    for host in patch_panel.hosts:
      host.addListener(DpPacketOut, generate_TraceHostDpPacketOut, priority=self.event_listener_priority)
      host.addListener(TraceHostDpPacketIn, self._handle_trace_event)
    
    def generate_TraceSwitchDpPacketOut(event):
      self._handle_trace_event(TraceSwitchDpPacketOut(event.node, event.port, event.packet))
    for s in patch_panel.switches:
      s.addListener(DpPacketOut, generate_TraceSwitchDpPacketOut, priority=self.event_listener_priority)
      s.addListener(TraceSwitchDpPacketIn, self._handle_trace_event)
      s.addListener(TraceOfMessageIn, self._handle_trace_event)                    
      s.addListener(TracePacketActionOutput, self._handle_trace_event)
      s.addListener(TracePacketActionResubmit, self._handle_trace_event)
      s.addListener(TracePacketActionModificationBegin, self._handle_trace_event)
      s.addListener(TracePacketActionModificationEnd, self._handle_trace_event)
      s.addListener(TracePacketBufferAllocate, self._handle_trace_event)
      s.addListener(TracePacketBufferFree, self._handle_trace_event)
      s.addListener(TraceFlowTableMatch, self._handle_trace_event)
      s.addListener(TraceFlowTableModificationBegin, self._handle_trace_event)
      s.addListener(TraceFlowTableModificationEnd, self._handle_trace_event)
      s.addListener(TraceFlowTableModificationExpired, self._handle_trace_event)
      
  def _handle_trace_event(self, event):
    self.counter += 1
    self.write(str(self.counter) + ': ' + str(type(event)) + ' => ' + str(serialize_trace_event(event)))


