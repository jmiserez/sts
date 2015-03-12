from _collections import defaultdict
import logging

from pox.lib.revent.revent import EventMixin
from sts.happensbefore.hb_sts_events import *
from sts.happensbefore.hb_tags import ObjectRegistry
from sts.happensbefore.hb_events import *
from pox.openflow.libopenflow_01 import *

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
  
  def _handle_dummy_ctl(self, event):
      print "XXXXX Dummy EVNET HANDLED: "
  
  def __init__(self, patch_panel, event_listener_priority=100):
    self.ignore_uninteresting_events = False
    
    self.output = None
    self.output_path = ""
    self.patch_panel = patch_panel
    self.event_listener_priority = event_listener_priority
    self.log = logging.getLogger("hb_logger")
    
    # State for linking of events
    self.pids = ObjectRegistry() # packet obj -> pid
    self.mids = ObjectRegistry() # message obj -> mid
    self.started_switch_event = dict() # dpid -> event
    self.started_host_event = dict() # hid -> event
    self.new_switch_events = defaultdict(list)
    self.new_host_events = defaultdict(list)
    self.pending_packet_update = dict() # dpid -> packet
    self.ignoring_switch_event = defaultdict(bool) # are we currently ignoring switch events
    
    self._subscribe_to_PatchPanel(patch_panel)
    
    
    
    from sts.util.procutils import DummyCtrlEvent
    from sts.util.procutils import prefixThreadEvents
    prefixThreadEvents.addListener(DummyCtrlEvent, self._handle_dummy_ctl)


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
    self.output = None
    # TODO JM: remove listeners for all connection objects.
  
  def write(self,msg):
    self.log.info(msg)
    if not self.output:
      raise Exception("Not opened -- call HappensBeforeLogger.open()")
    if not self.output.closed:
      self.output.write(str(msg) + '\n')
      self.output.flush() # TODO JM remove eventually
  
  def is_ignore_event(self, event):
    if self.ignore_uninteresting_events:
      if hasattr(event, 'dpid'):
        interesting_msg_types = [ofp_type_rev_map['OFPT_PACKET_IN'],
                                 ofp_type_rev_map['OFPT_FLOW_REMOVED'],
                                 ofp_type_rev_map['OFPT_PORT_STATUS'],
                                 ofp_type_rev_map['OFPT_PACKET_OUT'],
                                 ofp_type_rev_map['OFPT_FLOW_MOD'],
                                 ofp_type_rev_map['OFPT_PORT_MOD'],
                                 ofp_type_rev_map['OFPT_BARRIER_REQUEST'],
                                 ofp_type_rev_map['OFPT_BARRIER_REPLY'],
                                 ofp_type_rev_map['OFPT_HELLO'],
                                 ofp_type_rev_map['OFPT_VENDOR'],
                                 ]
         
        if isinstance(event, TraceSwitchMessageHandleBegin):
          if event.msg.header_type not in interesting_msg_types:
            self.ignoring_switch_event[event.dpid] = True
            return True
     
        if self.ignoring_switch_event[event.dpid]:
          if isinstance(event, TraceSwitchMessageHandleEnd):
            self.ignoring_switch_event[event.dpid] = False
            return True
             
        if isinstance(event, TraceSwitchMessageSend):
          if event.msg.header_type not in interesting_msg_types:
            return True
        return self.ignoring_switch_event[event.dpid]
      else:
        return False # never ignore Host events
    else:
      return False
    
  
  def handle_no_exceptions(self, event):
    """ Handle event, catch exceptions before they go back to STS/POX
    """
    try:
      if self.output is not None:
        if not self.is_ignore_event(event):
          event_handlers = {
              TraceHostPacketHandleBegin: self.handle_host_ph_begin,
              TraceHostPacketHandleEnd: self.handle_host_ph_end,
              TraceHostPacketSend: self.handle_host_ps,
              TraceSwitchPacketHandleBegin: self.handle_switch_ph_begin,
              TraceSwitchPacketHandleEnd: self.handle_switch_ph_end,
              TraceSwitchMessageHandleBegin: self.handle_switch_mh_begin,
              TraceSwitchMessageHandleEnd: self.handle_switch_mh_end,
              TraceSwitchMessageSend: self.handle_switch_ms,
              TraceSwitchPacketSend: self.handle_switch_ps,
              TraceSwitchFlowTableRead: self.handle_switch_table_read,
              TraceSwitchFlowTableWrite: self.handle_switch_table_write,
              TraceSwitchFlowTableEntryExpiry: self.handle_switch_table_entry_expiry,
              TraceSwitchBufferPut: self.handle_switch_buf_put,
              TraceSwitchBufferGet: self.handle_switch_buf_get,
              TraceSwitchPacketUpdateBegin: self.handle_switch_pu_begin,
              TraceSwitchPacketUpdateEnd: self.handle_switch_pu_end
          }
          handler = None
          if type(event) in event_handlers:
            handler = event_handlers[type(event)]
            handler(event)
    except Exception as e:
      # NOTE JM: do not remove, otherwise exceptions get swallowed by STS
      import traceback
      traceback.print_exc(file=sys.stdout)
  
  def subscribe_to_DeferredOFConnection(self, connection):
    connection.addListener(TraceSwitchMessageSend, self.handle_no_exceptions)
      
  def _subscribe_to_PatchPanel(self, patch_panel):
    for host in patch_panel.hosts:
      host.addListener(TraceHostPacketHandleBegin, self.handle_no_exceptions)
      host.addListener(TraceHostPacketHandleEnd, self.handle_no_exceptions)
      host.addListener(TraceHostPacketSend, self.handle_no_exceptions)
    
    for s in patch_panel.switches:
      s.addListener(TraceSwitchPacketHandleBegin, self.handle_no_exceptions)
      s.addListener(TraceSwitchPacketHandleEnd, self.handle_no_exceptions)
      s.addListener(TraceSwitchMessageHandleBegin, self.handle_no_exceptions)
      s.addListener(TraceSwitchMessageHandleEnd, self.handle_no_exceptions)
      s.addListener(TraceSwitchPacketSend, self.handle_no_exceptions)
      s.addListener(TraceSwitchFlowTableRead, self.handle_no_exceptions)
      s.addListener(TraceSwitchFlowTableWrite, self.handle_no_exceptions)
      s.addListener(TraceSwitchFlowTableEntryExpiry, self.handle_no_exceptions)
      s.addListener(TraceSwitchBufferPut, self.handle_no_exceptions)
      s.addListener(TraceSwitchBufferGet, self.handle_no_exceptions)
      s.addListener(TraceSwitchPacketUpdateBegin, self.handle_no_exceptions)
      s.addListener(TraceSwitchPacketUpdateEnd, self.handle_no_exceptions)
  
  
  def write_event_to_trace(self, event):
    self.write(event.to_json())
  
  #
  # Switch helper functions
  #
  
  def start_switch_event(self,dpid,event):
    for i in self.new_switch_events[dpid]:
      self.write_event_to_trace(i)
    del self.new_switch_events[dpid]
    assert event.dpid not in self.started_switch_event 
    
    self.started_switch_event[event.dpid] = event
  
  def finish_switch_event(self, dpid):
    assert dpid in self.started_switch_event
    
    self.write_event_to_trace(self.started_switch_event[dpid])
    del self.started_switch_event[dpid]
    for i in self.new_switch_events[dpid]:
      self.write_event_to_trace(i)
    del self.new_switch_events[dpid]
    
  def is_switch_event_started(self, dpid):
    return dpid in self.started_switch_event
  
  def add_operation_to_switch_event(self, event):
    if self.is_switch_event_started(event.dpid):
      self.started_switch_event[event.dpid].operations.append(event)
    else:
      # Ignore this operation, as there is no started switch event yet.
      self.log.info("Ignoring switch operation as there is no associated begin event.")

  def add_successor_to_switch_event(self, event, mid_in=None, pid_in=None):
    if self.is_switch_event_started(event.dpid):
      if mid_in is not None:
        self.started_switch_event[event.dpid].mid_out.append(mid_in) # link with latest event
      if pid_in is not None:
        self.started_switch_event[event.dpid].pid_out.append(pid_in) # link with latest event
      self.new_switch_events[event.dpid].append(event) # enqueue event to be output as soon as the end event is reached
    else:
      # Output this operation directly as we missed the preceding event.
      self.log.info("Writing switch event even though there was no associated begin event.")
      self.write_event_to_trace(event)

  #
  # Host helper functions
  #

  def start_host_event(self,hid,event):
    for i in self.new_host_events[hid]:
      self.write_event_to_trace(i)
    del self.new_host_events[hid]
    assert event.hid not in self.started_host_event 
    
    self.started_host_event[event.hid] = event
  def finish_host_event(self, hid):
    assert hid in self.started_host_event
    
    self.write_event_to_trace(self.started_host_event[hid])
    del self.started_host_event[hid]
    for i in self.new_host_events[hid]:
      self.write_event_to_trace(i)
    del self.new_host_events[hid]
    
  def is_host_event_started(self, hid):
    return hid in self.started_host_event
  
  def add_successor_to_host_event(self, event, pid_in=None):
    if self.is_host_event_started(event.hid):
      if pid_in is not None:
        self.started_host_event[event.hid].pid_out.append(pid_in) # link with latest event
      self.new_host_events[event.hid].append(event)
    else:
      # Output this operation directly as we missed the preceding event.
      self.log.info("Writing host event even though there was no associated begin event.")
      self.write_event_to_trace(event)
  
  #
  # Switch events
  #
  
  def handle_switch_ph_begin(self, event):
    pid_in = self.pids.get_tag(event.packet) # matches a pid_out as the Python object ids will be the same
    
    begin_event = HbPacketHandle(pid_in, dpid=event.dpid, packet=event.packet, in_port=event.in_port)
    self.start_switch_event(event.dpid, begin_event)
  
  def handle_switch_ph_end(self, event):
    self.finish_switch_event(event.dpid)
  
  def handle_switch_mh_begin(self, event):
      mid_in = self.mids.get_tag(event.msg) # filled in, but never matches a mid_out. This link will be filled in by controller instrumentation.
      msg_type = event.msg.header_type
      
      begin_event = HbMessageHandle(mid_in, msg_type, dpid=event.dpid, controller_id=event.controller_id, msg=event.msg)
      self.start_switch_event(event.dpid, begin_event)
  
  def handle_switch_mh_end(self, event):
    self.finish_switch_event(event.dpid)
  
  def handle_switch_ms(self, event):
    mid_in = self.mids.new_tag(event.msg) # tag changes here
    mid_out = self.mids.new_tag(event.msg) # filled in, but never matches a mid_in. This link will be filled in by controller instrumentation. 
    msg_type = event.msg.header_type
    
    # event.msg goes to the controller, and we cannot match it there. So we remove it from the ObjectRegistry.
    self.mids.remove_obj(event.msg)
    
    new_event = HbMessageSend(mid_in, mid_out, msg_type, dpid=event.dpid, controller_id=event.controller_id, msg=event.msg)   
    self.add_successor_to_switch_event(new_event, mid_in=mid_in)
  
  def handle_switch_ps(self, event):
    pid_in = self.pids.new_tag(event.packet) # tag changes here
    pid_out = self.pids.new_tag(event.packet) # tag changes here
    
    new_event = HbPacketSend(pid_in, pid_out, dpid=event.dpid, packet=event.packet, out_port=event.out_port)
    self.add_successor_to_switch_event(new_event, pid_in=pid_in)

  #
  # Switch operation events
  #

  def handle_switch_table_read(self, event):
    self.add_operation_to_switch_event(event)
    
  def handle_switch_table_write(self, event):
    self.add_operation_to_switch_event(event)
    
  def handle_switch_table_entry_expiry(self, event):
    self.add_operation_to_switch_event(event)
    
  def handle_switch_buf_put(self, event):
    if self.is_switch_event_started(event.dpid):
        assert isinstance(self.started_switch_event[event.dpid], HbPacketHandle)
        # the tag should still be the same, as no successor events should have been added yet
        assert self.pids.get_tag(event.packet) == self.started_switch_event[event.dpid].pid_in
        # generate pid_out for buffer write
        pid_out = self.pids.new_tag(event.packet) # tag changes here
        self.started_switch_event[event.dpid].pid_out.append(pid_out)
    self.add_operation_to_switch_event(event)
    
  def handle_switch_buf_get(self, event):
    if self.is_switch_event_started(event.dpid):
      assert isinstance(self.started_switch_event[event.dpid], HbMessageHandle)
      # update the pid_in of the current event using the packet from the buffer
      pid_in = self.pids.get_tag(event.packet)
      self.started_switch_event[event.dpid].pid_in = pid_in
    self.add_operation_to_switch_event(event)
  
  #
  # Switch bookkeeping operations
  #
  
  def handle_switch_pu_begin(self, event):
    """
    Mark an object in the ObjectRegistry for an update. This will keep the tags even if the Python object id (memory address) changes.
    """
    tag = self.pids.get_tag(event.packet)
    self.pending_packet_update[event.dpid] = tag
    
  def handle_switch_pu_end(self, event):
    """
    Swap out the marked object in the ObjectRegistry with the new one, while keeping the tags the same.
    """
    assert event.dpid in self.pending_packet_update 
    tag = self.pending_packet_update[event.dpid]
    obj = event.packet
    self.pids.replace_obj(tag, obj)
  
  #
  # Host events
  #
  
  def handle_host_ph_begin(self, event):
    pid_in = self.pids.get_tag(event.packet) # matches a pid_out as the Python object ids will be the same
    
    begin_event = HbHostHandle(pid_in, hid=event.hid, packet=event.packet, in_port=event.in_port)
    self.start_host_event(event.hid, begin_event)
    
  def handle_host_ph_end(self, event):
    self.finish_host_event(event.hid)
    
  def handle_host_ps(self, event):
    pid_in = self.pids.new_tag(event.packet) # tag changes here
    pid_out = self.pids.new_tag(event.packet) # tag changes here
    
    new_event = HbHostSend(pid_in, pid_out, hid=event.hid, packet=event.packet, out_port=event.out_port)
    self.add_successor_to_host_event(new_event, pid_in=pid_in)
  


