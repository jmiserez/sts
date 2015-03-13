# Copyright 2011-2013 Colin Scott
# Copyright 2012-2013 Sam Whitlock
# Copyright 2011-2013 Andreas Wundsam
# Copyright 2012-2012 Kyriakos Zarifis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from base64 import b64encode
"""
This module defines the basic simulated entities, such as openflow switches and
links.
"""

from pox.openflow.software_switch import DpPacketOut, OFConnection
from pox.openflow.nx_software_switch import NXSoftwareSwitch
from pox.openflow.flow_table import FlowTableModification, SwitchFlowTable
from pox.openflow.libopenflow_01 import *
from pox.lib.revent import EventMixin
import pox.lib.packet.ethernet as ethernet
import pox.lib.packet.ipv4 as ipv4
import pox.lib.packet.tcp as tcp
from pox.lib.util import assert_type
import pox.openflow.libopenflow_01 as of
from sts.openflow_buffer import OpenFlowBuffer

from sts.util.tabular import Tabular
from sts.util.convenience import base64_encode

from sts.entities.base import DirectedLinkAbstractClass
from sts.entities.base import BiDirectionalLinkAbstractClass
from sts.entities.hosts import HostInterface

from sts.util.revent_mixins import CombiningEventMixinMetaclass
from sts.happensbefore.hb_sts_events import *


import Queue
import logging
import pickle
import random
import time


class TracingOFConnection(OFConnection, EventMixin):
  """
  This version of OFConnection raises events when a message is sent
  """
  __metaclass__ = CombiningEventMixinMetaclass
  _eventMixin_events = set([TraceSwitchMessageSend, TraceSwitchMessageRx])
  
  def __init__(self, *args, **kw):
    OFConnection.__init__(self, *args, **kw)
  
  def send(self, ofp_message):
    ofp_message.pack()
    self.raiseEvent(TraceSwitchMessageSend(self.dpid, self.controller_id, ofp_message))
    super(TracingOFConnection, self).send(ofp_message)
    
  def read (self, io_worker):
    while True:
      message = io_worker.peek_receive_buf()
      msg_obj = None
      packet_length = 0
      try:
        (msg_obj, packet_length) = OFConnection.parse_of_packet(message)
      except ValueError as e:
        e = ValueError(e.__str__() + "on connection " + str(self))
        if self.error_handler:
          return self.error_handler(e)
        else:
          raise e

      if msg_obj is None:
        break
      else:
        self.raiseEvent(TraceSwitchMessageRx(msg_obj, base64_encode(message)))

      io_worker.consume_receive_buf(packet_length)

      # note: on_message_received is just a function, not a method
      if self.on_message_received is None:
        raise RuntimeError("on_message_receieved hasn't been set yet!")

      try:
        self.on_message_received(self, msg_obj)
      except Exception as e:
        if self.error_handler:
          return self.error_handler(e)
        else:
          raise e

    return True

class DeferredOFConnection(TracingOFConnection):
  def __init__(self, io_worker, cid, dpid, openflow_buffer):
    super(DeferredOFConnection, self).__init__(io_worker)
    self.cid = cid
    self.dpid = dpid
    self.openflow_buffer = openflow_buffer
    # Don't feed messages to the switch directly
    self.on_message_received = self.insert_pending_receipt
    self.true_on_message_handler = None

  @property
  def closed(self):
    return self.io_worker.closed

  def get_controller_id(self):
    return self.cid

  def insert_pending_receipt(self, _, ofp_msg):
    ''' Rather than pass directly on to the switch, feed into the openflow buffer'''
    self.openflow_buffer.insert_pending_receipt(self.dpid, self.cid, ofp_msg, self)

  def set_message_handler(self, handler):
    ''' Take the switch's handler, and store it for later use '''
    self.true_on_message_handler = handler

  def allow_message_receipt(self, ofp_message):
    ''' Allow the message to actually go through to the switch '''
    self.true_on_message_handler(self, ofp_message)

  def send(self, ofp_message):
    ''' Interpose on switch sends as well '''
    self.openflow_buffer.insert_pending_send(self.dpid, self.cid, ofp_message, self)

  def allow_message_send(self, ofp_message):
    ''' Allow message actually be sent to the controller '''
    super(DeferredOFConnection, self).send(ofp_message)

class ConnectionlessOFConnection(object):
  ''' For use with InteractiveReplayer, where controllers are mocked out, and
  events are replayed to headless switches.'''
  def __init__(self, cid, dpid):
    self.cid = cid
    self.dpid = dpid
    self.on_message_received = None
    OFConnection.ID += 1
    self.ID = OFConnection.ID

  @property
  def closed(self):
    return False

  def close(self):
    pass

  def get_controller_id(self):
    return self.cid

  def set_message_handler(self, handler):
    self.on_message_handler = handler

  def send(self, ofp_message):
    ''' Into the abyss you go!'''
    pass

  # N.B. different interface than OFConnection. It's OK, since we don't actually
  # use io_workers -- this is only invoked by
  # ControlMessageReceive.manually_inject()
  def read (self, ofp_message):
    self.on_message_handler(self, ofp_message)

class TracingSwitchFlowTable(SwitchFlowTable, EventMixin):
  __metaclass__ = CombiningEventMixinMetaclass
  _eventMixin_events = set([TraceSwitchFlowTableEntryExpiry, TraceSwitchFlowTableWrite])
  
  def __init__(self, switch, *args, **kw):
    SwitchFlowTable.__init__(self, *args, **kw)
    self.switch = switch
  
  def remove_expired_entries(self, now=None):
    removed = super(TracingSwitchFlowTable, self).remove_expired_entries(now)
    self.raiseEvent(TraceSwitchFlowTableEntryExpiry(self.switch.dpid, self, removed))
  
  def process_flow_mod(self, flow_mod):
    """ Process a flow mod sent to the switch
    @return a tuple (added|modified|removed, [list of affected entries])
    """
    self.raiseEvent(TraceSwitchFlowTableWrite(self.switch.dpid, self, flow_mod))
    #super(TracingSwitchFlowTable, self).process_flow_mod(flow_mod)
    # TODO JM: I *think* this is fixed now. Remove once we are sure.
    # FIXME (AH): a quick hack to solve the empty flow table problem
    from pox.openflow.libopenflow_01 import *
    from pox.openflow.software_switch import *
    from pox.openflow.flow_table import *
    if(flow_mod.flags & OFPFF_CHECK_OVERLAP):
      raise NotImplementedError("OFPFF_CHECK_OVERLAP checking not implemented")
    if(flow_mod.out_port != OFPP_NONE and
            flow_mod.command == ofp_flow_mod_command_rev_map['OFPFC_DELETE']):
      raise NotImplementedError("flow_mod outport checking not implemented")

    if flow_mod.command == OFPFC_ADD:
      # exactly matching entries have to be removed
      self.remove_matching_entries(flow_mod.match,flow_mod.priority, strict=True)
      return ("added", self.add_entry(TableEntry.from_flow_mod(flow_mod)))
    elif flow_mod.command == OFPFC_MODIFY or flow_mod.command == OFPFC_MODIFY_STRICT:
      is_strict = (flow_mod.command == OFPFC_MODIFY_STRICT)
      modified = []
      for entry in self.table:
        # update the actions field in the matching flows
        if(entry.is_matched_by(flow_mod.match, priority=flow_mod.priority, strict=is_strict)):
          entry.actions = flow_mod.actions
          modified.append(entry)
      if(len(modified) == 0):
        # if no matching entry is found, modify acts as add
        return ("added", self.add_entry(TableEntry.from_flow_mod(flow_mod)))
      else:
        return ("modified", modified)

    elif flow_mod.command == OFPFC_DELETE or flow_mod.command == OFPFC_DELETE_STRICT:
      is_strict = (flow_mod.command == OFPFC_DELETE_STRICT)
      return ("removed", self.remove_matching_entries(flow_mod.match, flow_mod.priority, is_strict))
    else:
      raise AttributeError("Command not yet implemented: %s" % flow_mod.command)



class TracingNXSoftwareSwitch(NXSoftwareSwitch, EventMixin):
  """
  A NXSoftwareSwitch with added methods for tracing packets and Openflow messages
  """
  # use metaclass to add new events
  __metaclass__ = CombiningEventMixinMetaclass
  _eventMixin_events = set([TraceSwitchPacketHandleBegin, TraceSwitchPacketHandleEnd,
     TraceSwitchMessageHandleBegin, TraceSwitchMessageHandleEnd,
     TraceSwitchMessageSend, TraceSwitchPacketSend, TraceSwitchMessageRx,
     TraceSwitchFlowTableRead,
     TraceSwitchFlowTableWrite, TraceSwitchFlowTableEntryExpiry,
     TraceSwitchBufferPut, TraceSwitchBufferGet, TraceSwitchPacketUpdateBegin,
     TraceSwitchPacketUpdateEnd])
  
  def reraise_event(self, event):
      self.raiseEvent(event)
  
  def __init__(self, *args, **kw):
    NXSoftwareSwitch.__init__(self, *args, **kw)
    self.table = TracingSwitchFlowTable(self) # overwrite SwitchFlowTable
    
    self.table.addListener(TraceSwitchFlowTableWrite, self.reraise_event)
    self.table.addListener(TraceSwitchFlowTableEntryExpiry, self.reraise_event)
        
  def set_connection(self, connection):
    NXSoftwareSwitch.set_connection(self,connection)
    if isinstance(connection, TracingOFConnection):
      connection.addListener(TraceSwitchMessageRx, self.reraise_event)
    

  def on_message_received(self, connection, msg):
    self.raiseEvent(TraceSwitchMessageHandleBegin(self.dpid, connection.controller_id, msg, msg.header_type))
    super(TracingNXSoftwareSwitch, self).on_message_received(connection, msg)
    self.raiseEvent(TraceSwitchMessageHandleEnd(self.dpid))
  
  def _output_packet(self, packet, out_port, in_port):
    """ send a packet out some port.
        packet: instance of ethernet
        out_port, in_port: the integer port number """
    assert_type("packet", packet, ethernet, none_ok=False)
    def real_send(port_no, allow_in_port=True):
      if type(port_no) == ofp_phy_port:
        port_no = port_no.port_no
      # The OF spec states that packets should not be forwarded out their
      # in_port unless OFPP_IN_PORT is explicitly used.
      if port_no == in_port and not allow_in_port:
        self.log.warn("out_port %d == in_port. Dropping" % (out_port,))
        return
      if port_no not in self.ports:
        raise ValueError("Invalid physical output port: %x" % port_no)
      if port_no in self.down_port_nos:
        #raise RuntimeError("output port %x currently down!" % port_no)
        self.log.warn("Port %d is currently down. Dropping packet", port_no)
      self.raiseEvent(TraceSwitchPacketSend(self.dpid, packet, port_no))
      self.raiseEvent(DpPacketOut(self, packet, self.ports[port_no]))

    if out_port < OFPP_MAX:
      real_send(out_port)
    elif out_port == OFPP_IN_PORT:
      real_send(in_port, allow_in_port=True)
    elif out_port == OFPP_FLOOD or out_port == OFPP_ALL:
      # no support for spanning tree yet -> flood=all
      for (no,port) in self.ports.iteritems():
        if no != in_port and port not in self.no_flood_ports:
          real_send(port)
    elif out_port == OFPP_CONTROLLER:
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_count.next(), reason=OFPR_ACTION)
    elif out_port == OFPP_TABLE:
      # There better be a table entry there, else we get infinite recurision
      # between switch<->controller
      # Note that this isn't infinite recursion, since the table entry's
      # out_port will not be OFPP_TABLE
      self.process_packet_internally(packet, in_port)
    else:
      raise("Unsupported virtual output port: %x" % out_port)
  
  def process_packet_internally(self, packet, in_port):
    assert_type("packet", packet, ethernet, none_ok=False)
    assert_type("in_port", in_port, int, none_ok=False)
    
    entry = self.table.entry_for_packet(packet, in_port)
    if(entry != None):
      now = time.time()
      plen = len(packet)
      self.raiseEvent(TraceSwitchFlowTableRead(self.dpid, packet, in_port, self.table, entry, plen, now))
      entry.touch_packet(plen, now)
      self._process_actions_for_packet(entry.actions, packet, in_port)
    else:
      # no matching entry
      self.raiseEvent(TraceSwitchFlowTableRead(self.dpid, packet, in_port, self.table, None, None, None))
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_count.next(), reason=OFPR_NO_MATCH)
  
  def process_packet(self, packet, in_port):
    # this completely overrides SoftwareSwitch's implementation and does not call super
    assert_type("packet", packet, ethernet, none_ok=False)
    assert_type("in_port", in_port, int, none_ok=False)
    
    self.raiseEvent(TraceSwitchPacketHandleBegin(self.dpid, packet, in_port))
    self.process_packet_internally(packet, in_port)
    self.raiseEvent(TraceSwitchPacketHandleEnd(self.dpid))
    

  def _buffer_packet(self, packet, in_port=None):
    """ Find a free buffer slot to buffer the packet in. """
    for (i, value) in enumerate(self.packet_buffer):
      if(value==None):
        self.packet_buffer[i] = (packet, in_port)
        return i + 1
    self.packet_buffer.append( (packet, in_port) )
    buffer_id = len(self.packet_buffer)
    # Note that a buffer_id of -1 would mean that it was sent to the controller rather than being buffered
    self.raiseEvent(TraceSwitchBufferPut(self.dpid, packet, in_port, buffer_id))
    return buffer_id
  
  def _process_actions_for_packet_from_buffer(self, actions, buffer_id):
    """ output and release a packet from the buffer """
    buffer_id = buffer_id - 1
    if(buffer_id >= len(self.packet_buffer)):
      self.log.warn("Invalid output buffer id: %x", buffer_id)
      return
    if(self.packet_buffer[buffer_id] is None):
      self.log.warn("Buffer %x has already been flushed", buffer_id)
      return
    (packet, in_port) = self.packet_buffer[buffer_id]
    
    self.raiseEvent(TraceSwitchBufferGet(self.dpid, packet, in_port, buffer_id))
    self._process_actions_for_packet(actions, packet, in_port)
    self.packet_buffer[buffer_id] = None
    
  def _process_actions_for_packet(self, actions, packet, in_port):
    """ process the output actions for a packet """
    assert_type("packet", packet, [ethernet, str], none_ok=False)

    if not isinstance(packet, ethernet):
      self.raiseEvent(TraceSwitchPacketUpdateBegin(self.dpid, packet))
      packet = ethernet.unpack(packet)
      self.raiseEvent(TraceSwitchPacketUpdateEnd(self.dpid, packet))

    def output_packet(action, packet):
      self._output_packet(packet, action.port, in_port)
      return packet
    def set_vlan_id(action, packet):
      if not isinstance(packet.next, vlan):
        packet.next = vlan(prev = packet.next)
        packet.next.eth_type = packet.type
        packet.type = ethernet.VLAN_TYPE
      packet.id = action.vlan_id
      return packet
    def set_vlan_pcp(action, packet):
      if not isinstance(packet.next, vlan):
        packet.next = vlan(prev = packet)
        packet.next.eth_type = packet.type
        packet.type = ethernet.VLAN_TYPE
      packet.pcp = action.vlan_pcp
      return packet
    def strip_vlan(action, packet):
      if isinstance(packet.next, vlan):
        packet.type = packet.next.eth_type
        packet.next = packet.next.next
      return packet
    def set_dl_src(action, packet):
      packet.src = action.dl_addr
      return packet
    def set_dl_dst(action, packet):
      packet.dst = action.dl_addr
      return packet
    def set_nw_src(action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.nw_src = action.nw_addr
      return packet
    def set_nw_dst(action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.nw_dst = action.nw_addr
      return packet
    def set_nw_tos(action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.tos = action.nw_tos
      return packet
    def set_tp_src(action, packet):
      if(isinstance(packet.next, udp) or isinstance(packet.next, tcp)):
        packet.next.srcport = action.tp_port
      return packet
    def set_tp_dst(action, packet):
      if(isinstance(packet.next, udp) or isinstance(packet.next, tcp)):
        packet.next.dstport = action.tp_port
      return packet
    def enqueue(action, packet):
      self.log.warn("output_enqueue not supported yet. Performing regular output")
      return output_packet(action.tp_port, packet)
    def push_mpls_tag(action, packet):
      bottom_of_stack = isinstance(packet.next, mpls)
      packet.next = mpls(prev = packet.pack())
      if bottom_of_stack:
        packet.next.s = 1
      packet.type = action.ethertype
      return packet
    def pop_mpls_tag(action, packet):
      if not isinstance(packet.next, mpls):
        return packet
      if not isinstance(packet.next.next, str):
        packet.next.next = packet.next.next.pack()
      if action.ethertype in ethernet.type_parsers:
        packet.next = ethernet.type_parsers[action.ethertype](packet.next.next)
      else:
        packet.next = packet.next.next
      packet.ethertype = action.ethertype
      return packet
    def set_mpls_label(action, packet):
      if not isinstance(packet.next, mpls):
        mock = ofp_action_push_mpls()
        packet = push_mpls_tag(mock, packet)
      packet.next.label = action.mpls_label
      return packet
    def set_mpls_tc(action, packet):
      if not isinstance(packet.next, mpls):
        mock = ofp_action_push_mpls()
        packet = push_mpls_tag(mock, packet)
      packet.next.tc = action.mpls_tc
      return packet
    def set_mpls_ttl(action, packet):
      if not isinstance(packet.next, mpls):
        mock = ofp_action_push_mpls()
        packet = push_mpls_tag(mock, packet)
      packet.next.ttl = action.mpls_ttl
      return packet
    def dec_mpls_ttl(action, packet):
      if not isinstance(packet.next, mpls):
        return packet
      packet.next.ttl = packet.next.ttl - 1
      return packet
    handler_map = {
        OFPAT_OUTPUT: output_packet,
        OFPAT_SET_VLAN_VID: set_vlan_id,
        OFPAT_SET_VLAN_PCP: set_vlan_pcp,
        OFPAT_STRIP_VLAN: strip_vlan,
        OFPAT_SET_DL_SRC: set_dl_src,
        OFPAT_SET_DL_DST: set_dl_dst,
        OFPAT_SET_NW_SRC: set_nw_src,
        OFPAT_SET_NW_DST: set_nw_dst,
        OFPAT_SET_NW_TOS: set_nw_tos,
        OFPAT_SET_TP_SRC: set_tp_src,
        OFPAT_SET_TP_DST: set_tp_dst,
        OFPAT_ENQUEUE: enqueue,
        OFPAT_PUSH_MPLS: push_mpls_tag,
        OFPAT_POP_MPLS: pop_mpls_tag,
        OFPAT_SET_MPLS_LABEL: set_mpls_label,
        OFPAT_SET_MPLS_TC: set_mpls_tc,
        OFPAT_SET_MPLS_TTL: set_mpls_ttl,
        OFPAT_DEC_MPLS_TTL: dec_mpls_ttl,
    }
    for action in actions:
      if action.type is OFPAT_RESUBMIT:
        self.process_packet_internally(packet, in_port)
        return
      if(action.type not in handler_map):
        raise NotImplementedError("Unknown action type: %x " % type)
      self.raiseEvent(TraceSwitchPacketUpdateBegin(self.dpid, packet))
      packet = handler_map[action.type](action, packet)
      self.raiseEvent(TraceSwitchPacketUpdateEnd(self.dpid, packet))


# A note on FuzzSoftwareSwitch Command Buffering
#   - When delaying flow_mods, we would like to buffer them and perturb the order in which they are processed.
#     self.barrier_deque is a queue of priority queues, with each priority queue representing an epoch, defined by one or two
#     barrier_in requests.
#   - When non-barrier_in flow_mods come in, they get added to the back-most (i.e. most recently added) priority queue of
#     self.barrier_deque. When a barrier_in request is received, we append that request to self.barrier_deque, together with a
#     new priority queue to buffer all subsequently received commands until all previously received commands have been processed
#     and the received barrier_in request is completed.
#   - When processing buffered commands, they are always pulled off from the front-most priority queue. If pulling off a command
#     makes the front-most queue empty, we are done with this epoch, and we can respond to the controller with a barrier_reply. We
#     then check if there is another priority queue waiting in self.barrier_deque. If there is,
#     we pop off the empty queue in front and reply to the barrier_in request that caused the creation of the next priority
#     queue. That priority queue is now at the front and is where we pull commands from.
#
# Command buffering flow chart
#   flow_mod arrived -----> insert into back-most PQ
#   barrier_in arrived ---> append (barrier_in, new PriorityQueue) to self.barrier_deque
#   flow_mod arrived -----> insert into back
# Command processing flow chart
#   get_next_command from front ---> if decide to let cmd through ---> process_delayed_command(cmd)
#                                                                 \
#                                                                  else ---> report flow mod failure
#                               ---> if front queue empty and another queue waiting ---> pop front queue off, reply to barrier_request
#                                                                                         (until the queue in front is not
#                                                                                           empty or only one queue is left)

class FuzzSoftwareSwitch (TracingNXSoftwareSwitch):
  """
  A mock switch implementation for testing purposes. Can simulate dropping dead.
  FuzzSoftwareSwitch supports three features:
    - flow_mod delays, where flow_mods are not processed immediately
    - flow_mod processing randomization, where the order in which flow_mods are applied to the routing table perturb
    - flow_mod dropping, where flow_mods are dropped according to a given filter. This is implemented by the caller of
      get_next_command() applying a filter to the returned command and selectively allowing them through via process_next_command()

    NOTE: flow_mod processing randomization and flow_mod dropping both require flow_mod delays to be activated, but
    are not dependent on each other.
  """
  _eventMixin_events = set([DpPacketOut])

  def __init__(self, dpid, name=None, ports=4, miss_send_len=128,
               n_buffers=100, n_tables=1, capabilities=None,
               can_connect_to_endhosts=True):
    TracingNXSoftwareSwitch.__init__(self, dpid, name, ports, miss_send_len,
                              n_buffers, n_tables, capabilities)

    # Whether this is a core or edge switch
    self.can_connect_to_endhosts = can_connect_to_endhosts
    self.create_connection = None

    self.failed = False
    self.log = logging.getLogger("FuzzSoftwareSwitch(%d)" % dpid)

    if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
      def _print_entry_remove(table_mod):
        if table_mod.removed != []:
          self.log.debug("Table entry removed %s" % str(table_mod.removed))
      self.table.addListener(FlowTableModification, _print_entry_remove)

    def error_handler(e):
      self.log.exception(e)
      raise e

    self.cid2connection = {}
    self.error_handler = error_handler
    self.controller_info = []

    # Tell our buffer to insert directly to our flow table whenever commands are let through by control_flow.
    self.delay_flow_mods = False
    self.openflow_buffer = OpenFlowBuffer()
    self.barrier_deque = None
    # Boolean representing whether to use randomize_flow_mod mode to prioritize the order in which flow_mods are processed.
    self.randomize_flow_mod_order = False
    # Uninitialized RNG (initialize through randomize_flow_mods())
    self.random = None
    self.port_violations = []

  def _output_packet(self, packet, out_port, in_port):
    try:
      return super(FuzzSoftwareSwitch, self)._output_packet(packet, out_port, in_port)
    except ValueError as e:
      self.log.warn("invalid arguments %s" % str(e))
      if type(out_port) == ofp_phy_port:
        out_port = out_port.port_no
      self.port_violations.append((self.dpid, out_port))

  def add_controller_info(self, info):
    self.controller_info.append(info)

  def _handle_ConnectionUp(self, event):
    self._setConnection(event.connection, event.ofp)

  def connect(self, create_connection, down_controller_ids=None,
              max_backoff_seconds=1024, controller_infos=None):
    ''' - create_connection is a factory method for creating Connection objects
          which are connected to controllers. Takes a ControllerConfig object
          and a reference to a switch (self) as a parameter
    '''
    if controller_infos is None:
      controller_infos = self.controller_info
    # Keep around the connection factory for fail/recovery later
    if down_controller_ids is None:
      down_controller_ids = set()
    self.create_connection = create_connection
    connected_to_at_least_one = False
    for info in controller_infos:
      # Don't connect to down controllers
      if info.cid not in down_controller_ids:
        conn = create_connection(info, self,
                                 max_backoff_seconds=max_backoff_seconds)
        self.set_connection(conn)
        # cause errors to be raised
        conn.error_handler = self.error_handler
        self.cid2connection[info.cid] = conn
        connected_to_at_least_one = True

    return connected_to_at_least_one

  def send(self, *args, **kwargs):
    if self.failed:
      self.log.warn("Currently down. Dropping send()")
    else:
      super(FuzzSoftwareSwitch, self).send(*args, **kwargs)

  def get_connection(self, cid):
    if cid not in self.cid2connection.keys():
      raise ValueError("No such connection %s" % str(cid))
    return self.cid2connection[cid]

  def is_connected_to(self, cid):
    if cid in self.cid2connection.keys():
      conn = self.get_connection(cid)
      return not conn.closed
    return False

  def fail(self):
    # TODO(cs): depending on the type of failure, a real switch failure
    # might not lead to an immediate disconnect
    if self.failed:
      self.log.warn("Switch already failed")
      return
    self.failed = True

    for connection in self.connections:
      connection.close()
    self.connections = []

  def recover(self, down_controller_ids=None):
    if not self.failed:
      self.log.warn("Switch already up")
      return
    if self.create_connection is None:
      self.log.warn("Never connected in the first place")

    # We should only ever reconnect to live controllers, so set
    # max_backoff_seconds to a low number.
    connected_to_at_least_one = self.connect(self.create_connection,
                                             down_controller_ids=down_controller_ids,
                                             max_backoff_seconds=2)
    if connected_to_at_least_one:
      self.failed = False
    return connected_to_at_least_one

  def serialize(self):
    # Skip over non-serializable data, e.g. sockets
    # TODO(cs): is self.log going to be a problem?
    serializable = FuzzSoftwareSwitch(self.dpid, self.parent_controller_name)
    # Can't serialize files
    serializable.log = None
    # TODO(cs): need a cleaner way to add in the NOM port representation
    if self.software_switch:
      serializable.ofp_phy_ports = self.software_switch.ports.values()
    return pickle.dumps(serializable, protocol=0)

  def use_delayed_commands(self):
    ''' Tell the switch to buffer flow mods '''
    self.delay_flow_mods = True
    self.on_message_received = self.on_message_received_delayed
    # barrier_deque has the structure: [(None, queue_1), (barrier_request_1, queue_2), ...] where...
    #   - its elements have the form (barrier_in_request, next_queue_to_use)
    #   - commands are always processed from the queue of the first element (i.e. barrier_deque[0][1])
    #   - when a new barrier_in request is received, a new tuple is appended to barrier_deque, containing:
    #   (<the just-received request>, <queue for subsequent non-barrier_in commands until all previous commands have been processed>)
    #   - the very first barrier_in is None because, there is no request to respond when we first start buffering commands
    self.barrier_deque = [(None, Queue.PriorityQueue())]

  def randomize_flow_mods(self, seed=None):
    ''' Initialize the RNG and tell switch to randomize order in which flow_mods
    are processed '''
    self.randomize_flow_mod_order = True
    self.random = random.Random()
    if seed is not None:
      self.random.seed(seed)

  @property
  def current_cmd_queue(self):
    ''' Alias for the current epoch's pending flow_mods. '''
    assert(len(self.barrier_deque) > 0)
    return self.barrier_deque[0][1]

  def _buffer_flow_mod(self, connection, msg, weight, buffr):
    ''' Called by on_message_received_delayed. Inserts a PendingReceive into self.openflow_buffer and sticks
    the message and receipt into the provided priority queue buffer for later retrieval. '''
    forwarder = TableInserter.instance_for_connection(connection=connection, insert_method=super(FuzzSoftwareSwitch, self).on_message_received)
    receive = self.openflow_buffer.insert_pending_receipt(self.dpid, connection.cid, msg, forwarder)
    buffr.put((weight, msg, receive))

  def on_message_received_delayed(self, connection, msg):
    ''' Precondition: use_delayed_commands() has been called. Replacement for
    NXSoftwareSwitch.on_message_received when delaying command processing '''
    # TODO(jl): use exponential moving average (define in params) rather than uniform distribution
    # to prioritize oldest flow_mods
    assert(self.delay_flow_mods)

    def choose_weight():
      ''' Return an appropriate weight to associate with a received command with when buffering. '''
      if self.randomize_flow_mod_order:
        # TODO(jl): use exponential moving average (define in params) rather than uniform distribution
        # to prioritize oldest flow_mods
        return self.random.random()
      else:
        # behave like a normal FIFO queue
        return time.time()

    def handle_with_active_barrier_in(connection, msg):
      ''' Handling of flow_mods and barriers while operating under a barrier_in request'''
      if isinstance(msg, ofp_barrier_request):
        # create a new priority queue for all subsequent flow_mods
        self.barrier_deque.append((msg, Queue.PriorityQueue()))
      elif isinstance(msg, ofp_flow_mod):
        # stick the flow_mod on the queue of commands since the last barrier request
        weight = choose_weight()
        # N.B. len(self.barrier_deque) > 1, because an active barrier_in implies we appended a queue to barrier_deque, which
        # already always has at least one element: the default queue
        self._buffer_flow_mod(connection, msg, weight, buffr=self.barrier_deque[-1][1])
      else:
        raise TypeError("Unsupported type for command buffering")

    def handle_without_active_barrier_in(connection, msg):
      if isinstance(msg, ofp_barrier_request):
        if self.current_cmd_queue.empty():
          # if no commands waiting, reply to barrier immediately
          self.log.debug("Barrier request %s %s", self.name, str(msg))
          barrier_reply = ofp_barrier_reply(xid = msg.xid)
          self.send(barrier_reply)
        else:
          self.barrier_deque.append((msg, Queue.PriorityQueue()))
      elif isinstance(msg, ofp_flow_mod):
        # proceed normally (no active or pending barriers)
        weight = choose_weight()
        self._buffer_flow_mod(connection, msg, weight, buffr=self.current_cmd_queue)
      else:
        raise TypeError("Unsupported type for command buffering")

    if isinstance(msg, ofp_flow_mod) or isinstance(msg, ofp_barrier_request):
      # Check if switch is currently operating under a barrier request
      # Note that we start out with len(self.barrier_deque) == 1, add an element for each barrier_in request, and never
      # delete when len(self.barrier_deque) == 1
      if len(self.barrier_deque) > 1:
        handle_with_active_barrier_in(connection, msg)
      else:
        handle_without_active_barrier_in(connection, msg)
    else:
      # Immediately process all other messages
      super(FuzzSoftwareSwitch, self).on_message_received(connection, msg)

  def has_pending_commands(self):
    return not self.current_cmd_queue.empty()

  def get_next_command(self):
    """ Precondition: use_delayed_commands() has been invoked. Invoked periodically from fuzzer.
    Retrieves the next buffered command and its PendingReceive receipt. Throws Queue.Empty if
    the queue is empty. """
    assert(self.delay_flow_mods)
    # tuples in barrier are of the form (weight, buffered command, pending receipt)
    (buffered_cmd, buffered_cmd_receipt) = self.current_cmd_queue.get_nowait()[1:]
    while self.current_cmd_queue.empty() and len(self.barrier_deque) > 1:
      # It's time to move to the next epoch and reply to the most recent barrier_request.
      # barrier_deque has the structure: [(None, queue_1), (barrier_request_1, queue_2), ...]
      # so when we empty queue_x, we just finished processing and thus must reply to barrier_request_x, which is coupled in
      # the next element in barrier_deque: (barrier_request_x, queue_x+1)
      self.barrier_deque.pop(0)
      finished_barrier_request = self.barrier_deque[0][0]
      if finished_barrier_request:
        self.log.debug("Barrier request %s %s", self.name, str(finished_barrier_request))
        barrier_reply = ofp_barrier_reply(xid = finished_barrier_request.xid)
        self.send(barrier_reply)
    return (buffered_cmd, buffered_cmd_receipt)

  def process_delayed_command(self, buffered_cmd_receipt):
    """ Precondition: use_delayed_commands() has been invoked and buffered_cmd_receipt is the PendingReceive
    for a previously received and buffered command (i.e. was returned by get_next_command()) Returns the
    original buffered command """
    assert(self.delay_flow_mods)
    return self.openflow_buffer.schedule(buffered_cmd_receipt)

  def show_flow_table(self):
    dl_types = { 0x0800: "IP",
                 0x0806: "ARP",
                 0x8100: "VLAN",
                 0x88cc: "LLDP",
                 0x888e: "PAE"
                 }
    nw_protos = { 1 : "ICMP", 6 : "TCP", 17 : "UDP" }

    ports = { v: k.replace("OFPP_","") for (k,v) in of.ofp_port_rev_map.iteritems() }

    def dl_type(e):
      d = e.match.dl_type
      if d is None:
        return d
      else:
        return dl_types[d] if d in dl_types else "%x" %d

    def nw_proto(e):
      p = e.match.nw_proto
      return nw_protos[p] if p in nw_protos else p

    def action(a):
      if isinstance(a, ofp_action_output):
        return ports[a.port] if a.port in ports else "output(%d)" % a.port
      else:
        return str(a)
    def actions(e):
      if len(e.actions) == 0:
        return "(drop)"
      else:
        return ", ".join(action(a) for a in e.actions)

    t = Tabular((("Prio", lambda e: e.priority),
                 ("in_port", lambda e: e.match.in_port),
                 ("dl_type", dl_type),
                 ("dl_src", lambda e: e.match.dl_src),
                 ("dl_dst", lambda e: e.match.dl_dst),
                 ("nw_proto", nw_proto),
                 ("nw_src", lambda e: e.match.nw_src),
                 ("nw_dst", lambda e: e.match.nw_dst),
                 ("tp_src", lambda e: e.match.tp_src),
                 ("tp_dst", lambda e: e.match.tp_dst),
                 ("actions", actions),
                ))
    t.show(self.table.entries)

class Link (DirectedLinkAbstractClass):
  """
  A network link between two switches

  Temporary stand in for Murphy's graph-library for the NOM.

  Note: Directed!
  """
  def __init__(self, start_software_switch, start_port,
               end_software_switch, end_port):
    if type(start_port) == int:
      assert(start_port in start_software_switch.ports)
      start_port = start_software_switch.ports[start_port]
    if type(end_port) == int:
      assert(end_port in start_software_switch.ports)
      end_port = end_software_switch.ports[end_port]
    super(Link, self).__init__(start_software_switch, start_port,
                               end_software_switch, end_port)
    assert_type("start_port", start_port, ofp_phy_port, none_ok=False)
    assert_type("end_port", end_port, ofp_phy_port, none_ok=False)
    self.start_software_switch = start_software_switch
    self.end_software_switch = end_software_switch

  def __eq__(self, other):
    if not type(other) == Link:
      return False
    ret = (self.start_software_switch.dpid == other.start_software_switch.dpid and
            self.start_port.port_no == other.start_port.port_no and
            self.end_software_switch.dpid == other.end_software_switch.dpid and
            self.end_port.port_no == other.end_port.port_no)
    return ret

  def __ne__(self, other):
    # NOTE: __ne__ in python does *NOT* by default delegate to eq
    return not self.__eq__(other)


  def __hash__(self):
    return (self.start_software_switch.dpid.__hash__() +  self.start_port.port_no.__hash__() +
           self.end_software_switch.dpid.__hash__() +  self.end_port.port_no.__hash__())

  def __repr__(self):
    return "(%d:%d) -> (%d:%d)" % (self.start_software_switch.dpid, self.start_port.port_no,
                                   self.end_software_switch.dpid, self.end_port.port_no)

  def reversed_link(self):
    '''Create a Link that is in the opposite direction of this Link.'''
    return Link(self.end_software_switch, self.end_port,
                self.start_software_switch, self.start_port)

class AccessLink (BiDirectionalLinkAbstractClass):
  '''
  Represents a bidirectional edge: host <-> ingress switch
  '''
  def __init__(self, host, interface, switch, switch_port):
    super(AccessLink, self).__init__(host, interface, switch, switch_port)
    assert_type("interface", interface, HostInterface, none_ok=False)
    assert_type("switch_port", switch_port, ofp_phy_port, none_ok=False)

  @property
  def host(self):
    return self.node1

  @property
  def interface(self):
    return self.port1

  @property
  def switch(self):
    return self.node2

  @property
  def switch_port(self):
    return self.port2



class SnapshotPopen(object):
  ''' Popen wrapper for processes that were not created by us. '''
  def __init__(self, pid):
    import psutil
    # See https://code.google.com/p/psutil/wiki/Documentation
    # for the full API.
    self.p = psutil.Process(pid)
    self.log = logging.getLogger("c%d" % pid)

  def poll(self):
    ''' A None value indicates that the process hasn't terminated yet. '''
    if self.p.is_running():
      return None
    else:
      return 1

  @property
  def pid(self):
    return self.p.pid

  def kill(self):
    import psutil
    self.log.info("Killing controller process %d" % self.pid)
    try:
      return self.p.kill()
    except psutil._error.NoSuchProcess:
      self.log.info("controller process %d already dead?" % self.pid)
      return None # Already dead

  def terminate(self):
    import psutil
    self.log.info("Terminating controller process %d" % self.pid)
    try:
      return self.p.terminate()
    except psutil._error.NoSuchProcess:
      self.log.info("controller process %d already dead?" % self.pid)
      return None # Already dead


class TableInserter(object):
  ''' Shim layer sitting between incoming messages and a switch. This class is duck-typed to offer the same
  (received message) API to OpenFlowBuffer as a DeferredOFConnection. Instances of this class should be created and
  retrieved by providing TableInserter.instance_for_connection() with a method to insert a flow_mod directly into
  a switch's table and the connection the flow_mod came in on. Each switch should create and use one TableInserter
  for each connection it receives a flow_mod from.
  '''
  connection2instance = {}

  @staticmethod
  def instance_for_connection(connection, insert_method):
    ''' Instantiates or retrieves the TableInserter for the given connection for the switch '''
    if connection.ID not in TableInserter.connection2instance:
      # Note: may cause memory leak if new connections w/ new connection.ID's are constanty created and not reused
      TableInserter.connection2instance[connection.ID] = TableInserter(connection, insert_method)
    return TableInserter.connection2instance[connection.ID]

  def __init__(self, connection, insert_method):
    self.connection = connection
    self.insert_method = insert_method

  def allow_message_receipt(self, message):
    return self.insert_method(self.connection, message)

