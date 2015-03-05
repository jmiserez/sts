from pox.lib.util import assert_type
from pox.lib.revent import Event, EventMixin
from pox.lib.packet import *
from pox.openflow.software_switch import DpPacketOut
from pox.openflow.libopenflow_01 import *
from pox.lib.addresses import IPAddr

from sts.util.convenience import object_fullname
from sts.util.convenience import class_fullname
from sts.util.convenience import load_class
from sts.util.convenience import get_json_attr

import json
import base64
import collections
import itertools
from functools import partial
from __builtin__ import list
from collections import OrderedDict, defaultdict


# TODO JM: Add some support for support for 
#   - events that are not packet/msg based (topology changes etc).
#   - events that STS or POX already fires

class TraceEvent(Event):
  _ids = itertools.count(0)
  
  def __init__(self):
    Event.__init__(self)
    self.id = self._ids.next()
    self.type = self.__class__.__name__
      
  def to_json(self):
    """
    Serialize every field that exists.
    """  
    attrs = ['id', # int
             'type', # str
             'msg_type',
             'msg_reason',
             'msg_xid',
             'precursor_id', # int
             'is_switch', # boolean
             'node', # int
             'port', # int
             'dpid', # int
             'hid', # int
             'cid', # int
             'buffer_id', # int
             'in_port', # int
             'out_port', # int
             'interface', # str
             'is_connected', # boolean
             'connected_is_switch', # boolean
             'connected_node', # int
             'connected_port', # int (hosts) or string (switches)
             'packet_register_event_id', #int
             'packet_obj_id', #int
             'msg_data',
             'msg_in',
             'msg_in_floodlight_sw_id',
             'msg_out',
             ('packet', lambda packet: base64.b64encode(packet.pack()).replace("\n", "")),
             ('msg', lambda msg: base64.b64encode(msg.pack()).replace("\n", "")),
             ('flow_mod', lambda flow_mod: base64.b64encode(flow_mod.pack()).replace("\n", "")),
             ('flow_table', 
                lambda flow_table: [base64.b64encode(entry.to_flow_mod().pack()).replace("\n", "") for entry in flow_table.table]),
             ('expired_flows',
                lambda expired_flows: [base64.b64encode(entry.to_flow_mod().pack()).replace("\n", "") for entry in expired_flows]),
             ('matched_flow',
                lambda matched_flow: base64.b64encode(matched_flow.to_flow_mod().pack()).replace("\n", "")),
             ('touched_flow',
                lambda touched_flow: base64.b64encode(touched_flow.to_flow_mod().pack()).replace("\n", "")),
             'touched_flow_bytes',
             ('touched_flow_now', lambda fp: repr(fp)), # str() is not precise for floating point numbers in Python < v3.2
             ('action', lambda action: base64.b64encode(action.pack()).replace("\n", "")),
             ('actions', 
                lambda actions: [base64.b64encode(action.pack()).replace("\n", "") for action in actions])
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
  
class TracePacketRegister(TraceEvent):
  def __init__(self, packet, packet_register_event_id=None):
    TraceEvent.__init__(self)
    self.packet_obj_id = id(packet)
    self.packet_register_event_id = packet_register_event_id
    
class TracePacketDeregister(TraceEvent):
  def __init__(self, packet_register_event_id, packet=None):
    """
    Takes either a packet object or an event id, as sometimes the event id is no longer available
    """
    assert (packet is not None) or (packet_register_event_id is not None)
    TraceEvent.__init__(self)
    self.packet_obj_id = id(packet) if packet is not None else None
    self.packet_register_event_id = packet_register_event_id
  
class TraceDpPacketOutHost(TraceEvent):
  def __init__ (self, host, interface, packet, packet_register_event_id=None, is_connected=None, connected_is_switch=None, connected_node=None, connected_port=None):
    
    TraceEvent.__init__(self)
    self._node = host
    self._port = interface
    
    self.node = host.hid
    self.port = interface.port_no
    self.hid = self.node
    self.interface = self.port
    
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.is_switch = False
    self.is_connected = is_connected
    self.connected_is_switch = connected_is_switch
    self.connected_node = connected_node
    self.connected_port = connected_port
   
class TraceDpPacketOutSwitch(TraceEvent):
  def __init__ (self, switch, port, packet, packet_register_event_id=None, is_connected=None, connected_is_switch=None, connected_node=None, connected_port=None):
    TraceEvent.__init__(self)
    self._node = switch
    self._port = port
    
    self.node = switch.dpid
    self.port = port.port_no
    self.dpid = self.node
    
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.is_switch = True
    self.is_connected = is_connected
    self.connected_is_switch = connected_is_switch
    self.connected_node = connected_node
    self.connected_port = connected_port
    

class TraceDpPacketInHost(TraceEvent):
  def __init__ (self, host, interface, packet, packet_register_event_id=None, is_connected=None, connected_is_switch=None, connected_node=None, connected_port=None):
    TraceEvent.__init__(self)
    self._node = host
    self._port = interface
    
    self.node = host.hid
    self.port = interface.port_no
    self.hid = self.node
    self.interface = self.port
    
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.is_switch = False
    self.is_connected = is_connected
    self.connected_is_switch = connected_is_switch
    self.connected_node = connected_node
    self.connected_port = connected_port
    
class TraceDpPacketInSwitch(TraceEvent):
  def __init__ (self, switch, port, packet, packet_register_event_id=None, is_connected=None, connected_is_switch=None, connected_node=None, connected_port=None):
    TraceEvent.__init__(self)
    self._node = switch
    self._port = port
    
    self.node = switch.dpid
    self.port = port.port_no
    self.dpid = self.node
    
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.is_switch = True
    self.is_connected = is_connected
    self.connected_is_switch = connected_is_switch
    self.connected_node = connected_node
    self.connected_port = connected_port

# TODO JM: instrument Hosts to do this
class TracePacketHostResponseBegin(TraceEvent):
  '''
  Event for responses from a Host, e.g. a Ping response. 
  '''
  def __init__ (self, host, interface, packet, packet_register_event_id, reason):
    TraceEvent.__init__(self)
    self.hid = host.hid
    self.interface = interface.port_no
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.reason = reason

# TODO JM: instrument Hosts to do this
class TracePacketHostResponseEnd(TraceEvent):
  '''
    Event for responses from a Host, e.g. a Ping response. 
  '''
  def __init__ (self, host, interface, packet, packet_register_event_id, reason, precursor_id):
    TraceEvent.__init__(self)
    self.hid = host.hid
    self.interface = interface.port_no if not isinstance(interface, basestring) else interface
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.reason = reason
    self.precursor_id = precursor_id

class OfHandleVendorHb(TraceEvent):
  '''
  Switch (Floodlight) -> Controller
  '''
  def __init__(self, dpid, cid, msg, msg_data):
    TraceEvent.__init__(self)
    self.dpid = dpid
    self.cid = cid # controller id
    self.msg = msg
    self.msg_data = msg_data
    
    p = msg_data.split(',')
    
    if p[0] == 'in':
      self.msg_in_floodlight_sw_id = p[1]
      self.msg_in = p[2]
    elif p[0] == 'out':
      self.msg_in_floodlight_sw_id = p[1]
      self.msg_in = p[2]
      self.msg_out = p[3]

class TraceOfGeneratePacketIn(TraceEvent):
  '''
  Switch -> Controller
  '''
  def __init__(self, switch, in_port, msg, xid, reason, buffer_id, packet, packet_register_event_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.msg = msg
    self.msg_xid = xid
    self.msg_reason = reason
    self.buffer_id = buffer_id
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    
class TraceOfHandlePacketOutFromRaw(TraceEvent):
  '''
  Controller -> Switch
  '''
  def __init__(self, switch, in_port, msg, xid, buffer_id, packet, packet_register_event_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.msg = msg
    self.msg_xid = xid
    self.buffer_id = buffer_id
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id

class TraceOfHandleFlowMod(TraceEvent):
  '''
  Controller -> Switch
  '''
  def __init__(self, switch, in_port, msg, xid, buffer_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port # not guaranteed to match the packet
    self.msg = msg
    self.msg_xid = xid
    self.buffer_id = buffer_id

class TraceOfHandleFlowModFromBuffer(TraceEvent):
  '''
  Controller -> Switch
  '''
  def __init__(self, switch, in_port, msg, xid, buffer_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port # not guaranteed to match the packet
    self.msg = msg
    self.msg_xid = xid
    self.buffer_id = buffer_id

class TraceOfHandlePacketOutFromBuffer(TraceEvent):
  '''
  Controller -> Switch
  '''
  def __init__(self, switch, in_port, msg, xid, buffer_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port # not guaranteed to match the packet
    self.msg = msg
    self.msg_xid = xid
    self.buffer_id = buffer_id
    
class TraceOfMessageToController(TraceEvent):
  '''
  Switch -> Controller
  '''
  def __init__(self, dpid, cid, msg):
    TraceEvent.__init__(self)
    self.dpid = dpid
    self.cid = cid # controller id
    self.msg = msg
    # TODO JM: move parsing of Openflow to read_trace.
    self.msg_type = ofp_type_rev_map.keys()[ofp_type_rev_map.values().index(msg.header_type)]
    self.msg_xid = msg.xid
    self.buffer_id = msg.buffer_id if hasattr(msg, "buffer_id") else -1

class TraceOfMessageFromController(TraceEvent):
  '''
  Controller -> Switch
  '''
  def __init__(self, dpid, cid, msg):
    TraceEvent.__init__(self)
    self.dpid = dpid
    self.cid = cid # controller id
    self.msg = msg
    self.msg_type = ofp_type_rev_map.keys()[ofp_type_rev_map.values().index(msg.header_type)]
    self.msg_xid = msg.xid
    self.buffer_id = msg.buffer_id if hasattr(msg, "buffer_id") else -1
    self.actions = msg.actions if hasattr(msg, "actions") else []

class TraceFlowTableModificationBefore(TraceEvent):
  def __init__ (self, switch, flow_table, flow_mod):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.flow_table = flow_table
    self.flow_mod = flow_mod
    self.msg = flow_mod
    
class TraceFlowTableModificationAfter(TraceEvent):
  def __init__ (self, switch, flow_table, flow_mod, precursor_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.flow_table = flow_table
    self.flow_mod = flow_mod
    self.msg = flow_mod
    
class TraceFlowTableModificationExpired(TraceEvent):
  def __init__ (self, switch, flow_table, removed):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.flow_table = flow_table
    self.expired_flows = removed
    
class TraceFlowTableMatch(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id, flow_table, entry):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.flow_table = flow_table
    self.matched_flow = entry
    self.actions = entry.actions
    
class TraceFlowTableTouch(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id, flow_table, entry, bytes, now):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.flow_table = flow_table
    self.touched_flow = entry
    self.touched_flow_bytes = bytes
    self.touched_flow_now = now
    self.actions = entry.actions

class TracePacketActionModificationBegin(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    
class TracePacketActionModificationEnd(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    
class TracePacketActionOutput(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id, out_port):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.out_port = out_port
    
class TracePacketActionResubmit(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id


class TracePacketBufferReadPacket(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id, buffer_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.buffer_id = buffer_id
    
class TracePacketBufferError(TraceEvent):
  def __init__ (self, switch, buffer_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.buffer_id = buffer_id

class TracePacketBufferWritePacket(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id, buffer_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.buffer_id = buffer_id
    
class TracePacketBufferFlushPacket(TraceEvent):
  def __init__ (self, switch, in_port, packet, packet_register_event_id, buffer_id):
    TraceEvent.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.packet_register_event_id = packet_register_event_id
    self.buffer_id = buffer_id

def raise_register_packet(self, packet):
    reg_event = TracePacketRegister(packet)
    self.raiseEvent(reg_event)
    return reg_event.id
  
def raise_deregister_packet(self, reg_event_id, packet=None):
  self.raiseEvent(TracePacketDeregister(reg_event_id, packet))
  
def raise_replace_register_packet(self, old_reg_event_id, new_packet):
  #replace packet
  reg_event = TracePacketRegister(new_packet, old_reg_event_id)
  self.raiseEvent(reg_event)
  self.raiseEvent(TracePacketDeregister(old_reg_event_id))
  return reg_event.id
