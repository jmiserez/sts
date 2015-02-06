from pox.lib.util import assert_type
from pox.lib.revent import Event, EventMixin
from pox.lib.packet import *
from pox.openflow.software_switch import DpPacketOut
# from sts.entities.sts_entities import FuzzSoftwareSwitch
from pox.openflow.libopenflow_01 import ofp_phy_port
from pox.lib.addresses import IPAddr

from sts.util.convenience import object_fullname
from sts.util.convenience import class_fullname
from sts.util.convenience import load_class
from sts.util.convenience import get_json_attr

import json
import base64
import collections
from functools import partial
from mercurial.templatefilters import stringify
from __builtin__ import list


# TODO JM: Add some support for support for 
#   - events that are linked together (OF PacketIn -> PacketOut + FlowMod)
#   - events that are not packet/msg based (topology changes etc).
#   - events that STS or POX already fires

def to_partial_json(obj, attrs):
  """
  Serialize the list of fields specified by attrs. Each element in attrs is one
  of:
  - string: the attribute with the given name will be serialized. If the
    attribute is iterable (except strings), then each element will be serialized
    individually. Attributes/elements will be serialized using either the 
    to_json, toStr, or str() methods.
  - tuple of (string, function): the attribute with the given name will be
    serialized using the given function
  - tuple of (string, attrs): calls this function recursively for each element
    of the attribute with the given name in attrs.
  """
    
  try:
    json_dict = {'__type__': obj.__class__.__name__}
    for attr in attrs:
      if isinstance(attr, tuple) and len(attr) > 1 and hasattr(obj, attr[0]): # entry is a tuple
        nested_obj = getattr(obj, attr[0], None)
        nested_attrs = attr[1]
        assert not isinstance(nested_attrs, basestring)
        value = nested_obj
        if callable(nested_attrs):
          # it is a function, call this function instead of using recursion
          value = nested_attrs(nested_obj)
        else:
          value = to_partial_json(nested_obj,nested_attrs)
        attr = attr[0]
        json_dict[attr] = value
      elif isinstance(attr, basestring) and hasattr(obj, attr):
        value = getattr(obj, attr, None)
        if hasattr(value, 'to_json'): # print attribute
          return value.to_json()
        elif hasattr(value, 'toStr'):
          return value.toStr()
        else:
          # try iteration, but not if it's a string
          if isinstance(value, collections.Iterable) and not isinstance(value, basestring): 
            v_list = list()
            for x in value:
              if hasattr(x, 'to_json'): # print attribute
                v_list.append(x.to_json())
              elif hasattr(x, 'toStr'):
                v_list.append(x.toStr())
            value = str(v_list)
          else:
            #fallback
            value = str(value)
        json_dict[attr] = value
    return json_dict
  except Exception, e:
    raise RuntimeError("to_partial_json: error")

def dump_Event(event):
  """
  Serialize every field that exists.
  """ 
  def dump_FlowTable(flow_table):
    table = list()
    for entry in flow_table.table:
      table.append()
    return table
  
  attrs = ['dpid',
           'hid',
           'cid',
           'in_port',
           'out_port',
           'buffer_id',
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
           ('action', lambda action: base64.b64encode(action.pack()).replace("\n", ""))
           ]
  fields = to_partial_json(event, attrs)
  return fields

def serialize_trace_event(event):
  fields = dump_Event(event)
  return json.dumps(fields)

class TraceHostDpPacketOut(Event):
  def __init__ (self, host, interface, packet):
#     assert_type("host", host, Host, none_ok=False)
#     assert_type("interface", interface, HostInterface, none_ok=False)
    Event.__init__(self)
    self.hid = host.hid
#     self.interface = interface
    self.packet = packet
   
class TraceSwitchDpPacketOut(Event):
  def __init__ (self, switch, port, packet):
#     assert_type("switch", switch, TracingNXSoftwareSwitch, none_ok=False)
#     assert_type("port", port, ofp_phy_port, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.out_port = port.port_no
    self.packet = packet

class TraceHostDpPacketIn(Event):
  def __init__ (self, host, interface, packet):
#     assert_type("host", host, Host, none_ok=False)
#     assert_type("interface", interface, HostInterface, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.hid = host.hid
#     self.interface = interface
    self.packet = packet
    
class TraceSwitchDpPacketIn(Event):
  def __init__ (self, switch, in_port, packet):
#     assert_type("switch", switch, FuzzSoftwareSwitch, none_ok=False)
#     assert_type("port", port, ofp_phy_port, none_ok=False)
#     assert_type("in_port", in_port, int, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    
class TraceOfMessageOut(Event):
  '''
  Switch -> Controller
  '''
  def __init__(self, dpid, cid, ofp_message, connection):
    Event.__init__(self)
    self.dpid = dpid
    self.cid = cid
    self.msg = ofp_message
#     self.connection = connection

class TraceOfMessageIn(Event):
  '''
  Controller -> Switch
  '''
  def __init__(self, switch, connection, msg):
    Event.__init__(self)
    self.dpid = switch.dpid
    self.cid = connection.cid
    self.msg = msg

class TraceFlowTableModificationBegin(Event):
  def __init__ (self, switch, flow_table, flow_mod):
    Event.__init__(self)
    self.dpid = switch.dpid
    self.flow_table = flow_table
    self.flow_mod = flow_mod
    
class TraceFlowTableModificationEnd(Event):
  def __init__ (self, switch, flow_table, flow_mod):
    Event.__init__(self)
    self.dpid = switch.dpid
    self.flow_table = flow_table
    self.flow_mod = flow_mod
    
class TraceFlowTableModificationExpired(Event):
  def __init__ (self, switch, flow_table, removed):
    Event.__init__(self)
    self.dpid = switch.dpid
    self.flow_table = flow_table
    self.expired_flows = removed
    
class TraceFlowTableMatch(Event):
  def __init__ (self, switch, in_port, packet, flow_table, entry):
#     assert_type("switch", switch, FuzzSoftwareSwitch, none_ok=False)
#     assert_type("in_port", in_port, int, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.flow_table = flow_table
    self.matched_flow = entry
    
class TraceFlowTableTouch(Event):
  def __init__ (self, switch, in_port, packet, flow_table, entry, bytes, now):
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.flow_table = flow_table
    self.touched_flow = entry
#     self.bytes = bytes
#     self.now = now

class TracePacketActionModificationBegin(Event):
  def __init__ (self, switch, in_port, packet, action):
#     assert_type("in_port", in_port, int, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
#     assert_type("precursor_packet", precursor_packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.action = action
    
class TracePacketActionModificationEnd(Event):
  def __init__ (self, switch, in_port, packet, action):
#     assert_type("in_port", in_port, int, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
#     assert_type("precursor_packet", precursor_packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.action = action
    
class TracePacketActionOutput(Event):
  def __init__ (self, switch, in_port, packet, action):
#     assert_type("in_port", in_port, int, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
#     assert_type("precursor_packet", precursor_packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.action = action
    
class TracePacketActionResubmit(Event):
  def __init__ (self, switch, in_port, packet, action):
#     assert_type("in_port", in_port, int, none_ok=False)
#     assert_type("packet", packet, ethernet, none_ok=False)
#     assert_type("precursor_packet", precursor_packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.action = action

class TracePacketBufferRead(Event):
  def __init__ (self, switch, in_port, packet, buffer_id):
#     assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.buffer_id = buffer_id

class TracePacketBufferAllocate(Event):
  def __init__ (self, switch, in_port, packet, buffer_id):
#     assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.packet = packet
    self.buffer_id = buffer_id
    
class TracePacketBufferFree(Event):
  def __init__ (self, switch, in_port, buffer_id):
#     assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.dpid = switch.dpid
    self.in_port = in_port
    self.buffer_id = buffer_id
    