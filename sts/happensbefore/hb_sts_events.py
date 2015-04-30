import base64
from collections import OrderedDict
import itertools
import json

from pox.lib.revent import Event
from pox.lib.util import assert_type
from sts.happensbefore.hb_json_event import JsonEvent, AttributeCombiningMetaclass
from sts.util.convenience import base64_encode, get_port_no, base64_encode_flow_table, base64_encode_flow_list, base64_encode_flow

class TraceSwitchEvent(JsonEvent):
  __metaclass__ = AttributeCombiningMetaclass
  _attr_combining_metaclass_args = ["_to_json_attrs"]
  
  #TODO(jm): clean up/remove unused ones, check which ones are actually used in hb_graph and hb_events and remove the ones that are not used.
  _to_json_attrs = ['dpid',
                    'controller_id', # socket.getpeername(), NOT the STS cid
                    'hid',
                    ('packet', base64_encode),
                    ('in_port', get_port_no),
                    ('out_port', get_port_no),
                    'buffer_id',
                    ('msg', base64_encode),
                    'flow_table', #encoded immediately
                    'flow_mod', #encoded immediately
                    'removed', #encoded immediately # TODO(jm): add this to race detector
                    ('expired_flows', base64_encode_flow_list),
                    ('matched_flow', base64_encode_flow),
                    ('touched_flow', base64_encode_flow),
                    'touched_flow_bytes',
                    ('touched_flow_now', lambda fp: repr(fp)), # str() is not precise for floating point numbers in Python < v3.2
                    ]
               
class TraceSwitchPacketHandleBegin(TraceSwitchEvent):
  def __init__(self, dpid, packet, in_port):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.in_port = in_port
  
class TraceSwitchPacketHandleEnd(TraceSwitchEvent):
  def __init__(self, dpid):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid

class TraceSwitchMessageRx(TraceSwitchEvent):
  def __init__(self, msg, b64msg):
    TraceSwitchEvent.__init__(self)
    self.msg = msg
    self.b64msg = b64msg

class TraceSwitchMessageHandleBegin(TraceSwitchEvent):
  def __init__(self, dpid, controller_id, msg, msg_type):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.controller_id = controller_id
    self.msg = msg
    self.msg_type = msg_type
  
class TraceSwitchMessageHandleEnd(TraceSwitchEvent):
  def __init__(self, dpid):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
  
class TraceSwitchMessageSend(TraceSwitchEvent):
  def __init__(self, dpid, controller_id, msg):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.controller_id = controller_id
    self.msg = msg

class TraceSwitchPacketSend(TraceSwitchEvent):
  def __init__(self, dpid, packet, out_port):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.out_port = out_port
  
class TraceSwitchFlowTableRead(TraceSwitchEvent):
  def __init__(self, dpid, packet, in_port, flow_table, entry, touch_bytes, touch_now):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.in_port = in_port
    self.flow_table = base64_encode_flow_table(flow_table)
    self.flow_mod = base64_encode_flow(entry)
    self.entry = entry
    self.touch_bytes = touch_bytes
    self.touch_now = touch_now
  
class TraceSwitchFlowTableWrite(TraceSwitchEvent):
  def __init__(self, dpid, flow_table, flow_mod):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.flow_table = base64_encode_flow_table(flow_table)
    self.flow_mod = base64_encode(flow_mod)
    
class TraceSwitchFlowTableEntryExpiry(TraceSwitchEvent):
  def __init__(self, dpid, flow_table, removed):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.flow_table = base64_encode_flow_table(flow_table)
    self.flow_mod = base64_encode_flow(removed)
    self.removed = base64_encode_flow(removed)

class TraceSwitchBufferPut(TraceSwitchEvent):
  def __init__(self, dpid, packet, in_port, buffer_id):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.in_port = in_port
    self.buffer_id = buffer_id

class TraceSwitchBufferGet(TraceSwitchEvent):
  def __init__(self, dpid, packet, in_port, buffer_id):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.in_port = in_port
    self.buffer_id = buffer_id

class TraceSwitchPacketUpdateBegin(TraceSwitchEvent):
  def __init__(self, dpid, packet):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet

class TraceSwitchPacketUpdateEnd(TraceSwitchEvent):
  def __init__(self, dpid, packet):
    TraceSwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    
class TraceHostEvent(Event):
  def __init__(self):
    Event.__init__(self)
    
class TraceHostPacketHandleBegin(TraceHostEvent):
  def __init__(self, hid, packet, in_port):
    TraceHostEvent.__init__(self)
    self.hid = hid
    self.packet = packet
    self.in_port = in_port
    
class TraceHostPacketHandleEnd(TraceHostEvent):
  def __init__(self, hid):
    TraceHostEvent.__init__(self)
    self.hid = hid

class TraceHostPacketSend(TraceHostEvent):
  def __init__(self, hid, packet, out_port):
    TraceHostEvent.__init__(self)
    self.hid = hid
    self.packet = packet
    self.out_port = out_port
    
    
    
    
