from pox.lib.revent import Event
from pox.openflow.libopenflow_01 import *
from sts.happensbefore.hb_json_event import JsonEvent, AttributeCombiningMetaclass
from sts.util.convenience import base64_encode, get_port_no, base64_encode_flow_table, base64_encode_flow_list, base64_encode_flow

import base64
from collections import OrderedDict
import itertools
import json

class HbEvent(JsonEvent):
  __metaclass__ = AttributeCombiningMetaclass
  _attr_combining_metaclass_args = ["_to_json_attrs"]
  
  _to_json_attrs = ['pid_in',
                    'pid_out',
                    'mid_in',
                    'mid_out',
                    ('msg_type', lambda ofp_type: ofp_type_rev_map.keys()[ofp_type_rev_map.values().index(ofp_type)]),
                    ('operations', lambda xs: [x.to_json() for x in xs]),
                    'dpid',
                    'controller_id', # socket.getpeername(), NOT the STS cid
                    'hid',
                    ('packet', base64_encode),
                    ('in_port', get_port_no),
                    ('out_port', get_port_no),
                    ('msg', base64_encode),
                    ]
                     
class HbPacketHandle(HbEvent):
  def __init__(self, pid_in, pid_out=None, mid_out=None, operations=None, dpid=None, packet=None, in_port=None, buffer_out=None):
    HbEvent.__init__(self)
    self.pid_in = pid_in
    self.pid_out = [] if pid_out is None else pid_out
    self.mid_out = [] if mid_out is None else mid_out
    
    self.operations = [] if operations is None else operations
    
    self.dpid = dpid
    self.packet = packet
    self.in_port = in_port
    
class HbPacketSend(HbEvent):
  def __init__(self, pid_in, pid_out, dpid=None, packet=None, out_port=None):
    HbEvent.__init__(self)
    self.pid_in = pid_in
    self.pid_out = pid_out
    
    self.dpid = dpid
    self.packet = packet
    self.out_port = out_port
    
class HbMessageHandle(HbEvent):
  def __init__(self, mid_in, msg_type, operations=None, pid_in=None, pid_out=None, mid_out=None, dpid=None, controller_id=None, msg=None, buffer_in=None):
    HbEvent.__init__(self)
    self.pid_in = pid_in # to be filled in when a read from buffer occurs
    self.mid_in = mid_in # filled in, but never matches a mid_out. This link will be filled in by controller instrumentation. 
    self.msg_type = msg_type
    self.pid_out = [] if pid_out is None else pid_out
    self.mid_out = [] if mid_out is None else mid_out

    self.operations = [] if operations is None else operations

    self.dpid = dpid # possibly needed to match with controller instrumentation
    self.controller_id = controller_id # possibly needed to match with controller instrumentation
    self.msg = msg
    
class HbMessageSend(HbEvent):
  def __init__(self, mid_in, mid_out, msg_type, dpid=None, controller_id=None, msg=None):
    HbEvent.__init__(self)
    self.mid_in = mid_in
    self.mid_out = mid_out # filled in, but never matches a mid_in. This link will be filled in by controller instrumentation.
    self.msg_type = msg_type

    self.dpid = dpid
    self.controller_id = controller_id
    self.msg = msg
    
class HbHostHandle(HbEvent):
  def __init__(self, pid_in, pid_out=None, operations=None, hid=None, packet=None, in_port=None):
    HbEvent.__init__(self)
    self.pid_in = pid_in
    self.pid_out = [] if pid_out is None else pid_out
    
    self.operations = [] if operations is None else operations
    
    self.hid = hid
    self.packet = packet
    self.in_port = in_port

class HbHostSend(HbEvent):
  def __init__(self, pid_in, pid_out, hid=None, packet=None, out_port=None):
    HbEvent.__init__(self)
    self.pid_in = pid_in
    self.pid_out = pid_out
    
    self.hid = hid
    self.packet = packet
    self.out_port = out_port
    
class HbControllerHandle(HbEvent):
  def __init__(self, mid_in, mid_out):
    HbEvent.__init__(self)
    self.mid_in = mid_in # Link with HbMessageSend
    self.mid_out = [mid_out] # Generated
    
class HbControllerSend(HbEvent):
  def __init__(self, mid_in, mid_out):
    HbEvent.__init__(self)
    self.mid_in = mid_in # Generated
    self.mid_out = [mid_out] # Link with HbMessageHandle
    
    
    
