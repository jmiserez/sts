from pox.lib.revent import Event

import base64
from collections import OrderedDict
import itertools
import json

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
              ('table_reads_writes', lambda xs: [x.to_json() for x in xs]),
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
  def __init__(self, dpid, pid_in, pid_out, mid_out, packet):
    self.dpid = dpid
    self.pid_in = pid_in
    self.pid_out = pid_out
    self.mid_out = mid_out
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