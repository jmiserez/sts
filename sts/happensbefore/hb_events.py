"""
HB events
"""


from pox.openflow.libopenflow_01 import *
import json

from hb_utils import *
from hb_json_event import JsonEvent
from hb_json_event import AttributeCombiningMetaclass


class HbEvent(JsonEvent):
  __metaclass__ = AttributeCombiningMetaclass
  _attr_combining_metaclass_args = ["_to_json_attrs"]
  
  _to_json_attrs = ['pid_in',  # Incoming Packet ID
                    'pid_out', # Outgoing Packet ID
                    'mid_in',  # Message ID (from the switch to the controller)
                    'mid_out', # Message ID (from the controller to the switch)
                    # The type of the message (what are the possible types?)
                    # is it just Pkt_In, Pkt_Out, Barrier_Req, Port_Mod, Flod_mod, Flow_Removed?)
                    ('msg_type', lambda ofp_type: ofp_type_rev_map.keys()[ofp_type_rev_map.values().index(ofp_type)]),
                    # ????
                    ('operations', lambda xs: [x.to_json() for x in xs]),
                    'dpid',  # The unique per switch datapath ID
                    'controller_id', # socket.getpeername(), NOT the STS cid (#NOTE (AH):  why not?)
                    'hid',  # Host ID
                    ('packet', base64_encode),  # The content of the packet
                    ('in_port', get_port_no),  # The ingress port number
                    ('out_port', get_port_no),  # The egress port number
                    ('msg', base64_encode),  # The content of the openflow message
                    ('msg_flowmod', base64_encode),  #NOTE (AH):  how is it different from the above?
                    ]

  _from_json_attrs = {
    'eid': lambda x: x,
    'pid_in': lambda x: x, # Incoming Packet ID
    'pid_out': lambda x: x, # Outgoing Packet ID
    'mid_in': lambda x: x,  # Message ID (from the switch to the controller)
    'mid_out': lambda x: x, # Message ID (from the controller to the switch)
    # The type of the message (what are the possible types?)
    # is it just Pkt_In, Pkt_Out, Barrier_Req, Port_Mod, Flod_mod, Flow_Removed?)
    'msg_type': lambda x: ofp_type_rev_map[x],
    # ????
    'operations': lambda v: [JsonEvent.from_json(json.loads(x)) for x in v],
    'dpid': lambda x: x,  # The unique per switch datapath ID
    'controller_id': lambda x: x, # socket.getpeername(), NOT the STS cid (#NOTE (AH):  why not?)
    'hid': lambda x: x,  # Host ID
    'packet': lambda x: decode_packet(x) if x else None,  # The content of the packet
    'in_port': lambda x: x,  # The ingress port number
    'out_port': lambda x: x,  # The egress port number
    'msg': base64_decode_openflow,  # The content of the openflow message
    'msg_flowmod': base64_decode,  #NOTE (AH):  how is it different from the above?
  }


  def __init__(self, eid=None):
    super(HbEvent, self).__init__(eid=eid)


class HbAsyncFlowExpiry(HbEvent):
  '''
  "Async", as flows expire due to a timer running out. As this can happen even during another event, it needs to be handled separately.
  Note that a single TraceSwitchFlowTableEntryExpiry operation is always part of this event once finished, but operations of this type
  can also be part of HbMessageHandle operations (specifically FLOW_MOD, DELETE messages).
  '''
  def __init__(self, mid_in=None, mid_out=None, operations=None, dpid=None,
               eid=None):
    HbEvent.__init__(self, eid=eid)
    self.mid_in = mid_in # to be filled in later: predecessor is the HbMessageHandle that installed the flow (with the same cookie)
    self.mid_out = check_list(mid_out)

    self.operations = check_list(operations)

    self.dpid = dpid


class HbPacketHandle(HbEvent):
  """
  When a switch finished processing packet PID_IN.
  The possible outcomes of this process are:
    1. OpenFlow message to the controller (Pkt_Out)
    2. Packet is forwarded, then PID_OUT will contain the new identifier.
  """
  #NOTE (AH): What about dropped packets?
  #NOTE (AH): What about duplicated packets? for example a switch can forward the same packet to multiple ports
  #NOTE (AH): What buffer_out is for? It's not used!
  def __init__(self,pid_in, pid_out=None, mid_out=None, operations=None,
               dpid=None, packet=None, in_port=None, buffer_out=None, eid=None):
    HbEvent.__init__(self, eid=eid)
    self.pid_in = pid_in
    self.pid_out = check_list(pid_out)
    self.mid_out = check_list(mid_out)
    
    self.operations = check_list(operations)
    
    self.dpid = dpid
    self.packet = packet
    self.in_port = in_port


class HbPacketSend(HbEvent):
  """
  Packet (PID_IN) was sent from switch (DPID) port (out_port) with new identifier (PID_OUT).
  """
  def __init__(self, pid_in, pid_out, dpid=None, packet=None, out_port=None,
               eid=None):
    HbEvent.__init__(self, eid=eid)
    self.pid_in = pid_in
    self.pid_out = check_list(pid_out)
    
    self.dpid = dpid
    self.packet = packet
    self.out_port = out_port


class HbMessageHandle(HbEvent):
  """
  Switch processing OpenFlow message (mid_in, msg_type, and content msg) from
  controller (controller_id).

  pid_in is set if the switch read a packet from the buffer as result
  from processing the OF message.
  """
  #NOTE (AH): what are the other arguments, mid_out, pid_out, operations?
  #NOTE (AH): is buffer_in used?
  def __init__(self, mid_in, msg_type, operations=None, pid_in=None,
               pid_out=None, mid_out=None, dpid=None, controller_id=None,
               msg=None, buffer_in=None, msg_flowmod=None, packet=None,
               in_port=None, eid=None):
    HbEvent.__init__(self, eid=eid)
    self.pid_in = pid_in # to be filled in when a read from buffer occurs
    self.mid_in = mid_in # filled in, but never matches a mid_out. This link will be filled in by controller instrumentation. 
    self.msg_type = msg_type
    self.pid_out = check_list(pid_out)
    self.mid_out = check_list(mid_out)

    self.operations = check_list(operations)

#     self.packet = None # possible to get through OFPP_TABLE/buffer put
#     self.in_port = None # possible to get through OFPP_TABLE/buffer put

    self.dpid = dpid # possibly needed to match with controller instrumentation
    self.controller_id = controller_id # possibly needed to match with controller instrumentation
    self.msg = msg
    self.packet = packet
    self.in_port = in_port
    if msg_flowmod is not None:
      self.msg_flowmod = msg_flowmod # needed for rule 3

  @property
  def msg_type_str(self):
    return ofp_type_to_str(self.msg_type)


class HbMessageSend(HbEvent):
  """
  OpenFlow message with mid_in was sent to the controller with the new identifier in mids_out.
  #NOTE (AH): Can you we explain this better?
  """
  def __init__(self, mid_in, mid_out, msg_type, dpid=None, controller_id=None,
               msg=None, eid=None):
    HbEvent.__init__(self, eid=eid)
    self.mid_in = mid_in
    self.mid_out = check_list(mid_out) # filled in, but never matches a mid_in. This link will be filled in by controller instrumentation.
    self.msg_type = msg_type

    self.dpid = dpid
    self.controller_id = controller_id
    self.msg = msg

  @property
  def msg_type_str(self):
    return ofp_type_to_str(self.msg_type)


class HbHostHandle(HbEvent):
  """
  A host (hid) handling a packet (pid_in, packet) on port (in_port)
  and maybe sending another packet in response (pid_out).
  """
  def __init__(self, pid_in, pid_out=None, operations=None, hid=None,
               packet=None, in_port=None, eid=None):
    HbEvent.__init__(self, eid=eid)
    self.pid_in = pid_in
    self.pid_out = check_list(pid_out)
    
    self.operations = check_list(operations)
    
    self.hid = hid
    self.packet = packet
    self.in_port = in_port


class HbHostSend(HbEvent):
  """
  A host (hid) is sending a packet (pid_out, packet) on port (out_port).
  """
  #NOTE (AH); what pid_in is for?
  def __init__(self, pid_in, pid_out, hid=None, packet=None, out_port=None,
               eid=None):
    HbEvent.__init__(self, eid=eid)
    self.pid_in = pid_in
    self.pid_out = check_list(pid_out)
    
    self.hid = hid
    self.packet = packet
    self.out_port = out_port


class HbControllerHandle(HbEvent):
  """
  Controller handled an OF message (mid_in)
  and maybe generated another (mid_out).
  """
  #NOTE (AH): Don't we need the CID?
  def __init__(self, mid_in, mid_out, eid=None):
    HbEvent.__init__(self, eid=eid)
    self.mid_in = mid_in
    self.mid_out = check_list(mid_out) # Generated, link with HbMessageSend


class HbControllerSend(HbEvent):
  """
  Controller send an OF message (mid_out).
  """
  #NOTE (AH): what mid_in is for?
  #NOTE (AH): Don't we need the CID?
  def __init__(self, mid_in, mid_out, eid=None):
    HbEvent.__init__(self, eid=eid)
    self.mid_in = mid_in # Generated, link with HbMessageHandle
    self.mid_out = check_list(mid_out)


JsonEvent.register_type(HbEvent)
JsonEvent.register_type(HbAsyncFlowExpiry)
JsonEvent.register_type(HbPacketHandle)
JsonEvent.register_type(HbPacketSend)
JsonEvent.register_type(HbMessageHandle)
JsonEvent.register_type(HbMessageSend)
JsonEvent.register_type(HbHostHandle)
JsonEvent.register_type(HbHostSend)
JsonEvent.register_type(HbControllerHandle)
JsonEvent.register_type(HbControllerSend)