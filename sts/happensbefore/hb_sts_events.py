from pox.lib.revent import Event

class SwitchEvent(Event):
  def __init__(self):
    Event.__init__(self)
    
class SwitchPacketHandleBegin(SwitchEvent):
  def __init__(self, dpid, packet, in_port):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.in_port = in_port
  
class SwitchPacketHandleEnd(SwitchEvent):
  def __init__(self, dpid):
    SwitchEvent.__init__(self)
    self.dpid = dpid
  
class SwitchMessageHandleBegin(SwitchEvent):
  def __init__(self, dpid, msg):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.msg = msg
  
class SwitchMessageHandleEnd(SwitchEvent):
  def __init__(self, dpid):
    SwitchEvent.__init__(self)
    self.dpid = dpid
  
class SwitchMessageSend(SwitchEvent):
  def __init__(self, dpid, msg):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.msg = msg

class SwitchPacketSend(SwitchEvent):
  def __init__(self, dpid, packet, out_port):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.out_port = out_port
  
class SwitchFlowTableRead(SwitchEvent):
  def __init__(self, dpid, in_port, packet, flow_table, entry, touch_bytes, touch_now):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.in_port = in_port
    self.packet = packet
    self.flow_table = flow_table
    self.entry = entry
    self.touch_bytes = touch_bytes
    self.touch_now = touch_now
  
class SwitchFlowTableWrite(SwitchEvent):
  def __init__(self, dpid, flow_table, flow_mod):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.flow_table = flow_table
    self.flow_mod = flow_mod
    
class SwitchFlowTableRuleExpired(SwitchEvent):
  def __init__(self, dpid, flow_table, removed):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.flow_table = flow_table
    self.removed = removed

class SwitchBufferPut(SwitchEvent):
  def __init__(self, dpid, packet, in_port, buffer_id):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.buffer_id = buffer_id

class SwitchBufferGet(SwitchEvent):
  def __init__(self, dpid, packet, in_port, buffer_id):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    self.buffer_id = buffer_id

class SwitchPacketUpdateBegin(SwitchEvent):
  def __init__(self, dpid, packet):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet

class SwitchPacketUpdateEnd(SwitchEvent):
  def __init__(self, dpid, packet):
    SwitchEvent.__init__(self)
    self.dpid = dpid
    self.packet = packet
    
class HostEvent(Event):
  def __init__(self):
    Event.__init__(self)
    
class HostPacketHandleBegin(HostEvent):
  def __init__(self, hid, packet):
    HostEvent.__init__(self)
    self.hid = hid
    self.packet = packet
    
class HostPacketHandleEnd(HostEvent):
  def __init__(self, hid, packet):
    HostEvent.__init__(self)
    self.hid = hid

class HostPacketSend(HostEvent):
  def __init__(self, hid, packet):
    HostEvent.__init__(self)
    self.hid = hid
    self.packet = packet
    
    
    
    
