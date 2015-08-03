"""
Various utils functions, some are copied from STS.
"""
import base64

from pox.lib.packet.ethernet import ethernet
from pox.openflow.flow_table import SwitchFlowTable
from pox.openflow.flow_table import TableEntry
from pox.openflow.software_switch import OFConnection
from pox.openflow.libopenflow_01 import ofp_flow_mod


def check_list(obj):
  if isinstance(obj, list):
    return obj
  return [obj] if obj else []


def get_port_no(obj):
  """
  Try obj, obj.port_no, obj.port_no()
  """
  if isinstance(obj, (basestring, int, long)):
    return obj
  if hasattr(obj, "port_no"):
    port_no = getattr(obj, "port_no")
    if isinstance(port_no, (basestring, int, long)):
      return port_no
    try:
      port_no = port_no()
      if isinstance(port_no, (basestring, int, long)):
        return port_no
      return str(port_no)
    except:
      return str(port_no)
  return str(obj)


def base64_encode_raw(packet):
  """Calling pack() on a Openflow message might modify/add an XID."""
  # base 64 occasionally adds extraneous newlines: bit.ly/aRTmNu
  if packet is None:
    return None
  return base64.b64encode(packet).replace("\n", "")


def base64_encode(packet):
  """Encode packet to base64 string"""
  if hasattr(packet, "pack"):
    packet = packet.pack()
  # base 64 occasionally adds extraneous newlines: bit.ly/aRTmNu
  return base64_encode_raw(packet)


def base64_decode(data):
  """Decode base64 string"""
  return base64.b64decode(data)

def base64_decode_openflow(data):
  """Decode openflow message from base64 string to msg object"""
  (msg, packet_length) = OFConnection.parse_of_packet(base64_decode(data))
  return msg


def decode_flow_mod(data):
  """Decode flow mod from base64 string to ofp_flow_mod object."""
  if data is None:
    return None
  bits = base64_decode(data)
  fm = ofp_flow_mod()
  fm.unpack(bits) # NOTE: unpack IS in-situ for ofp_flow_mod() type
  return fm


def decode_packet(data):
  """Decode a packet in base64 string to pox.lib.packet.ethernet object."""
  bits = base64_decode(data)
  p = ethernet()
  p = p.unpack(bits) # NOTE: unpack IS NOT in-situ for ethernet() type
  return p


def decode_flow_table(data):
  """Decode a list of flow from base64 to SwitchFlowTable object."""
  table = SwitchFlowTable()
  for row in data:
    flow_mod = decode_flow_mod(row)
    entry = TableEntry.from_flow_mod(flow_mod)
    table.add_entry(entry)
  return table


def base64_encode_flow(flow):
  tmp = flow if not hasattr(flow, 'to_flow_mod') else flow.to_flow_mod()
  return None if flow is None else base64_encode(tmp)


def base64_encode_flow_list(flows):
  return None if flows is None else [base64_encode_flow(entry) for entry in flows]


def base64_encode_flow_table(flow_table):
  return None if flow_table is None else base64_encode_flow_list(flow_table.table)
