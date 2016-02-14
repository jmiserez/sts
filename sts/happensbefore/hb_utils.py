"""
Various utils functions, some are copied from STS.
"""
import base64
from functools import partial


from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import _type_to_name as icmp_names
from pox.lib.packet.packet_utils import ipproto_to_str
from pox.openflow.flow_table import SwitchFlowTable
from pox.openflow.flow_table import TableEntry
from pox.openflow.software_switch import OFConnection
from pox.openflow.libopenflow_01 import ofp_flow_mod
from pox.openflow.libopenflow_01 import ofp_type_rev_map
from pox.openflow.libopenflow_01 import ofp_flow_mod_command_rev_map
from pox.openflow.libopenflow_01 import ofp_flow_removed_reason_rev_map


def enum(*sequential, **named):
  enums = dict(zip(sequential, range(len(sequential))), **named)
  reverse = dict((value, key) for key, value in enums.iteritems())
  @classmethod
  def _names(cls): # returns dict: ordinal -> string
    return reverse
  enums['_names'] = _names
  @classmethod
  def _ordinals(cls): # returns dict: string -> ordinal
    # filter _names, _ordinals
    return {k: v for k, v in enums.items() if not k.startswith('_')}
  enums['_ordinals'] = _ordinals
  return type('Enum', (), enums)


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


def base64_encode_flow(flow, set_zero_XID=False):
  """
  Optionally set the xid to 0 right before encoding, to enable comparisons on the base64 string.
  """
  if not hasattr(flow, 'to_flow_mod'):
    tmp = flow
  else:
    tmp = flow.to_flow_mod()
  if flow is None:
    return None
  else:
    if set_zero_XID:
      tmp.xid = 0
    return base64_encode(tmp)


def base64_encode_flow_list(flows, set_zero_XID=False):
  return None if flows is None else [base64_encode_flow(entry, set_zero_XID) for entry in flows]


def base64_encode_flow_table(flow_table, set_zero_XID=False):
  return None if flow_table is None else base64_encode_flow_list(flow_table.table, set_zero_XID)


def compare_flow_table(table, other):
  fm1 = []
  for i in table.table:
    fm1.append(i.to_flow_mod())
  fm2 = []
  for i in other.table:
    fm2.append(i.to_flow_mod())

  # TODO(jm): This could be improved by using anewer version of POX,
  # where flow table entries are always in priority order.
  # Then only one pass would be necessary.
  for i in fm1:
    if i not in fm2:
      return False
  for i in fm2:
    if i not in fm1:
      return False
  return True


def read_flow_table(table, packet, in_port):
  return table.entry_for_packet(packet, in_port)


def write_flow_table(table, flow_mod):
  return table.process_flow_mod(flow_mod)

def find_entries_in_flow_table(table, other_flow_mod):
  other = ofp_flow_mod()
  other.unpack(other_flow_mod.pack())
  other.xid = 0
  
  found = []
  for i in table.table:
    this_entry = ofp_flow_mod()
    this_entry.unpack(i.to_flow_mod().pack())
    this_entry.xid = 0
    if this_entry == other:
      found.append(i)
  return found


def nCr(n,r):
  """
  Implements multiplicative formula:
  https://en.wikipedia.org/wiki/Binomial_coefficient#Multiplicative_formula
  """
  if r < 0 or r > n:
    return 0
  if r == 0 or r == n:
      return 1
  c = 1
  for i in xrange(min(r, n - r)):
      c = c * (n - i) // (i + 1)
  return c


def ofp_type_to_str(t):
  return ofp_type_rev_map.keys()[ofp_type_rev_map.values().index(t)]

def ofp_flow_removed_reason_to_str(r):
  return ofp_flow_removed_reason_rev_map.keys()[ofp_flow_removed_reason_rev_map.values().index(r)]

def str_to_ofp_flow_removed_reason(r):
  return ofp_flow_removed_reason_rev_map[r]

def ofp_flow_mod_command_to_str(t):
  return ofp_flow_mod_command_rev_map.keys()[ofp_flow_mod_command_rev_map.values().index(t)]


def eth_repr(pkt):
  s = ''.join(('ETH: ', '[', str(EthAddr(pkt.src)), '>', str(EthAddr(pkt.dst)), ':',
              ethernet.getNameForType(pkt.type), ']'))
  if pkt.next is None:
    pass
  elif pkt.type == ethernet.LLDP_TYPE:
    s += "| LLDP"
  elif pkt.type == 35138:
    print "BUGGY PKT type {0} str type {1}".format(pkt.type, ethernet.getNameForType(pkt.type))
    s += "| Unkown PKT"
  else:
    s += "|" + str(pkt.next)
  return '\\n'.join(s.split('|'))


def icmp_repr(pkt):
  t = icmp_names.get(pkt.type, str(pkt.type))
  s = 'ICMP: {t:%s c:%i}' % (t, pkt.code)
  if pkt.next is None:
      return s
  return '|' + ''.join((s, str(pkt.next)))


def ipv4_repr(pkt):
  s = 'IPv4' + ''.join(('(','['#+'v:'+str(self.v),'hl:'+str(self.hl),\
                     #    'l:', str(self.iplen)
                     'ttl:', str(pkt.ttl), ']',
                      ipproto_to_str(pkt.protocol), \
                      #   ' cs:', '%x' %self.csum,
                      '[',str(pkt.srcip), '>', str(pkt.dstip),'])'))
  if pkt.next == None:
      return s
  return '|' + ''.join((s, str(pkt.next)))


def pkt_info(packet):
  """
  Returns a string representation of base64 encoded packet

  Note: this function moneky patches __str__ in ethernet, icmp, ipv4, etc..
  """
  ethernet.__str__ = eth_repr
  icmp.__str__ = icmp_repr
  ipv4.__str__ = ipv4_repr
  return str(packet)


def op_to_str(op):
  """Helper function to pretty print Operations"""
  if op.type == 'TraceSwitchFlowTableWrite':
    opstr = "Write: "
  elif op.type == 'TraceSwitchFlowTableRead':
    opstr = "Read: "
  else:
    opstr = op.type + ": "
  if op.flow_mod:
    opstr += ofp_flow_mod_command_to_str(op.flow_mod.command)
    opstr += " => " + TableEntry.from_flow_mod(op.flow_mod).show()
  elif hasattr(op, 'packet'):
    opstr += str(op.packet)
  else:
    opstr += "None"
  return opstr


def dfs_edge_filter(G, source, edges_iter_func=lambda g, start: iter(g[start]), filter_msg_type=None):
  """
  Do DFS over graph G starting from optional source.
  edges_iter_func is a function that takes two arguments (graph and a node) then
  it returns iterator over nodes connected to the start. This gives us the
  ability to interpose and filter certain edges.
  """
  if source is None:
    # produce edges for all components
    nodes = G
  else:
    # produce edges for components with source
    nodes = [source]
  visited=set()
  for start in nodes:
    if start in visited:
      continue
    visited.add(start)
    stack = [(start, edges_iter_func(G, start))]
    while stack:
      parent,children = stack[-1]
      try:
        child = next(children)
        if filter_msg_type and \
                getattr(G.node[child].get('event', None), 'msg_type_str', None) == filter_msg_type:
          continue
        if child not in visited:
          yield parent,child
          visited.add(child)
          stack.append((child, edges_iter_func(G, child)))
      except StopIteration:
          stack.pop()

def rel_filter(G, source, rel):
  for eid, attrs in G[source].iteritems():
    if attrs['rel'] == rel:
      yield eid


just_mid_iter = partial(rel_filter, rel='mid')


def pretty_match(match):
  if not match:
    return ''
  outstr = ''
  def append (f, formatter=str):
    v = match.__getattr__(f)
    if v is None: return ''
    return f + ": " + formatter(v) + " "
  outstr = ''
  outstr += append('in_port')
  outstr += append('dl_src')
  outstr += append('dl_dst')
  outstr += append('dl_vlan')
  outstr += append('dl_vlan_pcp')
  outstr += append('dl_type')
  outstr += append('nw_tos')
  outstr += append('nw_proto')
  outstr += append('nw_src')
  outstr += append('nw_dst')
  outstr += append('tp_src')
  outstr += append('tp_dst')
  return outstr