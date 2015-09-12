#!/usr/bin/env python

import argparse
import os
import sys
import pprint
import ast
import json
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import sts.happensbefore.hb_utils as hbu
from sts.happensbefore.hb_json_event import JsonEvent
import sts.happensbefore.hb_events
import sts.happensbefore.hb_sts_events
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ipv4 import ipv4
from pox.openflow.flow_table import TableEntry

"""
Sample usages:
./decode_base64_str.py -m AQ4AUAAAAA8AAAABAAASNFZ4AQISNFZ4AQP//wAACAAAAQAAe3sBAnt7AQMAAAAAAAAAAAAAAAAAAAAKAB6AAAAAAAL//wAAAAAACAADAAA=

./decode_base64_str.py -t '[\"AQ4AUAAAABkAAAABAAASNFZ4AQESNFZ4AQP//wAACAAAAQAAe3sBAXt7AQMAAAAAAAAAAAAAAAAAAAAKAB6AAAAAAAH//wAAAAAACAADAAA=\", \"AQ4AUAAAABsAAAABAAASNFZ4AQISNFZ4AQP//wAACAAAAQAAe3sBAnt7AQMAAAAAAAAAAAAAAAAAAAAKAB6AAAAAAAL//wAAAAAACAADAAA=\"]'

./decode_base64_str.py -p -d 2 EjRWeAEDEjRWeAEBCABFAABIVVcAAEABLGR7ewEBe3sBAwAADjdQaW5nUGluZ1BpbmdQaW5nUGluZ1BpbmdQaW5nUGluZ1BpbmdQaW5nUGluZ1Bpbmc=
"""

def recursive_dump(x, depth):
  if depth < 1:
    return x
  else:
    try:
      if isinstance(x, list):
        res = {}
        res['___type'] = 'list'
        res['___str'] = str(x)
        res['___repr'] = repr(x)
        res['___len'] = len(x)
        idx = 1
        for i in x:
          res[idx] = recursive_dump(i, depth-1)
          idx += 1
        return res
      else:
        v = vars(x)
        res = {}
        res['___type'] = x.__module__ + "." + x.__class__.__name__
        res['___str'] = str(x)
        res['___repr'] = repr(x)
        for i in v:
          res[i] = recursive_dump(getattr(x, i), depth-1)
        return res
    except Exception as e:
      return x

def recursive_print(x, depth=1):
  pprint.pprint(recursive_dump(x, args.depth), depth=depth)

def main(args):
  if True != (args.is_pkt or 
              args.is_msg or 
              args.is_flowmod or 
              args.is_flowtable or 
              args.is_event):
    print "No type specified."

  def print_pkt(pkt):
    pkt = hbu.decode_packet(args.encoded_str)
    print "=========="
    print "pkt_info:"
    print "=========="
    print hbu.pkt_info(pkt)
    print "=========="
    print "recursive print:"
    print "=========="
    recursive_print(pkt, depth=args.depth)
    
  def print_msg(msg):
    msg = hbu.base64_decode_openflow(args.encoded_str)
    print "=========="
    print "print:"
    print "=========="
    print msg
#     print "=========="
#     print "recursive print:"
#     print "=========="
#     recursive_print(msg, depth=args.depth)

  def print_flowmod(fm):
    fm = hbu.decode_flow_mod(args.encoded_str)
    print "=========="
    print "ofp_flow_mod_command_to_str:"
    print "=========="
    opstr = ""
    opstr += hbu.ofp_flow_mod_command_to_str(fm.command)
    opstr += " => " + TableEntry.from_flow_mod(fm).show()
    print opstr
    print "=========="
    print "recursive print:"
    print "=========="
    recursive_print(fm, depth=args.depth)
    
  def print_flowtable(t):
    escaped_str = args.encoded_str.replace('\\"', '"')
    print escaped_str
    flow_list = ast.literal_eval(escaped_str)
    table = hbu.decode_flow_table(flow_list)
    print "=========="
    print "print"
    print "=========="
    print table
    print "length: {}".format(len(table))
    i = 1
    for entry in table.table:
      print "Entry {}:".format(i), 
      print entry
      i += 1
    recursive_print(table, depth=args.depth)
    
  def print_event(ev):
    ev = JsonEvent.from_json(json.loads(args.encoded_str))
    print "=========="
    print "print: ev"
    print "=========="
    print ev
    print "=========="
    print "recursive print:"
    print "=========="
    recursive_print(ev, depth=args.depth)
    
  if args.is_pkt:
    print_pkt(args.encoded_str)
  if args.is_msg:
    print_msg(args.encoded_str)
  if args.is_flowmod:
    print_flowmod(args.encoded_str)
  if args.is_flowtable:
    print_flowtable(args.encoded_str)
  if args.is_event:
    print_event(args.encoded_str)
    

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('encoded_str')
  parser.add_argument('-p', dest='is_pkt', action='store_true', default=False, help="Decode as packet")
  parser.add_argument('-m', dest='is_msg', action='store_true', default=False, help="Decode as OpenFlow message")
  parser.add_argument('-f', dest='is_flowmod', action='store_true', default=False, help="Decode as flow mod")
  parser.add_argument('-t', dest='is_flowtable', action='store_true', default=False, help="Decode as flow table (list of flows mods)")
  parser.add_argument('-e', dest='is_event', action='store_true', default=False, help="Decode as JsonEvent")
  parser.add_argument('-d', dest='depth', action='store', type=int, default=1, help="Depth for printing")
  
  args = parser.parse_args()

  main(args)