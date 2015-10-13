#!/usr/bin/env python


import argparse
import csv
import glob
import os
from pylab import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages


# Values we care about
keys = []
keys.append('num_read')
keys.append('num_writes')
keys.append('num_ops')

keys.append('num_rw_time_edges')
keys.append('num_ww_time_edges')
keys.append('num_time_edges')

keys.append('num_harmful')
keys.append('num_commute')
keys.append('num_races')
keys.append('num_covered')

keys.append('num_per_pkt_races')
keys.append('num_per_pkt_inconsistent')
keys.append('num_per_pkt_inconsistent_covered')
keys.append('num_per_pkt_race_version')
keys.append('num_per_pkt_inconsistent_no_repeat')

keys.append('total_time_sec')
keys.append('load_time_sec')
keys.append('detect_races_time_sec')
keys.append('extract_traces_time_sec')
keys.append('find_reactive_cmds_time_sec')
keys.append('find_proactive_cmds_time_sec')
keys.append('find_covered_races_time')
keys.append('per_packet_inconsistent_time_sec')
keys.append('find_inconsistent_update_time_sec')


per_pkt_consistenty =  ['num_per_pkt_races', 'num_per_pkt_inconsistent',
                        'num_per_pkt_inconsistent_covered',
                        'num_per_pkt_race_version']

def main(result_dirs):
  tables = {}
  for name in result_dirs:
    fname = name
    if not fname.endswith('.csv'):
      fname = os.path.join(name, 'summary.csv')
    with open(fname) as csvfile:
      table = {}
      keys = []
      data = csv.reader(csvfile, delimiter=',')
      for row in data:
        if row[0] == 'key/t':
          row = [int(x) for x in row[1:] if x!= 'inf']
          row = ['key/t', 11] + row
        table[row[0]] = row[1:]
      short_name = os.path.basename(os.path.normpath(name))
      tables[short_name] = table
  

  keys_to_plot = ['num_harmful', 'num_commute', 'num_races', 'num_rw_time_edges', 'num_ww_time_edges',
            'num_per_pkt_races', 'num_per_pkt_inconsistent', 'num_per_pkt_inconsistent_covered', 'num_per_pkt_race_version', 'num_per_pkt_inconsistent_no_repeat']

  # Plot summaries for all values
  for key in keys_to_plot:
    plot_with_delta(tables, key, False)

  for name in tables:
    plot_with_delta_multiple(tables, name,
                             out_name=get_short_name(name) + "_pkt_consist",
                             keys=per_pkt_consistenty,
                             use_log=False)


def get_short_name(name):
  names = {}
  names['trace_floodlight_forwarding-BinaryLeafTreeTopology1-steps100'] = 'FL_FWD-BinTree1-steps100'
  names['trace_floodlight_forwarding-BinaryLeafTreeTopology1-steps200'] = 'FL_FWD-BinTree1-steps200'
  names['trace_floodlight_forwarding-BinaryLeafTreeTopology2-steps100'] = 'FL_FWD-BinTree2-steps100'
  names['trace_floodlight_forwarding-BinaryLeafTreeTopology2-steps200'] = 'FL_FWD-BinTree2-steps200'

  names['trace_pox_ConsistencyTopology-False-False-steps100'] = 'pox_Inconsistent-Wait-steps100'
  names['trace_pox_ConsistencyTopology-False-False-steps200'] = 'pox_Inconsistent-Wait-steps200'
  names['trace_pox_ConsistencyTopology-False-True-steps100'] = 'pox_Inconsistent-Barriers-steps100'
  names['trace_pox_ConsistencyTopology-False-True-steps200'] = 'pox_Inconsistent-Barriers-steps200'
  names['trace_pox_ConsistencyTopology-True-False-steps100'] = 'pox_Consistent-Wait-steps100'
  names['trace_pox_ConsistencyTopology-True-False-steps200'] = 'pox_Consistent-Wait-steps200'
  names['trace_pox_ConsistencyTopology-True-True-steps100'] = 'pox_Consistent-Barriers-steps100'
  names['trace_pox_ConsistencyTopology-True-True-steps200'] = 'pox_Consistent-Barriers-steps200'

  if name in names:
    return names[name]

  new_name = name
  new_name = new_name.replace('trace_', '')
  new_name = new_name.replace('floodlight', 'FL')
  new_name = new_name.replace('BinaryLeafTreeTopology', 'BinTree')
  return new_name

def plot_with_delta_multiple(tables, name, keys, out_name, use_log=True, formatter=int):
  plt.clf()
  fig = plt.figure()
  fig.suptitle(name, fontsize=14, fontweight='bold')
  ax = fig.add_subplot(111)
  ax.grid(True)


  ax.set_xlabel('$\epsilon$')
  #ax.set_ylabel(key)
  table = tables[name]
  for key in keys:
    values = [formatter(x) for x in table[key]]
    ax.plot(table['key/t'], values, label=get_short_name(key), marker='x')

  if use_log:
    ax.set_yscale('log')
  plt.legend(bbox_to_anchor=(1, 1), bbox_transform=plt.gcf().transFigure)

  # Shrink current axis's height by 10% on the bottom
  box = ax.get_position()
  ax.set_position([box.x0, box.y0 + box.height * 0.2,
                   box.width, box.height * 0.8])

  # Put a legend below current axis
  ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1),
            fancybox=True, shadow=True, ncol=1, prop={'size':6})


  pp = PdfPages('%s.pdf' % out_name)
  fig.savefig(pp, format='pdf')
  #pp.savefig()
  pp.close()


def plot_with_delta(tables, key, use_log=True, formatter=int):
  plt.clf()
  fig = plt.figure()
  fig.suptitle(key, fontsize=14, fontweight='bold')
  ax = fig.add_subplot(111)
  ax.grid(True)

  ax.set_xlabel('$\epsilon$')
  ax.set_ylabel(key)
  for name in tables:
    values = [formatter(x) for x in tables[name][key]]
    ax.plot(tables[name]['key/t'], values, label=get_short_name(name))

  if use_log:
    ax.set_yscale('log')
  plt.legend(bbox_to_anchor=(1, 1), bbox_transform=plt.gcf().transFigure)

  # Shrink current axis's height by 10% on the bottom
  box = ax.get_position()
  ax.set_position([box.x0, box.y0 + box.height * 0.2,
                   box.width, box.height * 0.8])

  # Put a legend below current axis
  ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1),
            fancybox=True, shadow=True, ncol=1, prop={'size':6})


  pp = PdfPages('%s.pdf' % key)
  fig.savefig(pp, format='pdf')
  #pp.savefig()
  pp.close()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('result_dirs', nargs='+' )
  args = parser.parse_args()
  main(args.result_dirs)


    
