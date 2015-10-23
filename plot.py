#!/usr/bin/env python


import argparse
import csv
import glob
import os
import itertools
from pylab import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from asyncore import loop


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
keys.append('num_per_pkt_entry_version_race')
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


per_pkt_consistency =  ['num_per_pkt_races', 'num_per_pkt_inconsistent',
                        'num_per_pkt_inconsistent_covered',
                        'num_per_pkt_entry_version_race']
prefixes = ['True-','False-']

timing_values = {'0': 0,
                 '1': 1,
                 '2': 2,
                 '3': 3,
                 '4': 4,
                 '5': 5,
                 '6': 6,
                 '7': 7,
                 '8': 8,
                 '9': 9,
                 '10': 10,
                 'inf': 11, # hack for plots
                 }

# http://matplotlib.org/api/markers_api.html
markers = ['x',
           '+',
           '.',
           'o',
           '*',
#            ',',
           '1',
           '2',
           '3',
           '4',
           '8',
           '<',
           '>',
           'D',
           'H',
           '^',
           '_',
           'd',
           'h',
           'p',
           's',
           'v',
           '|',
           0,
           1,
           2,
           3,
           4,
           5,
           6,
           7,]


def main(result_dirs):
  tables = {}
  base_names = []
  lookup_tables = {}
  row_mapping = {}
  col_mapping = {}
  for p in prefixes:
    tables[p] = {}
  for name in result_dirs:
    fname = name
    if not fname.endswith('.csv'):
      fname = os.path.join(name, 'summary.csv')
    with open(fname) as csvfile:
      table = {}
      keys = []
      base_name = os.path.basename(os.path.normpath(name))
      assert base_name not in base_names
      base_names.append(base_name)
      csviter = csv.reader(csvfile, delimiter=',')
      csvdata = []
      for row in csviter:
        csvdata.append(row)
      
      lookup_tables[base_name] = {}
      row_mapping[base_name] = {}
      for ridx,row in enumerate(csvdata):
        # first row has to contain header
        # generate a lookup table
        key = row[0]
        if ridx == 0:
          assert key == 'key/t'
          row_mapping[base_name][ridx] = key
          col_mapping[base_name] = {}
          for cidx, col_name in enumerate(row):
            col_mapping[base_name][cidx] = col_name
            lookup_tables[base_name][col_name] = {}
        else:
          assert base_name in col_mapping
          row_mapping[base_name][ridx] = key
          for cidx, field_value in enumerate(row):
            col_name = col_mapping[base_name][cidx]
            lookup_tables[base_name][col_name][key] = field_value
    
      for p in prefixes:
        table[p] = {}
        
        col_names_with_prefix = {}
        for col_name in lookup_tables[base_name]:
          if col_name != 'key/t' and str(col_name).startswith(p):
            timing_str = str(col_name).partition(p)[2]
            assert timing_str in timing_values
            timing_as_integer = timing_values[timing_str]
            col_names_with_prefix[col_name] = timing_as_integer
            
        # sort by timing so that pyplot can understand it, tuples of (key, value)
        sorted_col_names_with_prefix = sorted(col_names_with_prefix.items(), key=lambda x: x[1])
        
        for ridx,key in row_mapping[base_name].iteritems():
          row_values = []
          if ridx == 0:
            for col_name, timing in sorted_col_names_with_prefix:
              row_values.append(timing)
            table[p][key] = row_values
          else:
            for col_name, timing in sorted_col_names_with_prefix:
              field_value = lookup_tables[base_name][col_name][key]
              row_values.append(field_value)
            table[p][key] = row_values
        tables[p][base_name] = table[p]
  
  keys_to_plot = ['num_harmful', 'num_commute', 'num_races', 'num_rw_time_edges', 'num_ww_time_edges',
            'num_per_pkt_races', 'num_per_pkt_inconsistent', 'num_per_pkt_inconsistent_covered', 'num_per_pkt_entry_version_race', 'num_per_pkt_inconsistent_no_repeat']

  # Plot summaries for all values
  for p in prefixes:
    for key in keys_to_plot:
      plot_with_delta(tables[p], p, key, False)
    
    for name in tables[p]:
      plot_with_delta_multiple(tables[p], p, name,
                               out_name=get_short_name(name) + "_pkt_consist",
                               keys=per_pkt_consistency,
                               use_log=False)
      plot_with_delta_multiple(tables[p], p, name,
                               out_name=get_short_name(name) + "_overview_covered_races",
                               keys=['num_harmful', 
                                     'num_covered'],
                               use_log=True)
      plot_with_delta_multiple(tables[p], p, name,
                               out_name=get_short_name(name) + "_overview_covered_traces",
                               keys=['num_per_pkt_inconsistent',
                                     'num_per_pkt_inconsistent_covered',
                                     'num_per_pkt_entry_version_race',
                                     'num_per_pkt_inconsistent_no_repeat'],
                               use_log=True)

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

def plot_with_delta_multiple(tables, prefix, name, keys, out_name, use_log=True, formatter=int):
  plt.clf()
  fig = plt.figure()
  fig.suptitle(name, fontsize=14, fontweight='bold')
  ax = fig.add_subplot(111)
  ax.grid(True)

  marker = itertools.cycle(markers) # repeat forever

  ax.set_xlabel('$\epsilon$')
  #ax.set_ylabel(key)
  table = tables[name]
  for key in keys:
    values = [formatter(x) for x in table[key]]
    ax.plot(table['key/t'], values, label=get_short_name(key), marker=marker.next())

  if use_log:
    ax.set_yscale('log')
    ax.yaxis.set_major_formatter(ScalarFormatter())
    ax.ticklabel_format(style='plain', axis='y')
  plt.legend(bbox_to_anchor=(1, 1), bbox_transform=plt.gcf().transFigure)

  # Shrink current axis's height by 10% on the bottom
  box = ax.get_position()
  ax.set_position([box.x0, box.y0 + box.height * 0.2,
                   box.width, box.height * 0.8])

  # Put a legend below current axis
  ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1),
            fancybox=True, shadow=True, ncol=1, prop={'size':6})

  fname = '%s%s.pdf' % (prefix, out_name)
  print fname
  pp = PdfPages(fname)
  fig.savefig(pp, format='pdf')
  #pp.savefig()
  pp.close()
  plt.close(fig)

def plot_with_delta(tables, prefix, key, use_log=True, formatter=int):
  plt.clf()
  fig = plt.figure()
  fig.suptitle(key, fontsize=14, fontweight='bold')
  ax = fig.add_subplot(111)
  ax.grid(True)
  
  marker = itertools.cycle(markers) # repeat forever

  ax.set_xlabel('$\epsilon$')
  ax.set_ylabel(key)
  for name in tables:
    values = [formatter(x) for x in tables[name][key]]
    ax.plot(tables[name]['key/t'], values, label=get_short_name(name), marker=marker.next())

  if use_log:
    ax.set_yscale('log')
    ax.yaxis.set_major_formatter(ScalarFormatter())
    ax.ticklabel_format(style='plain', axis='y')
  plt.legend(bbox_to_anchor=(1, 1), bbox_transform=plt.gcf().transFigure)

  # Shrink current axis's height by 10% on the bottom
  box = ax.get_position()
  ax.set_position([box.x0, box.y0 + box.height * 0.2,
                   box.width, box.height * 0.8])

  # Put a legend below current axis
  ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1),
            fancybox=True, shadow=True, ncol=1, prop={'size':6})

  fname = '%s%s.pdf' % (prefix, key)
  print fname
  pp = PdfPages(fname)
  fig.savefig(pp, format='pdf')
  #pp.savefig()
  pp.close()
  plt.close(fig)

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('result_dirs', nargs='+' )
  args = parser.parse_args()
  main(args.result_dirs)


    
