#!/usr/bin/env python


"""
Helper script to extract all the data from *.dat files and generate one table
"""

import argparse
import csv
import glob
import os
import matplotlib.pyplot as plt


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

keys.append('num_per_pkt_races')
keys.append('num_per_pkt_inconsistent')
keys.append('num_per_pkt_inconsistent_covered')
keys.append('num_per_pkt_race_version')
keys.append('num_per_pkt_inconsistent_no_repeat')

keys.append('load_time_sec')
keys.append('detect_races_time_sec')
keys.append('extract_traces_time_sec')
keys.append('per_packet_inconsistent_time_sec')
keys.append('find_reactive_cmds_time_sec')
keys.append('find_proactive_cmds_time_sec')
keys.append('find_inconsistent_update_time_sec')





def main(result_dir):
  table = {}
  for key in keys:
    table[key] = {}
    
  for fname in glob.glob(os.path.join(result_dir, 'results*.dat')):
    print "READING FILE", fname
    with open(fname, 'r') as csvfile:
      data = csv.reader(csvfile, delimiter=',')
      t = None
      for row in data:
        key, value = row[0].strip(), row[1].strip()
        if key in ['rw_delta', 'ww_delta']:
          if value != 'inf':
            value = int(value)
          if t is None:
            t = value
          else:
            assert t == value
        if key in table:
          table[key][t] = value

  outname = os.path.join(result_dir, 'summary.csv')
  print "Saving results to", outname
  with open(outname, 'w') as f:
    wr = csv.writer(f, delimiter=',')
    for key, values in table.iteritems():
      row = ['key/t'] + list(reversed(sorted(values.keys())))
      wr.writerow(row)
      break
    for key in keys:
      values = table[key]
      times = reversed(sorted(values.keys()))
      row = [key] + [values[t] for t in times]
      wr.writerow(row)


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('result_dir')
  args = parser.parse_args()
  main(args.result_dir)
