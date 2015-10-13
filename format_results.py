#!/usr/bin/env python


"""
Helper script to extract all the data from *.dat files and generate one table
"""

import argparse
import csv
import glob
import os
import matplotlib.pyplot as plt
import re


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

timing_keys = []

timing_keys.append('total_time_sec')
timing_keys.append('load_time_sec')
timing_keys.append('detect_races_time_sec')
timing_keys.append('extract_traces_time_sec')
timing_keys.append('find_reactive_cmds_time_sec')
timing_keys.append('find_proactive_cmds_time_sec')
timing_keys.append('find_covered_races_time')
timing_keys.append('per_packet_inconsistent_time_sec')
timing_keys.append('find_inconsistent_update_time_sec')




def main(result_dir):
  
  def natural_keys(text):
    def atoi(text):
      return int(text) if text.isdigit() else text
    return [ atoi(c) for c in re.split('(\d+)', text) ]
 
  def format_dat_to_csv(keys, infiles, outname):
    table = {}
    for key in keys:
      table[key] = {}
    for fname in infiles:
      print "READING FILE", fname
      with open(fname, 'r') as csvfile:
        data = csv.reader(csvfile, delimiter=',')
        t = None
        ab = None
        for row in data:
          key, value = row[0].strip(), row[1].strip()
          if key in ['alt_barr']:
            ab = value
          if key in ['rw_delta', 'ww_delta']:
            if value != 'inf':
              value = int(value)
            if t is None:
              t = value
            else:
              # TODO(jm): This is a really weird way of checking that rw_delta == ww_delta. 
              #           We should make t a tuple (t_rw, t_ww) and print that out.
              #           If this assertion fails you might need to delete any *.dat files
              #           remaining from previous runs where rw_delta != ww_delta  
              assert t == value
          if key in table:
            table[key][str(ab) + '-' + str(t)] = value
  
    print "Saving results to", outname
    with open(outname, 'w') as f:
      wr = csv.writer(f, delimiter=',')
      for key, values in table.iteritems():
        row = ['key/t'] + list(sorted(values.keys(), key=natural_keys))
        wr.writerow(row)
        break
      for key in keys:
        values = table[key]
        times = reversed(sorted(values.keys()))
        row = [key] + [values[t] for t in times]
        wr.writerow(row)
        
  # results
  format_dat_to_csv(keys,
                    glob.glob(os.path.join(result_dir, 'results*.dat')),
                    os.path.join(result_dir, 'summary.csv'))
  # results
  format_dat_to_csv(timing_keys,
                    glob.glob(os.path.join(result_dir, 'timings*.dat')),
                    os.path.join(result_dir, 'summary_timings.csv'))
  


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('result_dir')
  args = parser.parse_args()
  main(args.result_dir)
