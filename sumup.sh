#!/bin/bash

find ../sdnracer-traces/ -maxdepth 1 -type d -name "trace_*" -print0 | sort -nz | xargs -0 ./plot.py --no-plots
