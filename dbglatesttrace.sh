#!/bin/bash

function mytracefun() {
  #TRACEDIR=`ls -td -- */ | head -n 1 | cut -d'/' -f1`
  TRACEDIR=`ls -td -- traces/* | head -n 1 | cut -d'/' -f1,2`
  echo "Latest trace directory: $TRACEDIR"
  echo -n "hb.json lines: "
  cat $TRACEDIR/hb.json | wc -l
  echo -n "simulator.out lines: "
  cat $TRACEDIR/simulator.out | wc -l
  echo -n "simulator.out rounds: "
  cat $TRACEDIR/simulator.out | grep Round | tail -n 1 | cut -d' ' -f1,2
}
export -f mytracefun
watch -n 1 bash -c "mytracefun"
