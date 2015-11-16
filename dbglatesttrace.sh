#!/bin/bash

function mytracefun() {
  #TRACEDIR=`ls -td -- */ | head -n 1 | cut -d'/' -f1`
  TRACEDIR=`ls -td -- */* | head -n 1 | cut -d'/' -f1,2`
  echo "Latest trace directory (last modified): $TRACEDIR"
  echo -n "hb.json lines: "
  cat $TRACEDIR/hb.json | wc -l
  echo -n "simulator.out lines: "
  cat $TRACEDIR/simulator.out | wc -l
  echo -n "simulator.out rounds: "
  cat $TRACEDIR/simulator.out | grep Round | tail -n 1 | cut -d' ' -f1,2
  echo -n "simulator.out # of: warn "
  cat $TRACEDIR/simulator.out | grep -i -c warn
  echo -n "simulator.out # of: error "
  cat $TRACEDIR/simulator.out | grep -i error | grep -v errorStatus | wc -l
  echo -n "simulator.out # of: assertion "
  cat $TRACEDIR/simulator.out | grep -i -c assertion
  echo -n "simulator.out # of: OFPP_TABLE "
  cat $TRACEDIR/simulator.out | grep -i -c OFPP_TABLE
  echo -n "simulator.out # of: \"out_port is OFPP_TABLE, but no entry was found\" "
  cat $TRACEDIR/simulator.out | grep -i -c "out_port is OFPP_TABLE, but no entry was found"
  echo -n "simulator.out # of: ECHO_REQUEST "
  cat $TRACEDIR/simulator.out | grep -i -c ECHO_REQUEST
  echo -n "simulator.out # of: ECHO_REPLY "
  cat $TRACEDIR/simulator.out | grep -i -c ECHO_REPLY
  echo -n "simulator.out # of: \"Both source and destination are on the same\" "
  cat $TRACEDIR/simulator.out | grep -i -c "Both source and destination are on the same"
  echo -n "simulator.out # of: \"Removed circuit\" "
  cat $TRACEDIR/simulator.out | grep -i -c "Removed circuit"
  echo -n "simulator.out # of: \"Installed circuit\" "
  cat $TRACEDIR/simulator.out | grep -i -c "Installed circuit"
  echo -n "simulator.out # of: \"Removing circuit\" "
  cat $TRACEDIR/simulator.out | grep -i -c "Removing circuit"
  echo -n "simulator.out # of: \"Installing circuit\" "
  cat $TRACEDIR/simulator.out | grep -i -c "Installing circuit"
  echo -n "simulator.out # of: \"XXXX\" "
  cat $TRACEDIR/simulator.out | grep -i -c "XXXX"
  echo -n "simulator.out # of: \"XXXX1\" "
  cat $TRACEDIR/simulator.out | grep -i -c "XXXX1"
  echo -n "simulator.out # of: \"XXXX2\" "
  cat $TRACEDIR/simulator.out | grep -i -c "XXXX2"
  echo -n "simulator.out # of: \"XXXX3\" "
  cat $TRACEDIR/simulator.out | grep -i -c "XXXX3"
}
export -f mytracefun
watch -n 2 bash -c "mytracefun"
